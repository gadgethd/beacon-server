// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicsource

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const MaxBatchSize = 500

var (
	ErrNotReady          = errors.New("public history source is not ready")
	ErrGenerationChanged = errors.New("public history generation changed; reconcile projection before resuming")
	ErrCursor            = errors.New("invalid public history cursor or network scope")
	ErrContract          = errors.New("unsupported or malformed public history contract")
)

// Cursor binds committed-order progress to its network set and privacy epoch.
// The all-zero value starts a new source; no timestamp is used as a watermark.
type Cursor struct {
	Version    int      `json:"version"`
	Generation int64    `json:"generation"`
	Sequence   int64    `json:"sequence"`
	Networks   []string `json:"networks"`
}

type Batch struct {
	Outcomes []Outcome
	Next     Cursor
}

type state struct {
	contract                 int32
	generation, materialized int64
	coverage                 int32
	ready                    bool
}

const stateSQL = `SELECT source_contract_version, COALESCE(generation,0),
 COALESCE(visibility_generation,0), COALESCE(ledger_coverage_version,0), ready
 FROM beacon_public.source_state`

const batchSQL = `SELECT seq, observation_id, time, network, iata,
 packet_uid, identity_version, identity_provenance, packet_hash, packet_type,
 topic, rx_node_id, src_node_id, path_hashes, path_hash_size_bytes, rssi, snr,
 direction, raw_input_status, raw_hex
 FROM beacon_public.packets
 WHERE seq > $1 AND network = ANY($2::text[])
 ORDER BY seq LIMIT $3`

// Source borrows the caller's restricted pool; it never owns/closes that pool
// or reads credentials. Construction does not open a database connection.
type Source struct {
	networks []string
	begin    func(context.Context, pgx.TxOptions) (pgx.Tx, error)
	current  func(context.Context) (state, error)
}

func New(pool *pgxpool.Pool, networks []string) (*Source, error) {
	if pool == nil {
		return nil, ErrContract
	}
	scope, err := networkSet(networks)
	if err != nil {
		return nil, err
	}
	return &Source{networks: scope, begin: pool.BeginTx,
		current: func(ctx context.Context) (state, error) { return readState(pool.QueryRow(ctx, stateSQL)) },
	}, nil
}

func networkSet(networks []string) ([]string, error) {
	if len(networks) == 0 {
		return nil, ErrCursor
	}
	out := append([]string(nil), networks...)
	sort.Strings(out)
	for i, network := range out {
		if network == "" || strings.TrimSpace(network) != network || i > 0 && network == out[i-1] {
			return nil, ErrCursor
		}
	}
	return out, nil
}

func readState(row pgx.Row) (state, error) {
	var value state
	if err := row.Scan(&value.contract, &value.generation, &value.materialized, &value.coverage, &value.ready); err != nil {
		return value, fmt.Errorf("read public source state: %w", err)
	}
	if value.contract != 1 || value.coverage != 1 {
		return value, ErrContract
	}
	if !value.ready || value.generation <= 0 || value.materialized != value.generation {
		return value, ErrNotReady
	}
	return value, nil
}

// ReadBatch returns at most limit per-observation outcomes. Generation changes
// never silently reset a cursor. A fresh post-transaction fence is required:
// checking twice inside Repeatable Read alone cannot observe a policy change.
func (s *Source) ReadBatch(ctx context.Context, cursor Cursor, limit int) (batch Batch, err error) {
	if limit < 1 || limit > MaxBatchSize {
		return batch, ErrCursor
	}
	initial := cursor.Version == 0 && cursor.Generation == 0 && cursor.Sequence == 0 && len(cursor.Networks) == 0
	if !initial && (cursor.Version != 1 || cursor.Generation <= 0 || cursor.Sequence < 0 || !slices.Equal(cursor.Networks, s.networks)) {
		return batch, ErrCursor
	}
	tx, err := s.begin(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return batch, fmt.Errorf("begin public source snapshot: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if closeErr := tx.Rollback(cleanup); closeErr != nil && !errors.Is(closeErr, pgx.ErrTxClosed) {
			err = errors.Join(err, fmt.Errorf("close public source snapshot: %w", closeErr))
			batch = Batch{}
		}
	}()
	before, err := readState(tx.QueryRow(ctx, stateSQL))
	if err != nil {
		return Batch{}, err
	}
	if !initial && cursor.Generation != before.generation {
		return Batch{}, ErrGenerationChanged
	}
	rows, err := tx.Query(ctx, batchSQL, cursor.Sequence, s.networks, limit)
	if err != nil {
		return Batch{}, fmt.Errorf("read public history: %w", err)
	}
	outcomes, last, err := collect(rows, cursor.Sequence, limit, s.networks)
	if err != nil {
		return Batch{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Batch{}, fmt.Errorf("commit public source snapshot: %w", err)
	}
	after, err := s.current(ctx)
	if err != nil {
		return Batch{}, err
	}
	if before.generation != after.generation {
		return Batch{}, ErrGenerationChanged
	}
	return Batch{Outcomes: outcomes, Next: Cursor{Version: 1, Generation: before.generation,
		Sequence: last, Networks: append([]string(nil), s.networks...)}}, nil
}

func collect(rows pgx.Rows, cursor int64, limit int, networks []string) ([]Outcome, int64, error) {
	defer rows.Close()
	out := make([]Outcome, 0, limit)
	seen := make(map[uuid.UUID]bool, limit)
	for rows.Next() {
		var row sourceRow
		if err := rows.Scan(&row.seq, &row.id, &row.at, &row.network, &row.iata,
			&row.uid, &row.version, &row.provenance, &row.alias, &row.packetType,
			&row.topic, &row.receiver, &row.source, &row.paths, &row.pathSize,
			&row.rssi, &row.snr, &row.direction, &row.status, &row.raw); err != nil {
			return nil, cursor, fmt.Errorf("read public observation: %w", err)
		}
		if len(out) >= limit || row.seq <= cursor || row.id == uuid.Nil || seen[row.id] || row.at.IsZero() || !sortIsMember(networks, row.network) || !knownStatus(row.status) {
			return nil, cursor, ErrContract
		}
		seen[row.id] = true
		cursor = row.seq
		out = append(out, verify(row))
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, fmt.Errorf("finish public history: %w", err)
	}
	return out, cursor, nil
}

func sortIsMember(networks []string, network string) bool {
	i := sort.SearchStrings(networks, network)
	return i < len(networks) && networks[i] == network
}

func knownStatus(status string) bool {
	switch status {
	case "candidate-for-decode", string(MissingUID), string(InvalidUID), string(UnsupportedVersion),
		string(InvalidObserver), string(MissingRaw), string(InvalidHex):
		return true
	default:
		return false
	}
}
