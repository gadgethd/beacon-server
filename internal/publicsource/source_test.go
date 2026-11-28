// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicsource

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func ptr[T any](v T) *T { return &v }

const payloadHex = "11aabb01010101010101010101010101010101"

func observationRow() sourceRow {
	uid, _ := hex.DecodeString("9d54cea2f71af7aff8e0c9a07ded55eaf3bee5f32f2385942166564ba6c91b74")
	return sourceRow{seq: 1, id: uuid.New(), at: time.Date(2020, 1, 2, 3, 4, 5, 123456000, time.UTC),
		network: "ukmesh", iata: ptr("LON"), uid: uid, version: ptr(UIDVersion),
		provenance: ptr("meshcore-decoded-wire"), alias: "unrelated-legacy-alias", packetType: 5,
		topic: "meshcore/LON/fixture/packets", receiver: ptr(strings.Repeat("aB", 32)),
		paths: []string{}, pathSize: ptr(int32(1)), status: "candidate-for-decode", raw: ptr("1500" + payloadHex)}
}

func TestVerifyNativeGroupTextAndExactDualIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, frame string
		paths       []string
		width       int32
	}{
		{"flood", "1500" + payloadHex, []string{}, 1},
		{"transport-two-byte-path", "141122334442AABBCCDD" + payloadHex, []string{"aabb", "CCDD"}, 2},
		{"direct-three-byte-path", "1682AABBCC010203" + payloadHex, []string{"AABBCC", "010203"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := observationRow()
			row.rssi, row.snr = ptr(-70.123456789), ptr(3.875691234)
			row.raw, row.paths, row.pathSize = &tc.frame, tc.paths, &tc.width
			out := verify(row)
			if out.Reason != "" || out.Observation == nil {
				t.Fatalf("rejected: %s", out.Reason)
			}
			got := out.Observation
			if got.ID != row.id || !got.Time.Equal(row.at) || got.Time.Nanosecond() != 123456000 {
				t.Fatal("changed upstream observation/time")
			}
			if hex.EncodeToString(got.UID[:]) != "9d54cea2f71af7aff8e0c9a07ded55eaf3bee5f32f2385942166564ba6c91b74" {
				t.Fatal("wrong UKMesh UID")
			}
			if hex.EncodeToString(got.BeaconHash[:]) != "ba2d3a679a03ef22" {
				t.Fatal("wrong native Beacon key")
			}
			if got.GroupText.ChannelHash != 0x11 || got.LegacyAlias != row.alias {
				t.Fatal("lost native group or alias metadata")
			}
			if *got.RSSI != *row.rssi || *got.SNR != *row.snr {
				t.Fatal("source signal precision changed")
			}
			if hex.EncodeToString(got.ObserverKey[:]) != strings.Repeat("ab", 32) {
				t.Fatal("observer key was not decoded losslessly")
			}
		})
	}
}

func TestVerifyRejectsUnsupportedAndInconsistentInputs(t *testing.T) {
	tests := []struct {
		name   string
		change func(*sourceRow)
		want   Reason
	}{
		{"source-missing", func(r *sourceRow) { r.status = string(MissingRaw); r.raw = nil }, MissingRaw},
		{"uid-missing", func(r *sourceRow) { r.uid = nil }, MissingUID},
		{"uid-short", func(r *sourceRow) { r.uid = r.uid[:8] }, InvalidUID},
		{"future-identity", func(r *sourceRow) { r.version = ptr("wire-v2") }, UnsupportedVersion},
		{"observer-prefix", func(r *sourceRow) { r.receiver = ptr("AB") }, InvalidObserver},
		{"observer-nonhex", func(r *sourceRow) { r.receiver = ptr(strings.Repeat("Z", 64)) }, InvalidObserver},
		{"raw-missing", func(r *sourceRow) { r.raw = nil }, MissingRaw},
		{"odd-hex", func(r *sourceRow) { r.raw = ptr("ABC") }, InvalidHex},
		{"truncated-framing", func(r *sourceRow) { r.raw = ptr("14") }, InvalidFrame},
		{"reserved-path-width", func(r *sourceRow) { r.raw = ptr("15C0" + payloadHex) }, InvalidFrame},
		{"other-payload", func(r *sourceRow) { r.raw = ptr("1100" + payloadHex) }, NotGroupText},
		{"non-group-row", func(r *sourceRow) { r.packetType = 4 }, NotGroupText},
		{"future-payload", func(r *sourceRow) { r.raw = ptr("5500" + payloadHex) }, UnsupportedPayload},
		{"short-group-mac", func(r *sourceRow) { r.raw = ptr("150011AA") }, InvalidGroupText},
		{"partial-cipher-block", func(r *sourceRow) { r.raw = ptr("150011AABB01") }, InvalidGroupText},
		{"uid-mismatch", func(r *sourceRow) { r.uid[0] ^= 0xff }, UIDMismatch},
		{"path-metadata", func(r *sourceRow) { r.paths = []string{"AA"} }, PathMismatch},
		{"path-width-metadata", func(r *sourceRow) { r.pathSize = ptr(int32(2)) }, PathMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := observationRow()
			tc.change(&row)
			got := verify(row)
			if got.Reason != tc.want || got.Observation != nil || got.ObservationID != row.id {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
		})
	}
}

type scanRow struct {
	values []any
	err    error
}

func (r scanRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("wrong scan width")
	}
	for i, value := range r.values {
		target := reflect.ValueOf(dest[i]).Elem()
		if value == nil {
			target.SetZero()
		} else {
			target.Set(reflect.ValueOf(value))
		}
	}
	return nil
}

type fakeRows struct {
	pgx.Rows
	data         []sourceRow
	index        int
	closed       bool
	err, scanErr error
}

func (r *fakeRows) Next() bool {
	if r.index >= len(r.data) {
		return false
	}
	r.index++
	return true
}
func (r *fakeRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	v := r.data[r.index-1]
	return (scanRow{values: []any{v.seq, v.id, v.at, v.network, v.iata, v.uid, v.version, v.provenance, v.alias,
		v.packetType, v.topic, v.receiver, v.source, v.paths, v.pathSize, v.rssi, v.snr, v.direction, v.status, v.raw}}).Scan(dest...)
}
func (r *fakeRows) Close()     { r.closed = true }
func (r *fakeRows) Err() error { return r.err }

type fakeTx struct {
	pgx.Tx
	state                            state
	rows                             *fakeRows
	queryErr, commitErr, rollbackErr error
	committed, rolledBack            bool
	args                             []any
	onQuery                          func()
	cleanupContextErr                error
}

func stateRow(s state) scanRow {
	return scanRow{values: []any{s.contract, s.generation, s.materialized, s.coverage, s.ready}}
}
func (f *fakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return stateRow(f.state) }
func (f *fakeTx) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if sql != batchSQL {
		return nil, errors.New("unexpected statement")
	}
	f.args = args
	if f.onQuery != nil {
		f.onQuery()
	}
	return f.rows, f.queryErr
}
func (f *fakeTx) Commit(context.Context) error {
	if f.commitErr == nil {
		f.committed = true
	}
	return f.commitErr
}
func (f *fakeTx) Rollback(ctx context.Context) error {
	f.rolledBack = true
	f.cleanupContextErr = ctx.Err()
	if f.committed {
		return pgx.ErrTxClosed
	}
	return f.rollbackErr
}

var ready = state{contract: 1, generation: 7, materialized: 7, coverage: 1, ready: true}

func sourceFixture(t *testing.T, data []sourceRow) (*Source, *fakeTx) {
	t.Helper()
	tx := &fakeTx{state: ready, rows: &fakeRows{data: data}}
	s := &Source{networks: []string{"ukmesh"}}
	s.begin = func(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
		if options.AccessMode != pgx.ReadOnly || options.IsoLevel != pgx.RepeatableRead {
			t.Fatal("source lost its read-only snapshot")
		}
		return tx, nil
	}
	s.current = func(context.Context) (state, error) {
		if !tx.committed {
			t.Fatal("current fence was read inside the historical snapshot")
		}
		return readState(stateRow(ready))
	}
	return s, tx
}

func TestBatchRetainsDistinctHearingsAndAccountsForRejections(t *testing.T) {
	a, b, c := observationRow(), observationRow(), observationRow()
	b.seq, c.seq, c.status, c.raw = 3, 5, string(MissingRaw), nil
	s, tx := sourceFixture(t, []sourceRow{a, b, c})
	batch, err := s.ReadBatch(context.Background(), Cursor{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Outcomes) != 3 || batch.Outcomes[0].Observation.ID == batch.Outcomes[1].Observation.ID || batch.Outcomes[2].Reason != MissingRaw {
		t.Fatal("collapsed hearings or lost rejected coverage")
	}
	if !reflect.DeepEqual(batch.Next, Cursor{Version: 1, Generation: 7, Sequence: 5, Networks: []string{"ukmesh"}}) {
		t.Fatalf("wrong cursor %+v", batch.Next)
	}
	if !reflect.DeepEqual(tx.args, []any{int64(0), []string{"ukmesh"}, 3}) || !tx.rows.closed || !tx.committed {
		t.Fatal("scope/limit or settlement changed")
	}
	// The next bounded page resumes by committed seq, including rollback gaps.
	next, nextTx := sourceFixture(t, nil)
	empty, err := next.ReadBatch(context.Background(), batch.Next, 3)
	if err != nil || empty.Next.Sequence != 5 || nextTx.args[0] != int64(5) {
		t.Fatal("bad resume or empty-source cursor")
	}
}

func TestCursorAndSourceContractFailClosed(t *testing.T) {
	for _, cursor := range []Cursor{
		{Version: 2, Generation: 7, Networks: []string{"ukmesh"}},
		{Version: 1, Generation: 7, Sequence: -1, Networks: []string{"ukmesh"}},
		{Version: 1, Generation: 7, Sequence: 1, Networks: []string{"another"}},
		{Version: 1, Generation: 0, Sequence: 1, Networks: []string{"ukmesh"}},
	} {
		s, _ := sourceFixture(t, nil)
		if _, err := s.ReadBatch(context.Background(), cursor, 1); !errors.Is(err, ErrCursor) {
			t.Fatalf("accepted cursor %+v", cursor)
		}
	}
	for _, limit := range []int{0, 501} {
		s, _ := sourceFixture(t, nil)
		if _, err := s.ReadBatch(context.Background(), Cursor{}, limit); !errors.Is(err, ErrCursor) {
			t.Fatal("accepted unbounded limit")
		}
	}
	for _, scope := range [][]string{nil, {""}, {" ukmesh"}, {"ukmesh", "ukmesh"}} {
		if _, err := networkSet(scope); !errors.Is(err, ErrCursor) {
			t.Fatalf("accepted scope %v", scope)
		}
	}
	for _, change := range []func(*sourceRow){
		func(r *sourceRow) { r.id = uuid.Nil }, func(r *sourceRow) { r.seq = 0 },
		func(r *sourceRow) { r.network = "another" }, func(r *sourceRow) { r.status = "future-status" },
	} {
		row := observationRow()
		change(&row)
		s, _ := sourceFixture(t, []sourceRow{row})
		if _, err := s.ReadBatch(context.Background(), Cursor{}, 1); !errors.Is(err, ErrContract) {
			t.Fatal("accepted malformed source row")
		}
	}
	a, b := observationRow(), observationRow()
	b.seq = 2
	b.id = a.id
	s, _ := sourceFixture(t, []sourceRow{a, b})
	if _, err := s.ReadBatch(context.Background(), Cursor{}, 2); !errors.Is(err, ErrContract) {
		t.Fatal("accepted duplicate upstream ID")
	}
}

func TestPrivacyEpochAndReadinessFences(t *testing.T) {
	for _, change := range []func(*state){
		func(s *state) { s.ready = false }, func(s *state) { s.materialized = 6 },
		func(s *state) { s.generation = 0 }, func(s *state) { s.coverage = 2 }, func(s *state) { s.contract = 2 },
	} {
		s, tx := sourceFixture(t, nil)
		change(&tx.state)
		if _, err := s.ReadBatch(context.Background(), Cursor{}, 1); err == nil || !tx.rolledBack || tx.committed {
			t.Fatal("admitted unavailable snapshot")
		}
	}
	s, tx := sourceFixture(t, []sourceRow{observationRow()})
	s.current = func(context.Context) (state, error) {
		changed := ready
		changed.generation = 8
		changed.materialized = 8
		return readState(stateRow(changed))
	}
	if batch, err := s.ReadBatch(context.Background(), Cursor{}, 1); !errors.Is(err, ErrGenerationChanged) || len(batch.Outcomes) != 0 || !tx.committed {
		t.Fatal("released data after privacy generation changed")
	}
	s, tx = sourceFixture(t, nil)
	if _, err := s.ReadBatch(context.Background(), Cursor{Version: 1, Generation: 6, Networks: []string{"ukmesh"}}, 1); !errors.Is(err, ErrGenerationChanged) || !tx.rolledBack {
		t.Fatal("silently restarted old generation")
	}
}

func TestReadAndCleanupErrorsNeverAdvanceCursor(t *testing.T) {
	problem := errors.New("owned failure")
	for _, stage := range []string{"query", "scan", "rows", "commit", "current", "rollback"} {
		t.Run(stage, func(t *testing.T) {
			s, tx := sourceFixture(t, []sourceRow{observationRow()})
			switch stage {
			case "query":
				tx.queryErr = problem
			case "scan":
				tx.rows.scanErr = problem
			case "rows":
				tx.rows.err = problem
			case "commit":
				tx.commitErr = problem
			case "current":
				s.current = func(context.Context) (state, error) { return state{}, problem }
			case "rollback":
				tx.queryErr = problem
				tx.rollbackErr = errors.New("cleanup failed")
			}
			batch, err := s.ReadBatch(context.Background(), Cursor{}, 1)
			if !errors.Is(err, problem) || batch.Next.Version != 0 || len(batch.Outcomes) != 0 || !tx.rolledBack {
				t.Fatal("error returned progress or escaped settlement")
			}
			if stage == "rollback" && !strings.Contains(err.Error(), "cleanup failed") {
				t.Fatal("lost cleanup cause")
			}
		})
	}
}

func TestCancellationSettlesWithAnUncancelledCleanupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, tx := sourceFixture(t, nil)
	tx.onQuery, tx.queryErr = cancel, context.Canceled
	batch, err := s.ReadBatch(ctx, Cursor{}, 1)
	if !errors.Is(err, context.Canceled) || !tx.rolledBack || tx.cleanupContextErr != nil || batch.Next.Version != 0 {
		t.Fatal("cancellation escaped snapshot cleanup or returned progress")
	}
}
