// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicprojection

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
	"github.com/MeshCore-Beacon/beacon-server/internal/publicsource"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

type PGStore struct {
	pool          *pgxpool.Pool
	retentionDays int
}

func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

// Install is an explicit migration-owner operation, never called by New or a
// read handler. It creates only the separate ukmesh_public namespace.
func (s *PGStore) Install(ctx context.Context) error { _, err := s.pool.Exec(ctx, schema); return err }

type checkpoint struct {
	generation                    int64
	registry                      string
	ready                         bool
	historyComplete, liveComplete bool
	revision                      int64
	history                       publicsource.Cursor
	live                          string
}

func (c checkpoint) matches(p Policy) bool {
	return c.generation == p.Generation && c.registry == p.RegistryVersion
}

func scanCheckpoint(row pgx.Row) (checkpoint, error) {
	var c checkpoint
	var raw []byte
	err := row.Scan(&c.generation, &c.registry, &c.ready, &raw, &c.live, &c.historyComplete, &c.liveComplete, &c.revision)
	if err == nil {
		err = json.Unmarshal(raw, &c.history)
	}
	return c, err
}

const checkpointSQL = `SELECT generation,registry_version,ready,history_cursor,live_cursor,history_complete,live_complete,revision FROM ukmesh_public.state WHERE singleton=true`

func (s *PGStore) state(ctx context.Context) (checkpoint, error) {
	return scanCheckpoint(s.pool.QueryRow(ctx, checkpointSQL))
}

func rollback(tx pgx.Tx, prior *error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		*prior = errors.Join(*prior, err)
	}
}

func (s *PGStore) reset(ctx context.Context, p *Policy) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	current, err := scanCheckpoint(tx.QueryRow(ctx, checkpointSQL+" FOR UPDATE"))
	if err != nil {
		return err
	}
	// reset(nil) establishes this invariant atomically with deletion. A long
	// authority outage must not rescan tables or create another epoch each poll.
	if p == nil && current.generation == 0 && current.registry == "" && !current.ready {
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM ukmesh_public.messages`); err != nil {
		return err
	}
	var generation int64
	var registry string
	if p != nil {
		generation, registry = p.Generation, p.RegistryVersion
		for _, ch := range p.Channels {
			_, err = tx.Exec(ctx, `INSERT INTO ukmesh_public.channels(registry_id,key_fingerprint,name,channel_hash,registry_version)
 VALUES($1,$2,$3,$4,$5) ON CONFLICT(registry_id,key_fingerprint) DO UPDATE
 SET name=EXCLUDED.name,channel_hash=EXCLUDED.channel_hash,registry_version=EXCLUDED.registry_version`,
				ch.ID, ch.KeyFingerprint, ch.Name, hex.EncodeToString([]byte{ch.hash}), registry)
			if err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(ctx, `UPDATE ukmesh_public.state SET generation=$1,registry_version=$2,revision=revision+1,ready=false,history_complete=false,live_complete=false,history_cursor='{}',live_cursor='0-0' WHERE singleton=true`, generation, registry)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var ErrConcurrent = errors.New("public projection checkpoint changed")

// Apply atomically owns idempotent observation/message writes and either input
// cursor. It never stores raw frames, keys, or a second event payload copy.
func (s *PGStore) apply(ctx context.Context, p Policy, previous checkpoint, history *publicsource.Cursor, live *string, historyComplete, liveComplete *bool, records []prepared) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	c, err := scanCheckpoint(tx.QueryRow(ctx, checkpointSQL+" FOR UPDATE"))
	if err != nil {
		return err
	}
	old, _ := json.Marshal(previous.history)
	now, _ := json.Marshal(c.history)
	if !c.matches(p) || !bytes.Equal(old, now) || c.live != previous.live || c.revision != previous.revision {
		return ErrConcurrent
	}
	for _, record := range records {
		if err = saveObservation(ctx, tx, p, record); err != nil {
			return err
		}
	}
	if history != nil {
		c.history = *history
	}
	if live != nil {
		c.live = *live
	}
	if historyComplete != nil {
		c.historyComplete = c.historyComplete || *historyComplete
	}
	if liveComplete != nil {
		c.liveComplete = *liveComplete
	}
	c.ready = c.historyComplete && c.liveComplete
	raw, err := json.Marshal(c.history)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE ukmesh_public.state SET history_cursor=$1,live_cursor=$2,ready=$3,history_complete=$4,live_complete=$5 WHERE singleton=true`, raw, c.live, c.ready, c.historyComplete, c.liveComplete)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func saveObservation(ctx context.Context, tx pgx.Tx, p Policy, record prepared) error {
	o := record.observation
	var channelID int32
	if err := tx.QueryRow(ctx, `SELECT id FROM ukmesh_public.channels WHERE registry_id=$1 AND key_fingerprint=$2 AND registry_version=$3`,
		record.channel.ID, record.channel.KeyFingerprint, p.RegistryVersion).Scan(&channelID); err != nil {
		return err
	}
	var messageID int64
	var sender, content string
	var sent int64
	var hash []byte
	var transport bool
	err := tx.QueryRow(ctx, `WITH added AS (
 INSERT INTO ukmesh_public.messages(channel_id,packet_uid,beacon_hash,sender,content,sent_at,transport)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(channel_id,packet_uid) DO NOTHING RETURNING *
) SELECT id,sender,content,sent_at,beacon_hash,transport FROM added
 UNION ALL SELECT id,sender,content,sent_at,beacon_hash,transport FROM ukmesh_public.messages WHERE channel_id=$1 AND packet_uid=$2 LIMIT 1`,
		channelID, o.UID[:], o.BeaconHash[:], record.payload.Sender, record.payload.Text, int64(record.payload.Timestamp)*1000, o.Packet.IsTransport()).
		Scan(&messageID, &sender, &content, &sent, &hash, &transport)
	if err != nil {
		return err
	}
	if sender != record.payload.Sender || content != record.payload.Text || sent != int64(record.payload.Timestamp)*1000 || !bytes.Equal(hash, o.BeaconHash[:]) {
		return publicsource.ErrContract
	}
	// Mutable relay framing may differ between *different* UUIDs of one UID.
	// Scope metadata belongs to each hearing; do not infer it from that UID.
	_ = transport
	var existingMessage int64
	var at time.Time
	var iata *string
	var receiver, digest []byte
	err = tx.QueryRow(ctx, `WITH added AS (
 INSERT INTO ukmesh_public.observations(observation_id,message_id,observed_at,iata,receiver,frame_digest)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(observation_id) DO NOTHING RETURNING *
) SELECT message_id,observed_at,iata,receiver,frame_digest FROM added
 UNION ALL SELECT message_id,observed_at,iata,receiver,frame_digest FROM ukmesh_public.observations WHERE observation_id=$1 LIMIT 1`,
		o.ID, messageID, o.Time, o.IATA, o.ObserverKey[:], record.digest[:]).Scan(&existingMessage, &at, &iata, &receiver, &digest)
	if err != nil {
		return err
	}
	if existingMessage != messageID || !at.Equal(o.Time) || !equalString(iata, o.IATA) || !bytes.Equal(receiver, o.ObserverKey[:]) || !bytes.Equal(digest, record.digest[:]) {
		return publicsource.ErrContract
	}
	return nil
}
func equalString(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// PruneBefore is explicitly owned by the deployment retention job. Callers
// must supply the same retained-history boundary as the authoritative source.
func (s *PGStore) PruneBefore(ctx context.Context, cutoff time.Time) (err error) {
	if cutoff.IsZero() {
		return publicsource.ErrContract
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	if _, err = tx.Exec(ctx, `SELECT singleton FROM ukmesh_public.state WHERE singleton=true FOR UPDATE`); err != nil {
		return err
	}
	observations, err := tx.Exec(ctx, `DELETE FROM ukmesh_public.observations WHERE observed_at<$1`, cutoff)
	if err != nil {
		return err
	}
	messages, err := tx.Exec(ctx, `DELETE FROM ukmesh_public.messages m WHERE NOT EXISTS(SELECT 1 FROM ukmesh_public.observations o WHERE o.message_id=m.id)`)
	if err != nil {
		return err
	}
	if observations.RowsAffected() > 0 || messages.RowsAffected() > 0 {
		if _, err = tx.Exec(ctx, `UPDATE ukmesh_public.state SET revision=revision+1 WHERE singleton=true`); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PGStore) latestEvent(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(event_id),0) FROM ukmesh_public.observations`).Scan(&n)
	return n, err
}

type ChannelSummary struct {
	api.ChannelSummary
	RegistryID     string `json:"registryId"`
	KeyFingerprint string `json:"keyFingerprint"`
}
type ChannelPage struct {
	api.Page[ChannelSummary]
	NextPageCursor *string `json:"nextPageCursor,omitempty"`
}

func (s *PGStore) channels(ctx context.Context, p Policy, limit int32, cursor int64, precise *api.ChannelCursor, iatas []string, hash string) (ChannelPage, error) {
	page := ChannelPage{Page: api.Page[ChannelSummary]{Items: []ChannelSummary{}}}
	var boundaryID int32
	if precise != nil {
		cursor = precise.LastSeen.UnixMilli()
		boundaryID = precise.ID
	}
	rows, err := s.pool.Query(ctx, `WITH listed AS (
 SELECT c.id,c.name,c.channel_hash,c.registry_id,c.key_fingerprint,COALESCE(MAX(m.sent_at) FILTER (
 WHERE EXISTS(SELECT 1 FROM ukmesh_public.observations o WHERE o.message_id=m.id AND (cardinality($2::text[])=0 OR o.iata=ANY($2)) AND ($7::int=0 OR o.observed_at>=now()-make_interval(days=>$7)))),0) AS last_seen
 FROM ukmesh_public.channels c LEFT JOIN ukmesh_public.messages m ON m.channel_id=c.id
 WHERE c.registry_version=$1 AND ($3='' OR c.channel_hash=$3) GROUP BY c.id
) SELECT id,name,channel_hash,registry_id,key_fingerprint,last_seen FROM listed
 WHERE ($4::bigint=0 AND $5::integer=0) OR ($5=0 AND last_seen<$4) OR ($5>0 AND (last_seen,id)<($4,$5))
 ORDER BY last_seen DESC,id DESC LIMIT $6`, p.RegistryVersion, iatas, hash, cursor, boundaryID, limit+1, s.retentionDays)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var ch ChannelSummary
		var name string
		if err = rows.Scan(&ch.ID, &name, &ch.ChannelHash, &ch.RegistryID, &ch.KeyFingerprint, &ch.LastSeen); err != nil {
			return page, err
		}
		ch.Name = &name
		ch.KeyKnown = true
		page.Items = append(page.Items, ch)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	page.HasMore = len(page.Items) > int(limit)
	if page.HasMore {
		page.Items = page.Items[:limit]
	}
	if len(page.Items) > 0 {
		last := page.Items[len(page.Items)-1]
		page.NextCursor = &last.LastSeen
		precise := api.ChannelCursor{LastSeen: time.UnixMilli(last.LastSeen), ID: int32(last.ID)}
		encoded := precise.String()
		page.NextPageCursor = &encoded
	}
	return page, nil
}

func (s *PGStore) channel(ctx context.Context, p Policy, id int32) (ChannelSummary, error) {
	var ch ChannelSummary
	var name string
	err := s.pool.QueryRow(ctx, `SELECT c.id,c.name,c.channel_hash,c.registry_id,c.key_fingerprint,COALESCE(MAX(m.sent_at) FILTER(WHERE EXISTS(SELECT 1 FROM ukmesh_public.observations o WHERE o.message_id=m.id AND ($3::int=0 OR o.observed_at>=now()-make_interval(days=>$3)))),0)
 FROM ukmesh_public.channels c LEFT JOIN ukmesh_public.messages m ON m.channel_id=c.id
 WHERE c.id=$1 AND c.registry_version=$2 GROUP BY c.id`, id, p.RegistryVersion, s.retentionDays).Scan(&ch.ID, &name, &ch.ChannelHash, &ch.RegistryID, &ch.KeyFingerprint, &ch.LastSeen)
	ch.Name = &name
	ch.KeyKnown = true
	return ch, err
}

const messageSelect = `SELECT m.id,encode(m.beacon_hash,'hex'),c.channel_hash,m.sender,m.content,m.sent_at,
 (SELECT count(*) FROM ukmesh_public.observations total WHERE total.message_id=m.id AND ($6::int=0 OR total.observed_at>=now()-make_interval(days=>$6))),
 c.id,c.registry_id,upper(encode(m.packet_uid,'hex')),m.transport
 FROM ukmesh_public.messages m JOIN ukmesh_public.channels c ON c.id=m.channel_id`

func scanMessage(row interface{ Scan(...any) error }) (Message, error) {
	var m Message
	var transport bool
	err := row.Scan(&m.ID, &m.PacketHash, &m.ChannelHash, &m.SenderName, &m.Content, &m.SentAt, &m.ObservationCount, &m.ChannelID, &m.RegistryID, &m.PacketUID, &transport)
	m.ScopeStatus = "unscoped"
	if transport {
		m.ScopeStatus = "unavailable"
	}
	return m, err
}

func (s *PGStore) history(ctx context.Context, p Policy, channel int32, cursor int64, limit int32, iatas []string, since int64) (api.Page[Message], error) {
	page := api.Page[Message]{Items: []Message{}}
	rows, err := s.pool.Query(ctx, messageSelect+` WHERE c.registry_version=$1 AND c.id=$2 AND ($3::bigint=0 OR m.id<$3)
 AND EXISTS(SELECT 1 FROM ukmesh_public.observations o WHERE o.message_id=m.id AND (cardinality($4::text[])=0 OR o.iata=ANY($4)) AND ($6::int=0 OR o.observed_at>=now()-make_interval(days=>$6)))
 AND ($7::bigint=0 OR m.sent_at>=$7)
 ORDER BY m.id DESC LIMIT $5`, p.RegistryVersion, channel, cursor, iatas, limit+1, s.retentionDays, since)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, m)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	page.HasMore = len(page.Items) > int(limit)
	if page.HasMore {
		page.Items = page.Items[:limit]
	}
	if len(page.Items) > 0 {
		last := page.Items[len(page.Items)-1].ID
		page.NextCursor = &last
	}
	return page, nil
}

type event struct {
	ID      int64
	IATA    string
	Message Message
}

func (s *PGStore) events(ctx context.Context, p Policy, after int64) ([]event, error) {
	// Keep the event order independently of message IDs: additional distinct
	// hearings update reach and must cross the live cursor too.
	rows, err := s.pool.Query(ctx, `SELECT o.event_id,COALESCE(o.iata,''),m.id,encode(m.beacon_hash,'hex'),c.channel_hash,m.sender,m.content,m.sent_at,
 (SELECT count(*) FROM ukmesh_public.observations total WHERE total.message_id=m.id AND ($3::int=0 OR total.observed_at>=now()-make_interval(days=>$3))),c.id,c.registry_id,upper(encode(m.packet_uid,'hex')),m.transport
 FROM ukmesh_public.observations o JOIN ukmesh_public.messages m ON m.id=o.message_id JOIN ukmesh_public.channels c ON c.id=m.channel_id
 WHERE o.event_id>$1 AND c.registry_version=$2 AND ($3::int=0 OR o.observed_at>=now()-make_interval(days=>$3)) ORDER BY o.event_id LIMIT 100`, after, p.RegistryVersion, s.retentionDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []event{}
	for rows.Next() {
		var e event
		var transport bool
		m := &e.Message
		if err = rows.Scan(&e.ID, &e.IATA, &m.ID, &m.PacketHash, &m.ChannelHash, &m.SenderName, &m.Content, &m.SentAt, &m.ObservationCount, &m.ChannelID, &m.RegistryID, &m.PacketUID, &transport); err != nil {
			return nil, err
		}
		m.ScopeStatus = "unscoped"
		if transport {
			m.ScopeStatus = "unavailable"
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
