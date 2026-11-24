// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicsource

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Root's owned SQL fixture invokes this binary once per phase with a generated
// restricted credential in the environment. This test never provisions data,
// changes policy, or logs the endpoint (including on connection failure).
func TestPublicSourceFixtureIntegration(t *testing.T) {
	endpoint := os.Getenv("BEACON_PUBLIC_FIXTURE_URL")
	if endpoint == "" {
		t.Skip("BEACON_PUBLIC_FIXTURE_URL is required")
	}
	phase := os.Getenv("BEACON_PUBLIC_FIXTURE_PHASE")
	if phase != "ready" && phase != "unavailable" {
		t.Fatal("fixture phase must be ready or unavailable")
	}
	ids := strings.Split(os.Getenv("BEACON_PUBLIC_FIXTURE_OBSERVATIONS"), ",")
	if len(ids) != 2 {
		t.Fatal("fixture requires exactly two observation UUIDs")
	}
	expected := make(map[uuid.UUID]bool, 2)
	for _, encoded := range ids {
		id, err := uuid.Parse(strings.TrimSpace(encoded))
		if err != nil || id == uuid.Nil || expected[id] {
			t.Fatal("fixture observation UUIDs must be valid and distinct")
		}
		expected[id] = true
	}
	config, err := pgxpool.ParseConfig(endpoint)
	if err != nil {
		t.Fatal("invalid fixture connection configuration")
	}
	local := func(host string, port uint16) bool {
		return (host == "127.0.0.1" || host == "localhost") && port == 5433
	}
	if !local(config.ConnConfig.Host, config.ConnConfig.Port) ||
		!regexp.MustCompile(`^lean_verify_[a-z0-9_]{1,38}$`).MatchString(config.ConnConfig.Database) {
		t.Fatal("fixture must use an owned verification database on loopback port 5433")
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if !local(fallback.Host, fallback.Port) {
			t.Fatal("fixture connection fallback escapes loopback port 5433")
		}
	}
	// A single physical slot also detects any attempt to query the fresh fence
	// before releasing the snapshot's connection.
	config.MaxConns, config.MinConns = 1, 0
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		cancel()
		t.Fatal("could not construct fixture pool")
	}
	defer func() { cancel(); pool.Close() }()
	var current, session, database string
	var elevated, member bool
	err = pool.QueryRow(ctx, `SELECT current_user, session_user, current_database(),
 r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit,
 EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid)
 FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`).Scan(&current, &session, &database, &elevated, &member)
	if err != nil {
		t.Fatal("could not establish fixture session identity")
	}
	if current != config.ConnConfig.User || session != current || database != config.ConnConfig.Database || elevated || member {
		t.Fatal("fixture session is not the isolated unprivileged reader")
	}
	source, err := New(pool, []string{"ukmesh"})
	if err != nil {
		t.Fatal("could not construct restricted fixture source")
	}
	begin := source.begin
	source.begin = func(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
		tx, err := begin(ctx, options)
		if err != nil {
			return nil, errors.New("fixture snapshot could not begin")
		}
		var readonly bool
		var isolation string
		if err = tx.QueryRow(ctx, `SELECT current_setting('transaction_read_only')::boolean,
 current_setting('transaction_isolation')`).Scan(&readonly, &isolation); err != nil || !readonly || isolation != "repeatable read" {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			closeErr := tx.Rollback(cleanup)
			return nil, errors.Join(errors.New("fixture snapshot lost read-only repeatable-read isolation"), closeErr)
		}
		return tx, nil
	}
	if phase == "unavailable" {
		batch, err := source.ReadBatch(ctx, Cursor{}, 1)
		if !errors.Is(err, ErrNotReady) || len(batch.Outcomes) != 0 || batch.Next.Version != 0 {
			t.Fatal("unavailable privacy state returned source data or progress")
		}
		return
	}
	expectedTime := time.Date(2026, 11, 24, 1, 2, 3, 123456000, time.UTC)
	uid, _ := hex.DecodeString("9d54cea2f71af7aff8e0c9a07ded55eaf3bee5f32f2385942166564ba6c91b74")
	wire, _ := hex.DecodeString("1500" + payloadHex)
	wantReasons := map[Reason]int{MissingUID: 1, InvalidUID: 1, UnsupportedVersion: 1,
		InvalidObserver: 1, MissingRaw: 1, InvalidHex: 2}
	reasons := make(map[Reason]int)
	seen := make(map[uuid.UUID]bool)
	accepted := make(map[uuid.UUID]bool)
	cursor := Cursor{}
	for page := 0; ; page++ {
		if page >= 10 {
			t.Fatal("fixture paging exceeded its nine-row bound plus final empty page")
		}
		batch, err := source.ReadBatch(ctx, cursor, 1)
		if err != nil {
			t.Fatal("real fixture page read failed")
		}
		if batch.Next.Version != 1 || batch.Next.Generation != 7 || len(batch.Next.Networks) != 1 || batch.Next.Networks[0] != "ukmesh" {
			t.Fatal("fixture cursor lost source version, generation or network binding")
		}
		if len(batch.Outcomes) == 0 {
			if batch.Next.Sequence != cursor.Sequence {
				t.Fatal("empty fixture page changed committed-order progress")
			}
			break
		}
		if len(batch.Outcomes) != 1 {
			t.Fatal("fixture ignored page limit one")
		}
		out := batch.Outcomes[0]
		if out.Sequence <= cursor.Sequence || batch.Next.Sequence != out.Sequence || seen[out.ObservationID] {
			t.Fatal("fixture cursor replayed, reordered or collapsed an observation")
		}
		seen[out.ObservationID] = true
		if out.Observation == nil {
			if expected[out.ObservationID] || out.Reason == "" {
				t.Fatal("valid fixture observation rejected or rejection reason absent")
			}
			reasons[out.Reason]++
		} else {
			observation := out.Observation
			if !expected[out.ObservationID] || observation.ID != out.ObservationID || out.Reason != "" || observation.Network != "ukmesh" {
				t.Fatal("fixture accepted an unexpected or unscoped observation")
			}
			if !observation.Time.Equal(expectedTime) || observation.Time.Nanosecond() != 123456000 ||
				observation.IdentityVersion != UIDVersion || !bytes.Equal(observation.UID[:], uid) ||
				hex.EncodeToString(observation.BeaconHash[:]) != "ba2d3a679a03ef22" {
				t.Fatal("fixture changed exact time or either packet identity")
			}
			reencoded, err := observation.Packet.ToBytes()
			if err != nil || !bytes.Equal(reencoded, wire) || observation.GroupText.ChannelHash != 0x11 {
				t.Fatal("fixture native GroupText decode changed the frame")
			}
			accepted[out.ObservationID] = true
		}
		cursor = batch.Next
	}
	if len(seen) != 9 || len(accepted) != 2 || len(reasons) != len(wantReasons) {
		t.Fatal("fixture lost or gained accepted/rejected observations")
	}
	for reason, count := range wantReasons {
		if reasons[reason] != count {
			t.Fatalf("fixture rejection count differs for %s", reason)
		}
	}
	other, err := New(pool, []string{"isolated-test-network"})
	if err != nil {
		t.Fatal("could not bind separate fixture network")
	}
	separate, err := other.ReadBatch(ctx, Cursor{}, 1)
	if err != nil || len(separate.Outcomes) != 1 || separate.Outcomes[0].Observation == nil {
		t.Fatal("separate network fixture candidate unavailable")
	}
	observation := separate.Outcomes[0].Observation
	if observation.Network != "isolated-test-network" || seen[observation.ID] {
		t.Fatal("separate fixture network leaked into the main cursor")
	}
}
