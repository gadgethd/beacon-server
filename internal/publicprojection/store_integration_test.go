// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicprojection

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
	"github.com/MeshCore-Beacon/beacon-server/internal/publicsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meshcore-go/meshcore-go"
)

type fixtureAuthority struct{ policy Policy }

func (a *fixtureAuthority) Current(context.Context) (Policy, error) { return a.policy, nil }

type fixtureHistory struct {
	authority    *fixtureAuthority
	observations []*publicsource.Observation
	revoked      bool
}

func (f *fixtureHistory) ReadBatch(_ context.Context, c publicsource.Cursor, _ int) (publicsource.Batch, error) {
	next := publicsource.Cursor{Version: 1, Generation: f.authority.policy.Generation, Sequence: c.Sequence, Networks: []string{"ukmesh"}}
	batch := publicsource.Batch{Next: next, Outcomes: []publicsource.Outcome{}}
	if !f.revoked && c.Sequence < int64(len(f.observations)) {
		o := f.observations[c.Sequence]
		batch.Next.Sequence++
		batch.Outcomes = append(batch.Outcomes, publicsource.Outcome{Sequence: batch.Next.Sequence, ObservationID: o.ID, Observation: o})
	}
	return batch, nil
}

type fixtureLive struct {
	authority    *fixtureAuthority
	observations []*publicsource.Observation
	calls        int
}

func (f *fixtureLive) ReadBatch(_ context.Context, after string) (publicsource.LiveBatch, error) {
	f.calls++
	batch := publicsource.LiveBatch{Generation: f.authority.policy.Generation, Next: "2-0", CaughtUp: f.calls > 1}
	if after == "0-0" && len(f.authority.policy.Channels) > 0 {
		for _, o := range f.observations {
			batch.Outcomes = append(batch.Outcomes, publicsource.Outcome{ObservationID: o.ID, Observation: o})
		}
	}
	return batch, nil
}

type fixtureGeography struct{}

func (fixtureGeography) ListIATAs(context.Context) ([]api.IATA, error) { return []api.IATA{}, nil }
func (fixtureGeography) ListRegions(context.Context) ([]api.Region, error) {
	return []api.Region{}, nil
}
func (fixtureGeography) GetRegion(context.Context, int32) (*api.Region, error) {
	return &api.Region{IATAs: []string{}}, nil
}
func (fixtureGeography) GetRegionBySlug(context.Context, string) (*api.Region, error) {
	return &api.Region{IATAs: []string{}}, nil
}

// An existing owned-fixture runner installs schema.sql with its migration
// owner and grants the generated runtime role only this schema's DML/sequence
// access. This test does not create/drop databases, roles, or schemas.
func TestProjectionOwnedPostgresIntegration(t *testing.T) {
	endpoint := os.Getenv("BEACON_PUBLIC_PROJECTION_FIXTURE_URL")
	if endpoint == "" {
		t.Skip("BEACON_PUBLIC_PROJECTION_FIXTURE_URL is required")
	}
	config, err := pgxpool.ParseConfig(endpoint)
	if err != nil {
		t.Fatal("invalid projection fixture configuration")
	}
	if config.ConnConfig.Host != "127.0.0.1" || config.ConnConfig.Port != 5435 || !strings.HasPrefix(config.ConnConfig.Database, "lean_verify_") {
		t.Fatal("owned local verification database required")
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback.Host != "127.0.0.1" || fallback.Port != 5435 {
			t.Fatal("fixture fallback escapes owned endpoint")
		}
	}
	config.MaxConns, config.MinConns = 2, 0
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("could not construct fixture pool")
	}
	defer pool.Close()
	var safe bool
	err = pool.QueryRow(ctx, `SELECT current_user=session_user AND NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication OR rolinherit)
 FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&safe)
	if err != nil || !safe {
		t.Fatal("dedicated runtime fixture principal required")
	}
	store := NewPGStore(pool)
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	policy, err := decodePolicy(authorityBody(key, "public"))
	if err != nil {
		t.Fatal(err)
	}
	authority := &fixtureAuthority{policy: policy}
	content := meshcore.GroupTextPayload{Timestamp: 1700000000, Sender: "Alice", Text: "Durable 🛰️ public message"}
	fp := sha256.Sum256(key)
	group, err := content.Encrypt(fp[0], key)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := group.ToBytes()
	packet, err := meshcore.PacketFromBytes(append([]byte{0x15, 0}, payload...))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := publicsource.CanonicalUID(packet)
	iata := "LON"
	one := &publicsource.Observation{ID: uuid.New(), Time: time.Date(2026, 11, 24, 1, 2, 3, 123456000, time.UTC), Network: "ukmesh", IATA: &iata,
		UID: uid, IdentityVersion: publicsource.UIDVersion, Packet: packet, GroupText: group, BeaconHash: packet.PacketHash()}
	for i := range one.ObserverKey {
		one.ObserverKey[i] = 0xab
	}
	two := *one
	two.ID = uuid.New()
	history := &fixtureHistory{authority: authority, observations: []*publicsource.Observation{one, &two}}
	live := &fixtureLive{authority: authority, observations: history.observations}
	service, err := New(store, history, live, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.SetRetentionDays(30); err != nil {
		t.Fatal("fixture retention configuration failed")
	}
	// Direct bounded rounds exercise the same production SyncOnce/state/fence
	// code without starting a service, network listener, or polling goroutine.
	service.running.Store(true)
	defer service.running.Store(false)
	handler := service.Handler(fixtureGeography{}, nil)
	request := func(path string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		return response
	}
	for i := 0; i < 3; i++ {
		if err = service.SyncOnce(ctx); err != nil {
			t.Fatal("fixture projection round failed")
		}
		response := request("/readyz")
		if i < 2 && response.Code != 503 {
			t.Fatal("partial history/live backfill certified ready")
		}
		if i == 2 && response.Code != 200 {
			t.Fatal("complete projection unavailable")
		}
	}
	var messages, observations int
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ukmesh_public.messages),(SELECT count(*) FROM ukmesh_public.observations)`).Scan(&messages, &observations); err != nil || messages != 1 || observations != 2 {
		t.Fatal("history/live overlap duplicated or collapsed observations")
	}
	response := request("/api/v1/channels")
	var directory ChannelPage
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &directory) != nil || len(directory.Items) != 1 || directory.Items[0].RegistryID != "public" {
		t.Fatal("public directory differs")
	}
	id := directory.Items[0].ID
	path := "/api/v1/channels/" + formatGeneration(int64(id)) + "/messages"
	response = request(path)
	var page api.Page[Message]
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].Content != content.Text || page.Items[0].ObservationCount != 2 {
		t.Fatal("native history/identity differs")
	}
	if request(path+"?scope=unproven").Code != 503 {
		t.Fatal("unproven RF scope silently mapped")
	}
	// Persisted readiness alone cannot admit a restarted listener. Its first
	// committed-tail append is visible in history before it installs baseline.
	startup := *one
	startup.ID = uuid.New()
	history.observations = append(history.observations, &startup)
	restarted, err := New(store, history, live, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.SetRetentionDays(30); err != nil {
		t.Fatal(err)
	}
	restarted.running.Store(true)
	defer restarted.running.Store(false)
	restartedHandler := restarted.Handler(fixtureGeography{}, nil)
	opening := httptest.NewRecorder()
	restartedHandler.ServeHTTP(opening, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if opening.Code != 503 {
		t.Fatal("persisted readiness admitted clients before startup baseline")
	}
	if err = restarted.SyncOnce(ctx); err != nil {
		t.Fatal("restart committed-tail append failed")
	}
	closing := httptest.NewRecorder()
	restartedHandler.ServeHTTP(closing, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if closing.Code != 200 {
		t.Fatal("restart baseline never became usable")
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ukmesh_public.observations`).Scan(&observations); err != nil || observations != 3 {
		t.Fatal("startup committed-tail observation lost")
	}
	// Hold a response after its initial authorization, purge and completely
	// rebuild under the *same* authority, then release it. Only the durable
	// projection revision can distinguish these two usable epochs.
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	inflight := httptest.NewRecorder()
	released := false
	go func() {
		defer close(done)
		service.respond(inflight, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx), func(Policy) (any, error) {
			close(entered)
			<-resume
			return map[string]string{"content": "stale-response"}, nil
		})
	}()
	defer func() {
		if !released {
			close(resume)
		}
		<-done
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("in-flight fixture response did not start")
	}
	if err = store.reset(ctx, &authority.policy); err != nil {
		t.Fatal("same-policy fixture rebuild could not begin")
	}
	for i := 0; i < len(history.observations)+1; i++ {
		if err = service.SyncOnce(ctx); err != nil {
			t.Fatal("same-policy fixture rebuild failed")
		}
	}
	close(resume)
	released = true
	<-done
	if inflight.Code != 503 || strings.Contains(inflight.Body.String(), "stale-response") {
		t.Fatal("HTTP crossed a same-policy purge/rebuild revision")
	}
	// Registry revocation immediately blocks old data, then removes all stored
	// plaintext while retaining no dependency on Beacon saved channel groups.
	authority.policy.RegistryVersion = strings.Repeat("d", 64)
	authority.policy.Channels = nil
	history.revoked = true
	if request(path).Code != 503 {
		t.Fatal("revocation did not block existing content")
	}
	if err = service.SyncOnce(ctx); err != nil {
		t.Fatal("revoked projection did not settle")
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ukmesh_public.messages`).Scan(&messages); err != nil || messages != 0 {
		t.Fatal("revoked plaintext retained in active projection")
	}
	if response = request("/api/v1/channels"); response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &directory) != nil || len(directory.Items) != 0 {
		t.Fatal("revoked directory observable")
	}
	if err = store.reset(ctx, nil); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal("fixture projection cleanup failed")
	}
	first, err := store.state(ctx)
	if err != nil {
		t.Fatal("purged checkpoint unavailable")
	}
	if err = store.reset(ctx, nil); err != nil {
		t.Fatal("repeated unavailable purge failed")
	}
	second, err := store.state(ctx)
	if err != nil || first.revision != second.revision {
		t.Fatal("unavailable purge created another revision")
	}
}
