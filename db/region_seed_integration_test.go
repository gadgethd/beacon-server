// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	sqlc "github.com/MeshCore-Beacon/beacon-server/db/sqlc"
	"github.com/MeshCore-Beacon/beacon-server/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

type regionSeedSnapshot struct {
	body, tuple string
	updated     time.Time
}

func regionSeedRead(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id int32) regionSeedSnapshot {
	t.Helper()
	var out regionSeedSnapshot
	if err := pool.QueryRow(ctx, "SELECT to_jsonb(r)::text, ctid::text, updated_at FROM regions r WHERE id=$1", id).Scan(&out.body, &out.tuple, &out.updated); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRegionSeedPreservesUnchangedPostgres(t *testing.T) {
	ctx, pool := schemaPool(t)
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := &Store{q: sqlc.New(pool)}
	cfg := &config.Config{Regions: []config.RegionConfig{{Slug: "same", Name: "Same", IATAs: []string{"LHR"}}}}
	if err := config.Seed(ctx, cfg, store); err != nil {
		t.Fatal(err)
	}
	var id int32
	if err := pool.QueryRow(ctx, "UPDATE regions SET created_at='2025-01-01', updated_at='2025-02-01' WHERE slug='same' RETURNING id").Scan(&id); err != nil {
		t.Fatal(err)
	}
	before := regionSeedRead(t, ctx, pool, id)
	for range 2 {
		if err := config.Seed(ctx, cfg, store); err != nil {
			t.Fatalf("repeated unchanged config seed: %v", err)
		}
		if after := regionSeedRead(t, ctx, pool, id); after != before {
			t.Fatalf("unchanged startup rewrote region row: before=%+v after=%+v", before, after)
		}
	}
}

func TestRegionSeedAppliesEachChangePostgres(t *testing.T) {
	ctx, pool := schemaPool(t)
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := &Store{q: sqlc.New(pool)}
	ptr := func(value float64) *float64 { return &value }
	intPtr := func(value int) *int { return &value }
	base := config.RegionConfig{Name: "Before", Description: "About", DisplayOrder: 1, CenterLat: ptr(51), CenterLng: ptr(-1), ZoomLevel: intPtr(8)}
	cases := []struct {
		name    string
		mutate  func(*config.RegionConfig)
		prepare string
	}{
		{"name", func(r *config.RegionConfig) { r.Name = "After" }, ""},
		{"description", func(r *config.RegionConfig) { r.Description = "Changed" }, ""},
		{"display_order", func(r *config.RegionConfig) { r.DisplayOrder = 2 }, ""},
		{"center_lat", func(r *config.RegionConfig) { r.CenterLat = ptr(52) }, ""},
		{"center_lng", func(r *config.RegionConfig) { r.CenterLng = ptr(-2) }, ""},
		{"zoom_level", func(r *config.RegionConfig) { r.ZoomLevel = intPtr(9) }, ""},
		{"lat_null", func(r *config.RegionConfig) { r.CenterLat = nil }, ""},
		{"lng_null", func(r *config.RegionConfig) { r.CenterLng = nil }, ""},
		{"zoom_null", func(r *config.RegionConfig) { r.ZoomLevel = nil }, ""},
		{"lat_from_null", func(*config.RegionConfig) {}, "center_lat=NULL"},
		{"lng_from_null", func(*config.RegionConfig) {}, "center_lng=NULL"},
		{"zoom_from_null", func(*config.RegionConfig) {}, "zoom_level=NULL"},
		{"description_from_null", func(*config.RegionConfig) {}, "description=NULL"},
		{"order_from_null", func(*config.RegionConfig) {}, "display_order=NULL"},
		{"imported_takeover", func(*config.RegionConfig) {}, "imported=TRUE"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Slug = fmt.Sprintf("changed-%d", i)
			upsert := func(r config.RegionConfig) int32 {
				t.Helper()
				id, err := store.UpsertRegion(ctx, r.Slug, r.Name, r.Description, r.DisplayOrder, r.CenterLat, r.CenterLng, r.ZoomLevel)
				if err != nil {
					t.Fatal(err)
				}
				return id
			}
			id := upsert(cfg)
			setup := "created_at='2025-01-01', updated_at='2025-02-01'"
			if tc.prepare != "" {
				setup += ", " + tc.prepare
			}
			if _, err := pool.Exec(ctx, "UPDATE regions SET "+setup+" WHERE id=$1", id); err != nil {
				t.Fatal(err)
			}
			before := regionSeedRead(t, ctx, pool, id)
			tc.mutate(&cfg)
			if got := upsert(cfg); got != id {
				t.Fatalf("changed seed ID=%d want %d", got, id)
			}
			after := regionSeedRead(t, ctx, pool, id)
			if !after.updated.After(before.updated) || after.tuple == before.tuple {
				t.Fatal("real config change did not update its timestamp/tuple")
			}
			var current map[string]any
			if err := json.Unmarshal([]byte(after.body), &current); err != nil {
				t.Fatal(err)
			}
			number := func(v *float64) any {
				if v == nil {
					return nil
				}
				return *v
			}
			var zoom any
			if cfg.ZoomLevel != nil {
				zoom = float64(*cfg.ZoomLevel)
			}
			want := map[string]any{"name": cfg.Name, "description": cfg.Description, "display_order": float64(cfg.DisplayOrder), "center_lat": number(cfg.CenterLat), "center_lng": number(cfg.CenterLng), "zoom_level": zoom, "imported": false}
			for column, value := range want {
				if !reflect.DeepEqual(current[column], value) {
					t.Fatalf("changed %s=%v want %v", column, current[column], value)
				}
			}
			if got := upsert(cfg); got != id {
				t.Fatalf("repeated changed ID=%d", got)
			}
			if repeat := regionSeedRead(t, ctx, pool, id); repeat != after {
				t.Fatal("repeated changed config rewrote the region again")
			}
		})
	}
}
