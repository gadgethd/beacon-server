// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProjectionStartupOwnedFixture(t *testing.T) {
	endpoint := os.Getenv("BEACON_PUBLIC_PROJECTION_FIXTURE_URL")
	if endpoint == "" {
		t.Skip("BEACON_PUBLIC_PROJECTION_FIXTURE_URL is required")
	}
	config, err := pgxpool.ParseConfig(endpoint)
	if err != nil {
		t.Fatal("invalid fixture endpoint")
	}
	if config.ConnConfig.Host != "127.0.0.1" || config.ConnConfig.Port != 5435 || !strings.HasPrefix(config.ConnConfig.Database, "lean_verify_") {
		t.Fatal("owned local Beacon fixture required")
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback.Host != "127.0.0.1" || fallback.Port != 5435 {
			t.Fatal("fixture fallback escaped local Beacon")
		}
	}
	config.MaxConns, config.MinConns = 2, 0
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("fixture pool unavailable")
	}
	defer pool.Close()
	if restricted(ctx, pool) != nil || destination(ctx, pool, config.ConnConfig.Database) != nil || projectionPermissions(ctx, pool) != nil {
		t.Fatal("runtime fixture did not satisfy startup identity/permission policy")
	}
	if destination(ctx, pool, "wrong-database") == nil {
		t.Fatal("actual database identity was not checked")
	}
}

func TestSourceStartupOwnedFixture(t *testing.T) {
	endpoint := os.Getenv("BEACON_PUBLIC_SOURCE_FIXTURE_URL")
	if endpoint == "" {
		t.Skip("BEACON_PUBLIC_SOURCE_FIXTURE_URL is required")
	}
	config, err := pgxpool.ParseConfig(endpoint)
	if err != nil {
		t.Fatal("invalid source fixture endpoint")
	}
	if config.ConnConfig.Host != "127.0.0.1" || config.ConnConfig.Port != 5433 || !strings.HasPrefix(config.ConnConfig.Database, "lean_verify_") {
		t.Fatal("owned local source fixture required")
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback.Host != "127.0.0.1" || fallback.Port != 5433 {
			t.Fatal("source fixture fallback escaped owned endpoint")
		}
	}
	config.MaxConns, config.MinConns = 1, 0
	readonlySource(config)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("source fixture unavailable")
	}
	defer pool.Close()
	if restricted(ctx, pool) != nil || destination(ctx, pool, config.ConnConfig.Database) != nil || sourcePermissions(ctx, pool) != nil {
		t.Fatal("restricted source identity/permissions refused")
	}
	var readOnly bool
	if err = pool.QueryRow(ctx, `SELECT current_setting('transaction_read_only')::boolean`).Scan(&readOnly); err != nil || !readOnly {
		t.Fatal("source session was not read-only")
	}
}
