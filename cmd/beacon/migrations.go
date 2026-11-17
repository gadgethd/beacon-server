// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/MeshCore-Beacon/beacon-server/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

type databaseMode struct {
	migrateOnly bool
	attest      bool
	external    bool
}

func parseDatabaseMode(args []string, external string) (databaseMode, error) {
	var mode databaseMode
	flags := flag.NewFlagSet("beacon", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&mode.migrateOnly, "migrate-only", false, "apply migrations and exit before starting services")
	flags.BoolVar(&mode.attest, "attest-migrations", false, "attest canonical migration hashes in the operator migration job")
	if err := flags.Parse(args); err != nil {
		return mode, err
	}
	if flags.NArg() != 0 {
		return mode, fmt.Errorf("unexpected positional arguments")
	}
	if mode.attest && !mode.migrateOnly {
		return mode, fmt.Errorf("--attest-migrations requires --migrate-only")
	}
	if strings.TrimSpace(external) != "" {
		value, err := strconv.ParseBool(strings.TrimSpace(external))
		if err != nil {
			return mode, fmt.Errorf("BEACON_EXTERNAL_MIGRATIONS must be true or false")
		}
		mode.external = value
	}
	return mode, nil
}

func runMigrationOnly(ctx context.Context, dsn string, attest bool) error {
	if strings.TrimSpace(dsn) == "" {
		return fmt.Errorf("POSTGRES_DSN is required for the migration job")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("invalid PostgreSQL connection configuration; check POSTGRES_DSN")
	}
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("invalid PostgreSQL connection configuration; check POSTGRES_DSN")
	}
	defer pool.Close()
	if attest {
		return db.RunAttestedMigrations(ctx, pool)
	}
	return db.RunMigrations(ctx, pool)
}
