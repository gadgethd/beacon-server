// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type migrationInventory map[string]string

func migrationChecksum(sql string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(sql)))
}

func embeddedMigrationInventory() (migrationInventory, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	inventory := make(migrationInventory)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, err
		}
		inventory[entry.Name()] = migrationChecksum(string(body))
	}
	return inventory, nil
}

type migrationHistory struct {
	applied  map[string]bool
	hashes   migrationInventory
	attested bool
}

type migrationQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// readMigrationHistory only reads catalogs and the two metadata tables. Missing
// metadata is a state the explicit bootstrap can attest; verification rejects it.
func readMigrationHistory(ctx context.Context, q migrationQuery) (migrationHistory, error) {
	history := migrationHistory{applied: make(map[string]bool), hashes: make(migrationInventory)}
	var ledger bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL,
		to_regclass('schema_migration_integrity') IS NOT NULL`).Scan(&ledger, &history.attested); err != nil {
		return history, err
	}
	if !ledger {
		if history.attested {
			return history, fmt.Errorf("migration integrity exists without its ledger")
		}
		return history, nil
	}
	rows, err := q.Query(ctx, "SELECT filename FROM schema_migrations")
	if err != nil {
		return history, err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return history, err
		}
		history.applied[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return history, err
	}
	if !history.attested {
		return history, nil
	}
	rows, err = q.Query(ctx, "SELECT filename, checksum_sha256 FROM schema_migration_integrity")
	if err != nil {
		return history, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, hash string
		if err := rows.Scan(&name, &hash); err != nil {
			return history, err
		}
		history.hashes[name] = hash
	}
	return history, rows.Err()
}

func (history migrationHistory) verifyKnown(expected migrationInventory) error {
	for name := range history.applied {
		want, known := expected[name]
		if !known {
			return fmt.Errorf("unknown applied migration %s", name)
		}
		if history.attested {
			got, recorded := history.hashes[name]
			if !recorded {
				return fmt.Errorf("migration %s has no attested checksum", name)
			}
			if got != want {
				return fmt.Errorf("migration %s checksum mismatch", name)
			}
		}
	}
	for name := range history.hashes {
		if !history.applied[name] {
			return fmt.Errorf("migration checksum %s has no applied ledger row", name)
		}
	}
	return nil
}

func (history migrationHistory) verifyComplete(expected migrationInventory) error {
	if !history.attested {
		return fmt.Errorf("migration checksums are not attested; run --migrate-only --attest-migrations with the operator credential")
	}
	if err := history.verifyKnown(expected); err != nil {
		return err
	}
	for name := range expected {
		if !history.applied[name] {
			return fmt.Errorf("pending migration %s; run the migration job", name)
		}
	}
	return nil
}

// VerifyMigrations checks the canonical filename/hash inventory in a read-only
// snapshot. It never creates metadata, applies DDL or repairs a missing checksum.
func VerifyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	expected, err := embeddedMigrationInventory()
	if err != nil {
		return err
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	history, err := readMigrationHistory(ctx, tx)
	if err != nil {
		return fmt.Errorf("read migration verification metadata: %w", err)
	}
	if err := history.verifyComplete(expected); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RunAttestedMigrations is an explicit operator action for external migration
// deployments. Legacy filename-only rows attest this reviewed embedded source;
// they cannot prove the bytes executed before checksums were introduced.
// Existing attestations are immutable: missing or changed historical hashes fail.
func RunAttestedMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	expected, err := embeddedMigrationInventory()
	if err != nil {
		return err
	}
	return withMigrationLock(ctx, pool, func(conn *pgxpool.Conn) error {
		before, err := readMigrationHistory(ctx, conn)
		if err != nil {
			return err
		}
		if err := before.verifyKnown(expected); err != nil {
			return err
		}
		if err := prepareMigrationLedger(ctx, conn); err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migration_integrity (
			filename TEXT PRIMARY KEY REFERENCES schema_migrations(filename) ON DELETE CASCADE,
			checksum_sha256 TEXT NOT NULL CHECK(checksum_sha256 ~ '^[0-9a-f]{64}$'),
			attested_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		if !before.attested {
			for name := range before.applied {
				if _, err := tx.Exec(ctx, `INSERT INTO schema_migration_integrity(filename,checksum_sha256)
					VALUES($1,$2)`, name, expected[name]); err != nil {
					return err
				}
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		// New filenames and checksums are recorded together with transactional
		// DDL (or one atomic record after concurrent-index DDL), so a crash can
		// never leave an applied filename that cannot resume verification.
		if err := runMigrations(ctx, conn, pool, true); err != nil {
			return err
		}
		history, err := readMigrationHistory(ctx, conn)
		if err != nil {
			return err
		}
		if err := history.verifyComplete(expected); err != nil {
			return err
		}
		return nil
	})
}
