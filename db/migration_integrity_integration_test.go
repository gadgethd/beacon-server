// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestExternalMigrationIntegrityReadOnlyPostgres(t *testing.T) {
	ctx, pool := schemaPool(t)
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var integrity bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('schema_migration_integrity') IS NOT NULL").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity {
		t.Fatal("default upstream migration path created attestation metadata")
	}
	if err := VerifyMigrations(ctx, pool); err == nil {
		t.Fatal("unattested database verified")
	}
	if err := RunAttestedMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}

	var schema, database string
	if err := pool.QueryRow(ctx, "SELECT current_schema(),current_database()").Scan(&schema, &database); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("beacon_integrity_%d_%d", os.Getpid(), time.Now().UnixNano())
	quotedRole := pgx.Identifier{role}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE ROLE "+quotedRole+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD 'owned-integrity-only'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+quotedRole+"; DROP ROLE "+quotedRole); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{database}.Sanitize() + " TO " + quotedRole,
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + quotedRole,
		"GRANT SELECT ON schema_migrations,schema_migration_integrity TO " + quotedRole,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("BEACON_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = "owned-integrity-only"
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.MaxConns = 1
	reader, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	var sessionUser string
	if err := reader.QueryRow(ctx, "SELECT session_user").Scan(&sessionUser); err != nil || sessionUser != role {
		t.Fatalf("actual login=%s error=%v", sessionUser, err)
	}
	if err := VerifyMigrations(ctx, reader); err != nil {
		t.Fatalf("SELECT-only read-only runtime verification: %v", err)
	}
	expected, err := embeddedMigrationInventory()
	if err != nil {
		t.Fatal(err)
	}
	name := baselineMigration
	if _, err := pool.Exec(ctx, "UPDATE schema_migration_integrity SET checksum_sha256=$1 WHERE filename=$2", strings.Repeat("0", 64), name); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMigrations(ctx, reader); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("changed source verified: %v", err)
	}
	if err := RunAttestedMigrations(ctx, pool); err == nil {
		t.Fatal("operator job silently overwrote existing checksum mismatch")
	}
	if _, err := pool.Exec(ctx, "UPDATE schema_migration_integrity SET checksum_sha256=$1 WHERE filename=$2", expected[name], name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migration_integrity WHERE filename=$1", name); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMigrations(ctx, reader); err == nil || !strings.Contains(err.Error(), "no attested checksum") {
		t.Fatalf("missing hash verified: %v", err)
	}
	if err := RunAttestedMigrations(ctx, pool); err == nil {
		t.Fatal("operator job silently repaired a missing historic hash")
	}
	if _, err := pool.Exec(ctx, "INSERT INTO schema_migration_integrity(filename,checksum_sha256) VALUES($1,$2)", name, expected[name]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE filename=$1", name); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMigrations(ctx, reader); err == nil || !strings.Contains(err.Error(), "pending migration") {
		t.Fatalf("pending migration verified: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO schema_migrations(filename) VALUES($1);", name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO schema_migration_integrity(filename,checksum_sha256) VALUES($1,$2)", name, expected[name]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO schema_migrations(filename) VALUES('999_unknown.sql')"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMigrations(ctx, reader); err == nil || !strings.Contains(err.Error(), "unknown applied migration") {
		t.Fatalf("unknown migration verified: %v", err)
	}
}

func TestAttestedMigrationRecordsAtomicPostgres(t *testing.T) {
	ctx, pool := schemaPool(t)
	_, err := pool.Exec(ctx, `CREATE TABLE schema_migrations(filename text PRIMARY KEY);
		CREATE TABLE schema_migration_integrity(filename text PRIMARY KEY REFERENCES schema_migrations(filename),
		checksum_sha256 text NOT NULL, CONSTRAINT reject_metadata CHECK(false));`)
	if err != nil {
		t.Fatal(err)
	}
	ddl := "CREATE TABLE atomic_integrity_probe(v integer)"
	if err := applyAndRecord(ctx, pool, "900_atomic.sql", ddl, true); err == nil {
		t.Fatal("metadata failure was ignored")
	}
	var created bool
	var count int
	if err := pool.QueryRow(ctx, "SELECT to_regclass('atomic_integrity_probe') IS NOT NULL,(SELECT count(*) FROM schema_migrations)").Scan(&created, &count); err != nil || created || count != 0 {
		t.Fatalf("failed metadata committed DDL/filename: created=%v rows=%d error=%v", created, count, err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE schema_migration_integrity DROP CONSTRAINT reject_metadata"); err != nil {
		t.Fatal(err)
	}
	if err := applyAndRecord(ctx, pool, "900_atomic.sql", ddl, true); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations JOIN schema_migration_integrity USING(filename)").Scan(&count); err != nil || count != 1 {
		t.Fatalf("atomic restart rows=%d error=%v", count, err)
	}

	if _, err := pool.Exec(ctx, "ALTER TABLE schema_migration_integrity ADD CONSTRAINT reject_next CHECK(filename <> '901_concurrent.sql')"); err != nil {
		t.Fatal(err)
	}
	indexDDL := "CREATE INDEX CONCURRENTLY atomic_integrity_idx ON atomic_integrity_probe(v)"
	if err := applyAndRecord(ctx, pool, "901_concurrent.sql", indexDDL, true); err == nil {
		t.Fatal("concurrent metadata failure was ignored")
	}
	var indexID, afterID uint32
	if err := pool.QueryRow(ctx, "SELECT 'atomic_integrity_idx'::regclass::oid,(SELECT count(*) FROM schema_migrations WHERE filename='901_concurrent.sql')").Scan(&indexID, &count); err != nil || count != 0 {
		t.Fatalf("partial concurrent record rows=%d error=%v", count, err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE schema_migration_integrity DROP CONSTRAINT reject_next"); err != nil {
		t.Fatal(err)
	}
	if err := applyAndRecord(ctx, pool, "901_concurrent.sql", indexDDL, true); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT 'atomic_integrity_idx'::regclass::oid,(SELECT count(*) FROM schema_migrations JOIN schema_migration_integrity USING(filename))").Scan(&afterID, &count); err != nil || count != 2 || afterID != indexID {
		t.Fatalf("concurrent restart index changed or record incomplete: before=%d after=%d rows=%d error=%v", indexID, afterID, count, err)
	}
}

func TestAttestedFreshMigrationResumesAfterMetadataFailurePostgres(t *testing.T) {
	ctx, pool := schemaPool(t)
	_, err := pool.Exec(ctx, `CREATE TABLE schema_migrations(filename text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now());
		CREATE TABLE schema_migration_integrity(filename text PRIMARY KEY REFERENCES schema_migrations(filename),
		checksum_sha256 text NOT NULL,attested_at timestamptz NOT NULL DEFAULT now(),
		CONSTRAINT reject_baseline CHECK(filename <> '001_baseline.sql'));`)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunAttestedMigrations(ctx, pool); err == nil {
		t.Fatal("injected checksum failure did not stop migrations")
	}
	var packets bool
	var count int
	if err := pool.QueryRow(ctx, "SELECT to_regclass('packets') IS NOT NULL,(SELECT count(*) FROM schema_migrations)").Scan(&packets, &count); err != nil || packets || count != 0 {
		t.Fatalf("failed baseline left partial state: packets=%v rows=%d error=%v", packets, count, err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE schema_migration_integrity DROP CONSTRAINT reject_baseline"); err != nil {
		t.Fatal(err)
	}
	if err := RunAttestedMigrations(ctx, pool); err != nil {
		t.Fatalf("migration job did not recover: %v", err)
	}
	if err := VerifyMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := RunAttestedMigrations(ctx, pool); err != nil {
		t.Fatalf("attested migration restart was not idempotent: %v", err)
	}
}
