# Separate migration and runtime credentials

Beacon keeps its existing automatic migration behavior by default. An operator
can instead run migrations as a one-shot job and start the server with credentials
that cannot create schema objects or change the migration ledger.

Run the operator job with its own `POSTGRES_DSN`:

```sh
beacon --migrate-only --attest-migrations
```

This job opens one database connection and exits before config seeding, MQTT,
background jobs or HTTP startup. It applies the canonical migrations and records
their embedded SHA256 hashes in `schema_migration_integrity`. The optional
attestation is explicit because the original filename-only ledger cannot prove
which SQL bytes executed before checksums existed. A legacy attestation records
the reviewed current embedded source; it does not establish historical bit identity.
Existing attestations are immutable: a changed or missing historical checksum
fails before further migration work rather than being replaced.

Start the application with:

```sh
POSTGRES_DSN=postgres://beacon_runtime:...@database/beacon \
BEACON_MAINTENANCE_DSN=postgres://beacon_maint:...@database/beacon \
BEACON_EXTERNAL_MIGRATIONS=1 beacon
```

The external mode checks every canonical filename and checksum in a read-only
snapshot before seeding or starting writers. Missing metadata, pending or unknown
migrations, and checksum mismatches fail startup. It never falls back to running
DDL with runtime credentials. `--attest-migrations` is valid only with
`--migrate-only`; it is not a runtime repair switch.

`BEACON_MAINTENANCE_DSN` selects only the maintenance pool. API and ingest pools
use `POSTGRES_DSN`; both credentials must address the same host, port and database.
Without the maintenance setting, all pools retain the original single-credential
behavior. Pool sizes and session settings are unchanged.

Provision privileges before application startup:

The optional UKMesh local-development profile keeps its explicit relation grants
and derived-object ownership policy in `deploy/ukmesh-dev/access.sql`. Its calling
launcher must verify the local database/container ownership before running it.
This fixture bootstrap is separate from Beacon's default deployment behavior.

- Runtime and maintenance need `SELECT` on `schema_migrations` and
  `schema_migration_integrity`, with no writes to either metadata table.
- Preserve application DML for config seeding, ingestion, reconciliation,
  retention, imports and other enabled jobs. Both roles stay `NOSUPERUSER`, with
  no database or role creation. Runtime must not own raw measurements.
- Maintenance needs `TEMPORARY` for rollups and reconfirmation. On PostgreSQL16,
  its existing `VACUUM (ANALYZE)` and concurrent materialized-view refresh require
  ownership of the two derived tables `packet_sites`, `channel_message_iatas`
  and the derived view `mv_radio_presets`. Keep ownership limited to those
  objects; grant only their required input reads and business DML elsewhere.
  Concurrent refresh also needs `INSERT` and `DELETE` on the materialized view
  if its owner's ordinary table privileges have been explicitly revoked.
- Maintenance needs inherited `pg_read_all_stats` to observe cross-role writer
  transactions and the existing operator query statistics. This does not need
  permission to assume that role with `SET ROLE`.
- Put trusted application schemas ahead of `pg_temp` in the role's explicit
  database search path and deny permanent schema creation.
- Keep migration credentials in the one-shot job. Backups require their existing
  table reads and sequence reads; they do not require a runtime superuser.

This mode preserves config seeding, read-model repair, MQTT and background jobs.
The separate `server.read_only` setting retains its existing behavior.
