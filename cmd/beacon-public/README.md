`beacon-public` is a separate, opt-in private listener. The standard Beacon
command, ports, MQTT ingestion, saved groups and routes are unchanged. Do not
point it at original stores as a shortcut to installing or testing it.

Set these values through the service owner's environment, never DSN arguments:

- `BEACON_PUBLIC_PROJECTION_DSN`: dedicated Beacon-side projection runtime role.
- `BEACON_PUBLIC_PROJECTION_DATABASE`: its exact expected database name. It must
  differ from the source database name, including during `-install-schema`.
- `BEACON_PUBLIC_SOURCE_DSN`: restricted UKMesh `beacon_public` reader. The pool
  has one slot, read-only sessions and read-only repeatable-read batch queries.
- `BEACON_PUBLIC_AUTHORITY_URL`: exact `/internal/beacon/authority` URL.
- `BEACON_PUBLIC_READ_TOKEN`: the distinct authority Bearer credential.
- `BEACON_PUBLIC_LISTEN_ADDR`: explicit private/loopback literal IP and port.
  Wildcard/public binds and implicit defaults are refused.
- `BEACON_PUBLIC_RETENTION_DAYS`: explicit matching source retention, 30 in DEV.
  The accepted bound is30–365; a different value requires a matching change to
  the authoritative lifecycle. There is no silent shorter-history default.
- Optional `BEACON_PUBLIC_ALLOWED_ORIGIN`: native Beacon origin pattern. An
  absent value retains same-origin admission; `*` is refused.

Durable mode uses the committed PostgreSQL ledger as both history and live tail.
RAM mode additionally sets `BEACON_PUBLIC_LIVE_URL` to the protected
`/internal/ingest/public/entries` endpoint and supplies its separate
`BEACON_PUBLIC_LIVE_TOKEN`. A configured but unavailable live source fails
closed. This command never changes MQTT ingest mode or falls back between modes.

The migration owner explicitly invokes `beacon-public -install-schema` against
the separate destination first. This creates only `ukmesh_public`. Grant the
runtime role USAGE on that schema; SELECT/UPDATE on `state`;
SELECT/INSERT/UPDATE on `channels`; SELECT/INSERT/DELETE on `messages` and
`observations`; and USAGE on their three generated-ID sequences. Persistent
DDL/schema creation and role inheritance must remain unavailable. Startup
checks actual identities and effective privileges; it does not attempt DDL to
prove denial. The owned native fixture verifies the DML and DDL-denial contract.

The destination also needs the existing native Beacon geography catalog:
`public.iata_codes`, `public.regions`, `public.region_iatas`, populated by its
existing migration/configuration owner and SELECT-only for this runtime role.
These are geographic IATA memberships, never UKMesh RF scopes. Startup refuses
missing geography. Nonempty RF `scope` filters return explicit503 until an
authoritative packet-scope contract exists; they are never mapped to IATA.

The only listener paths are `/readyz`, `/api/v1/iatas`, `/api/v1/regions`,
`/api/v1/regions/<id>`, `/api/v1/channels`, channel detail/history, and `/ws`.
The edge strips `/beacon`, removes cookies/auth headers, and owns browser origin
routing. Readiness contains only `{version:1,generation,registryVersion}` after
history backfill, any configured RAM overlap, and the live event baseline are
settled. Every HTTP reply and WS write is fenced by the complete projection
revision; revocation closes active sockets with1008. No saved-group API exists.

Only authenticated public-registry GroupText is stored, once per full UID and
exact channel identity. Compact UUID observation rows provide reach counts and
idempotent history/live overlap. No raw frames or keys are persisted. Logical
reads enforce retention on observation time; hourly cleanup removes expired
observations and orphan plaintext, incrementing the local epoch when it changes
data. Retention deliberately does not use the sender's embedded timestamp.

Opt-in native tests use `BEACON_PUBLIC_PROJECTION_FIXTURE_URL` for a generated
NOINHERIT application role on an owned `lean_verify_*` database at127.0.0.1:5435.
The external fixture owner installs schema and grants access, then executes
`TestProjectionOwnedPostgresIntegration` and `TestProjectionStartupOwnedFixture`.
No test provisions or mutates original databases; absent fixture env skips them.
`TestSourceStartupOwnedFixture` additionally accepts
`BEACON_PUBLIC_SOURCE_FIXTURE_URL` for the restricted source role on a separate
owned127.0.0.1:5433 fixture. Both real role tests are required before promotion;
the projection role test alone does not establish source permission safety.

Deployment wiring, geography population, both real role proofs, native listener
integration, performance/resource qualification and source-eligibility coverage
remain promotion requirements. Unsupported source records are not certified as
messages; repairing historical identity/raw data requires a deliberate rebuild.
