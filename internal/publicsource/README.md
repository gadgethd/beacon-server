This library is an opt-in reader of UKMesh's `beacon_public` fixture contract.
Nothing imports it from Beacon startup, and it does not write Beacon tables.

The caller supplies a restricted `pgxpool.Pool` and an explicit network set.
`ReadBatch` starts a read-only repeatable-read transaction, checks contract and
privacy readiness, and reads at most 500 GroupText source rows in ledger sequence
order. A fresh state read after the transaction refuses data if privacy changed.
The returned cursor binds sequence, generation, and network set. A generation
change requires reconciliation; the library never quietly resets that cursor.

Each result retains its upstream observation UUID, exact timestamp and metadata.
Unsupported/ineligible observations carry reasons and still count toward source
progress. Supported version-0 GroupText frames are decoded by meshcore-go; the
32-byte UKMesh `wire-sha256-v1` UID is recomputed and checked independently of the
native 8-byte Beacon packet hash. Stored path metadata must match the raw frame.
GroupText parsing does not prove its MAC or decrypt its body. A caller must use
the existing channel-key/authentication owner before presenting a message.

There is deliberately no importer, persistent cursor, public endpoint, polling
loop, source selection, or default rollout here. In particular, this library
does not solve revocation of durable copies or change Beacon's legacy
`UNIQUE(packet_hash,observer_id)` cardinality. Those are prerequisites for a
subsequent projection, not claims made by this source reader.

The source SQL lives in UKMesh `scripts/full-dev/beacon-reader.sql`; its real
fixture permission/data contract is checked by `test-beacon-reader.mjs` there.
This package's tests exercise native frame decoding plus cursor, snapshot,
fresh-generation fence, rejection accounting and transaction cleanup behavior
without a live database.

`TestPublicSourceFixtureIntegration` is opt-in. UKMesh's disposable fixture owner
supplies `BEACON_PUBLIC_FIXTURE_URL` only as an environment variable, phase
`BEACON_PUBLIC_FIXTURE_PHASE=ready|unavailable`, and the two expected UUIDs in
`BEACON_PUBLIC_FIXTURE_OBSERVATIONS`. It checks true pgx limit-one paging,
read-only snapshot settings, rejection accounting and the unavailable-policy
case. It provisions nothing and never prints the connection string.
