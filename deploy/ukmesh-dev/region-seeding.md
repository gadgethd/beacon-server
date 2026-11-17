# Region seed ownership

Config seeding runs at startup. An identical region seed must preserve its row
and `updated_at`; changing a config-owned value must still update the row. This
includes the first takeover of an imported region. PostgreSQL's null-safe tuple
comparison owns that decision. The store resolves the unchanged slug through
its existing reader when the conditional upsert has no returned row.

This avoids coupling runtime recreation to protected operator-data changes.
Database protection checks retain every column, including the timestamp.
