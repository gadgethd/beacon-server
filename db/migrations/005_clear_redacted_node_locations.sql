-- Copyright 2026 Beacon Contributors
-- SPDX-License-Identifier: agpl

-- 005_clear_redacted_node_locations.sql
-- Backfill: permanently null the stored coordinates of every node that has
-- already opted its location out via the redaction marker (🚫) in its name.
-- Going forward the advert pipeline clears these on every advert, but rows that
-- were upserted before that change still hold coordinates that were only masked
-- on read. Null them outright so the location is gone from the DB and the map.
UPDATE nodes
SET latitude = NULL, longitude = NULL, location_source = NULL
WHERE name LIKE '%🚫%'
  AND (latitude IS NOT NULL OR longitude IS NOT NULL OR location_source IS NOT NULL);
