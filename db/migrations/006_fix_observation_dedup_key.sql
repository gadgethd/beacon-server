-- 006_fix_observation_dedup_key.sql
--
-- The previous unique constraint on (packet_hash, observer_id, heard_at) was
-- too permissive: heard_at is stamped at ingest time (time.Now()), so MQTT
-- redeliveries of the same packet arrive with slightly different timestamps
-- and bypass dedup, producing duplicate observations for the same observer.
--
-- An observer either heard a packet or they didn't. Drop heard_at from the
-- constraint so that (packet_hash, observer_id) is the dedup key.

-- Keep the earliest observation for each (packet_hash, observer_id) pair in a
-- temporary table, then repopulate the original table. Rewriting the smaller
-- deduplicated set avoids a very expensive NOT IN materialization and millions
-- of row-by-row deletes on large installations.
CREATE TEMP TABLE packet_observations_dedup
ON COMMIT DROP
AS
SELECT DISTINCT ON (packet_hash, observer_id) *
FROM packet_observations
ORDER BY packet_hash, observer_id, id;

TRUNCATE TABLE packet_observations;

INSERT INTO packet_observations
SELECT * FROM packet_observations_dedup;

-- Explicit inserts do not advance the BIGSERIAL sequence.
SELECT setval(
    pg_get_serial_sequence('packet_observations', 'id'),
    COALESCE((SELECT MAX(id) FROM packet_observations), 1),
    EXISTS(SELECT 1 FROM packet_observations)
);

ALTER TABLE packet_observations
    DROP CONSTRAINT packet_observations_packet_hash_observer_id_heard_at_key;

ALTER TABLE packet_observations
    ADD CONSTRAINT packet_observations_packet_hash_observer_id_key
    UNIQUE (packet_hash, observer_id);
