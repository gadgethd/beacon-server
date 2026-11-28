-- Explicit opt-in migration in Beacon's separate database, never a UKMesh raw
-- schema or an automatic addition to Beacon's standalone migration chain.
CREATE SCHEMA IF NOT EXISTS ukmesh_public;
REVOKE ALL ON SCHEMA ukmesh_public FROM PUBLIC;
CREATE TABLE IF NOT EXISTS ukmesh_public.state (
  singleton boolean PRIMARY KEY CHECK(singleton), generation bigint NOT NULL DEFAULT 0,
  registry_version text NOT NULL DEFAULT '', ready boolean NOT NULL DEFAULT false,
  history_complete boolean NOT NULL DEFAULT false, live_complete boolean NOT NULL DEFAULT false,
  revision bigint NOT NULL DEFAULT 1,
  history_cursor jsonb NOT NULL DEFAULT '{}', live_cursor text NOT NULL DEFAULT '0-0'
);
INSERT INTO ukmesh_public.state(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS ukmesh_public.channels (
  id serial PRIMARY KEY, registry_id text NOT NULL, key_fingerprint text NOT NULL,
  name text NOT NULL, channel_hash text NOT NULL, registry_version text NOT NULL,
  UNIQUE(registry_id,key_fingerprint)
);
CREATE TABLE IF NOT EXISTS ukmesh_public.messages (
  id bigserial PRIMARY KEY, channel_id integer NOT NULL REFERENCES ukmesh_public.channels(id),
  packet_uid bytea NOT NULL CHECK(octet_length(packet_uid)=32), beacon_hash bytea NOT NULL CHECK(octet_length(beacon_hash)=8),
  sender text NOT NULL, content text NOT NULL, sent_at bigint NOT NULL,
  transport boolean NOT NULL, UNIQUE(channel_id,packet_uid)
);
CREATE TABLE IF NOT EXISTS ukmesh_public.observations (
  event_id bigserial PRIMARY KEY, observation_id uuid NOT NULL UNIQUE,
  message_id bigint NOT NULL REFERENCES ukmesh_public.messages(id) ON DELETE CASCADE,
  observed_at timestamptz NOT NULL, iata text, receiver bytea NOT NULL CHECK(octet_length(receiver)=32),
  frame_digest bytea NOT NULL CHECK(octet_length(frame_digest)=32)
);
CREATE INDEX IF NOT EXISTS ukmesh_public_observation_message ON ukmesh_public.observations(message_id,event_id);
CREATE INDEX IF NOT EXISTS ukmesh_public_observation_iata ON ukmesh_public.observations(iata,message_id);
CREATE INDEX IF NOT EXISTS ukmesh_public_observation_time ON ukmesh_public.observations(observed_at);
REVOKE ALL ON ALL TABLES IN SCHEMA ukmesh_public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA ukmesh_public FROM PUBLIC;
