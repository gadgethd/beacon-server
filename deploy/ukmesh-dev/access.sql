\set ON_ERROR_STOP on
BEGIN;
DO $roles$
DECLARE service_role text;
BEGIN
  FOREACH service_role IN ARRAY ARRAY['beacon_runtime', 'beacon_maint'] LOOP
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname=service_role) THEN
      EXECUTE format('CREATE ROLE %I LOGIN', service_role);
    END IF;
    IF EXISTS (SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
        JOIN pg_roles granted ON granted.oid=m.roleid WHERE r.rolname=service_role
          AND NOT (r.rolname='beacon_maint' AND granted.rolname='pg_read_all_stats')) THEN
      RAISE EXCEPTION 'Unexpected Beacon runtime role membership';
    END IF;
    EXECUTE format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
      service_role, 'local-full-dev-only');
  END LOOP;
END
$roles$;
GRANT pg_read_all_stats TO beacon_maint WITH INHERIT TRUE, SET FALSE;

-- This dedicated local cluster also retains originals and inactive fixtures.
-- Global logins must not enter those stores through PUBLIC's default CONNECT.
DO $databases$
DECLARE database_record record;
BEGIN
  FOR database_record IN SELECT datname FROM pg_database LOOP
    IF database_record.datname NOT IN ('beacon_dev','postgres','template0','template1')
      AND database_record.datname !~ '^lean_(beacon|verify)_[a-z0-9_]{1,45}$' THEN
      RAISE EXCEPTION 'Unexpected database in owned local Beacon cluster';
    END IF;
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC, beacon_runtime, beacon_maint', database_record.datname);
  END LOOP;
END
$databases$;
GRANT CONNECT ON DATABASE :"beacon_database" TO beacon_runtime, beacon_maint;
GRANT TEMPORARY ON DATABASE :"beacon_database" TO beacon_maint;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM beacon_runtime, beacon_maint;
GRANT USAGE ON SCHEMA public TO beacon_runtime, beacon_maint;

-- Current API/ingest/maintenance/backup relations from the canonical queries.
-- A new or unrelated relation receives nothing on a later bootstrap run until
-- its owning feature explicitly adds it here. Metadata remains SELECT-only.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM beacon_runtime, beacon_maint;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  accounts, channels, channel_keys, channel_messages, channel_iatas,
  channel_config_scopes, channel_message_iatas,
  iata_codes, regions, region_iatas, transport_scopes,
  nodes, node_iatas, node_neighbors, node_short_ids, known_routes,
  observers, observer_brokers, observer_locations, observer_owners,
  observer_scopes, observer_telemetry,
  packets, packet_observations, packet_sites,
  meshmapper_channel_catalogues, meshmapper_channel_members,
  meshmapper_scope_catalogues, meshmapper_zone_boundaries, meshmapper_zone_lists,
  meshmapper_repeater_sources, meshmapper_repeaters,
  trace_iatas, trace_tags,
  analytics_dirty_hours, analytics_raw_state, analytics_rollup_hours, analytics_state,
  analytics_hourly_advert_hearings, analytics_hourly_advert_sets,
  analytics_hourly_iata_observations, analytics_hourly_node_activity,
  analytics_hourly_observer_activity, analytics_hourly_observer_identity,
  analytics_hourly_packet_sets, analytics_hourly_paths,
  analytics_hourly_payload_breakdown, analytics_hourly_scope_nodes,
  analytics_hourly_scope_observers, analytics_hourly_scope_sets,
  analytics_hourly_signal, analytics_hourly_talker_sets, background_state
TO beacon_runtime, beacon_maint;
GRANT SELECT ON mv_radio_presets TO beacon_runtime, beacon_maint;
-- Concurrent refresh applies its delta with INSERT/DELETE even for the owner.
GRANT INSERT, DELETE ON mv_radio_presets TO beacon_maint;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM beacon_runtime, beacon_maint;
GRANT USAGE, SELECT ON SEQUENCE channels_id_seq, channel_messages_id_seq,
  known_routes_new_id_seq, observer_telemetry_id_seq, packet_observations_id_seq,
  regions_id_seq, transport_scopes_id_seq TO beacon_runtime, beacon_maint;
REVOKE ALL ON schema_migrations, schema_migration_integrity FROM beacon_runtime, beacon_maint;
GRANT SELECT ON schema_migrations, schema_migration_integrity TO beacon_runtime, beacon_maint;

-- PostgreSQL 16 requires ownership for VACUUM and materialized-view refresh.
-- Grant it only for the existing derived read models used by those jobs.
GRANT CREATE ON SCHEMA public TO beacon_maint;
ALTER TABLE packet_sites OWNER TO beacon_maint;
ALTER TABLE channel_message_iatas OWNER TO beacon_maint;
ALTER MATERIALIZED VIEW mv_radio_presets OWNER TO beacon_maint;
REVOKE CREATE ON SCHEMA public FROM beacon_maint;
ALTER ROLE beacon_runtime IN DATABASE :"beacon_database" SET search_path = public, pg_temp;
ALTER ROLE beacon_maint IN DATABASE :"beacon_database" SET search_path = public, pg_temp;
COMMIT;
