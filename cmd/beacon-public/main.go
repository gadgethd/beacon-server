// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// beacon-public is an explicit private listener. The ordinary beacon command,
// its configuration, MQTT ingestion and public/admin routes remain unchanged.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/db"
	"github.com/MeshCore-Beacon/beacon-server/internal/publicprojection"
	"github.com/MeshCore-Beacon/beacon-server/internal/publicsource"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func privateBind(raw string) bool {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && ip != nil && !ip.IsUnspecified() && (ip.IsPrivate() || ip.IsLoopback())
}

func configuration(key string, max int32) (*pgxpool.Config, error) {
	value := os.Getenv(key)
	if value == "" {
		return nil, errors.New("required database endpoint missing")
	}
	config, err := pgxpool.ParseConfig(value)
	if err != nil {
		return nil, errors.New("invalid database endpoint")
	}
	config.MaxConns, config.MinConns = max, 0
	if config.ConnConfig.ConnectTimeout == 0 {
		config.ConnConfig.ConnectTimeout = 5 * time.Second
	}
	return config, nil
}

func distinctTargets(target, source *pgxpool.Config, expected string) bool {
	return target != nil && source != nil && expected != "" && target.ConnConfig.Database == expected && source.ConnConfig.Database != "" && target.ConnConfig.Database != source.ConnConfig.Database
}

func readonlySource(config *pgxpool.Config) {
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET default_transaction_read_only = on")
		return err
	}
}

func destination(ctx context.Context, pool *pgxpool.Pool, expected string) error {
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var database string
	if err := pool.QueryRow(check, `SELECT current_database()`).Scan(&database); err != nil || database != expected {
		return errors.New("projection database identity mismatch")
	}
	return nil
}

func projectionPermissions(ctx context.Context, pool *pgxpool.Pool) error {
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var allowed bool
	err := pool.QueryRow(check, `SELECT has_schema_privilege(current_user,'ukmesh_public','USAGE')
 AND NOT has_schema_privilege(current_user,'ukmesh_public','CREATE')
 AND NOT has_schema_privilege(current_user,'public','CREATE')
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND NOT EXISTS (SELECT 1 FROM (VALUES
 ('state','SELECT'),('state','UPDATE'),('channels','SELECT'),('channels','INSERT'),('channels','UPDATE'),
 ('messages','SELECT'),('messages','INSERT'),('messages','DELETE'),('observations','SELECT'),('observations','INSERT'),('observations','DELETE')
 ) required(relation,privilege) WHERE NOT has_table_privilege(current_user,'ukmesh_public.'||relation,privilege))
 AND NOT EXISTS (SELECT 1 FROM (VALUES ('channels_id_seq'),('messages_id_seq'),('observations_event_id_seq')) required(relation)
 WHERE NOT has_sequence_privilege(current_user,'ukmesh_public.'||relation,'USAGE'))`).Scan(&allowed)
	if err != nil || !allowed {
		return errors.New("dedicated projection permissions required")
	}
	return nil
}

func sourcePermissions(ctx context.Context, pool *pgxpool.Pool) error {
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var allowed bool
	err := pool.QueryRow(check, `SELECT has_schema_privilege(current_user,'beacon_public','USAGE')
 AND has_table_privilege(current_user,'beacon_public.packets','SELECT')
 AND has_table_privilege(current_user,'beacon_public.source_state','SELECT')
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
 AND (n.nspowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) OR has_schema_privilege(current_user,n.oid,'CREATE')))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('beacon_public','mesh','core','ops','public') AND c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE (n.nspname='mesh' AND c.relname IN ('packets','ingest_observation_ledger','packet_identity_aliases')
 OR n.nspname='core' AND c.relname IN ('nodes','private_node_prefixes')) AND
 (has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,TRIGGER')))`).Scan(&allowed)
	if err != nil || !allowed {
		return errors.New("restricted public source permissions required")
	}
	return nil
}

func restricted(ctx context.Context, pool *pgxpool.Pool) error {
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var allowed bool
	err := pool.QueryRow(check, `SELECT current_user=session_user AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid)
 FROM pg_catalog.pg_roles r WHERE rolname=current_user`).Scan(&allowed)
	if err != nil || !allowed {
		return errors.New("dedicated unprivileged database principal required")
	}
	return nil
}

func run(ctx context.Context, install bool) error {
	target, err := configuration("BEACON_PUBLIC_PROJECTION_DSN", 2)
	if err != nil {
		return err
	}
	source, err := configuration("BEACON_PUBLIC_SOURCE_DSN", 1)
	if err != nil {
		return err
	}
	readonlySource(source)
	expected := os.Getenv("BEACON_PUBLIC_PROJECTION_DATABASE")
	if !distinctTargets(target, source, expected) {
		return errors.New("explicit distinct projection database required")
	}
	projectionPool, err := pgxpool.NewWithConfig(ctx, target)
	if err != nil {
		return err
	}
	defer projectionPool.Close()
	if err = destination(ctx, projectionPool, expected); err != nil {
		return err
	}
	store := publicprojection.NewPGStore(projectionPool)
	if install {
		return store.Install(ctx)
	}
	if err = restricted(ctx, projectionPool); err != nil {
		return err
	}
	if err = projectionPermissions(ctx, projectionPool); err != nil {
		return err
	}
	bind := os.Getenv("BEACON_PUBLIC_LISTEN_ADDR")
	if !privateBind(bind) {
		return errors.New("explicit private or loopback literal listen address required")
	}
	authority, err := publicprojection.NewHTTPAuthority(os.Getenv("BEACON_PUBLIC_AUTHORITY_URL"), os.Getenv("BEACON_PUBLIC_READ_TOKEN"))
	if err != nil {
		return err
	}
	sourcePool, err := pgxpool.NewWithConfig(ctx, source)
	if err != nil {
		return err
	}
	defer sourcePool.Close()
	if err = restricted(ctx, sourcePool); err != nil {
		return err
	}
	if err = destination(ctx, sourcePool, source.ConnConfig.Database); err != nil {
		return err
	}
	if err = sourcePermissions(ctx, sourcePool); err != nil {
		return err
	}
	history, err := publicsource.New(sourcePool, []string{"ukmesh"})
	if err != nil {
		return err
	}
	var live publicprojection.LiveSource
	if endpoint := os.Getenv("BEACON_PUBLIC_LIVE_URL"); endpoint != "" {
		if os.Getenv("BEACON_PUBLIC_LIVE_TOKEN") == os.Getenv("BEACON_PUBLIC_READ_TOKEN") {
			return errors.New("live and authority credentials must be distinct")
		}
		live, err = publicsource.NewLiveHTTPSource(endpoint, os.Getenv("BEACON_PUBLIC_LIVE_TOKEN"))
		if err != nil {
			return err
		}
	} else if os.Getenv("BEACON_PUBLIC_LIVE_TOKEN") != "" {
		return errors.New("live token configured without an authorized live endpoint")
	}
	service, err := publicprojection.New(store, history, live, authority)
	if err != nil {
		return err
	}
	days, parseErr := strconv.Atoi(os.Getenv("BEACON_PUBLIC_RETENTION_DAYS"))
	if parseErr != nil {
		return errors.New("explicit matching projection retention days required")
	}
	if err = service.SetRetentionDays(days); err != nil {
		return err
	}
	origins := []string{}
	// Empty retains native same-origin admission. Explicit patterns use the
	// existing Beacon WebSocket OriginPatterns contract, never a wildcard.
	if origin := os.Getenv("BEACON_PUBLIC_ALLOWED_ORIGIN"); origin != "" {
		if origin == "*" {
			return errors.New("wildcard origin is not allowed")
		}
		origins = append(origins, origin)
	}
	geography := db.New(projectionPool, nil, 0, 0)
	geoCtx, stopGeo := context.WithTimeout(ctx, 5*time.Second)
	_, geoErr := geography.ListIATAs(geoCtx)
	if geoErr == nil {
		_, geoErr = geography.ListRegions(geoCtx)
	}
	stopGeo()
	if geoErr != nil {
		return errors.New("native Beacon geography is not provisioned")
	}
	server := &http.Server{Addr: bind, Handler: service.Handler(geography, origins), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	owned, cancel := context.WithCancel(ctx)
	defer cancel()
	server.BaseContext = func(net.Listener) context.Context { return owned }
	workerDone, serverDone := make(chan error, 1), make(chan error, 1)
	go func() { workerDone <- service.Run(owned) }()
	go func() { serverDone <- server.ListenAndServe() }()
	var workerErr, serverErr error
	workerFinished, serverFinished := false, false
	select {
	case <-ctx.Done():
	case workerErr = <-workerDone:
		workerFinished = true
	case serverErr = <-serverDone:
		serverFinished = true
	}
	cancel()
	closing, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	closeErr := server.Shutdown(closing)
	if closeErr != nil {
		closeErr = errors.Join(closeErr, server.Close())
	}
	if !workerFinished {
		workerErr = <-workerDone
	}
	if !serverFinished {
		serverErr = <-serverDone
	}
	if errors.Is(workerErr, context.Canceled) {
		workerErr = nil
	}
	if errors.Is(serverErr, http.ErrServerClosed) {
		serverErr = nil
	}
	return errors.Join(workerErr, serverErr, closeErr)
}

func main() {
	install := flag.Bool("install-schema", false, "explicitly install only the private projection schema")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *install); err != nil {
		// Endpoint/authority errors may contain credentials; detailed deployment
		// diagnostics belong to the credential owner, never the public log.
		slog.Error("private public-message listener stopped", "component", "ukmesh-public")
		os.Exit(1)
	}
}
