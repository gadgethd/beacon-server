// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"strings"
	"testing"

	"github.com/MeshCore-Beacon/beacon-server/db/planpolicy"
)

func TestPoolCredentialsKeepMaintenanceSeparate(t *testing.T) {
	runtime := "postgres://runtime:owned-only@127.0.0.1:1/beacon?sslmode=disable"
	maint := "postgres://maintenance:owned-only@127.0.0.1:1/beacon?sslmode=disable"
	pools, err := OpenPoolsWithCredentials(context.Background(), PoolCredentials{Runtime: runtime, Maintenance: maint}, planpolicy.CustomAll)
	if err != nil {
		t.Fatal(err)
	}
	defer pools.Close()
	for name, pool := range map[string]string{
		PoolAPICustom: pools.APICustom.Config().ConnConfig.User,
		PoolIngest:    pools.Ingest.Config().ConnConfig.User,
		PoolMaint:     pools.Maint.Config().ConnConfig.User,
	} {
		want := "runtime"
		if name == PoolMaint {
			want = "maintenance"
		}
		if pool != want {
			t.Fatalf("%s credential=%s; want %s", name, pool, want)
		}
	}
	if pools.Total() != 8+ingestPoolSize()+4 {
		t.Fatalf("pool sizes changed: %d", pools.Total())
	}
}

func TestPoolCredentialsRejectOtherDatabaseAndHideSecrets(t *testing.T) {
	runtime := "postgres://runtime:owned-secret@127.0.0.1:1/beacon?sslmode=disable"
	for _, maint := range []string{
		"postgres://maintenance:owned-secret@127.0.0.1:1/other?sslmode=disable",
		"postgres://maintenance:owned-secret@127.0.0.1:2/beacon?sslmode=disable",
		"postgres://maintenance:owned-secret@127.0.0.1:bad-port/beacon",
	} {
		pools, err := OpenPoolsWithCredentials(context.Background(), PoolCredentials{Runtime: runtime, Maintenance: maint}, planpolicy.CustomAll)
		if err == nil {
			pools.Close()
			t.Fatal("invalid maintenance endpoint accepted")
		}
		if strings.Contains(err.Error(), "owned-secret") {
			t.Fatal("error exposed DSN password")
		}
	}
}
