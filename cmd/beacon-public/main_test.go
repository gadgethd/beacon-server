// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestListenerRequiresExplicitPrivateLiteral(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:8081", "[::1]:8081", "172.18.0.2:8081"} {
		if !privateBind(bind) {
			t.Fatal("private bind refused")
		}
	}
	for _, bind := range []string{"", ":8081", "0.0.0.0:8081", "[::]:8081", "8.8.8.8:8081", "localhost:8081", "127.0.0.1:0"} {
		if privateBind(bind) {
			t.Fatal("implicit/public bind accepted")
		}
	}
}

func TestInstallAndRuntimeRequireExplicitDistinctDatabase(t *testing.T) {
	target, _ := pgxpool.ParseConfig("postgres://127.0.0.1/projection")
	source, _ := pgxpool.ParseConfig("postgres://127.0.0.1/ukmesh")
	if !distinctTargets(target, source, "projection") {
		t.Fatal("explicit distinct target refused")
	}
	for _, expected := range []string{"", "another"} {
		if distinctTargets(target, source, expected) {
			t.Fatal("implicit/wrong target accepted")
		}
	}
	source.ConnConfig.Database = "projection"
	source.ConnConfig.Host = "another-host"
	if distinctTargets(target, source, "projection") {
		t.Fatal("same named source database accepted through another endpoint")
	}
}
