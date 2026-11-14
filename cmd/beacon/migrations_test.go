// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"
)

func TestDatabaseStartupModes(t *testing.T) {
	for _, test := range []struct {
		name                    string
		args                    []string
		external                string
		migrate, attest, verify bool
		invalid                 bool
	}{
		{name: "upstream default"},
		{name: "external runtime", external: "1", verify: true},
		{name: "migration only", args: []string{"--migrate-only"}, migrate: true},
		{name: "explicit attestation", args: []string{"--migrate-only", "--attest-migrations"}, migrate: true, attest: true},
		{name: "attestation requires operator mode", args: []string{"--attest-migrations"}, invalid: true},
		{name: "unknown CLI flag rejected", args: []string{"--unknown"}, invalid: true},
		{name: "test binary flags remain invalid CLI flags", args: []string{"-test.run=TestStartupLogging"}, invalid: true},
		{name: "invalid external flag fails closed", external: "enable-typo", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode, err := parseDatabaseMode(test.args, test.external)
			if (err != nil) != test.invalid {
				t.Fatalf("mode=%+v error=%v", mode, err)
			}
			if err == nil && (mode.migrateOnly != test.migrate || mode.attest != test.attest || mode.external != test.verify) {
				t.Fatalf("mode=%+v", mode)
			}
		})
	}
}

func TestMigrationJobRequiresExplicitDSN(t *testing.T) {
	if err := runMigrationOnly(context.Background(), "", false); err == nil {
		t.Fatal("migration job used implicit PostgreSQL credentials")
	}
}
