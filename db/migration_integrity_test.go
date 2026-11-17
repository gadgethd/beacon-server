// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"strings"
	"testing"
)

func TestMigrationChecksumKnownVector(t *testing.T) {
	if got := migrationChecksum("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("migration checksum is not SHA256: %s", got)
	}
}

func TestMigrationInventoryFailsClosed(t *testing.T) {
	expected := migrationInventory{"001.sql": "good-one", "002.sql": "good-two"}
	cases := []struct {
		name    string
		history migrationHistory
		failure string
	}{
		{"complete", migrationHistory{map[string]bool{"001.sql": true, "002.sql": true}, migrationInventory{"001.sql": "good-one", "002.sql": "good-two"}, true}, ""},
		{"missing attestation", migrationHistory{map[string]bool{"001.sql": true}, nil, false}, "not attested"},
		{"pending", migrationHistory{map[string]bool{"001.sql": true}, migrationInventory{"001.sql": "good-one"}, true}, "pending migration 002.sql"},
		{"mismatch", migrationHistory{map[string]bool{"001.sql": true, "002.sql": true}, migrationInventory{"001.sql": "changed", "002.sql": "good-two"}, true}, "checksum mismatch"},
		{"missing hash", migrationHistory{map[string]bool{"001.sql": true, "002.sql": true}, migrationInventory{"001.sql": "good-one"}, true}, "no attested checksum"},
		{"unknown migration", migrationHistory{map[string]bool{"900.sql": true}, migrationInventory{"900.sql": "other"}, true}, "unknown applied migration"},
		{"orphan hash", migrationHistory{map[string]bool{"001.sql": true, "002.sql": true}, migrationInventory{"001.sql": "good-one", "002.sql": "good-two", "900.sql": "other"}, true}, "no applied ledger row"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := test.history.verifyComplete(expected)
			if test.failure == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.failure) {
				t.Fatalf("got %v; want %s", err, test.failure)
			}
		})
	}
}

func TestAttestationAllowsOnlyKnownLegacySource(t *testing.T) {
	expected, err := embeddedMigrationInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) == 0 {
		t.Fatal("embedded migration inventory is empty")
	}
	legacy := migrationHistory{applied: make(map[string]bool), hashes: make(migrationInventory)}
	for name, hash := range expected {
		if len(hash) != 64 {
			t.Fatalf("%s checksum is not SHA256", name)
		}
		legacy.applied[name] = true
	}
	if err := legacy.verifyKnown(expected); err != nil {
		t.Fatal(err)
	}
	if err := legacy.verifyComplete(expected); err == nil {
		t.Fatal("filename-only history qualified as attested")
	}
	legacy.applied["unknown.sql"] = true
	if err := legacy.verifyKnown(expected); err == nil {
		t.Fatal("unknown legacy migration accepted")
	}
}
