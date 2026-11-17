// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"github.com/MeshCore-Beacon/beacon-server/db/planpolicy"
	"testing"
	"time"
)

func TestClampQueryLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int32
		want  int32
	}{
		{name: "negative", limit: -1, want: 1},
		{name: "zero", limit: 0, want: 1},
		{name: "minimum", limit: 1, want: 1},
		{name: "within range", limit: 20, want: 20},
		{name: "maximum", limit: 2000, want: 2000},
		{name: "above maximum", limit: 2001, want: 2000},
		{name: "int32 maximum", limit: 2147483647, want: 2000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clampQueryLimit(tt.limit); got != tt.want {
				t.Errorf("clampQueryLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

func TestStoreNodeMaximumPreservesUpstreamPages(t *testing.T) {
	if got := clampQueryLimitUpTo(2000, 2000); got != 2000 {
		t.Fatalf("node maximum = %d", got)
	}
	if got := clampQueryLimitUpTo(2147483647, 2000); got != 2000 {
		t.Fatalf("unbounded node page = %d", got)
	}
}

func TestAPIReadBoundsPreserveMaintenanceVerification(t *testing.T) {
	apiStore := NewAPIStore(&Pools{}, planpolicy.CustomAll, nil, 0, 0)
	maintenance := &Store{}
	if got := apiStore.boundQueryLimit(5000); got != 2000 {
		t.Fatalf("API bound = %d", got)
	}
	if got := maintenance.boundQueryLimit(5000); got != 5000 {
		t.Fatalf("maintenance verification truncated = %d", got)
	}
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	public, stopPublic := apiStore.readContext(parent)
	defer stopPublic()
	internal, stopInternal := maintenance.readContext(parent)
	defer stopInternal()
	publicDeadline, _ := public.Deadline()
	internalDeadline, _ := internal.Deadline()
	parentDeadline, _ := parent.Deadline()
	if publicDeadline.After(time.Now().Add(6 * time.Second)) {
		t.Fatal("API deadline lost")
	}
	if internalDeadline != parentDeadline {
		t.Fatal("maintenance caller deadline changed")
	}
}
