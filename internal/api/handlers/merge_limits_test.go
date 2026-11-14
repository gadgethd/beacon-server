// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http/httptest"
	"testing"
)

func TestMergedLimitsRejectAmbiguousValuesAndRetainLargeNodePages(t *testing.T) {
	for _, query := range []string{"limit=1&limit=2", "limit=01", "limit=%2B1", "limit=1.0"} {
		if _, err := parseLimitUpTo(httptest.NewRequest("GET", "/?"+query, nil), 50, maxNodeListLimit); err == nil {
			t.Errorf("accepted %s", query)
		}
	}
	got, err := parseLimitUpTo(httptest.NewRequest("GET", "/?limit=2000", nil), 50, maxNodeListLimit)
	if err != nil || got != 2000 {
		t.Fatalf("node page changed: %d %v", got, err)
	}
}
