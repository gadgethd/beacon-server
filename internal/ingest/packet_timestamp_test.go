// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"testing"
	"time"
)

func TestParseEnvelopeTimestampAcceptsRFC3339Z(t *testing.T) {
	tests := []string{
		"2026-06-12T00:44:31Z",
		"2026-06-12T00:44:32.340969Z",
		"2026-06-12T00:44:31.340969+00:00",
		"2026-06-12T00:44:31.340969",
		"2026-06-12T00:44:31",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			got, err := parseEnvelopeTimestamp(tt)
			if err != nil {
				t.Fatalf("parseEnvelopeTimestamp() error = %v", err)
			}
			if got.IsZero() {
				t.Fatal("parseEnvelopeTimestamp() returned zero time")
			}
			if got.Year() != 2026 || got.Month() != time.June || got.Day() != 12 {
				t.Fatalf("parseEnvelopeTimestamp() = %s, want 2026-06-12", got)
			}
		})
	}
}
