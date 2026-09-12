// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import "testing"

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
		{name: "maximum", limit: 100, want: 100},
		{name: "above maximum", limit: 101, want: 100},
		{name: "int32 maximum", limit: 2147483647, want: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clampQueryLimit(tt.limit); got != tt.want {
				t.Errorf("clampQueryLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}
