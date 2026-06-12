// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"testing"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
)

func ptr[T any](v T) *T { return &v }

func TestLocationRedacted(t *testing.T) {
	tests := []struct {
		name string
		in   *string
		want bool
	}{
		{"nil name", nil, false},
		{"empty name", ptr(""), false},
		{"plain name", ptr("Repeater North"), false},
		{"marker only", ptr(api.LocationRedactionMarker), true},
		{"marker prefix", ptr(api.LocationRedactionMarker + " Hidden Node"), true},
		{"marker suffix", ptr("Hidden Node " + api.LocationRedactionMarker), true},
		{"marker mid-string", ptr("Home " + api.LocationRedactionMarker + " base"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := api.LocationRedacted(tt.in); got != tt.want {
				t.Errorf("LocationRedacted(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactLocation(t *testing.T) {
	lat, lng := 51.5, -0.12

	t.Run("redacted name nils both coords", func(t *testing.T) {
		name := "Secret " + api.LocationRedactionMarker
		gotLat, gotLng := api.RedactLocation(&name, &lat, &lng)
		if gotLat != nil || gotLng != nil {
			t.Errorf("expected (nil, nil), got (%v, %v)", gotLat, gotLng)
		}
	})

	t.Run("plain name passes coords through", func(t *testing.T) {
		name := "Public Node"
		gotLat, gotLng := api.RedactLocation(&name, &lat, &lng)
		if gotLat != &lat || gotLng != &lng {
			t.Errorf("expected coords unchanged, got (%v, %v)", gotLat, gotLng)
		}
	})

	t.Run("nil name passes coords through", func(t *testing.T) {
		gotLat, gotLng := api.RedactLocation(nil, &lat, &lng)
		if gotLat != &lat || gotLng != &lng {
			t.Errorf("expected coords unchanged, got (%v, %v)", gotLat, gotLng)
		}
	})
}
