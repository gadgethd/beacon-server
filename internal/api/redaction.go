// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "strings"

// LocationRedactionMarker is the marker a node operator can place anywhere in
// their advertised node name to opt the node's location out of public display.
// When present, Beacon strips the node's coordinates from every list, detail,
// neighbor, path-resolution, and live-update response. The coordinates are
// still stored (the marker is reversible by re-advertising without it) but are
// never sent to clients, so a redacted node simply has no location: it drops
// off the map and shows "—" in the nodes list.
const LocationRedactionMarker = "🚫"

// LocationRedacted reports whether a node name opts its location out of display.
// A nil name never opts out.
func LocationRedacted(name *string) bool {
	return name != nil && strings.Contains(*name, LocationRedactionMarker)
}

// RedactLocation returns the coordinates to expose for a node: the originals,
// or (nil, nil) when the node name carries the LocationRedactionMarker. Call it
// at every point a node's coordinates are mapped into an API or WebSocket
// response so redaction stays consistent across surfaces.
func RedactLocation(name *string, lat, lng *float64) (*float64, *float64) {
	if LocationRedacted(name) {
		return nil, nil
	}
	return lat, lng
}
