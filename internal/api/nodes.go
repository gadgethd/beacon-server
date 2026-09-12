// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"strings"

	"github.com/google/uuid"
	"github.com/meshcore-go/meshcore-go"
)

// NodeNeighbor is the internal node-neighbor read model. Use ToPublicNodeNeighbor
// before returning it from a public handler.
type NodeNeighbor struct {
	ID               uuid.UUID `json:"id"`
	Name             *string   `json:"name,omitempty"`
	PublicKey        string    `json:"publicKey"`
	NodeType         int16     `json:"nodeType"`
	NodeTypeName     string    `json:"nodeTypeName"`
	Latitude         *float64  `json:"lat,omitempty"`
	Longitude        *float64  `json:"lng,omitempty"`
	IATA             string    `json:"iata"`
	ObservationCount int64     `json:"observationCount"`
	FirstSeen        int64     `json:"firstSeen"` // epoch ms
	LastSeen         int64     `json:"lastSeen"`  // epoch ms
	SNR              *float32  `json:"snr,omitempty"`
}

// NodeIATA represents a single IATA code and the last time the node was heard there.
type NodeIATA struct {
	IATA      string `json:"iata"`
	LastHeard int64  `json:"lastHeard"` // epoch ms
}

// NodeSummary is the internal node read model used in list responses.
type NodeSummary struct {
	ID                 uuid.UUID   `json:"id"`
	PublicKey          string      `json:"publicKey"` // hex-encoded Ed25519 public key
	NodeType           int16       `json:"nodeType"`  // 1=companion, 2=repeater, 3=room_server, 4=sensor
	NodeTypeName       string      `json:"nodeTypeName"`
	Name               *string     `json:"name,omitempty"`
	IsObserver         bool        `json:"isObserver"`             // true if this node is also a known observer
	ObserverID         *uuid.UUID  `json:"observerId,omitempty"`   // UUID of the associated observer row, if any
	Latitude           *float64    `json:"lat,omitempty"`          // decimal degrees, from advert AppData
	Longitude          *float64    `json:"lng,omitempty"`          // decimal degrees, from advert AppData
	Radio              *string     `json:"radio,omitempty"`        // shorthand: "freqMhz,bwKhz,sf" e.g. "910.525,62.5,7"
	IATAs              []NodeIATA  `json:"iatas"`                  // IATAs where this node has been heard, with last heard timestamps
	DefaultScope       *string     `json:"defaultScope,omitempty"` // most recently matched transport scope name e.g. "#bc"
	KnownNeighborCount int64       `json:"knownNeighborCount"`
	NeighborIDs        []uuid.UUID `json:"neighborIds,omitempty"` // only populated when the list request opts in; see ?neighbors=true
	// Stale is true when the node hasn't been seen (last_seen) within the configured
	// staleness window (default 24h; internal/config.ResolvedConfig.NodeStaleThreshold).
	// Applies to every node type, unlike ClockDriftSeconds/ClockOutOfSync on Node, which
	// are repeater/room-server only.
	Stale bool `json:"stale"`
}

// Node is the internal full node read model. It may contain database metadata;
// use ToPublicNode before serializing it in a public response.
type Node struct {
	NodeSummary
	LocationSource          *string        `json:"locationSource,omitempty"`     // "advert" or "manual"
	LastAdvertAt            *int64         `json:"lastAdvertAt,omitempty"`       // epoch ms, nil if no advert received
	SupportsMultibytePaths  bool           `json:"supportsMultibytePaths"`       // firmware >= 1.14.0; detected via path hash size
	SupportsMultibyteTraces bool           `json:"supportsMultibyteTraces"`      // firmware >= 1.11.0; detected via trace hash size
	MinFirmwareVersion      *string        `json:"minFirmwareVersion,omitempty"` // derived from capability flags
	FirstSeen               int64          `json:"firstSeen"`                    // epoch ms
	LastSeen                int64          `json:"lastSeen"`                     // epoch ms
	Metadata                any            `json:"metadata,omitempty"`           // raw JSONB metadata
	Neighbors               []NodeNeighbor `json:"neighbors"`
	// Clock drift, repeaters/room servers only (nodeType 2/3); omitted entirely for other
	// node types or when no qualifying advert has been measured yet. Device minus server
	// time, in seconds, from the advert's self-reported timestamp: +ve = device ahead.
	// clockCheckedAt is the server receive time of the advert this was measured from (same
	// moment as lastAdvertAt). clockOutOfSync is |clockDriftSeconds| exceeding a configured
	// threshold (default 5m) -- see internal/config.ResolvedConfig.ClockDriftThreshold.
	ClockDriftSeconds *int   `json:"clockDriftSeconds,omitempty"`
	ClockOutOfSync    *bool  `json:"clockOutOfSync,omitempty"`
	ClockCheckedAt    *int64 `json:"clockCheckedAt,omitempty"`
}

// PublicNodeIATA is the public representation of a node's IATA history.
type PublicNodeIATA struct {
	IATA      string `json:"iata"`
	LastHeard int64  `json:"lastHeard"` // epoch ms
}

// PublicNodeNeighbor is the public representation of a neighboring node
// relationship. It intentionally contains no database-only fields.
type PublicNodeNeighbor struct {
	ID               uuid.UUID `json:"id"`
	Name             *string   `json:"name,omitempty"`
	PublicKey        string    `json:"publicKey"`
	NodeType         int16     `json:"nodeType"`
	NodeTypeName     string    `json:"nodeTypeName"`
	Latitude         *float64  `json:"lat,omitempty"`
	Longitude        *float64  `json:"lng,omitempty"`
	IATA             string    `json:"iata"`
	ObservationCount int64     `json:"observationCount"`
	FirstSeen        int64     `json:"firstSeen"` // epoch ms
	LastSeen         int64     `json:"lastSeen"`  // epoch ms
	SNR              *float32  `json:"snr,omitempty"`
}

// PublicNodeSummary is the allowlisted node representation returned by public
// list endpoints.
type PublicNodeSummary struct {
	ID                 uuid.UUID        `json:"id"`
	PublicKey          string           `json:"publicKey"`
	NodeType           int16            `json:"nodeType"`
	NodeTypeName       string           `json:"nodeTypeName"`
	Name               *string          `json:"name,omitempty"`
	IsObserver         bool             `json:"isObserver"`
	ObserverID         *uuid.UUID       `json:"observerId,omitempty"`
	Latitude           *float64         `json:"lat,omitempty"`
	Longitude          *float64         `json:"lng,omitempty"`
	Radio              *string          `json:"radio,omitempty"`
	IATAs              []PublicNodeIATA `json:"iatas"`
	DefaultScope       *string          `json:"defaultScope,omitempty"`
	KnownNeighborCount int64            `json:"knownNeighborCount"`
	NeighborIDs        []uuid.UUID      `json:"neighborIds,omitempty"`
	Stale              bool             `json:"stale"`
}

// PublicNode is the allowlisted node detail response. Metadata is deliberately
// absent: Node.Metadata is an internal/raw JSONB field and must not cross the
// public API boundary.
type PublicNode struct {
	PublicNodeSummary
	LocationSource          *string              `json:"locationSource,omitempty"`
	LastAdvertAt            *int64               `json:"lastAdvertAt,omitempty"`
	SupportsMultibytePaths  bool                 `json:"supportsMultibytePaths"`
	SupportsMultibyteTraces bool                 `json:"supportsMultibyteTraces"`
	MinFirmwareVersion      *string              `json:"minFirmwareVersion,omitempty"`
	FirstSeen               int64                `json:"firstSeen"`
	LastSeen                int64                `json:"lastSeen"`
	Neighbors               []PublicNodeNeighbor `json:"neighbors"`
	ClockDriftSeconds       *int                 `json:"clockDriftSeconds,omitempty"`
	ClockOutOfSync          *bool                `json:"clockOutOfSync,omitempty"`
	ClockCheckedAt          *int64               `json:"clockCheckedAt,omitempty"`
}

// ToPublicNodeIATA maps an internal node IATA record to its public DTO.
func ToPublicNodeIATA(iata NodeIATA) PublicNodeIATA {
	return PublicNodeIATA{
		IATA:      iata.IATA,
		LastHeard: iata.LastHeard,
	}
}

// ToPublicNodeNeighbor maps an internal node-neighbor record to its public DTO.
func ToPublicNodeNeighbor(neighbor NodeNeighbor) PublicNodeNeighbor {
	return PublicNodeNeighbor{
		ID:               neighbor.ID,
		Name:             neighbor.Name,
		PublicKey:        neighbor.PublicKey,
		NodeType:         neighbor.NodeType,
		NodeTypeName:     neighbor.NodeTypeName,
		Latitude:         neighbor.Latitude,
		Longitude:        neighbor.Longitude,
		IATA:             neighbor.IATA,
		ObservationCount: neighbor.ObservationCount,
		FirstSeen:        neighbor.FirstSeen,
		LastSeen:         neighbor.LastSeen,
		SNR:              neighbor.SNR,
	}
}

// ToPublicNodeSummary maps an internal node summary to its public DTO.
func ToPublicNodeSummary(node NodeSummary) PublicNodeSummary {
	public := PublicNodeSummary{
		ID:                 node.ID,
		PublicKey:          node.PublicKey,
		NodeType:           node.NodeType,
		NodeTypeName:       node.NodeTypeName,
		Name:               node.Name,
		IsObserver:         node.IsObserver,
		ObserverID:         node.ObserverID,
		Latitude:           node.Latitude,
		Longitude:          node.Longitude,
		Radio:              node.Radio,
		DefaultScope:       node.DefaultScope,
		KnownNeighborCount: node.KnownNeighborCount,
		Stale:              node.Stale,
	}
	if node.IATAs != nil {
		public.IATAs = make([]PublicNodeIATA, len(node.IATAs))
		for i, iata := range node.IATAs {
			public.IATAs[i] = ToPublicNodeIATA(iata)
		}
	}
	if node.NeighborIDs != nil {
		public.NeighborIDs = append([]uuid.UUID(nil), node.NeighborIDs...)
	}
	return public
}

// ToPublicNodePage maps a node list page to an allowlisted public page.
func ToPublicNodePage(page Page[NodeSummary]) Page[PublicNodeSummary] {
	public := Page[PublicNodeSummary]{
		NextCursor: page.NextCursor,
		HasMore:    page.HasMore,
	}
	if page.Items != nil {
		public.Items = make([]PublicNodeSummary, len(page.Items))
		for i, node := range page.Items {
			public.Items[i] = ToPublicNodeSummary(node)
		}
	}
	return public
}

// ToPublicNode maps an internal full node read model to its public DTO.
func ToPublicNode(node *Node) *PublicNode {
	if node == nil {
		return nil
	}
	public := &PublicNode{
		PublicNodeSummary:       ToPublicNodeSummary(node.NodeSummary),
		LocationSource:          node.LocationSource,
		LastAdvertAt:            node.LastAdvertAt,
		SupportsMultibytePaths:  node.SupportsMultibytePaths,
		SupportsMultibyteTraces: node.SupportsMultibyteTraces,
		MinFirmwareVersion:      node.MinFirmwareVersion,
		FirstSeen:               node.FirstSeen,
		LastSeen:                node.LastSeen,
		ClockDriftSeconds:       node.ClockDriftSeconds,
		ClockOutOfSync:          node.ClockOutOfSync,
		ClockCheckedAt:          node.ClockCheckedAt,
	}
	if node.Neighbors != nil {
		public.Neighbors = make([]PublicNodeNeighbor, len(node.Neighbors))
		for i, neighbor := range node.Neighbors {
			public.Neighbors[i] = ToPublicNodeNeighbor(neighbor)
		}
	}
	return public
}

// ToPublicNodeNeighbors maps internal node-neighbor records to public DTOs.
func ToPublicNodeNeighbors(neighbors []NodeNeighbor) []PublicNodeNeighbor {
	if neighbors == nil {
		return nil
	}
	public := make([]PublicNodeNeighbor, len(neighbors))
	for i, neighbor := range neighbors {
		public[i] = ToPublicNodeNeighbor(neighbor)
	}
	return public
}

// NodeTypeName returns a human-readable name for a node type integer.
// NOTE: truncation is fine here until there are at least over 200 types of node
func NodeTypeName(t int16) string {
	switch byte(t) {
	case meshcore.AdvertTypeChat:
		return "companion"
	case meshcore.AdvertTypeRepeater:
		return "repeater"
	case meshcore.AdvertTypeRoom:
		return "room_server"
	case meshcore.AdvertTypeSensor:
		return "sensor"
	default:
		return "unknown"
	}
}

// NodeTypeFromString returns the integer node type for a given name.
// Returns 0 (no filter) if the string is empty or unrecognized.
func NodeTypeFromString(s string) int16 {
	switch strings.ToLower(s) {
	case "companion", "chat":
		return int16(meshcore.AdvertTypeChat)
	case "repeater":
		return int16(meshcore.AdvertTypeRepeater)
	case "room_server", "roomserver", "room-server", "room":
		return int16(meshcore.AdvertTypeRoom)
	case "sensor":
		return int16(meshcore.AdvertTypeSensor)
	default:
		return 0
	}
}
