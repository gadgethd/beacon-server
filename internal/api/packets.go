// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/meshcore-go/meshcore-go"
)

// PacketLatestObserver is the internal most recent observer summary rolled into
// a packet list item. Use ToPublicPacketLatestObserver at the public boundary.
type PacketLatestObserver struct {
	ID          uuid.UUID `json:"id"`
	DisplayName *string   `json:"displayName,omitempty"`
	IATA        string    `json:"iata"`
	// PathLength/PathBytes are cheap -- already-stored columns on packet_observations -- and
	// populated everywhere PacketLatestObserver appears: the REST list/backfill endpoints and
	// the WS feed alike. ResolvedPath/ResolvedSource/ResolvedDestination require a per-hash DB
	// resolution lookup; they're populated on the WS feed (already computed once at ingest, so
	// effectively free there) but deliberately left nil on the REST endpoints, which are
	// paginated/high-volume and used only for scrollback and reconnect-gap backfill -- full
	// resolution stays a GET /packets/{packetHash}-only feature.
	PathLength          *PacketPathLength `json:"pathLength,omitempty"`
	PathBytes           *string           `json:"pathBytes,omitempty"` // hex-encoded accumulated path hashes
	ResolvedPath        []ResolvedHop     `json:"resolvedPath,omitempty"`
	ResolvedSource      *ResolvedHop      `json:"resolvedSource,omitempty"`
	ResolvedDestination *ResolvedHop      `json:"resolvedDestination,omitempty"`
}

// PacketSummary is the internal packet read model used in list responses.
// Includes the latest observation rolled in for display purposes.
type PacketSummary struct {
	PacketHash       string                `json:"packetHash"` // hex-encoded
	PayloadType      int16                 `json:"payloadType"`
	PayloadTypeName  string                `json:"payloadTypeName"`
	RouteType        int16                 `json:"routeType"`
	RouteTypeName    string                `json:"routeTypeName"`
	Scope            *string               `json:"scope,omitempty"` // matched transport scope name e.g. "#bc"
	FirstHeardAt     int64                 `json:"firstHeardAt"`    // epoch ms
	LastHeardAt      int64                 `json:"lastHeardAt"`     // epoch ms
	ObservationCount int32                 `json:"observationCount"`
	LatestObserver   *PacketLatestObserver `json:"latestObserver,omitempty"`
	Summary          *string               `json:"summary,omitempty"` // human-readable payload summary
}

// PacketPathLength is the decoded path_length byte from a packet observation.
// The raw byte encodes both hash size and hop count in a bit-packed format (§2.5).
type PacketPathLength struct {
	Raw      string `json:"raw"`      // hex-encoded single byte
	HashSize int16  `json:"hashSize"` // per-hop hash size in bytes (1, 2, or 3)
	HopCount int16  `json:"hopCount"` // number of path hashes present
}

// PacketObservationDetail is a full observation including radio settings and resolved path.
type PacketObservationDetail struct {
	ID                int64            `json:"id"`
	ObserverID        uuid.UUID        `json:"observerId"`
	ObserverName      *string          `json:"observerName,omitempty"`
	IATA              string           `json:"iata"`
	HeardAt           int64            `json:"heardAt"` // epoch ms
	PathLength        PacketPathLength `json:"pathLength"`
	PathBytes         *string          `json:"pathBytes,omitempty"` // hex-encoded accumulated path hashes
	RSSI              *int16           `json:"rssi,omitempty"`
	SNR               *float32         `json:"snr,omitempty"`
	PropagationTimeMs *int32           `json:"propagationTimeMs"` // ms since first observation; 0 for first
	Radio             *PacketRadio     `json:"radio,omitempty"`
	SourceBroker      string           `json:"sourceBroker"`
	ResolvedPath      []ResolvedHop    `json:"resolvedPath"` // per-observation resolved path hashes
	// ResolvedSource/ResolvedDestination are the packet's endpoints, when the payload type
	// carries a resolvable one: an exact match for ADVERT's full pubkey, an ambiguous
	// hash-prefix match (like intermediate hops) for TEXT_MESSAGE/PATH/ANON_REQ's 1-byte
	// source/destination hashes. Nil when the payload type doesn't carry one at all (e.g.
	// GRP_TXT/GRP_DATA/TRACE aren't node-to-node addressed) -- see BuildResolvedPath and
	// ResolveExactNode for how each is built.
	ResolvedSource      *ResolvedHop `json:"resolvedSource,omitempty"`
	ResolvedDestination *ResolvedHop `json:"resolvedDestination,omitempty"`
}

// PacketRadio holds the radio settings copied from the observer at observation time.
type PacketRadio struct {
	FreqMHz      *float32 `json:"freqMhz,omitempty"`
	SpreadFactor *int16   `json:"spreadFactor,omitempty"`
	BandwidthKHz *float32 `json:"bandwidthKhz,omitempty"`
	CodingRate   *int16   `json:"codingRate,omitempty"`
}

// ResolvedHop is a single hop in a packet's resolved path.
// Confidence is "high" (exactly one match), "ambiguous" (multiple matches), or "none" (no match).
type ResolvedHop struct {
	Confidence string         `json:"confidence"` // "high", "ambiguous", or "none"
	SNR        *float32       `json:"snr,omitempty"`
	Nodes      []ResolvedNode `json:"nodes"` // empty for "none", one for "high", multiple for "ambiguous"
}

// ResolvedNode is a node reference within a resolved path hop.
type ResolvedNode struct {
	ID        uuid.UUID `json:"id"`
	Name      *string   `json:"name,omitempty"`
	PublicKey string    `json:"publicKey"` // hex-encoded prefix used for resolution
	Latitude  *float64  `json:"latitude,omitempty"`
	Longitude *float64  `json:"longitude,omitempty"`
}

// ResolvedPathEntry is an internal type used by the store layer to carry node
// details returned from ResolvePathHashes before mapping to ResolvedNode.
type ResolvedPathEntry struct {
	NodeID    uuid.UUID
	Name      *string
	Latitude  *float64
	Longitude *float64
	PublicKey []byte
}

// PacketHeader holds the decoded header byte and its bit-packed fields.
// The raw header byte encodes payload version, payload type, and route type (§2.3).
type PacketHeader struct {
	Raw             string `json:"raw"`             // hex-encoded single byte
	RouteType       int16  `json:"routeType"`       // bits 0-1
	RouteTypeName   string `json:"routeTypeName"`   // FLOOD, DIRECT, TRANSPORT_FLOOD, TRANSPORT_DIRECT
	PayloadType     int16  `json:"payloadType"`     // bits 2-5
	PayloadTypeName string `json:"payloadTypeName"` // advert, request, group_text, etc.
	PayloadVersion  int16  `json:"payloadVersion"`  // bits 6-7
}

// PacketTransportCodes holds the decoded transport codes present in TRANSPORT_FLOOD
// and TRANSPORT_DIRECT packets. RegionCode is transport_code_1; SubRegionCode is
// transport_code_2 (reserved in v1, always 0 on the wire).
type PacketTransportCodes struct {
	RegionCode    int32 `json:"regionCode"`
	SubRegionCode int32 `json:"subRegionCode"`
}

// Packet is the internal full packet read model. It contains raw and parsed
// payloads plus detailed observations; use ToPublicPacket before serializing it
// in a public response.
type Packet struct {
	PacketHash       string                    `json:"packetHash"`
	Header           PacketHeader              `json:"header"`
	TransportCodes   *PacketTransportCodes     `json:"transportCodes,omitempty"`
	OriginPubkey     *string                   `json:"originPubkey,omitempty"` // hex-encoded; nil when not extractable from payload
	ParsedPayload    json.RawMessage           `json:"parsedPayload,omitempty"`
	RawPayload       string                    `json:"rawPayload"`            // hex-encoded payload bytes (excludes header and path)
	Decrypted        bool                      `json:"decrypted"`             // true if group text was successfully decrypted
	ChannelHash      *string                   `json:"channelHash,omitempty"` // hex-encoded single byte; non-nil for group_text/group_data
	Scope            *string                   `json:"scope,omitempty"`       // matched transport scope name e.g. "#bc"
	FirstHeardAt     int64                     `json:"firstHeardAt"`          // epoch ms
	LastHeardAt      int64                     `json:"lastHeardAt"`           // epoch ms
	FirstToLastMs    int64                     `json:"firstToLastMs"`         // ms between first and last observation
	ObservationCount int32                     `json:"observationCount"`
	ResolvedRoute    []ResolvedHop             `json:"resolvedRoute,omitempty"` // trace packets only: resolved intended route
	Observations     []PacketObservationDetail `json:"observations"`
}

// PublicPacketLatestObserver is the allowlisted latest-observer representation
// used in public packet list responses.
type PublicPacketLatestObserver struct {
	ID                  uuid.UUID         `json:"id"`
	DisplayName         *string           `json:"displayName,omitempty"`
	IATA                string            `json:"iata"`
	PathLength          *PacketPathLength `json:"pathLength,omitempty"`
	PathBytes           *string           `json:"pathBytes,omitempty"`
	ResolvedPath        []ResolvedHop     `json:"resolvedPath,omitempty"`
	ResolvedSource      *ResolvedHop      `json:"resolvedSource,omitempty"`
	ResolvedDestination *ResolvedHop      `json:"resolvedDestination,omitempty"`
}

// PublicPacketSummary is the allowlisted packet representation returned by
// public list and reconnect-backfill endpoints.
type PublicPacketSummary struct {
	PacketHash       string                      `json:"packetHash"`
	PayloadType      int16                       `json:"payloadType"`
	PayloadTypeName  string                      `json:"payloadTypeName"`
	RouteType        int16                       `json:"routeType"`
	RouteTypeName    string                      `json:"routeTypeName"`
	Scope            *string                     `json:"scope,omitempty"`
	FirstHeardAt     int64                       `json:"firstHeardAt"`
	LastHeardAt      int64                       `json:"lastHeardAt"`
	ObservationCount int32                       `json:"observationCount"`
	LatestObserver   *PublicPacketLatestObserver `json:"latestObserver,omitempty"`
	Summary          *string                     `json:"summary,omitempty"`
}

// PublicPacketObservationSummary is the allowlisted lightweight observation
// representation used by public node/observer list endpoints.
type PublicPacketObservationSummary struct {
	ID              int64    `json:"id"`
	PacketHash      string   `json:"packetHash"`
	PayloadType     int16    `json:"payloadType"`
	PayloadTypeName string   `json:"payloadTypeName"`
	IATA            string   `json:"iata"`
	HeardAt         int64    `json:"heardAt"`
	RSSI            *int16   `json:"rssi,omitempty"`
	SNR             *float32 `json:"snr,omitempty"`
	HopCount        *int16   `json:"hopCount,omitempty"`
}

// PublicAdvertObservation is the allowlisted advert observation representation
// used by the observer adverts endpoint.
type PublicAdvertObservation struct {
	PublicPacketObservationSummary
	NodeName      *string `json:"nodeName,omitempty"`
	NodePublicKey *string `json:"nodePublicKey,omitempty"`
}

// PublicPacket is the allowlisted packet detail response. ParsedPayload,
// RawPayload, and Observations are intentionally absent: they can contain raw
// packet data, decrypted content, and high-volume internal observation detail.
type PublicPacket struct {
	PacketHash       string                `json:"packetHash"`
	Header           PacketHeader          `json:"header"`
	TransportCodes   *PacketTransportCodes `json:"transportCodes,omitempty"`
	OriginPubkey     *string               `json:"originPubkey,omitempty"`
	Decrypted        bool                  `json:"decrypted"`
	ChannelHash      *string               `json:"channelHash,omitempty"`
	Scope            *string               `json:"scope,omitempty"`
	FirstHeardAt     int64                 `json:"firstHeardAt"`
	LastHeardAt      int64                 `json:"lastHeardAt"`
	FirstToLastMs    int64                 `json:"firstToLastMs"`
	ObservationCount int32                 `json:"observationCount"`
	ResolvedRoute    []ResolvedHop         `json:"resolvedRoute,omitempty"`
}

// ToPublicPacketLatestObserver maps an internal latest-observer record to its
// public DTO.
func ToPublicPacketLatestObserver(observer *PacketLatestObserver) *PublicPacketLatestObserver {
	if observer == nil {
		return nil
	}
	public := &PublicPacketLatestObserver{
		ID:                  observer.ID,
		DisplayName:         observer.DisplayName,
		IATA:                observer.IATA,
		PathLength:          observer.PathLength,
		PathBytes:           observer.PathBytes,
		ResolvedSource:      observer.ResolvedSource,
		ResolvedDestination: observer.ResolvedDestination,
	}
	if observer.ResolvedPath != nil {
		public.ResolvedPath = append([]ResolvedHop(nil), observer.ResolvedPath...)
	}
	return public
}

// ToPublicPacketSummary maps an internal packet summary to its public DTO.
func ToPublicPacketSummary(packet PacketSummary) PublicPacketSummary {
	return PublicPacketSummary{
		PacketHash:       packet.PacketHash,
		PayloadType:      packet.PayloadType,
		PayloadTypeName:  packet.PayloadTypeName,
		RouteType:        packet.RouteType,
		RouteTypeName:    packet.RouteTypeName,
		Scope:            packet.Scope,
		FirstHeardAt:     packet.FirstHeardAt,
		LastHeardAt:      packet.LastHeardAt,
		ObservationCount: packet.ObservationCount,
		LatestObserver:   ToPublicPacketLatestObserver(packet.LatestObserver),
		Summary:          packet.Summary,
	}
}

// ToPublicPacketPage maps a packet list page to an allowlisted public page.
func ToPublicPacketPage(page Page[PacketSummary]) Page[PublicPacketSummary] {
	public := Page[PublicPacketSummary]{
		NextCursor: page.NextCursor,
		HasMore:    page.HasMore,
	}
	if page.Items != nil {
		public.Items = make([]PublicPacketSummary, len(page.Items))
		for i, packet := range page.Items {
			public.Items[i] = ToPublicPacketSummary(packet)
		}
	}
	return public
}

// ToPublicPacketSummaries maps packet summaries to public DTOs.
func ToPublicPacketSummaries(packets []PacketSummary) []PublicPacketSummary {
	if packets == nil {
		return nil
	}
	public := make([]PublicPacketSummary, len(packets))
	for i, packet := range packets {
		public[i] = ToPublicPacketSummary(packet)
	}
	return public
}

// ToPublicPacketObservationSummary maps an internal observation summary to its
// public DTO.
func ToPublicPacketObservationSummary(observation PacketObservationSummary) PublicPacketObservationSummary {
	return PublicPacketObservationSummary{
		ID:              observation.ID,
		PacketHash:      observation.PacketHash,
		PayloadType:     observation.PayloadType,
		PayloadTypeName: observation.PayloadTypeName,
		IATA:            observation.IATA,
		HeardAt:         observation.HeardAt,
		RSSI:            observation.RSSI,
		SNR:             observation.SNR,
		HopCount:        observation.HopCount,
	}
}

// ToPublicPacketObservationPage maps an observation list page to an
// allowlisted public page.
func ToPublicPacketObservationPage(page Page[PacketObservationSummary]) Page[PublicPacketObservationSummary] {
	public := Page[PublicPacketObservationSummary]{
		NextCursor: page.NextCursor,
		HasMore:    page.HasMore,
	}
	if page.Items != nil {
		public.Items = make([]PublicPacketObservationSummary, len(page.Items))
		for i, observation := range page.Items {
			public.Items[i] = ToPublicPacketObservationSummary(observation)
		}
	}
	return public
}

// ToPublicAdvertObservation maps an internal advert observation to its public
// DTO.
func ToPublicAdvertObservation(observation AdvertObservation) PublicAdvertObservation {
	return PublicAdvertObservation{
		PublicPacketObservationSummary: ToPublicPacketObservationSummary(observation.PacketObservationSummary),
		NodeName:                       observation.NodeName,
		NodePublicKey:                  observation.NodePublicKey,
	}
}

// ToPublicAdvertObservationPage maps an advert list page to an allowlisted
// public page.
func ToPublicAdvertObservationPage(page Page[AdvertObservation]) Page[PublicAdvertObservation] {
	public := Page[PublicAdvertObservation]{
		NextCursor: page.NextCursor,
		HasMore:    page.HasMore,
	}
	if page.Items != nil {
		public.Items = make([]PublicAdvertObservation, len(page.Items))
		for i, observation := range page.Items {
			public.Items[i] = ToPublicAdvertObservation(observation)
		}
	}
	return public
}

// ToPublicPacket maps an internal full packet read model to its public DTO.
func ToPublicPacket(packet *Packet) *PublicPacket {
	if packet == nil {
		return nil
	}
	public := &PublicPacket{
		PacketHash:       packet.PacketHash,
		Header:           packet.Header,
		TransportCodes:   packet.TransportCodes,
		OriginPubkey:     packet.OriginPubkey,
		Decrypted:        packet.Decrypted,
		ChannelHash:      packet.ChannelHash,
		Scope:            packet.Scope,
		FirstHeardAt:     packet.FirstHeardAt,
		LastHeardAt:      packet.LastHeardAt,
		FirstToLastMs:    packet.FirstToLastMs,
		ObservationCount: packet.ObservationCount,
	}
	if packet.ResolvedRoute != nil {
		public.ResolvedRoute = append([]ResolvedHop(nil), packet.ResolvedRoute...)
	}
	return public
}

// AdvertObservation extends PacketObservationSummary with node identity fields
// specific to advert packets (payload_type=4).
type AdvertObservation struct {
	PacketObservationSummary
	NodeName      *string `json:"nodeName,omitempty"`
	NodePublicKey *string `json:"nodePublicKey,omitempty"` // hex-encoded
}

// PacketObservationSummary is a lightweight packet+observation pair used in
// list contexts such as observer adverts and node observations.
type PacketObservationSummary struct {
	ID              int64    `json:"id"`         // observation ID, use as cursor for pagination
	PacketHash      string   `json:"packetHash"` // hex-encoded
	PayloadType     int16    `json:"payloadType"`
	PayloadTypeName string   `json:"payloadTypeName"`
	IATA            string   `json:"iata"`
	HeardAt         int64    `json:"heardAt"` // epoch ms
	RSSI            *int16   `json:"rssi,omitempty"`
	SNR             *float32 `json:"snr,omitempty"`
	HopCount        *int16   `json:"hopCount,omitempty"`
}

// PayloadTypeName returns a human-readable name for a payload type integer.
func PayloadTypeName(t int16) string {
	switch t {
	case 0x00:
		return "request"
	case 0x01:
		return "response"
	case 0x02:
		return "text_message"
	case 0x03:
		return "acknowledgement"
	case 0x04:
		return "advert"
	case 0x05:
		return "group_text"
	case 0x06:
		return "group_data"
	case 0x07:
		return "anonymous_request"
	case 0x08:
		return "path"
	case 0x09:
		return "trace"
	case 0x0A:
		return "multipart"
	case 0x0B:
		return "control"
	case 0x0C:
		fallthrough
	case 0x0D:
		fallthrough
	case 0x0E:
		return "reserved"
	case 0x0F:
		return "raw_custom"
	default:
		return "unknown"
	}
}

// PayloadTypeFromString returns the integer payload type for a given name.
// Returns -1 (no filter) if the string is empty or unrecognized.
func PayloadTypeFromString(s string) int16 {
	switch strings.ToLower(s) {
	case "request", "req":
		return int16(meshcore.PayloadTypeReq)
	case "response":
		return int16(meshcore.PayloadTypeResponse)
	case "txt_msg", "txtmsg", "text", "direct":
		return int16(meshcore.PayloadTypeTxtMsg)
	case "acknowledgement", "ack":
		return int16(meshcore.PayloadTypeAck)
	case "advertisement", "advert":
		return int16(meshcore.PayloadTypeAdvert)
	case "grp_txt", "grptxt", "group_text", "group":
		return int16(meshcore.PayloadTypeGrpTxt)
	case "grp_data", "grpdata", "group_data", "data":
		return int16(meshcore.PayloadTypeGrpData)
	case "anonymous_request", "anon_req", "anonreq":
		return int16(meshcore.PayloadTypeAnonReq)
	case "path":
		return int16(meshcore.PayloadTypePath)
	case "trace":
		return int16(meshcore.PayloadTypeTrace)
	case "multipart", "multi-part":
		return int16(meshcore.PayloadTypeMultiPart)
	case "control":
		return int16(meshcore.PayloadTypeControl)
	case "raw_custom", "raw", "custom":
		return int16(meshcore.PayloadTypeRawCustom)
	default:
		return -1
	}
}

// RouteTypeName returns a human-readable name for a route type integer.
func RouteTypeName(t int16) string {
	switch byte(t) {
	case meshcore.RouteTypeFlood:
		return "FLOOD"
	case meshcore.RouteTypeDirect:
		return "DIRECT"
	case meshcore.RouteTypeTransportFlood:
		return "TRANSPORT_FLOOD"
	case meshcore.RouteTypeTransportDirect:
		return "TRANSPORT_DIRECT"
	default:
		return "unknown"
	}
}

// BuildResolvedPath maps an ordered list of path hashes and their resolved
// candidates (as returned by ResolvePathHashes) into per-hop confidence
// records: "high" for exactly one match, "ambiguous" for multiple matches,
// "none" for zero. Shared by the REST packet/observation endpoints and the
// ingest packetObservation WS event so both report path resolution the same way.
func BuildResolvedPath(hashes [][]byte, resolved map[string][]ResolvedPathEntry) []ResolvedHop {
	path := make([]ResolvedHop, 0, len(hashes))
	for _, hash := range hashes {
		key := hex.EncodeToString(hash)
		entries := resolved[key]
		hop := ResolvedHop{Nodes: make([]ResolvedNode, 0, len(entries))}
		switch len(entries) {
		case 0:
			hop.Confidence = "none"
		case 1:
			hop.Confidence = "high"
		default:
			hop.Confidence = "ambiguous"
		}
		for _, e := range entries {
			hop.Nodes = append(hop.Nodes, ResolvedNode{
				ID:        e.NodeID,
				Name:      e.Name,
				Latitude:  e.Latitude,
				Longitude: e.Longitude,
				PublicKey: hex.EncodeToString(e.PublicKey),
			})
		}
		path = append(path, hop)
	}
	return path
}

// ResolveExactNode builds a ResolvedHop for an endpoint resolved by an exact, unambiguous
// key -- e.g. an ADVERT's full public key already resolved to a single node -- as opposed
// to BuildResolvedPath's hash-prefix matching, which can be ambiguous. Confidence is always
// "high" when a node was found, "none" when it wasn't (unknown node, or lookup failed).
func ResolveExactNode(node *ResolvedNode) ResolvedHop {
	if node == nil {
		return ResolvedHop{Confidence: "none", Nodes: []ResolvedNode{}}
	}
	return ResolvedHop{Confidence: "high", Nodes: []ResolvedNode{*node}}
}
