// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package publicsource reads the restricted UKMesh GroupText history contract.
// It neither writes Beacon's ingest tables nor enables a runtime source.
package publicsource

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/meshcore-go/meshcore-go"
)

const UIDVersion = "wire-sha256-v1"

// Reason describes a rejected observation without logging its raw frame.
type Reason string

const (
	MissingUID         Reason = "missing-uid"
	InvalidUID         Reason = "invalid-uid"
	UnsupportedVersion Reason = "unsupported-identity-version"
	InvalidObserver    Reason = "invalid-observer-key"
	MissingRaw         Reason = "missing-raw"
	InvalidHex         Reason = "invalid-raw-hex"
	InvalidFrame       Reason = "unsupported-or-invalid-frame"
	NotGroupText       Reason = "not-group-text"
	UnsupportedPayload Reason = "unsupported-payload-version"
	InvalidGroupText   Reason = "invalid-group-text"
	UIDMismatch        Reason = "uid-mismatch"
	PathMismatch       Reason = "path-metadata-mismatch"
)

// Observation retains the upstream UUID, including multiple hearings that
// Beacon's legacy UNIQUE(packet_hash,observer_id) would otherwise collapse.
// Verified identities do not assert GroupText MAC authentication/decryption.
type Observation struct {
	Sequence           int64
	ID                 uuid.UUID
	Time               time.Time
	Network            string
	IATA               *string
	UID                [sha256.Size]byte
	IdentityVersion    string
	IdentityProvenance *string
	LegacyAlias        string
	ObserverKey        [32]byte
	SourceKey          *string
	Topic              string
	Direction          *string
	RSSI               *float64
	SNR                *float64
	BeaconHash         [meshcore.PacketHashSize]byte
	Packet             *meshcore.Packet    `json:"-"`
	GroupText          *meshcore.GroupText `json:"-"`
}

// Outcome accounts for every returned source row. A rejected row advances the
// source cursor but cannot be represented as an accepted Beacon observation.
type Outcome struct {
	Sequence      int64
	ObservationID uuid.UUID
	Reason        Reason
	Observation   *Observation
}

type sourceRow struct {
	seq                 int64
	id                  uuid.UUID
	at                  time.Time
	network             string
	iata                *string
	uid                 []byte
	version, provenance *string
	alias               string
	packetType          int32
	topic               string
	receiver, source    *string
	paths               []string
	pathSize            *int32
	rssi, snr           *float64
	direction           *string
	status              string
	raw                 *string
}

func verify(row sourceRow) Outcome {
	out := Outcome{Sequence: row.seq, ObservationID: row.id}
	reject := func(reason Reason) Outcome { out.Reason = reason; return out }
	if row.status != "candidate-for-decode" {
		return reject(Reason(row.status))
	}
	if row.uid == nil {
		return reject(MissingUID)
	}
	if len(row.uid) != sha256.Size {
		return reject(InvalidUID)
	}
	if row.version == nil || *row.version != UIDVersion {
		return reject(UnsupportedVersion)
	}
	if row.receiver == nil || len(*row.receiver) != 64 {
		return reject(InvalidObserver)
	}
	observer, err := hex.DecodeString(*row.receiver)
	if err != nil {
		return reject(InvalidObserver)
	}
	if row.raw == nil || strings.TrimSpace(*row.raw) == "" {
		return reject(MissingRaw)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(*row.raw))
	if err != nil {
		return reject(InvalidHex)
	}
	packet, err := meshcore.PacketFromBytes(raw)
	if err != nil || len(packet.Payload) == 0 {
		return reject(InvalidFrame)
	}
	if row.packetType != int32(meshcore.PayloadTypeGrpTxt) || packet.PayloadType() != meshcore.PayloadTypeGrpTxt {
		return reject(NotGroupText)
	}
	if packet.PayloadVer() != 0 {
		return reject(UnsupportedPayload)
	}
	// GroupTextFromBytes accepts short partial MAC reads; refuse those and
	// incomplete AES blocks before offering the native encrypted payload.
	if len(packet.Payload) < 3+aes.BlockSize || (len(packet.Payload)-3)%aes.BlockSize != 0 {
		return reject(InvalidGroupText)
	}
	group, err := meshcore.GroupTextFromBytes(packet.Payload)
	if err != nil {
		return reject(InvalidGroupText)
	}
	h := sha256.New()
	h.Write([]byte{packet.Header & 0xfc})
	h.Write(packet.Payload)
	if !bytes.Equal(h.Sum(nil), row.uid) {
		return reject(UIDMismatch)
	}
	if len(row.paths) != int(packet.PathHashCount()) || row.pathSize == nil || *row.pathSize != int32(packet.PathHashSize()) {
		return reject(PathMismatch)
	}
	for i, encoded := range row.paths {
		path, err := hex.DecodeString(encoded)
		width := int(packet.PathHashSize())
		if err != nil || len(path) != width || !bytes.Equal(path, packet.Path[i*width:(i+1)*width]) {
			return reject(PathMismatch)
		}
	}
	observation := &Observation{
		Sequence: row.seq, ID: row.id, Time: row.at, Network: row.network,
		IATA: row.iata, IdentityVersion: UIDVersion, IdentityProvenance: row.provenance,
		LegacyAlias: row.alias, SourceKey: row.source, Topic: row.topic,
		Direction: row.direction, RSSI: row.rssi, SNR: row.snr,
		BeaconHash: packet.PacketHash(), Packet: packet, GroupText: group,
	}
	copy(observation.UID[:], row.uid)
	copy(observation.ObserverKey[:], observer)
	out.Observation = observation
	return out
}
