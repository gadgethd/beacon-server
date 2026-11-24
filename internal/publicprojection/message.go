// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicprojection

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"unicode/utf8"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
	"github.com/MeshCore-Beacon/beacon-server/internal/publicsource"
	"github.com/meshcore-go/meshcore-go"
)

func formatGeneration(g int64) string { return strconv.FormatInt(g, 10) }

// Message keeps Beacon's client shape and adds full UKMesh identity. The native
// short hash is an alias, never the storage key or overlap identity.
type Message struct {
	api.ChannelMessage
	ChannelID  int32  `json:"channelId"`
	RegistryID string `json:"registryId"`
	PacketUID  string `json:"packetUid"`
}

type prepared struct {
	observation *publicsource.Observation
	channel     Channel
	payload     *meshcore.GroupTextPayload
	digest      [32]byte
}

var ErrRejected = errors.New("GroupText did not authenticate to exactly one public registry key")

func authenticate(policy Policy, observation *publicsource.Observation) (prepared, error) {
	if observation == nil || observation.Network != policy.Network || observation.IdentityVersion != publicsource.UIDVersion ||
		observation.Packet == nil || observation.Packet.PayloadType() != meshcore.PayloadTypeGrpTxt || observation.Packet.PayloadVer() != 0 {
		return prepared{}, ErrRejected
	}
	uid, err := publicsource.CanonicalUID(observation.Packet)
	if err != nil || uid != observation.UID || observation.Packet.PacketHash() != observation.BeaconHash {
		return prepared{}, ErrRejected
	}
	group, err := meshcore.GroupTextFromBytes(observation.Packet.Payload)
	if err != nil {
		return prepared{}, ErrRejected
	}
	var accepted *prepared
	for _, channel := range policy.Channels {
		if channel.hash != group.ChannelHash {
			continue
		}
		payload, err := group.DecryptStruct(channel.key[:])
		if err != nil || payload == nil || !utf8.ValidString(payload.Sender) || !utf8.ValidString(payload.Text) {
			continue
		}
		if accepted != nil {
			return prepared{}, ErrRejected
		}
		candidate := prepared{observation: observation, channel: channel, payload: payload}
		accepted = &candidate
	}
	if accepted == nil {
		return prepared{}, ErrRejected
	}
	raw, err := observation.Packet.ToBytes()
	if err != nil {
		return prepared{}, ErrRejected
	}
	accepted.digest = sha256.Sum256(raw)
	return *accepted, nil
}
