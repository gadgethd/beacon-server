// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func jsonObject(t *testing.T, value any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal public DTO: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(b, &object); err != nil {
		t.Fatalf("decode public DTO: %v", err)
	}
	return object
}

func assertJSONKeysAbsent(t *testing.T, object map[string]json.RawMessage, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := object[key]; ok {
			t.Errorf("public DTO contains internal field %q", key)
		}
	}
}

func TestToPublicNodeOmitsMetadata(t *testing.T) {
	node := &Node{
		NodeSummary: NodeSummary{ID: uuid.New(), PublicKey: "public-key"},
		Metadata: map[string]any{
			"internalSecret": "must not be serialized",
		},
	}

	object := jsonObject(t, ToPublicNode(node))
	assertJSONKeysAbsent(t, object, "metadata")
	if _, ok := object["publicKey"]; !ok {
		t.Error("public DTO omitted public node fields")
	}
}

func TestToPublicObserverOmitsStatusMetadata(t *testing.T) {
	observer := &Observer{
		ObserverSummary: ObserverSummary{ID: uuid.New(), Status: "online"},
		StatusMetadata: map[string]any{
			"internalSecret": "must not be serialized",
		},
	}

	object := jsonObject(t, ToPublicObserver(observer))
	assertJSONKeysAbsent(t, object, "statusMetadata")
	if _, ok := object["status"]; !ok {
		t.Error("public DTO omitted public observer fields")
	}
}

func TestToPublicPacketOmitsPayloadsAndObservations(t *testing.T) {
	packet := &Packet{
		PacketHash:    "packet-hash",
		ParsedPayload: json.RawMessage(`{"secret":"must not be serialized"}`),
		RawPayload:    "deadbeef",
		Observations:  []PacketObservationDetail{{ID: 42}},
	}

	object := jsonObject(t, ToPublicPacket(packet))
	assertJSONKeysAbsent(t, object, "parsedPayload", "rawPayload", "observations")
	if _, ok := object["packetHash"]; !ok {
		t.Error("public DTO omitted public packet fields")
	}
}
