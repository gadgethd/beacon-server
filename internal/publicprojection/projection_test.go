// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicprojection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/publicsource"
	"github.com/google/uuid"
	"github.com/meshcore-go/meshcore-go"
)

func authorityBody(key []byte, id string) []byte {
	fp := sha256.Sum256(key)
	value := map[string]any{"version": 1, "generation": 7, "registryVersion": strings.Repeat("c", 64), "network": "ukmesh",
		"channels": []any{map[string]any{"id": id, "name": "Public test", "keyFingerprint": hex.EncodeToString(fp[:]), "secretHex": hex.EncodeToString(key)}}}
	raw, _ := json.Marshal(value)
	return raw
}

func TestRegistryAcceptsOnlyExactPublicKeyIdentity(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	body := authorityBody(key, "test")
	policy, err := decodePolicy(body)
	if err != nil || policy.Channels[0].ID != "test" {
		t.Fatal("valid authority refused")
	}
	serialized, _ := json.Marshal(policy.Channels)
	if strings.Contains(string(serialized), hex.EncodeToString(key)) {
		t.Fatal("registry key escaped private ownership")
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["network"] = "other" }, func(v map[string]any) { v["generation"] = 0 },
		func(v map[string]any) { v["generation"] = true }, func(v map[string]any) { v["version"] = 2 },
		func(v map[string]any) { v["registryVersion"] = "short" },
		func(v map[string]any) {
			v["channels"].([]any)[0].(map[string]any)["keyFingerprint"] = strings.Repeat("0", 64)
		},
		func(v map[string]any) {
			channels := v["channels"].([]any)
			v["channels"] = append(channels, channels[0])
		},
	} {
		var value map[string]any
		_ = json.Unmarshal(body, &value)
		change(value)
		raw, _ := json.Marshal(value)
		if _, err := decodePolicy(raw); err == nil {
			t.Fatal("malformed authority accepted")
		}
	}
}

func TestBearerAuthorityDoesNotRedirectOrExposeCredentials(t *testing.T) {
	token := strings.Repeat("owned-fixture-token", 3)
	key := make([]byte, 16)
	var received, redirect atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing distinct authority credential")
		}
		received.Store(true)
		if redirect.Load() {
			http.Redirect(w, r, "/other", http.StatusFound)
			return
		}
		_, _ = w.Write(authorityBody(key, "public"))
	}))
	defer server.Close()
	client, err := NewHTTPAuthority(server.URL+"/internal/beacon/authority", token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Current(context.Background()); err != nil || !received.Load() {
		t.Fatal("authority request failed")
	}
	redirect.Store(true)
	if _, err = client.Current(context.Background()); err == nil {
		t.Fatal("followed unauthorized redirect")
	}
}

func TestAuthenticatedChannelCollisionUsesFullRegistryIdentity(t *testing.T) {
	// Find deterministic distinct keys sharing the 1-byte channel hash. A
	// successful MAC, not that short hash, selects the publication registry ID.
	keys := map[byte][]byte{}
	var a, b []byte
	for i := 0; i < 4096; i++ {
		candidate := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		key := append([]byte(nil), candidate[:16]...)
		fp := sha256.Sum256(key)
		if prior := keys[fp[0]]; prior != nil {
			a, b = prior, key
			break
		}
		keys[fp[0]] = key
	}
	if a == nil {
		t.Fatal("no deterministic collision")
	}
	first, _ := decodePolicy(authorityBody(a, "first"))
	second, _ := decodePolicy(authorityBody(b, "second"))
	first.Channels = append(first.Channels, second.Channels[0])
	payload := meshcore.GroupTextPayload{Timestamp: 1700000000, Sender: "Alice", Text: "Unicode 🛰️", Flags: 0}
	fp := sha256.Sum256(b)
	group, err := payload.Encrypt(fp[0], b)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := group.ToBytes()
	raw := append([]byte{0x15, 0}, body...)
	packet, err := meshcore.PacketFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	content := append([]byte{packet.Header & 0xfc}, packet.Payload...)
	uid := sha256.Sum256(content)
	o := &publicsource.Observation{ID: uuid.New(), Time: time.Now(), Network: "ukmesh", IdentityVersion: publicsource.UIDVersion, UID: uid, Packet: packet, GroupText: group, BeaconHash: packet.PacketHash()}
	record, err := authenticate(first, o)
	if err != nil || record.channel.ID != "second" || record.payload.Text != payload.Text {
		t.Fatal("wire collision selected wrong registry entry")
	}
	packet.Payload[1] ^= 1
	o.UID, _ = publicsource.CanonicalUID(packet)
	o.BeaconHash = packet.PacketHash()
	if _, err := authenticate(first, o); err == nil {
		t.Fatal("unauthenticated plaintext accepted")
	}
	packet.Payload[1] ^= 1
	o.UID, _ = publicsource.CanonicalUID(packet)
	o.BeaconHash = packet.PacketHash()
	if _, err := authenticate(secondWithNoChannels(first), o); err == nil {
		t.Fatal("saved/unapproved key was observable")
	}
	o.Network = "other"
	if _, err := authenticate(first, o); err == nil {
		t.Fatal("cross-network publication")
	}
}

func secondWithNoChannels(p Policy) Policy { p.Channels = nil; return p }
