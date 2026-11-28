// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/hub"
	"github.com/coder/websocket"
)

func TestPrivateEpochRevokesIdleAndBufferedEventsWith1008(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	h := hub.New()
	done := make(chan struct{})
	go func() { defer close(done); h.RunContext(ctx) }()
	defer func() { cancel(); <-done }()
	var epoch atomic.Value
	epoch.Store("7:registry-a")
	server := httptest.NewServer(NewTransport(h, nil, Limits{MaxConnections: 4, MaxConnsPerIP: 4, MaxConnectsPerMinute: 10},
		Access{Authority: func(context.Context) (string, error) { return epoch.Load().(string), nil }}))
	defer server.Close()
	connect := func() *websocket.Conn {
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, raw, err := conn.Read(ctx)
		if err != nil || !strings.Contains(string(raw), `"hello"`) {
			t.Fatal("missing native hello")
		}
		if err = conn.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"subscribe","id":"one","scope":{"events":["channelMessage"]}}`)); err != nil {
			t.Fatal(err)
		}
		_, raw, err = conn.Read(ctx)
		if err != nil || !strings.Contains(string(raw), `"subscribed"`) {
			t.Fatal("missing native subscribed")
		}
		return conn
	}
	idle := connect()
	defer idle.CloseNow()
	epoch.Store("8:registry-b")
	if _, _, err := idle.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatal("idle epoch change did not close1008")
	}
	stale := connect()
	defer stale.CloseNow()
	h.Broadcast(hub.Event{Type: hub.EventChannelMessage, Payload: json.RawMessage(`{"content":"old"}`), AuthorityToken: "7:registry-a"})
	if _, _, err := stale.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatal("stale buffered event escaped epoch binding")
	}
	fresh := connect()
	defer fresh.CloseNow()
	h.Broadcast(hub.Event{Type: hub.EventChannelMessage, Payload: json.RawMessage(`{"content":"fresh"}`), AuthorityToken: "8:registry-b"})
	_, raw, err := fresh.Read(ctx)
	if err != nil || !strings.Contains(string(raw), `"fresh"`) {
		t.Fatal("fresh native event unavailable")
	}
}
