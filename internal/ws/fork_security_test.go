// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/MeshCore-Beacon/beacon-server/internal/hub"
)

func TestDecodeClientMessage_BoundsStringsAndScopeCardinality(t *testing.T) {
	tests := []struct {
		name string
		msg  clientMessage
	}{
		{
			name: "message ID",
			msg:  clientMessage{V: 1, Type: "ping", ID: strings.Repeat("x", maxMessageIDBytes+1)},
		},
		{
			name: "subscription ID",
			msg:  clientMessage{V: 1, Type: "unsubscribe", SubscriptionID: strings.Repeat("x", maxSubscriptionIDBytes+1)},
		},
		{
			name: "scope array",
			msg: clientMessage{V: 1, Type: "subscribe", Scope: &subscribeScope{
				IATAs: repeatString("YVR", maxScopeArrayItems+1),
			}},
		},
		{
			name: "scope string",
			msg: clientMessage{V: 1, Type: "subscribe", Scope: &subscribeScope{
				IATAs: []string{strings.Repeat("x", maxScopeStringBytes+1)},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.msg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeClientMessage(raw); err == nil {
				t.Fatal("expected bounded message to be rejected")
			}
		})
	}
}

func TestNormalizeScope_CanonicalizesAndDeduplicates(t *testing.T) {
	server := NewHandler(hub.New(), nil, Options{})
	scope, err := server.normalizeScope(context.Background(), &subscribeScope{
		IATAs:         []string{" yvr ", "YVR", "yyj"},
		PayloadTypes:  []uint8{4, 1, 4},
		ChannelHashes: []string{"AB", "ab"},
		Events:        []hub.EventType{hub.EventNodeUpdate, hub.EventPacketObservation, hub.EventNodeUpdate},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(scope.IATAs); got != "[YVR YYJ]" {
		t.Fatalf("IATAs = %s", got)
	}
	if got := fmt.Sprint(scope.PayloadTypes); got != "[1 4]" {
		t.Fatalf("PayloadTypes = %s", got)
	}
	if got := fmt.Sprint(scope.ChannelHashes); got != "[ab]" {
		t.Fatalf("ChannelHashes = %s", got)
	}
	if len(scope.Events) != 2 {
		t.Fatalf("Events = %v, want two unique values", scope.Events)
	}
}

func TestNormalizeScope_RejectsInvalidEventAndChannelHash(t *testing.T) {
	server := NewHandler(hub.New(), nil, Options{})
	if _, err := server.normalizeScope(context.Background(), &subscribeScope{Events: []hub.EventType{"not-real"}}); err == nil {
		t.Fatal("expected invalid event to be rejected")
	}
	if _, err := server.normalizeScope(context.Background(), &subscribeScope{ChannelHashes: []string{"xyz"}}); err == nil {
		t.Fatal("expected invalid channel hash to be rejected")
	}
}

func TestHandler_EnforcesGlobalConnectionCap(t *testing.T) {
	h := hub.New()
	go h.Run()
	server := NewHandler(h, nil, Options{
		MaxConnections:      1,
		MaxConnectionsPerIP: 10,
		HandshakesPerMinute: 10,
	})
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http")
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer conn.CloseNow()
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read hello: %v", err)
	}

	second, response, err := websocket.Dial(ctx, url, nil)
	if second != nil {
		_ = second.CloseNow()
	}
	if err == nil {
		t.Fatal("second dial should exceed global cap")
	}
	if response == nil || response.StatusCode != 429 {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("second dial status = %d, want 429", status)
	}
}

func TestHandler_EvictsIdleConnection(t *testing.T) {
	h := hub.New()
	go h.Run()
	server := NewHandler(h, nil, Options{HandshakesPerMinute: 10})
	server.idleFor = 25 * time.Millisecond
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http")
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("idle connection remained open")
	}
	deadline := time.Now().Add(time.Second)
	for server.metrics.idleEvictions.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := server.metrics.idleEvictions.Load(); got != 1 {
		t.Fatalf("idle evictions = %d, want 1", got)
	}
}

func TestHandler_EnforcesSubscriptionCap(t *testing.T) {
	h := hub.New()
	go h.Run()
	server := NewHandler(h, nil, Options{HandshakesPerMinute: 10})
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http")
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read hello: %v", err)
	}

	for i := 0; i <= hub.MaxSubscriptionsPerClient; i++ {
		request := fmt.Sprintf(`{"v":1,"type":"subscribe","id":"%d","scope":{}}`, i)
		if err := conn.Write(ctx, websocket.MessageText, []byte(request)); err != nil {
			t.Fatalf("write subscription %d: %v", i, err)
		}
		_, raw, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read subscription %d: %v", i, err)
		}
		var response map[string]any
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		wantType := "subscribed"
		if i == hub.MaxSubscriptionsPerClient {
			wantType = "error"
		}
		if response["type"] != wantType {
			t.Fatalf("response %d type = %v, want %s", i, response["type"], wantType)
		}
	}
}

func TestMetricsHandler_ExportsWebSocketCounters(t *testing.T) {
	server := NewHandler(hub.New(), nil, Options{})
	server.metrics.connections.Add(2)
	server.metrics.messagesReceived.Add(3)
	server.metrics.recordEviction(evictionIdle)

	recorder := httptest.NewRecorder()
	server.ServeMetrics(recorder, httptest.NewRequest("GET", "/metrics", nil))
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"beacon_ws_connections_total 2",
		"beacon_ws_messages_received_total 3",
		"beacon_ws_evictions_total 1",
		"beacon_ws_idle_evictions_total 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func repeatString(value string, count int) []string {
	result := make([]string, count)
	for i := range result {
		result[i] = value
	}
	return result
}
