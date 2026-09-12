// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ws handles the WebSocket endpoint at GET /ws.
//
// Protocol (from design doc):
//
//	On connect: server sends hello { v:1, type:"hello", serverTime:<ms>, connectionId:"uuid" }
//
//	Client → Server:
//	  subscribe   { v, type, id, scope }         → server replies subscribed { v, type, id, subscriptionId }
//	  unsubscribe { v, type, id, subscriptionId }
//	  configure   { v, type, id, resolvePath }   → server replies configured { v, type, id, resolvePath }
//	  ping        { v, type, id }                → server replies pong { v, type, id }
//
//	Server → Client events (unsolicited):
//	  packetObservation, observerStatus, nodeUpdate, channelMessage
//	  lagged { v, type, droppedCount, since, lastObservationId }
//	  error  { v, type, code, message }
//
// Clients should send a ping at least every 30 seconds. Connections with no
// client messages for 60 seconds are evicted.
package ws

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
	"github.com/MeshCore-Beacon/beacon-server/internal/hub"
)

const (
	idleTimeout                  = 60 * time.Second
	writeTimeout                 = 10 * time.Second
	handshakeWindow              = time.Minute
	maxMessageBytes        int64 = 16 * 1024
	maxMessageIDBytes            = 128
	maxSubscriptionIDBytes       = 64
	maxScopeArrayItems           = 64
	maxScopeItems                = 128
	maxScopeStringBytes          = 128
	maxExpandedIATAs             = 64
	messagesPerMinute            = 120
	messageBurst                 = 32
)

var errWriteTimeout = errors.New("websocket write timed out")

// Options controls WebSocket admission. Non-positive limits receive the safe
// defaults shown in config.yaml.example.
type Options struct {
	MaxConnections      int
	MaxConnectionsPerIP int
	HandshakesPerMinute int
	TrustedProxyCIDRs   []string
}

// Server owns one WebSocket handler's limiters and metrics.
type Server struct {
	h       *hub.Hub
	reader  api.Reader
	limits  *admissionLimiter
	clients *clientIPResolver
	metrics wsMetrics
	now     func() time.Time
	idleFor time.Duration
	writeIn time.Duration
}

// NewHandler constructs the bounded WebSocket handler.
func NewHandler(h *hub.Hub, reader api.Reader, opts Options) *Server {
	if opts.MaxConnections <= 0 {
		opts.MaxConnections = 1000
	}
	if opts.MaxConnectionsPerIP <= 0 {
		opts.MaxConnectionsPerIP = 50
	}
	if opts.HandshakesPerMinute <= 0 {
		opts.HandshakesPerMinute = 5
	}
	clients, invalidCIDRs := newClientIPResolver(opts.TrustedProxyCIDRs)
	for _, cidr := range invalidCIDRs {
		log.Printf("ws: ignoring invalid trusted proxy CIDR %q", cidr)
	}
	return &Server{
		h:       h,
		reader:  reader,
		limits:  newAdmissionLimiter(opts.MaxConnections, opts.MaxConnectionsPerIP, opts.HandshakesPerMinute, handshakeWindow),
		clients: clients,
		now:     time.Now,
		idleFor: idleTimeout,
		writeIn: writeTimeout,
	}
}

// Handler preserves the original constructor for internal callers. New code
// should use NewHandler so its metrics endpoint can be mounted as well.
func Handler(h *hub.Hub, reader api.Reader, maxConnectionsPerIP int) http.HandlerFunc {
	server := NewHandler(h, reader, Options{MaxConnectionsPerIP: maxConnectionsPerIP})
	return server.ServeHTTP
}

// ServeHTTP upgrades an admitted request and runs its read/write pumps.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := s.clients.clientIP(r)
	if result := s.limits.acquire(ip); result != admissionAllowed {
		s.metrics.connectionRejections.Add(1)
		w.Header().Set("Retry-After", "60")
		log.Printf("ws: rejected connection from %s: %s", ip, result)
		http.Error(w, "websocket connection limit exceeded", http.StatusTooManyRequests)
		return
	}
	defer s.limits.release(ip)

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Printf("ws: failed to accept connection from %s: %v", ip, err)
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxMessageBytes)

	s.metrics.connections.Add(1)
	s.metrics.activeConnections.Add(1)
	defer s.metrics.activeConnections.Add(-1)

	connID := uuid.NewString()
	client := s.h.NewClient()
	defer s.h.Remove(client)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var evictionRecorded atomic.Bool
	recordEviction := func(kind evictionKind) {
		if evictionRecorded.CompareAndSwap(false, true) {
			s.metrics.recordEviction(kind)
		}
	}

	hello := map[string]any{
		"v":            1,
		"type":         "hello",
		"serverTime":   s.now().UnixMilli(),
		"connectionId": connID,
	}
	if err := s.writeJSON(ctx, conn, hello); err != nil {
		log.Printf("ws[%s]: failed to send hello: %v", connID, err)
		if errors.Is(err, errWriteTimeout) {
			recordEviction(evictionWriteTimeout)
		}
		return
	}
	log.Printf("ws[%s]: connected from %s", connID, ip)

	// Write pump: forward hub events to the WebSocket connection.
	go func() {
		for {
			select {
			case evt, ok := <-client.Send:
				if !ok {
					return
				}
				msg := map[string]any{
					"v":     1,
					"type":  "event",
					"event": evt.Type,
					"data":  json.RawMessage(evt.Payload),
				}
				if err := s.writeJSON(ctx, conn, msg); err != nil {
					log.Printf("ws[%s]: failed to write hub event: %v", connID, err)
					if errors.Is(err, errWriteTimeout) {
						recordEviction(evictionWriteTimeout)
					}
					cancel()
					return
				}

			case lag, ok := <-client.LaggedCH():
				if !ok {
					return
				}
				msg := map[string]any{
					"v":            1,
					"type":         "lagged",
					"droppedCount": lag.DroppedCount,
					"since":        s.now().UnixMilli(),
				}
				if err := s.writeJSON(ctx, conn, msg); err != nil {
					log.Printf("ws[%s]: failed to write lagged notice: %v", connID, err)
					if errors.Is(err, errWriteTimeout) {
						recordEviction(evictionWriteTimeout)
					}
					cancel()
					return
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	messageRate := newMessageLimiter(messagesPerMinute, messageBurst, s.now())
	for {
		readCtx, readCancel := context.WithTimeout(ctx, s.idleFor)
		messageType, raw, readErr := conn.Read(readCtx)
		idle := errors.Is(readCtx.Err(), context.DeadlineExceeded)
		readCancel()
		if readErr != nil {
			switch {
			case idle:
				recordEviction(evictionIdle)
				_ = conn.Close(websocket.StatusPolicyViolation, "idle timeout")
			case websocket.CloseStatus(readErr) == websocket.StatusMessageTooBig:
				s.metrics.messageRejections.Add(1)
				log.Printf("ws[%s]: message exceeded %d-byte limit", connID, maxMessageBytes)
			case ctx.Err() == nil && websocket.CloseStatus(readErr) == -1:
				log.Printf("ws[%s]: read error: %v", connID, readErr)
			}
			return
		}

		s.metrics.messagesReceived.Add(1)
		if !messageRate.allow(s.now()) {
			s.metrics.messageRejections.Add(1)
			_ = s.writeError(ctx, conn, "rate_limit", "client message rate limit exceeded", "")
			recordEviction(evictionMessageRate)
			_ = conn.Close(websocket.StatusPolicyViolation, "message rate limit")
			return
		}
		if messageType != websocket.MessageText {
			s.metrics.messageRejections.Add(1)
			if err := s.writeError(ctx, conn, "invalid_message", "text messages are required", ""); err != nil {
				return
			}
			continue
		}
		if err := s.handleClientMessage(ctx, client, conn, connID, raw); err != nil {
			log.Printf("ws[%s]: failed to handle client message: %v", connID, err)
			if errors.Is(err, errWriteTimeout) {
				recordEviction(evictionWriteTimeout)
			}
			return
		}
	}
}

// clientMessage is the shape of every client → server message.
type clientMessage struct {
	V              int             `json:"v"`
	Type           string          `json:"type"`
	ID             string          `json:"id"`
	SubscriptionID string          `json:"subscriptionId,omitempty"`
	Scope          *subscribeScope `json:"scope,omitempty"`
	ResolvePath    bool            `json:"resolvePath,omitempty"`
}

type subscribeScope struct {
	IATAs         []string        `json:"iatas"`
	RegionIDs     []string        `json:"regionIds"`
	RegionSlugs   []string        `json:"regionSlugs"`
	PayloadTypes  []uint8         `json:"payloadTypes"`
	RouteTypes    []uint8         `json:"routeTypes"`
	ChannelHashes []string        `json:"channelHashes"`
	ObserverIDs   []string        `json:"observerIds"`
	Events        []hub.EventType `json:"events"`
}

func (s *Server) handleClientMessage(ctx context.Context, client *hub.Client, conn *websocket.Conn, connID string, raw []byte) error {
	msg, err := decodeClientMessage(raw)
	if err != nil {
		s.metrics.messageRejections.Add(1)
		return s.writeError(ctx, conn, "invalid_message", err.Error(), "")
	}

	switch msg.Type {
	case "subscribe":
		if msg.Scope == nil {
			s.metrics.messageRejections.Add(1)
			return s.writeError(ctx, conn, "invalid_scope", "subscribe requires a scope", msg.ID)
		}
		scope, err := s.normalizeScope(ctx, msg.Scope)
		if err != nil {
			s.metrics.messageRejections.Add(1)
			return s.writeError(ctx, conn, "invalid_scope", err.Error(), msg.ID)
		}
		subID := uuid.NewString()
		if !s.h.AddScope(client, subID, scope) {
			s.metrics.messageRejections.Add(1)
			return s.writeError(ctx, conn, "subscription_limit", fmt.Sprintf("at most %d subscriptions are allowed", hub.MaxSubscriptionsPerClient), msg.ID)
		}
		log.Printf("ws[%s]: subscribed %s -> %s", connID, msg.ID, subID)
		return s.writeJSON(ctx, conn, map[string]any{
			"v": 1, "type": "subscribed", "id": msg.ID, "subscriptionId": subID,
		})

	case "unsubscribe":
		if msg.SubscriptionID == "" {
			s.metrics.messageRejections.Add(1)
			return s.writeError(ctx, conn, "invalid_subscription", "subscriptionId is required", msg.ID)
		}
		s.h.RemoveScope(client, msg.SubscriptionID)
		log.Printf("ws[%s]: unsubscribed %s", connID, msg.SubscriptionID)
		return s.writeJSON(ctx, conn, map[string]any{
			"v": 1, "type": "unsubscribed", "id": msg.ID, "subscriptionId": msg.SubscriptionID,
		})

	case "configure":
		s.h.SetResolvePath(client, msg.ResolvePath)
		return s.writeJSON(ctx, conn, map[string]any{
			"v": 1, "type": "configured", "id": msg.ID, "resolvePath": msg.ResolvePath,
		})

	case "ping":
		return s.writeJSON(ctx, conn, map[string]any{"v": 1, "type": "pong", "id": msg.ID})

	default:
		s.metrics.messageRejections.Add(1)
		return s.writeError(ctx, conn, "unknown_type", "unsupported message type", msg.ID)
	}
}

func decodeClientMessage(raw []byte) (clientMessage, error) {
	var msg clientMessage
	if int64(len(raw)) > maxMessageBytes {
		return msg, fmt.Errorf("message exceeds %d bytes", maxMessageBytes)
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return msg, errors.New("message must be valid JSON")
	}
	if msg.V != 1 {
		return msg, errors.New("unsupported protocol version")
	}
	if msg.Type == "" || len(msg.Type) > 32 {
		return msg, errors.New("invalid message type")
	}
	if len(msg.ID) > maxMessageIDBytes {
		return msg, fmt.Errorf("id exceeds %d bytes", maxMessageIDBytes)
	}
	if len(msg.SubscriptionID) > maxSubscriptionIDBytes {
		return msg, fmt.Errorf("subscriptionId exceeds %d bytes", maxSubscriptionIDBytes)
	}
	if msg.Scope != nil {
		if err := validateScopeShape(msg.Scope); err != nil {
			return msg, err
		}
	}
	return msg, nil
}

func validateScopeShape(scope *subscribeScope) error {
	counts := []struct {
		name  string
		count int
	}{
		{"iatas", len(scope.IATAs)},
		{"regionIds", len(scope.RegionIDs)},
		{"regionSlugs", len(scope.RegionSlugs)},
		{"payloadTypes", len(scope.PayloadTypes)},
		{"routeTypes", len(scope.RouteTypes)},
		{"channelHashes", len(scope.ChannelHashes)},
		{"observerIds", len(scope.ObserverIDs)},
		{"events", len(scope.Events)},
	}
	total := 0
	for _, field := range counts {
		if field.count > maxScopeArrayItems {
			return fmt.Errorf("scope.%s exceeds %d items", field.name, maxScopeArrayItems)
		}
		total += field.count
	}
	if total > maxScopeItems {
		return fmt.Errorf("scope exceeds %d total items", maxScopeItems)
	}

	stringFields := []struct {
		name   string
		values []string
	}{
		{"iatas", scope.IATAs},
		{"regionIds", scope.RegionIDs},
		{"regionSlugs", scope.RegionSlugs},
		{"channelHashes", scope.ChannelHashes},
		{"observerIds", scope.ObserverIDs},
	}
	for _, field := range stringFields {
		for _, value := range field.values {
			if len(value) == 0 || len(value) > maxScopeStringBytes {
				return fmt.Errorf("scope.%s contains an invalid string", field.name)
			}
		}
	}
	for _, event := range scope.Events {
		if len(event) == 0 || len(event) > 32 {
			return errors.New("scope.events contains an invalid string")
		}
	}
	return nil
}

// normalizeScope canonicalizes and de-duplicates filter values before storing
// them in the hub. Region expansion is also bounded, so a small request cannot
// create an unexpectedly large in-memory subscription.
func (s *Server) normalizeScope(ctx context.Context, input *subscribeScope) (hub.Scope, error) {
	iataSet := make(map[string]struct{})
	addIATA := func(raw string) error {
		value := strings.ToUpper(strings.TrimSpace(raw))
		if value == "" || len(value) > maxScopeStringBytes {
			return errors.New("scope.iatas contains an invalid value")
		}
		iataSet[value] = struct{}{}
		if len(iataSet) > maxExpandedIATAs {
			return fmt.Errorf("expanded IATA filter exceeds %d items", maxExpandedIATAs)
		}
		return nil
	}
	for _, value := range input.IATAs {
		if err := addIATA(value); err != nil {
			return hub.Scope{}, err
		}
	}

	regionIDs, err := normalizeStrings(input.RegionIDs, func(value string) string {
		return strings.TrimSpace(value)
	})
	if err != nil {
		return hub.Scope{}, err
	}
	regionSlugs, err := normalizeStrings(input.RegionSlugs, func(value string) string {
		return strings.ToLower(strings.TrimSpace(value))
	})
	if err != nil {
		return hub.Scope{}, err
	}
	if (len(regionIDs) > 0 || len(regionSlugs) > 0) && s.reader == nil {
		return hub.Scope{}, errors.New("region lookup is unavailable")
	}
	for _, value := range regionIDs {
		id, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return hub.Scope{}, fmt.Errorf("invalid regionId %q", value)
		}
		region, err := s.reader.GetRegion(ctx, int32(id))
		if err != nil {
			return hub.Scope{}, fmt.Errorf("region %d was not found", id)
		}
		for _, value := range region.IATAs {
			if err := addIATA(value); err != nil {
				return hub.Scope{}, err
			}
		}
	}
	for _, slug := range regionSlugs {
		region, err := s.reader.GetRegionBySlug(ctx, slug)
		if err != nil {
			return hub.Scope{}, fmt.Errorf("region slug %q was not found", slug)
		}
		for _, value := range region.IATAs {
			if err := addIATA(value); err != nil {
				return hub.Scope{}, err
			}
		}
	}

	iatas := make([]string, 0, len(iataSet))
	for value := range iataSet {
		iatas = append(iatas, value)
	}
	slices.Sort(iatas)

	channelHashes, err := normalizeStrings(input.ChannelHashes, func(value string) string {
		return strings.ToLower(strings.TrimSpace(value))
	})
	if err != nil {
		return hub.Scope{}, err
	}
	for _, value := range channelHashes {
		if len(value)%2 != 0 {
			return hub.Scope{}, fmt.Errorf("channel hash %q is not hexadecimal", value)
		}
		if _, err := hex.DecodeString(value); err != nil {
			return hub.Scope{}, fmt.Errorf("channel hash %q is not hexadecimal", value)
		}
	}

	payloadTypes := slices.Clone(input.PayloadTypes)
	slices.Sort(payloadTypes)
	payloadTypes = slices.Compact(payloadTypes)

	eventSet := make(map[hub.EventType]struct{})
	for _, event := range input.Events {
		switch event {
		case hub.EventPacketObservation, hub.EventObserverStatus, hub.EventNodeUpdate, hub.EventChannelMessage:
			eventSet[event] = struct{}{}
		default:
			return hub.Scope{}, fmt.Errorf("unsupported event %q", event)
		}
	}
	events := make([]hub.EventType, 0, len(eventSet))
	for event := range eventSet {
		events = append(events, event)
	}
	slices.Sort(events)

	return hub.Scope{
		IATAs:         iatas,
		PayloadTypes:  payloadTypes,
		ChannelHashes: channelHashes,
		Events:        events,
	}, nil
}

func normalizeStrings(values []string, normalize func(string) string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := normalize(raw)
		if value == "" || len(value) > maxScopeStringBytes {
			return nil, errors.New("scope contains an invalid string")
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result, nil
}

func (s *Server) writeJSON(ctx context.Context, conn *websocket.Conn, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, s.writeIn)
	defer cancel()
	if err := conn.Write(writeCtx, websocket.MessageText, payload); err != nil {
		if errors.Is(writeCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%w: %v", errWriteTimeout, err)
		}
		return err
	}
	s.metrics.messagesSent.Add(1)
	return nil
}

func (s *Server) writeError(ctx context.Context, conn *websocket.Conn, code, message, id string) error {
	return s.writeJSON(ctx, conn, map[string]any{
		"v": 1, "type": "error", "code": code, "message": message, "id": id,
	})
}

type evictionKind int

const (
	evictionIdle evictionKind = iota
	evictionMessageRate
	evictionWriteTimeout
)

type wsMetrics struct {
	activeConnections     atomic.Int64
	connections           atomic.Uint64
	connectionRejections  atomic.Uint64
	messagesReceived      atomic.Uint64
	messagesSent          atomic.Uint64
	messageRejections     atomic.Uint64
	evictions             atomic.Uint64
	idleEvictions         atomic.Uint64
	messageRateEvictions  atomic.Uint64
	writeTimeoutEvictions atomic.Uint64
}

func (m *wsMetrics) recordEviction(kind evictionKind) {
	m.evictions.Add(1)
	switch kind {
	case evictionIdle:
		m.idleEvictions.Add(1)
	case evictionMessageRate:
		m.messageRateEvictions.Add(1)
	case evictionWriteTimeout:
		m.writeTimeoutEvictions.Add(1)
	}
}

// ServeMetrics exports WebSocket counters in Prometheus text format without an
// additional metrics dependency.
func (s *Server) ServeMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	metrics := []struct {
		name     string
		typeName string
		help     string
		value    any
	}{
		{"beacon_ws_connections_active", "gauge", "Current admitted WebSocket connections.", s.metrics.activeConnections.Load()},
		{"beacon_ws_connections_total", "counter", "Accepted WebSocket connections.", s.metrics.connections.Load()},
		{"beacon_ws_connection_rejections_total", "counter", "WebSocket handshakes rejected by admission limits.", s.metrics.connectionRejections.Load()},
		{"beacon_ws_messages_received_total", "counter", "Client WebSocket messages received.", s.metrics.messagesReceived.Load()},
		{"beacon_ws_messages_sent_total", "counter", "WebSocket messages written successfully.", s.metrics.messagesSent.Load()},
		{"beacon_ws_message_rejections_total", "counter", "Client messages rejected by validation or rate limits.", s.metrics.messageRejections.Load()},
		{"beacon_ws_evictions_total", "counter", "Connections evicted by resource controls.", s.metrics.evictions.Load()},
		{"beacon_ws_idle_evictions_total", "counter", "Connections evicted after the idle timeout.", s.metrics.idleEvictions.Load()},
		{"beacon_ws_message_rate_evictions_total", "counter", "Connections evicted for exceeding the message rate.", s.metrics.messageRateEvictions.Load()},
		{"beacon_ws_write_timeout_evictions_total", "counter", "Connections evicted after a write timeout.", s.metrics.writeTimeoutEvictions.Load()},
	}
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", metric.name, metric.help, metric.name, metric.typeName, metric.name, metric.value)
	}
}
