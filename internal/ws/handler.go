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
//	  unsubscribe { v, type, id, subscriptionId } → server replies unsubscribed { v, type, id, subscriptionId }
//	  configure   { v, type, id, resolvePath, includeObserverKey, includeRepeats }
//	              → server replies configured { v, type, id, resolvePath, includeObserverKey, includeRepeats }
//	  ping        { v, type, id }                → server replies pong { v, type, id }
//
//	configure's flags are connection-wide settings, not per-subscription.
//	resolvePath adds per-hop resolvedPath data to packetObservation events,
//	includeObserverKey adds observation.observerPublicKey, and includeRepeats
//	also streams later hearings of an already-stored observation over a new
//	path, as packetObservation events with packet.isRepeat true and
//	observationCount 0. Each configure sets all three to exactly the values
//	sent, so an omitted flag turns off. All default false.
//
//	Server → Client events (unsolicited):
//	  packetObservation, observerStatus, nodeUpdate, channelMessage
//	  lagged { v, type, droppedCount, since }
//
//	lagged also reports events dropped by the per-connection send budget,
//	at most once per budgetNoticeInterval.
//
//	With websocket.require_origin on, an upgrade without an Origin needs a ticket from
//	GET /api/v1/ws-ticket in the X-Beacon-Ticket header, or it gets 403.
//
//	Idle connections (no ping) closed after 90s.
//	Client should ping every 30s.
package ws

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
	"github.com/MeshCore-Beacon/beacon-server/internal/hub"
	"github.com/MeshCore-Beacon/beacon-server/internal/wsticket"
	"github.com/coder/websocket"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"
)

const (
	pingTimeout = 90 * time.Second // server closes connection if no message received within this window
)

// budgetNoticeInterval spaces out send-budget lagged notices, since each one makes the client refetch.
var budgetNoticeInterval = 30 * time.Second

// Limits bounds what one address and one connection may use. A zero send rate means no send budget.
type Limits struct {
	MaxConnections       int
	MaxConnsPerIP        int
	MaxConnectsPerMinute int
	SendBytesPerSecond   int
	SendBurstBytes       int
}

// Access decides who may open /ws. A browser always sends an Origin; RequireOrigin makes every
// other client show a ticket instead.
type Access struct {
	AllowedOrigins []string
	RequireOrigin  bool
	Tickets        *wsticket.Issuer
	// Authority is optional. A private listener binds every write to the epoch
	// authorized at connect; ordinary Beacon traffic leaves it nil.
	Authority func(context.Context) (string, error)
}

type RegionReader interface {
	GetRegion(context.Context, int32) (*api.Region, error)
	GetRegionBySlug(context.Context, string) (*api.Region, error)
}
type authorityKey struct{}

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
	serve     http.HandlerFunc
	h         *hub.Hub
	reader    RegionReader
	authority func(context.Context) (string, error)
	limits    *admissionLimiter
	clients   *clientIPResolver
	metrics   wsMetrics
	now       func() time.Time
	idleFor   time.Duration
	writeIn   time.Duration
}

// NewHandler constructs the bounded WebSocket handler.
func NewHandler(h *hub.Hub, reader RegionReader, opts Options) *Server {
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
		slog.Warn("ws: ignoring invalid trusted proxy CIDR", "cidr", cidr)
	}
	s := &Server{
		h:       h,
		reader:  reader,
		limits:  newAdmissionLimiter(opts.MaxConnections, opts.MaxConnectionsPerIP, opts.HandshakesPerMinute, handshakeWindow),
		clients: clients,
		now:     time.Now,
		idleFor: idleTimeout,
		writeIn: writeTimeout,
	}
	s.serve = s.handler(Limits{MaxConnections: opts.MaxConnections, MaxConnsPerIP: opts.MaxConnectionsPerIP, MaxConnectsPerMinute: opts.HandshakesPerMinute}, Access{})
	return s

}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.serve(w, r) }
func NewTransport(h *hub.Hub, reader RegionReader, limits Limits, access Access) *Server {
	if limits.MaxConnections <= 0 {
		limits.MaxConnections = 1000
	}
	s := &Server{h: h, reader: reader, authority: access.Authority, now: time.Now, idleFor: pingTimeout, writeIn: writeTimeout}
	s.serve = s.handler(limits, access)
	return s
}

// Handler serves the current protocol with bounded admission, messages and writes.
func Handler(h *hub.Hub, reader RegionReader, limits Limits, access Access) http.HandlerFunc {
	s := NewTransport(h, reader, limits, access)
	return s.ServeHTTP
}
func (s *Server) handler(limits Limits, access Access) http.HandlerFunc {
	h, reader := s.h, s.reader
	_ = reader

	acceptOpts := &websocket.AcceptOptions{
		OriginPatterns: access.AllowedOrigins,
		// The live feed is repetitive JSON; a shared window cuts its bytes ~3x for ~1.2 MB per socket.
		CompressionMode: websocket.CompressionContextTakeover,
	}
	plainOpts := &websocket.AcceptOptions{OriginPatterns: access.AllowedOrigins, CompressionMode: websocket.CompressionDisabled}
	limiter := newIPLimiter(limits.MaxConnsPerIP)
	global := newIPLimiter(limits.MaxConnections)
	attempts := httprate.NewRateLimiter(limits.MaxConnectsPerMinute, time.Minute,
		httprate.WithResponseHeaders(httprate.ResponseHeaders{RetryAfter: "Retry-After"}))
	return func(w http.ResponseWriter, r *http.Request) {
		var epoch string
		if s.clients != nil {
			clone := r.Clone(r.Context())
			clone.RemoteAddr = s.clients.clientIP(r)
			r = clone
		}
		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		// Count attempts before Accept, including failed handshakes. RemoteAddr
		// was already resolved by TrustedProxyIP; never read forwarding headers here.
		// Both limits share an IPv6 /64, so rotating addresses inside one doesn't add sockets.
		key := wsticket.ClientKey(r)
		if attempts.RespondOnLimit(w, r, key) {
			s.metrics.connectionRejections.Add(1)
			return
		}
		if access.RequireOrigin && r.Header.Get("Origin") == "" && !access.Tickets.Valid(r.Header.Get(wsticket.Header), key) {
			http.Error(w, "an Origin or a ticket is required", http.StatusForbidden)
			return
		}
		if !global.acquire("all") {
			s.metrics.connectionRejections.Add(1)
			w.Header().Set("Retry-After", "60")
			http.Error(w, "websocket connection limit exceeded", http.StatusTooManyRequests)
			return
		}
		defer global.release("all")
		if s.authority != nil {
			var err error
			epoch, err = s.authority(r.Context())
			if err != nil || epoch == "" {
				http.Error(w, "public authority unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		opts := plainOpts
		if compressesFor(r.UserAgent()) {
			opts = acceptOpts
		}
		conn, err := websocket.Accept(w, r, opts)
		if err != nil {
			slog.Warn("ws: failed to accept connection", "component", "ws", "error", err)
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(maxMessageBytes)
		if !limiter.acquire(key) {
			s.metrics.connectionRejections.Add(1)
			// This attempt passed the rate budget. Give the accepted socket a
			// browser-visible backoff signal before allocating a hub client.
			slog.Warn("ws: connection limit reached", "component", "ws", "client_ip", ip)
			_ = conn.Close(websocket.StatusTryAgainLater, "connection limit reached")
			return
		}
		defer limiter.release(key)
		s.metrics.connections.Add(1)
		s.metrics.activeConnections.Add(1)
		defer s.metrics.activeConnections.Add(-1)
		var evictionRecorded atomic.Bool
		recordEviction := func(kind evictionKind) {
			if evictionRecorded.CompareAndSwap(false, true) {
				s.metrics.recordEviction(kind)
			}
		}
		write := func(ctx context.Context, kind websocket.MessageType, payload []byte) error {
			if err := s.checkAuthority(ctx, conn); err != nil {
				return err
			}
			writeCtx, cancelWrite := context.WithTimeout(ctx, s.writeIn)
			defer cancelWrite()
			err := conn.Write(writeCtx, kind, payload)
			if err == nil {
				s.metrics.messagesSent.Add(1)
			} else if errors.Is(writeCtx.Err(), context.DeadlineExceeded) {
				recordEviction(evictionWriteTimeout)
			}
			return err
		}

		connID := uuid.NewString()
		client := h.NewClient()
		defer h.Remove(client)

		ctx, cancel := context.WithCancel(context.WithValue(r.Context(), authorityKey{}, epoch))
		defer cancel()

		// Send hello
		hello := map[string]any{
			"v":            1,
			"type":         "hello",
			"serverTime":   time.Now().UnixMilli(),
			"connectionId": connID,
		}
		helloBytes, _ := json.Marshal(hello)
		slog.Debug("connected", "component", "ws", "connection_id", connID)
		err = write(ctx, websocket.MessageText, helloBytes)
		if err != nil {
			slog.Warn(fmt.Sprintf("ws[%s]: failed to send hello", connID), "component", "ws", "error", err)
			return
		}

		// Write pump: forward hub events to the WS connection.
		go func() {
			defer cancel()
			var tick <-chan time.Time
			if s.authority != nil {
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				tick = ticker.C
			}
			budget := newSendBudget(limits.SendBytesPerSecond, limits.SendBurstBytes, time.Now())
			budgetDropped := 0
			var lastNotice time.Time
			var noticeDue <-chan time.Time
			writeLagged := func(dropped int) error {
				lagged := map[string]any{
					"v":            1,
					"type":         "lagged",
					"droppedCount": dropped,
					"since":        time.Now().UnixMilli(),
				}
				lagBytes, _ := json.Marshal(lagged)
				return write(ctx, websocket.MessageText, lagBytes)
			}
			for {
				select {
				case evt, ok := <-client.Send:
					if !ok {
						return
					}
					if s.authority != nil && evt.AuthorityToken != epoch {
						_ = conn.Close(websocket.StatusPolicyViolation, "public authority changed")
						return
					}
					msg := map[string]any{
						"v":     1,
						"type":  "event",
						"event": evt.Type,
						"data":  json.RawMessage(evt.Payload),
					}
					msgBytes, _ := json.Marshal(msg)
					if !budget.allow(len(msgBytes), time.Now()) {
						budgetDropped++
						if noticeDue == nil {
							noticeDue = time.After(time.Until(lastNotice.Add(budgetNoticeInterval)))
						}
						continue
					}
					if err := write(ctx, websocket.MessageText, msgBytes); err != nil {
						slog.Warn(fmt.Sprintf("ws[%s]: failed to write hub event", connID), "component", "ws", "error", err)
						cancel()
						return
					}

				case <-noticeDue:
					noticeDue = nil
					slog.Warn(fmt.Sprintf("ws[%s]: send budget exceeded, dropped events", connID), "component", "ws", "client_ip", ip, "dropped", budgetDropped)
					if err := writeLagged(budgetDropped); err != nil {
						slog.Warn(fmt.Sprintf("ws[%s]: failed to write lagged notice", connID), "component", "ws", "error", err)
						cancel()
						return
					}
					budgetDropped = 0
					lastNotice = time.Now()

				case lag, ok := <-client.LaggedCH():
					if !ok {
						return
					}
					if err := writeLagged(lag.DroppedCount); err != nil {
						slog.Warn(fmt.Sprintf("ws[%s]: failed to write lagged notice", connID), "component", "ws", "error", err)
						cancel()
						return
					}

				case <-tick:
					if err := s.checkAuthority(ctx, conn); err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		messageRate := newMessageLimiter(messagesPerMinute, messageBurst, s.now())
		// Read pump: handle subscribe / unsubscribe / ping from the client.
		// Drives the idle timeout; any message resets the deadline.
		for {
			readCtx, readCancel := context.WithTimeout(ctx, s.idleFor)
			messageType, msgBytes, err := conn.Read(readCtx)
			idle := errors.Is(readCtx.Err(), context.DeadlineExceeded)
			readCancel()
			if err != nil {
				if idle {
					recordEviction(evictionIdle)
					_ = conn.Close(websocket.StatusPolicyViolation, "idle timeout")
				}
				if websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
					s.metrics.messageRejections.Add(1)
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
			if err := s.handleClientMessage(ctx, client, conn, connID, msgBytes); err != nil {
				return
			}
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

	// Only read for "configure" messages. See package doc.
	ResolvePath        bool `json:"resolvePath,omitempty"`
	IncludeObserverKey bool `json:"includeObserverKey,omitempty"`
	IncludeRepeats     bool `json:"includeRepeats,omitempty"`
}

// subscribeScope mirrors the scope object in the subscribe message.
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
		slog.Debug("ws: subscribed", "component", "ws", "subscription_id", subID)
		return s.writeJSON(ctx, conn, map[string]any{
			"v": 1, "type": "subscribed", "id": msg.ID, "subscriptionId": subID,
		})

	case "unsubscribe":
		if msg.SubscriptionID == "" {
			s.metrics.messageRejections.Add(1)
			return s.writeError(ctx, conn, "invalid_subscription", "subscriptionId is required", msg.ID)
		}
		s.h.RemoveScope(client, msg.SubscriptionID)
		slog.Debug("ws: unsubscribed", "component", "ws")
		return s.writeJSON(ctx, conn, map[string]any{
			"v": 1, "type": "unsubscribed", "id": msg.ID, "subscriptionId": msg.SubscriptionID,
		})

	case "configure":
		s.h.Configure(client, hub.ClientOptions{ResolvePath: msg.ResolvePath, IncludeObserverKey: msg.IncludeObserverKey, IncludeRepeats: msg.IncludeRepeats})
		return s.writeJSON(ctx, conn, map[string]any{
			"v": 1, "type": "configured", "id": msg.ID, "resolvePath": msg.ResolvePath, "includeObserverKey": msg.IncludeObserverKey, "includeRepeats": msg.IncludeRepeats,
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
	if err := s.checkAuthority(ctx, conn); err != nil {
		return err
	}
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

func (s *Server) checkAuthority(ctx context.Context, conn *websocket.Conn) error {
	if s.authority == nil {
		return nil
	}
	expected, _ := ctx.Value(authorityKey{}).(string)
	current, err := s.authority(ctx)
	if err != nil || expected == "" || current != expected {
		_ = conn.Close(websocket.StatusPolicyViolation, "public authority changed")
		return errors.New("public websocket authority unavailable")
	}
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
