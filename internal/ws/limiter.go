// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	maxForwardedForBytes = 1024
	maxForwardedHops     = 16
	maxRealIPBytes       = 64
)

type admissionResult string

const (
	admissionAllowed       admissionResult = ""
	admissionGlobalLimit   admissionResult = "global_limit"
	admissionPerIPLimit    admissionResult = "per_ip_limit"
	admissionHandshakeRate admissionResult = "handshake_rate"
)

type handshakeRecord struct {
	started time.Time
	count   int
}

// admissionLimiter applies the handshake rate limit and the concurrent global
// and per-IP connection caps under one lock. This makes admission atomic: a
// rejected request never consumes a connection slot.
type admissionLimiter struct {
	mu sync.Mutex

	activeGlobal int
	activeByIP   map[string]int
	handshakes   map[string]handshakeRecord

	maxGlobal          int
	maxPerIP           int
	maxHandshakes      int
	handshakeWindow    time.Duration
	nextHandshakeSweep time.Time
	now                func() time.Time
}

func newAdmissionLimiter(maxGlobal, maxPerIP, maxHandshakes int, window time.Duration) *admissionLimiter {
	return &admissionLimiter{
		activeByIP:      make(map[string]int),
		handshakes:      make(map[string]handshakeRecord),
		maxGlobal:       maxGlobal,
		maxPerIP:        maxPerIP,
		maxHandshakes:   maxHandshakes,
		handshakeWindow: window,
		now:             time.Now,
	}
}

// acquire records a handshake attempt and, if every limit allows it, reserves
// one active connection slot. Handshake attempts rejected by a connection cap
// still count toward the rate limit.
func (l *admissionLimiter) acquire(ip string) admissionResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweepHandshakes(now)

	w := l.handshakes[ip]
	if w.started.IsZero() || now.Sub(w.started) >= l.handshakeWindow {
		w = handshakeRecord{started: now}
	}
	if w.count >= l.maxHandshakes {
		l.handshakes[ip] = w
		return admissionHandshakeRate
	}
	w.count++
	l.handshakes[ip] = w

	if l.activeGlobal >= l.maxGlobal {
		return admissionGlobalLimit
	}
	if l.activeByIP[ip] >= l.maxPerIP {
		return admissionPerIPLimit
	}

	l.activeGlobal++
	l.activeByIP[ip]++
	return admissionAllowed
}

func (l *admissionLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.activeByIP[ip] <= 0 {
		return
	}
	l.activeByIP[ip]--
	l.activeGlobal--
	if l.activeByIP[ip] == 0 {
		delete(l.activeByIP, ip)
	}
}

// sweepHandshakes keeps the per-IP handshake map bounded over time without
// scanning it on every request.
func (l *admissionLimiter) sweepHandshakes(now time.Time) {
	if !l.nextHandshakeSweep.IsZero() && now.Before(l.nextHandshakeSweep) {
		return
	}
	for ip, w := range l.handshakes {
		if now.Sub(w.started) >= l.handshakeWindow {
			delete(l.handshakes, ip)
		}
	}
	l.nextHandshakeSweep = now.Add(l.handshakeWindow)
}

// clientIPResolver only accepts forwarding headers from explicitly trusted
// socket peers. With no matching proxy CIDR, the socket peer is authoritative.
type clientIPResolver struct {
	trusted []netip.Prefix
}

func newClientIPResolver(cidrs []string) (*clientIPResolver, []string) {
	r := &clientIPResolver{}
	var invalid []string
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			invalid = append(invalid, raw)
			continue
		}
		r.trusted = append(r.trusted, prefix.Masked())
	}
	return r, invalid
}

func (r *clientIPResolver) clientIP(req *http.Request) string {
	peer, ok := parseIP(req.RemoteAddr)
	if !ok {
		// RemoteAddr is populated by net/http, but a shared sentinel is safer
		// than accepting a user-controlled header if a custom transport omits it.
		return "unknown"
	}
	if !r.isTrusted(peer) {
		return peer.String()
	}

	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		if len(xff) > maxForwardedForBytes {
			return peer.String()
		}
		parts := strings.Split(xff, ",")
		if len(parts) > maxForwardedHops {
			return peer.String()
		}
		forwarded := make([]netip.Addr, 0, len(parts))
		for _, part := range parts {
			addr, ok := parseIP(strings.TrimSpace(part))
			if !ok {
				return peer.String()
			}
			forwarded = append(forwarded, addr)
		}
		// Walk from the proxy nearest the server toward the client and stop at
		// the first untrusted hop. This ignores spoofed values prepended by a
		// client while still supporting multiple trusted proxies.
		for i := len(forwarded) - 1; i >= 0; i-- {
			if !r.isTrusted(forwarded[i]) {
				return forwarded[i].String()
			}
		}
		if len(forwarded) > 0 {
			return forwarded[0].String()
		}
	}

	if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		if len(realIP) > maxRealIPBytes {
			return peer.String()
		}
		if addr, ok := parseIP(strings.TrimSpace(realIP)); ok {
			return addr.String()
		}
	}
	return peer.String()
}

func (r *clientIPResolver) isTrusted(addr netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parseIP(value string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	addr, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// messageLimiter is a per-connection token bucket. It permits a small burst
// while bounding sustained client messages.
type messageLimiter struct {
	tokens     float64
	burst      float64
	perSecond  float64
	lastRefill time.Time
}

func newMessageLimiter(messagesPerMinute, burst int, now time.Time) *messageLimiter {
	return &messageLimiter{
		tokens:     float64(burst),
		burst:      float64(burst),
		perSecond:  float64(messagesPerMinute) / 60,
		lastRefill: now,
	}
}

func (l *messageLimiter) allow(now time.Time) bool {
	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.perSecond
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.lastRefill = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
