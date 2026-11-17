// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAdmissionLimiter_PerIPAndGlobalCaps(t *testing.T) {
	l := newAdmissionLimiter(2, 1, 100, time.Minute)
	if got := l.acquire("192.0.2.1"); got != admissionAllowed {
		t.Fatalf("first acquire = %q, want allowed", got)
	}
	if got := l.acquire("192.0.2.1"); got != admissionPerIPLimit {
		t.Fatalf("second acquire for same IP = %q, want per-IP limit", got)
	}
	if got := l.acquire("192.0.2.2"); got != admissionAllowed {
		t.Fatalf("second IP acquire = %q, want allowed", got)
	}
	if got := l.acquire("192.0.2.3"); got != admissionGlobalLimit {
		t.Fatalf("third active connection = %q, want global limit", got)
	}

	l.release("192.0.2.1")
	if got := l.acquire("192.0.2.3"); got != admissionAllowed {
		t.Fatalf("acquire after release = %q, want allowed", got)
	}
}

func TestAdmissionLimiter_HandshakeRateResetsAndDoesNotLeakSlots(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAdmissionLimiter(10, 10, 2, time.Minute)
	l.now = func() time.Time { return now }

	if got := l.acquire("192.0.2.1"); got != admissionAllowed {
		t.Fatalf("first acquire = %q", got)
	}
	l.release("192.0.2.1")
	if got := l.acquire("192.0.2.1"); got != admissionAllowed {
		t.Fatalf("second acquire = %q", got)
	}
	l.release("192.0.2.1")
	if got := l.acquire("192.0.2.1"); got != admissionHandshakeRate {
		t.Fatalf("third handshake = %q, want handshake rate", got)
	}
	if l.activeGlobal != 0 || len(l.activeByIP) != 0 {
		t.Fatalf("rejection leaked an active slot: global=%d byIP=%v", l.activeGlobal, l.activeByIP)
	}

	now = now.Add(time.Minute)
	if got := l.acquire("192.0.2.1"); got != admissionAllowed {
		t.Fatalf("acquire after window = %q, want allowed", got)
	}
}

func TestAdmissionLimiter_ReleaseIsIdempotent(t *testing.T) {
	l := newAdmissionLimiter(2, 2, 10, time.Minute)
	l.release("192.0.2.1")
	if l.activeGlobal != 0 {
		t.Fatalf("release without acquire made global count %d", l.activeGlobal)
	}
}

func TestClientIPResolver_UntrustedPeerIgnoresHeaders(t *testing.T) {
	r, invalid := newClientIPResolver([]string{"10.0.0.0/8"})
	if len(invalid) != 0 {
		t.Fatalf("unexpected invalid CIDRs: %v", invalid)
	}
	req := &http.Request{
		RemoteAddr: "203.0.113.9:4321",
		Header: http.Header{
			"X-Forwarded-For": []string{"198.51.100.5"},
			"X-Real-Ip":       []string{"198.51.100.6"},
		},
	}
	if got := r.clientIP(req); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want socket peer", got)
	}
}

func TestClientIPResolver_TrustedProxyWalksXForwardedForRightToLeft(t *testing.T) {
	r, _ := newClientIPResolver([]string{"10.0.0.0/8"})
	req := &http.Request{
		RemoteAddr: "10.0.0.2:4321",
		Header: http.Header{
			// The leftmost value is client-supplied spoofing. The rightmost
			// untrusted address is the client seen by the first trusted proxy.
			"X-Forwarded-For": []string{"192.0.2.99, 198.51.100.5, 10.0.0.1"},
		},
	}
	if got := r.clientIP(req); got != "198.51.100.5" {
		t.Fatalf("clientIP = %q, want 198.51.100.5", got)
	}
}

func TestClientIPResolver_MalformedForwardingHeaderFallsBackToPeer(t *testing.T) {
	r, _ := newClientIPResolver([]string{"10.0.0.0/8"})
	req := &http.Request{
		RemoteAddr: "10.0.0.2:4321",
		Header:     http.Header{"X-Forwarded-For": []string{"198.51.100.5, garbage"}},
	}
	if got := r.clientIP(req); got != "10.0.0.2" {
		t.Fatalf("clientIP = %q, want trusted socket peer fallback", got)
	}
}

func TestClientIPResolver_BoundsForwardedHeaderCardinality(t *testing.T) {
	r, _ := newClientIPResolver([]string{"10.0.0.0/8"})
	req := &http.Request{
		RemoteAddr: "10.0.0.2:4321",
		Header:     http.Header{"X-Forwarded-For": []string{strings.Repeat("192.0.2.1,", maxForwardedHops+1)}},
	}
	if got := r.clientIP(req); got != "10.0.0.2" {
		t.Fatalf("clientIP = %q, want socket peer for oversized chain", got)
	}
}

func TestClientIPResolver_InvalidCIDRsAreNotTrusted(t *testing.T) {
	r, invalid := newClientIPResolver([]string{"not-a-cidr"})
	if len(invalid) != 1 {
		t.Fatalf("invalid CIDRs = %v, want one entry", invalid)
	}
	req := &http.Request{RemoteAddr: "127.0.0.1:1234", Header: http.Header{"X-Real-Ip": []string{"192.0.2.1"}}}
	if got := r.clientIP(req); got != "127.0.0.1" {
		t.Fatalf("clientIP = %q, want socket peer", got)
	}
}

func TestMessageLimiter_BoundsBurstAndRefills(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newMessageLimiter(60, 2, now)
	if !l.allow(now) || !l.allow(now) {
		t.Fatal("initial burst should be allowed")
	}
	if l.allow(now) {
		t.Fatal("message over burst should be rejected")
	}
	if !l.allow(now.Add(time.Second)) {
		t.Fatal("one token should refill after one second")
	}
}
