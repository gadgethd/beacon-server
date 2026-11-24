// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package hub

import (
	"context"
	"testing"
	"time"
)

func TestOwnedShutdownSettlesPendingScopeAndRemove(t *testing.T) {
	h := New()
	client := h.NewClient()
	result := make(chan bool, 1)
	go func() { result <- h.AddScope(client, "pending", Scope{}) }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { h.RunContext(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("hub shutdown did not settle")
	}
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("scope acknowledgement stranded after shutdown")
	}
	removed := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			h.Remove(client)
		}
		close(removed)
	}()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("remove blocked after shutdown")
	}
}
