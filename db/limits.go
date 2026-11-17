// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"time"
)

const (
	maxQueryLimit    int32 = 2000
	statementTimeout       = 5 * time.Second
)

// clampQueryLimit is the store-layer backstop for callers that bypass the HTTP
// handlers. Internal verification also reads larger pages; HTTP handlers apply
// their smaller endpoint-specific bounds before reaching the store.
func clampQueryLimit(limit int32) int32 { return clampQueryLimitUpTo(limit, maxQueryLimit) }

func clampQueryLimitUpTo(limit, maxLimit int32) int32 {
	if limit < 1 {
		return 1
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

// withStatementTimeout gives pgx a per-query deadline so a slow pagination
// request cannot hold a database connection indefinitely.
func withStatementTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, statementTimeout)
}

// Internal verification compares complete pages with legacy statements and may
// deliberately request more rows than a public page. Bind the backstop to the
// API store; maintenance retains its caller's limits and deadline.
func (s *Store) boundQueryLimit(limit int32) int32 {
	if !s.publicReads {
		return limit
	}
	return clampQueryLimit(limit)
}

func (s *Store) readContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if !s.publicReads {
		return context.WithCancel(ctx)
	}
	return withStatementTimeout(ctx)
}
