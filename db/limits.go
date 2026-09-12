// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"time"
)

const (
	maxQueryLimit    int32 = 100
	statementTimeout       = 5 * time.Second
)

// clampQueryLimit is the store-layer backstop for callers that bypass the HTTP
// handlers. It keeps every paginated database read within the public API bound.
func clampQueryLimit(limit int32) int32 {
	if limit < 1 {
		return 1
	}
	if limit > maxQueryLimit {
		return maxQueryLimit
	}
	return limit
}

// withStatementTimeout gives pgx a per-query deadline so a slow pagination
// request cannot hold a database connection indefinitely.
func withStatementTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, statementTimeout)
}
