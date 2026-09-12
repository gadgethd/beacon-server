// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"
	"strconv"
)

const (
	defaultLimit int32 = 20
	maxLimit     int64 = 100
)

// parseLimit returns the bounded pagination limit supplied by the request.
// Missing limits use defaultLimit; explicit limits must be a single canonical,
// positive decimal integer. Values above maxLimit are safely clamped.
func parseLimit(r *http.Request) (int32, error) {
	values, ok := r.URL.Query()["limit"]
	if !ok {
		return defaultLimit, nil
	}
	if len(values) != 1 {
		return 0, errors.New("limit must be specified once")
	}

	limit, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || strconv.FormatInt(limit, 10) != values[0] {
		return 0, errors.New("limit must be an integer")
	}
	if limit <= 0 {
		return 0, errors.New("limit must be positive")
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return int32(limit), nil
}
