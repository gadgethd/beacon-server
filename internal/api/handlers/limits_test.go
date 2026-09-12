// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestParseLimit(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		want      int32
		wantError bool
	}{
		{name: "missing", want: 20},
		{name: "minimum", query: "?limit=1", want: 1},
		{name: "maximum", query: "?limit=100", want: 100},
		{name: "clamped", query: "?limit=101", want: 100},
		{name: "int32 boundary", query: "?limit=2147483647", want: 100},
		{name: "zero", query: "?limit=0", wantError: true},
		{name: "negative", query: "?limit=-1", wantError: true},
		{name: "empty", query: "?limit=", wantError: true},
		{name: "non numeric", query: "?limit=abc", wantError: true},
		{name: "duplicate", query: "?limit=1&limit=2", wantError: true},
		{name: "leading plus", query: "?limit=%2B1", wantError: true},
		{name: "leading zero", query: "?limit=01", wantError: true},
		{name: "int64 overflow", query: "?limit=9223372036854775808", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/items"+tt.query, nil)
			got, err := parseLimit(req)
			if tt.wantError {
				if err == nil {
					t.Fatalf("parseLimit() error = nil, want error (got limit %d)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLimit() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseLimit() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAllPaginatedRoutesUseBoundedLimit(t *testing.T) {
	routes := []struct {
		name    string
		pattern string
		path    string
		handler func(api.Reader) http.HandlerFunc
	}{
		{name: "channels", pattern: "/channels", path: "/channels", handler: listChannels},
		{name: "channel messages", pattern: "/channels/{channelID}/messages", path: "/channels/1/messages", handler: listChannelMessages},
		{name: "messages", pattern: "/messages", path: "/messages", handler: listMessages},
		{name: "message backfill", pattern: "/messages/backfill", path: "/messages/backfill?afterId=1", handler: listMessagesBackfill},
		{name: "nodes", pattern: "/nodes", path: "/nodes", handler: listNodes},
		{name: "node observations", pattern: "/nodes/{nodeId}/observations", path: "/nodes/00000000-0000-0000-0000-000000000001/observations", handler: listNodeObservations},
		{name: "observers", pattern: "/observers", path: "/observers", handler: listObservers},
		{name: "observer adverts", pattern: "/observers/{observerId}/adverts", path: "/observers/00000000-0000-0000-0000-000000000001/adverts", handler: listObserverAdverts},
		{name: "packets", pattern: "/packets", path: "/packets", handler: listPackets},
		{name: "packet backfill", pattern: "/packets/backfill", path: "/packets/backfill?afterObservationId=1", handler: listPacketsBackfill},
		{name: "routes", pattern: "/routes", path: "/routes", handler: listKnownRoutes},
		{name: "top nodes", pattern: "/stats/top-nodes", path: "/stats/top-nodes", handler: getStatsTopNodes},
		{name: "top observers", pattern: "/stats/top-observers", path: "/stats/top-observers", handler: getStatsTopObservers},
		{name: "top advertisers", pattern: "/stats/top-advertisers", path: "/stats/top-advertisers", handler: getStatsTopAdvertisers},
		{name: "clock drift", pattern: "/stats/clock-drift", path: "/stats/clock-drift", handler: getStatsClockDrift},
		{name: "top talkers", pattern: "/stats/top-talkers", path: "/stats/top-talkers", handler: getStatsTopTalkers},
		{name: "traces", pattern: "/traces", path: "/traces", handler: listTraceTags},
	}

	inputs := []struct {
		name       string
		value      string
		wantStatus int
		wantLimit  int32
	}{
		{name: "default", wantStatus: http.StatusOK, wantLimit: 20},
		{name: "maximum", value: "100", wantStatus: http.StatusOK, wantLimit: 100},
		{name: "clamped", value: "2147483647", wantStatus: http.StatusOK, wantLimit: 100},
		{name: "zero", value: "0", wantStatus: http.StatusBadRequest},
		{name: "negative", value: "-1", wantStatus: http.StatusBadRequest},
		{name: "invalid", value: "abc", wantStatus: http.StatusBadRequest},
	}

	for _, route := range routes {
		for _, input := range inputs {
			t.Run(route.name+"/"+input.name, func(t *testing.T) {
				captured := int32(-1)
				reader := paginationStub(&captured)
				router := chi.NewRouter()
				router.Get(route.pattern, route.handler(reader))

				path := route.path
				if input.value != "" {
					separator := "?"
					if strings.Contains(path, "?") {
						separator = "&"
					}
					path += separator + "limit=" + input.value
				}
				req := httptest.NewRequest(http.MethodGet, path, nil)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				if rec.Code != input.wantStatus {
					t.Fatalf("status = %d, want %d; body=%s", rec.Code, input.wantStatus, rec.Body.String())
				}
				if input.wantStatus == http.StatusOK && captured != input.wantLimit {
					t.Errorf("store limit = %d, want %d", captured, input.wantLimit)
				}
				if input.wantStatus != http.StatusOK && captured != -1 {
					t.Errorf("reader called with limit %d for rejected request", captured)
				}
			})
		}
	}
}

func paginationStub(captured *int32) stubReader {
	record := func(limit int32) { *captured = limit }
	return stubReader{
		listChannels: func(_ context.Context, limit int32, _ []byte, _ []string, _ int64) (api.Page[api.ChannelSummary], error) {
			record(limit)
			return api.Page[api.ChannelSummary]{}, nil
		},
		listChannelMessages: func(_ context.Context, _ *int32, _ time.Time, limit int32, _ []string, _ string, _ int64) (api.Page[api.ChannelMessage], error) {
			record(limit)
			return api.Page[api.ChannelMessage]{}, nil
		},
		listMessagesAfterID: func(_ context.Context, _ int64, _ []string, _ string, limit int32) ([]api.ChannelMessage, error) {
			record(limit)
			return nil, nil
		},
		listObservers: func(_ context.Context, _ []string, _, _, _, _, _ string, _ int64, limit int32) (api.Page[api.ObserverSummary], error) {
			record(limit)
			return api.Page[api.ObserverSummary]{}, nil
		},
		listObserverAdverts: func(_ context.Context, _ uuid.UUID, _ int64, limit int32) (api.Page[api.AdvertObservation], error) {
			record(limit)
			return api.Page[api.AdvertObservation]{}, nil
		},
		listNodes: func(_ context.Context, _ int16, _ []string, _, _ *bool, _ []byte, _, _, _ string, _ int64, limit int32, _ bool) (api.Page[api.NodeSummary], error) {
			record(limit)
			return api.Page[api.NodeSummary]{}, nil
		},
		listNodeObservations: func(_ context.Context, _ uuid.UUID, _ int64, limit int32) (api.Page[api.PacketObservationSummary], error) {
			record(limit)
			return api.Page[api.PacketObservationSummary]{}, nil
		},
		listPackets: func(_ context.Context, _, _ []int16, _, _ []string, _, _ time.Time, _ int64, limit int32) (api.Page[api.PacketSummary], error) {
			record(limit)
			return api.Page[api.PacketSummary]{}, nil
		},
		listPacketsAfterID: func(_ context.Context, _ int64, _, _ int16, _ []string, _ string, limit int32) ([]api.PacketSummary, error) {
			record(limit)
			return nil, nil
		},
		getStatsTopNodes: func(_ context.Context, _ []string, limit int32) ([]api.TopNode, error) {
			record(limit)
			return nil, nil
		},
		getStatsTopObservers: func(_ context.Context, _ []string, _ time.Time, limit int32) ([]api.TopObserver, error) {
			record(limit)
			return nil, nil
		},
		getStatsTopAdvertisers: func(_ context.Context, _ []string, _ time.Time, limit int32) ([]api.TopAdvertiser, error) {
			record(limit)
			return nil, nil
		},
		getStatsClockDrift: func(_ context.Context, _ []string, limit int32) ([]api.ClockDriftEntry, error) {
			record(limit)
			return nil, nil
		},
		getStatsTopTalkers: func(_ context.Context, _ []string, _ time.Time, limit int32) ([]api.TopTalker, error) {
			record(limit)
			return nil, nil
		},
		listTraceTags: func(_ context.Context, _ []string, _, _ string, _, _, _ time.Time, limit int32) ([]api.TraceTagSummary, error) {
			record(limit)
			return nil, nil
		},
		listKnownRoutes: func(_ context.Context, _ string, _ int32, _ time.Time, limit int32) ([]api.KnownRoute, error) {
			record(limit)
			return nil, nil
		},
	}
}
