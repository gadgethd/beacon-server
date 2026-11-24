// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicprojection

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/api"
	"github.com/MeshCore-Beacon/beacon-server/internal/ws"
	"github.com/MeshCore-Beacon/beacon-server/internal/wsticket"
	"github.com/jackc/pgx/v5"
)

// Geography is the existing Beacon geographic read owner. RF scopes are not
// inferred from this catalog. Saved channel groups are deliberately absent.
type Geography interface {
	ws.RegionReader
	ListIATAs(context.Context) ([]api.IATA, error)
	ListRegions(context.Context) ([]api.Region, error)
}

var errBadRequest = errors.New("invalid public message request")
var errScopeUnready = errors.New("authoritative packet RF scope is unavailable")

// Handler returns only the private listener's native Beacon paths. The edge
// owns same-origin routing and removes /beacon; no standard route is replaced.
func (s *Service) Handler(geography Geography, origins []string) http.Handler {
	if geography == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "public geography unavailable", http.StatusServiceUnavailable)
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, func(p Policy) (any, error) {
			return struct {
				Version         int    `json:"version"`
				Generation      int64  `json:"generation"`
				RegistryVersion string `json:"registryVersion"`
			}{1, p.Generation, p.RegistryVersion}, nil
		})
	})
	mux.HandleFunc("GET /api/v1/iatas", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, func(Policy) (any, error) {
			if geography == nil {
				return nil, ErrUnavailable
			}
			return geography.ListIATAs(r.Context())
		})
	})
	mux.HandleFunc("GET /api/v1/regions", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, func(Policy) (any, error) {
			if geography == nil {
				return nil, ErrUnavailable
			}
			return geography.ListRegions(r.Context())
		})
	})
	mux.HandleFunc("GET /api/v1/regions/{regionID}", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, func(Policy) (any, error) {
			id, err := strconv.ParseInt(r.PathValue("regionID"), 10, 32)
			if err != nil || id <= 0 {
				return nil, errBadRequest
			}
			if geography == nil {
				return nil, ErrUnavailable
			}
			return geography.GetRegion(r.Context(), int32(id))
		})
	})
	mux.HandleFunc("GET /api/v1/channels", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, func(p Policy) (any, error) {
			limit, cursor, err := listParams(r)
			if err != nil {
				return nil, err
			}
			iatas, err := resolveIATAs(r, geography)
			if err != nil {
				return nil, err
			}
			var precise *api.ChannelCursor
			if raw := r.URL.Query().Get("pageCursor"); raw != "" {
				if cursor > 0 {
					return nil, errBadRequest
				}
				precise, err = api.ParseChannelCursor(raw)
				if err != nil {
					return nil, errBadRequest
				}
			}
			hash := strings.ToLower(r.URL.Query().Get("hash"))
			if hash != "" {
				decoded, err := hex.DecodeString(hash)
				if err != nil || len(decoded) != 1 {
					return nil, errBadRequest
				}
			}
			if q := r.URL.Query(); q.Has("keyKnown") {
				switch q.Get("keyKnown") {
				case "false":
					return ChannelPage{Page: api.Page[ChannelSummary]{Items: []ChannelSummary{}}}, nil
				case "true":
				default:
					return nil, errBadRequest
				}
			}
			return s.store.channels(r.Context(), p, limit, cursor, precise, iatas, hash)
		})
	})
	mux.HandleFunc("GET /api/v1/channels/{channelID}", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, func(p Policy) (any, error) {
			id, err := channelID(r)
			if err != nil {
				return nil, err
			}
			return s.store.channel(r.Context(), p, id)
		})
	})
	mux.HandleFunc("GET /api/v1/channels/{channelID}/messages", func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, func(p Policy) (any, error) {
			id, err := channelID(r)
			if err != nil {
				return nil, err
			}
			limit, cursor, err := listParams(r)
			if err != nil {
				return nil, err
			}
			if r.URL.Query().Get("scope") != "" {
				return nil, errScopeUnready
			}
			iatas, err := resolveIATAs(r, geography)
			if err != nil {
				return nil, err
			}
			if _, err = s.store.channel(r.Context(), p, id); err != nil {
				return nil, err
			}
			var since int64
			if raw := r.URL.Query().Get("since"); raw != "" {
				since, err = strconv.ParseInt(raw, 10, 64)
				if err != nil || since < 0 {
					return nil, errBadRequest
				}
			}
			return s.store.history(r.Context(), p, id, cursor, limit, iatas, since)
		})
	})
	mux.Handle("GET /ws", ws.NewTransport(s.hub, geography, ws.Limits{MaxConnections: 64, MaxConnsPerIP: 8, MaxConnectsPerMinute: 10,
		SendBytesPerSecond: 256 << 10, SendBurstBytes: 512 << 10}, ws.Access{AllowedOrigins: origins, RequireOrigin: true, Tickets: wsticket.New(), Authority: s.epoch}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			mux.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Service) respond(w http.ResponseWriter, r *http.Request, load func(Policy) (any, error)) {
	w.Header().Set("Cache-Control", "no-store")
	policy, epoch, err := s.authorized(r.Context())
	var value any
	if err == nil {
		value, err = load(policy)
	}
	var body []byte
	if err == nil {
		body, err = json.Marshal(value)
	}
	if err == nil {
		_, after, fenceErr := s.authorized(r.Context())
		if fenceErr != nil || after != epoch {
			err = ErrUnavailable
		}
	}
	if err != nil {
		code, status := "service_unavailable", http.StatusServiceUnavailable
		if errors.Is(err, errBadRequest) {
			code, status = "invalid_request", http.StatusBadRequest
		}
		if errors.Is(err, pgx.ErrNoRows) {
			code, status = "not_found", http.StatusNotFound
		}
		if errors.Is(err, errScopeUnready) {
			code = "scope_unavailable"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func channelID(r *http.Request) (int32, error) {
	id, err := strconv.ParseInt(r.PathValue("channelID"), 10, 32)
	if err != nil || id <= 0 {
		return 0, errBadRequest
	}
	return int32(id), nil
}
func listParams(r *http.Request) (int32, int64, error) {
	limit := int64(50)
	var cursor int64
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || limit < 1 {
			return 0, 0, errBadRequest
		}
		if limit > 200 {
			limit = 200
		}
	}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || cursor < 0 {
			return 0, 0, errBadRequest
		}
	}
	return int32(limit), cursor, nil
}

func resolveIATAs(r *http.Request, geo Geography) ([]string, error) {
	q := r.URL.Query()
	values := q.Get("iatas")
	if values == "" {
		values = q.Get("iata")
	}
	set := map[string]bool{}
	if values != "" {
		for _, value := range strings.Split(values, ",") {
			value = strings.ToUpper(strings.TrimSpace(value))
			if len(value) != 3 {
				return nil, errBadRequest
			}
			for _, c := range value {
				if c < 'A' || c > 'Z' {
					return nil, errBadRequest
				}
			}
			set[value] = true
		}
	}
	if slug := q.Get("region"); slug != "" {
		if geo == nil {
			return nil, ErrUnavailable
		}
		region, err := geo.GetRegionBySlug(r.Context(), slug)
		if err != nil {
			return nil, err
		}
		for _, value := range region.IATAs {
			set[value] = true
		}
	}
	if raw := q.Get("regionId"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || id <= 0 {
			return nil, errBadRequest
		}
		if geo == nil {
			return nil, ErrUnavailable
		}
		region, err := geo.GetRegion(r.Context(), int32(id))
		if err != nil {
			return nil, err
		}
		for _, value := range region.IATAs {
			set[value] = true
		}
	}
	// A known empty region must match no observations, never all geography.
	if len(set) == 0 && (q.Get("region") != "" || q.Get("regionId") != "") {
		return []string{"!empty-region"}, nil
	}
	out := []string{}
	for value := range set {
		out = append(out, value)
	}
	if len(out) > 64 {
		return nil, errBadRequest
	}
	return out, nil
}
