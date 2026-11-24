// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicsource

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type LiveBatch struct {
	Generation int64
	Next       string
	Outcomes   []Outcome
	CaughtUp   bool
}
type LiveHTTPSource struct {
	endpoint, token string
	client          *http.Client
}

func NewLiveHTTPSource(endpoint, token string) (*LiveHTTPSource, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "/internal/ingest/public/entries" || u.RawQuery != "" || u.Fragment != "" || len(token) < 32 {
		return nil, ErrContract
	}
	return &LiveHTTPSource{endpoint: endpoint, token: token, client: &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func streamParts(id string) ([2]uint64, bool) {
	var out [2]uint64
	parts := strings.Split(id, "-")
	if len(parts) != 2 {
		return out, false
	}
	for i, part := range parts {
		if part == "" || len(part) > 20 {
			return out, false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return out, false
			}
		}
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
func compareStream(a, b string) (int, bool) {
	x, ok := streamParts(a)
	if !ok {
		return 0, false
	}
	y, ok := streamParts(b)
	if !ok {
		return 0, false
	}
	for i := range x {
		if x[i] < y[i] {
			return -1, true
		}
		if x[i] > y[i] {
			return 1, true
		}
	}
	return 0, true
}

func (s *LiveHTTPSource) ReadBatch(ctx context.Context, after string) (LiveBatch, error) {
	if _, ok := streamParts(after); !ok {
		return LiveBatch{}, ErrCursor
	}
	u, _ := url.Parse(s.endpoint)
	query := u.Query()
	query.Set("after", after)
	query.Set("limit", "500")
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return LiveBatch{}, ErrContract
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	res, err := s.client.Do(req)
	if err != nil {
		return LiveBatch{}, errors.New("authorized live source unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return LiveBatch{}, ErrNotReady
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return LiveBatch{}, ErrContract
	}
	return decodeLiveBatch(raw, after)
}

func decodeLiveBatch(raw []byte, after string) (LiveBatch, error) {
	var wire struct {
		Generation int64  `json:"generation"`
		Next       string `json:"nextCursor"`
		HasMore    *bool  `json:"hasMore"`
		Entries    []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"entries"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.Generation <= 0 || len(wire.Entries) > 500 {
		return LiveBatch{}, ErrContract
	}
	if order, ok := compareStream(wire.Next, after); !ok || order < 0 {
		return LiveBatch{}, ErrContract
	}
	order, _ := compareStream(wire.Next, after)
	if wire.HasMore != nil && *wire.HasMore && order == 0 {
		return LiveBatch{}, ErrContract
	}
	out := LiveBatch{Generation: wire.Generation, Next: wire.Next, Outcomes: []Outcome{}, CaughtUp: wire.HasMore != nil && !*wire.HasMore || wire.HasMore == nil && order == 0}
	previous := after
	for _, entry := range wire.Entries {
		if order, ok := compareStream(entry.ID, previous); !ok || order <= 0 {
			return LiveBatch{}, ErrContract
		}
		if order, ok := compareStream(entry.ID, wire.Next); !ok || order > 0 {
			return LiveBatch{}, ErrContract
		}
		row, err := decodeLiveEntry(entry.Value)
		if err != nil {
			return LiveBatch{}, ErrContract
		}
		out.Outcomes = append(out.Outcomes, verify(row))
		previous = entry.ID
	}
	return out, nil
}

func decodeLiveEntry(raw string) (sourceRow, error) {
	var wire struct {
		Version int    `json:"v"`
		Kind    string `json:"k"`
		ID      string `json:"o"`
		Private int    `json:"ip"`
		Visible int    `json:"vo"`
		Input   struct {
			Time       string   `json:"time"`
			Network    string   `json:"network"`
			IATA       *string  `json:"iata"`
			UID        *string  `json:"packetUid"`
			Version    *string  `json:"identityVersion"`
			Provenance *string  `json:"identityProvenance"`
			Alias      string   `json:"packetHash"`
			Type       int32    `json:"packetType"`
			Topic      string   `json:"topic"`
			Receiver   *string  `json:"rxNodeId"`
			Source     *string  `json:"srcNodeId"`
			Paths      []string `json:"pathHashes"`
			PathSize   *int32   `json:"pathHashSizeBytes"`
			RSSI, SNR  *float64
			Raw        *string `json:"rawHex"`
		} `json:"d"`
	}
	if json.Unmarshal([]byte(raw), &wire) != nil || wire.Version != 1 || wire.Kind != "p" || wire.Private != 0 || wire.Visible != 1 || wire.Input.Network == "" {
		return sourceRow{}, ErrContract
	}
	id, err := uuid.Parse(wire.ID)
	if err != nil || id == uuid.Nil {
		return sourceRow{}, ErrContract
	}
	if wire.Input.Network != "ukmesh" {
		return sourceRow{id: id, network: wire.Input.Network, status: string(OutsideNetwork)}, nil
	}
	at, err := time.Parse(time.RFC3339Nano, wire.Input.Time)
	if err != nil {
		return sourceRow{}, ErrContract
	}
	r := sourceRow{id: id, at: at, network: wire.Input.Network, iata: wire.Input.IATA, version: wire.Input.Version, provenance: wire.Input.Provenance,
		alias: wire.Input.Alias, packetType: wire.Input.Type, topic: wire.Input.Topic, receiver: wire.Input.Receiver, source: wire.Input.Source,
		paths: wire.Input.Paths, pathSize: wire.Input.PathSize, rssi: wire.Input.RSSI, snr: wire.Input.SNR, raw: wire.Input.Raw, status: "candidate-for-decode"}
	if wire.Input.UID != nil {
		r.uid, err = hex.DecodeString(*wire.Input.UID)
		if err != nil {
			r.status = string(InvalidUID)
		}
	}
	return r, nil
}
