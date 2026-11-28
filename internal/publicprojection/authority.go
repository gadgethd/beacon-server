// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package publicprojection owns the opt-in UKMesh public message projection.
// It never reads Beacon's saved channel groups or enables standard ingest.
package publicprojection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var ErrUnavailable = errors.New("public projection authority unavailable")

type Channel struct {
	ID, Name, KeyFingerprint string
	key                      [16]byte
	hash                     byte
}

type Policy struct {
	Generation               int64
	RegistryVersion, Network string
	Channels                 []Channel
}

func (p Policy) Epoch() string {
	return p.RegistryVersion + ":" + p.Network + ":" + formatGeneration(p.Generation)
}

type Authority interface {
	Current(context.Context) (Policy, error)
}

type HTTPAuthority struct {
	endpoint, token string
	client          *http.Client
}

func NewHTTPAuthority(endpoint, token string) (*HTTPAuthority, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Path != "/internal/beacon/authority" || u.RawQuery != "" || u.Fragment != "" || len(token) < 32 {
		return nil, ErrUnavailable
	}
	return &HTTPAuthority{endpoint: endpoint, token: token, client: &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (a *HTTPAuthority) Current(ctx context.Context) (Policy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint, nil)
	if err != nil {
		return Policy{}, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	res, err := a.client.Do(req)
	if err != nil {
		return Policy{}, ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Policy{}, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return Policy{}, ErrUnavailable
	}
	return decodePolicy(raw)
}

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var registryID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

func decodePolicy(raw []byte) (Policy, error) {
	var wire struct {
		Version         int    `json:"version"`
		Generation      int64  `json:"generation"`
		RegistryVersion string `json:"registryVersion"`
		Network         string `json:"network"`
		Channels        []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Fingerprint string `json:"keyFingerprint"`
			Secret      string `json:"secretHex"`
		} `json:"channels"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.Version != 1 || wire.Generation <= 0 || wire.Generation > 9007199254740991 ||
		wire.Network != "ukmesh" || !hexDigest.MatchString(wire.RegistryVersion) || len(wire.Channels) > 256 {
		return Policy{}, ErrUnavailable
	}
	policy := Policy{Generation: wire.Generation, RegistryVersion: wire.RegistryVersion, Network: wire.Network}
	ids, fingerprints := map[string]bool{}, map[string]bool{}
	for _, ch := range wire.Channels {
		key, err := hex.DecodeString(ch.Secret)
		if err != nil || len(key) != 16 || !registryID.MatchString(ch.ID) || len(ch.Name) == 0 || len(ch.Name) > 256 ||
			!hexDigest.MatchString(ch.Fingerprint) || ids[ch.ID] || fingerprints[ch.Fingerprint] {
			return Policy{}, ErrUnavailable
		}
		fingerprint := sha256.Sum256(key)
		if hex.EncodeToString(fingerprint[:]) != ch.Fingerprint {
			return Policy{}, ErrUnavailable
		}
		entry := Channel{ID: ch.ID, Name: ch.Name, KeyFingerprint: ch.Fingerprint, hash: fingerprint[0]}
		copy(entry.key[:], key)
		policy.Channels = append(policy.Channels, entry)
		ids[ch.ID], fingerprints[ch.Fingerprint] = true, true
	}
	return policy, nil
}
