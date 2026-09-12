// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoad_FileNotFound(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if cfg == nil {
		t.Fatal("expected empty config, got nil")
	}
}

func TestLoad_ValidFile(t *testing.T) {
	f, err := os.CreateTemp("", "beacon-config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	_, _ = f.WriteString(`
iatas:
  YVR:
    name: Vancouver
    lat: 49.1967
    lng: -123.1815
regions:
  - slug: bc
    name: British Columbia
    display_order: 1
    iatas: [YVR]
`)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.IATAs["YVR"]; !ok {
		t.Error("expected YVR in IATAs")
	}
	if len(cfg.Regions) != 1 {
		t.Errorf("expected 1 region, got %d", len(cfg.Regions))
	}
	if cfg.Regions[0].Slug != "bc" {
		t.Errorf("expected slug bc, got %s", cfg.Regions[0].Slug)
	}
}

func TestLoad_IngestFilters(t *testing.T) {
	f, err := os.CreateTemp("", "beacon-config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	_, _ = f.WriteString(`
ingest:
  allow_countries: [GB]
  allow_continents: [EU]
  allow_iatas: [BHX, BOH]
  allow_observer_pubkeys:
    - "1155ABBF9B01168031BD70A1E7691AA345747604A5F2197182D03782CD34771A"
    - "15C00C4887505D9F8563BDA0F94770504921980CF131073AD425A9EB6733CB8D"
`)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ingest.AllowIatas) != 2 || cfg.Ingest.AllowIatas[0] != "BHX" {
		t.Errorf("unexpected allow_iatas: %v", cfg.Ingest.AllowIatas)
	}
	if len(cfg.Ingest.AllowObserverPubkeys) != 2 {
		t.Errorf("expected 2 allow_observer_pubkeys, got %d", len(cfg.Ingest.AllowObserverPubkeys))
	}
	if len(cfg.Ingest.AllowCountries) != 1 || cfg.Ingest.AllowCountries[0] != "GB" {
		t.Errorf("unexpected allow_countries: %v", cfg.Ingest.AllowCountries)
	}
	if len(cfg.Ingest.AllowContinents) != 1 || cfg.Ingest.AllowContinents[0] != "EU" {
		t.Errorf("unexpected allow_continents: %v", cfg.Ingest.AllowContinents)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "beacon-config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	_, _ = f.WriteString(`not: valid: yaml: [`)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestResolve_Defaults(t *testing.T) {
	r := Resolve(&Config{})
	if r.TelemetryResolution != time.Hour {
		t.Errorf("expected TelemetryResolution 1h, got %v", r.TelemetryResolution)
	}
	if r.TelemetryRetention != 28*24*time.Hour {
		t.Errorf("expected TelemetryRetention 672h, got %v", r.TelemetryRetention)
	}
	if r.PacketRetention != 30*24*time.Hour {
		t.Errorf("expected PacketRetention 720h, got %v", r.PacketRetention)
	}
	if r.WebSocket.MaxConnections != 1000 {
		t.Errorf("expected MaxConnections 1000, got %d", r.WebSocket.MaxConnections)
	}
	if r.WebSocket.MaxConnectionsPerIP != 50 {
		t.Errorf("expected MaxConnectionsPerIP 50, got %d", r.WebSocket.MaxConnectionsPerIP)
	}
	if r.WebSocket.HandshakesPerMinute != 5 {
		t.Errorf("expected HandshakesPerMinute 5, got %d", r.WebSocket.HandshakesPerMinute)
	}
	if r.ViewRefreshInterval != time.Hour {
		t.Errorf("expected ViewRefreshInterval 1h, got %v", r.ViewRefreshInterval)
	}
	if r.ReconfirmInterval != time.Hour {
		t.Errorf("expected ReconfirmInterval 1h, got %v", r.ReconfirmInterval)
	}
	if r.CleanupInterval != time.Hour {
		t.Errorf("expected CleanupInterval 1h, got %v", r.CleanupInterval)
	}
	if r.ClockDriftThreshold != 5*time.Minute {
		t.Errorf("expected ClockDriftThreshold 5m, got %v", r.ClockDriftThreshold)
	}
	if r.NodeStaleThreshold != 24*time.Hour {
		t.Errorf("expected NodeStaleThreshold 24h, got %v", r.NodeStaleThreshold)
	}
	if r.NodeDeleteAfter != 30*24*time.Hour {
		t.Errorf("expected NodeDeleteAfter 720h (same default as PacketRetention), got %v", r.NodeDeleteAfter)
	}
}

func TestResolve_ExplicitValues(t *testing.T) {
	cfg := &Config{}
	cfg.Telemetry.Resolution.Duration = 30 * time.Minute
	cfg.Telemetry.Retention.Duration = 14 * 24 * time.Hour
	cfg.Packets.Retention.Duration = 7 * 24 * time.Hour
	cfg.WebSocket.MaxConnections = 200
	cfg.WebSocket.MaxConnectionsPerIP = 10
	cfg.WebSocket.HandshakesPerMinute = 7
	cfg.WebSocket.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	cfg.Background.ViewRefresh.Duration = 2 * time.Hour
	cfg.Background.Reconfirm.Duration = 3 * time.Hour
	cfg.Background.Cleanup.Duration = 4 * time.Hour

	r := Resolve(cfg)
	if r.TelemetryResolution != 30*time.Minute {
		t.Errorf("expected 30m, got %v", r.TelemetryResolution)
	}
	if r.WebSocket.MaxConnections != 200 {
		t.Errorf("expected 200, got %d", r.WebSocket.MaxConnections)
	}
	if r.WebSocket.MaxConnectionsPerIP != 10 {
		t.Errorf("expected 10, got %d", r.WebSocket.MaxConnectionsPerIP)
	}
	if r.WebSocket.HandshakesPerMinute != 7 {
		t.Errorf("expected 7, got %d", r.WebSocket.HandshakesPerMinute)
	}
	if len(r.WebSocket.TrustedProxyCIDRs) != 1 || r.WebSocket.TrustedProxyCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("unexpected trusted proxies: %v", r.WebSocket.TrustedProxyCIDRs)
	}
	if r.ViewRefreshInterval != 2*time.Hour {
		t.Errorf("expected 2h, got %v", r.ViewRefreshInterval)
	}
}

func TestResolvedConfig_String(t *testing.T) {
	r := Resolve(&Config{})
	s := r.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
	if !strings.Contains(s, "telemetryResolution=") {
		t.Error("expected telemetryResolution in string")
	}
	if !strings.Contains(s, "wsMaxConnsPerIP=") {
		t.Error("expected wsMaxConnsPerIP in string")
	}
}

func TestResolve_RouteDefaults(t *testing.T) {
	r := Resolve(&Config{})
	if r.RouteRetention != 336*time.Hour {
		t.Errorf("RouteRetention = %s, want 336h", r.RouteRetention)
	}
	if r.RouteGrace != 168*time.Hour {
		t.Errorf("RouteGrace = %s, want 168h", r.RouteGrace)
	}
	if r.RouteMinObservations != 3 {
		t.Errorf("RouteMinObservations = %d, want 3", r.RouteMinObservations)
	}
}
