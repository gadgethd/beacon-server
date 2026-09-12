// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "github.com/google/uuid"

// ObserverSummary is the internal observer read model used in list responses.
type ObserverSummary struct {
	ID           uuid.UUID `json:"id"`
	DisplayName  *string   `json:"displayName,omitempty"`  // friendly name from /status messages
	ObserverType *string   `json:"observerType,omitempty"` // e.g. "meshcoretomqtt", "meshcoreha"
	IATA         string    `json:"iata"`                   // most recently heard IATA
	Status       string    `json:"status"`                 // "online" or "offline" derived from last_status_at
	Radio        *string   `json:"radio,omitempty"`        // friendly radio param string: freqMhz,BwKhz,SF e.g. "910.525,62.5,7"
	Scopes       []string  `json:"scopes,omitempty"`       // list of observer forwarded scopes matched to config
}

// ObserverBroker represents a single MQTT broker an observer has been seen on,
// including timestamps for diagnosing partial outages — e.g. distinguishing
// "observer is down" from "one broker stopped delivering for this observer".
type ObserverBroker struct {
	Name         string `json:"name"`         // broker name e.g. "mqtt1"
	LastSeenAt   int64  `json:"lastSeenAt"`   // epoch ms, last time observer was seen on this broker
	LastPacketAt int64  `json:"lastPacketAt"` // epoch ms, last packet received via this broker; 0 if none
}

// Observer is the internal full observer read model. It may contain raw status
// metadata; use ToPublicObserver before serializing it in a public response.
type Observer struct {
	ObserverSummary
	PublicKey        string           `json:"publicKey"` // hex-encoded public key
	SoftwareVersion  *string          `json:"softwareVersion,omitempty"`
	HardwareModel    *string          `json:"hardwareModel,omitempty"`
	FirmwareVersion  *string          `json:"firmwareVersion,omitempty"`
	FirmwareBuild    *string          `json:"firmwareBuild,omitempty"`
	RadioFreqMHz     *float32         `json:"radioFreqMhz,omitempty"` // MHz e.g. 910.525
	RadioSF          *int16           `json:"radioSf,omitempty"`      // LoRa spreading factor
	RadioBWKHz       *float32         `json:"radioBwKhz,omitempty"`   // bandwidth in kHz
	RadioCR          *int16           `json:"radioCr,omitempty"`      // coding rate denominator
	BatteryLevel     *float32         `json:"batteryLevel,omitempty"` // volts, nil if mains powered
	UptimeSeconds    *int64           `json:"uptimeSeconds,omitempty"`
	StatusMetadata   any              `json:"statusMetadata,omitempty"` // raw /status JSON payload
	LastStatusAt     *int64           `json:"lastStatusAt,omitempty"`   // epoch ms
	FirstSeen        int64            `json:"firstSeen"`                // epoch ms
	LastSeen         int64            `json:"lastSeen"`                 // epoch ms
	ObservationCount int64            `json:"observationCount"`
	Brokers          []ObserverBroker `json:"brokers"` // broker names this observer has been seen on
}

// PublicObserverBroker is the public representation of an observer's broker
// membership history.
type PublicObserverBroker struct {
	Name         string `json:"name"`
	LastSeenAt   int64  `json:"lastSeenAt"`   // epoch ms
	LastPacketAt int64  `json:"lastPacketAt"` // epoch ms, 0 if none
}

// PublicObserverSummary is the allowlisted observer representation returned by
// public list endpoints.
type PublicObserverSummary struct {
	ID           uuid.UUID `json:"id"`
	DisplayName  *string   `json:"displayName,omitempty"`
	ObserverType *string   `json:"observerType,omitempty"`
	IATA         string    `json:"iata"`
	Status       string    `json:"status"`
	Radio        *string   `json:"radio,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// PublicObserver is the allowlisted observer detail response. StatusMetadata
// is deliberately absent because it contains the raw /status JSON payload.
type PublicObserver struct {
	PublicObserverSummary
	PublicKey        string                 `json:"publicKey"`
	SoftwareVersion  *string                `json:"softwareVersion,omitempty"`
	HardwareModel    *string                `json:"hardwareModel,omitempty"`
	FirmwareVersion  *string                `json:"firmwareVersion,omitempty"`
	FirmwareBuild    *string                `json:"firmwareBuild,omitempty"`
	RadioFreqMHz     *float32               `json:"radioFreqMhz,omitempty"`
	RadioSF          *int16                 `json:"radioSf,omitempty"`
	RadioBWKHz       *float32               `json:"radioBwKhz,omitempty"`
	RadioCR          *int16                 `json:"radioCr,omitempty"`
	BatteryLevel     *float32               `json:"batteryLevel,omitempty"`
	UptimeSeconds    *int64                 `json:"uptimeSeconds,omitempty"`
	LastStatusAt     *int64                 `json:"lastStatusAt,omitempty"`
	FirstSeen        int64                  `json:"firstSeen"`
	LastSeen         int64                  `json:"lastSeen"`
	ObservationCount int64                  `json:"observationCount"`
	Brokers          []PublicObserverBroker `json:"brokers"`
}

// ToPublicObserverBroker maps an internal broker membership to its public DTO.
func ToPublicObserverBroker(broker ObserverBroker) PublicObserverBroker {
	return PublicObserverBroker{
		Name:         broker.Name,
		LastSeenAt:   broker.LastSeenAt,
		LastPacketAt: broker.LastPacketAt,
	}
}

// ToPublicObserverSummary maps an internal observer summary to its public DTO.
func ToPublicObserverSummary(observer ObserverSummary) PublicObserverSummary {
	public := PublicObserverSummary{
		ID:           observer.ID,
		DisplayName:  observer.DisplayName,
		ObserverType: observer.ObserverType,
		IATA:         observer.IATA,
		Status:       observer.Status,
		Radio:        observer.Radio,
	}
	if observer.Scopes != nil {
		public.Scopes = append([]string(nil), observer.Scopes...)
	}
	return public
}

// ToPublicObserverPage maps an observer list page to an allowlisted public page.
func ToPublicObserverPage(page Page[ObserverSummary]) Page[PublicObserverSummary] {
	public := Page[PublicObserverSummary]{
		NextCursor: page.NextCursor,
		HasMore:    page.HasMore,
	}
	if page.Items != nil {
		public.Items = make([]PublicObserverSummary, len(page.Items))
		for i, observer := range page.Items {
			public.Items[i] = ToPublicObserverSummary(observer)
		}
	}
	return public
}

// ToPublicObserver maps an internal full observer read model to its public DTO.
func ToPublicObserver(observer *Observer) *PublicObserver {
	if observer == nil {
		return nil
	}
	public := &PublicObserver{
		PublicObserverSummary: ToPublicObserverSummary(observer.ObserverSummary),
		PublicKey:             observer.PublicKey,
		SoftwareVersion:       observer.SoftwareVersion,
		HardwareModel:         observer.HardwareModel,
		FirmwareVersion:       observer.FirmwareVersion,
		FirmwareBuild:         observer.FirmwareBuild,
		RadioFreqMHz:          observer.RadioFreqMHz,
		RadioSF:               observer.RadioSF,
		RadioBWKHz:            observer.RadioBWKHz,
		RadioCR:               observer.RadioCR,
		BatteryLevel:          observer.BatteryLevel,
		UptimeSeconds:         observer.UptimeSeconds,
		LastStatusAt:          observer.LastStatusAt,
		FirstSeen:             observer.FirstSeen,
		LastSeen:              observer.LastSeen,
		ObservationCount:      observer.ObservationCount,
	}
	if observer.Brokers != nil {
		public.Brokers = make([]PublicObserverBroker, len(observer.Brokers))
		for i, broker := range observer.Brokers {
			public.Brokers[i] = ToPublicObserverBroker(broker)
		}
	}
	return public
}

// ObserverTelemetryPoint is a single telemetry snapshot for an observer.
type ObserverTelemetryPoint struct {
	T             int64    `json:"t"` // epoch ms
	BatteryMV     *int32   `json:"batteryMv,omitempty"`
	AirtimeTxPct  *float32 `json:"airtimeTxPct,omitempty"`
	AirtimeRxPct  *float32 `json:"airtimeRxPct,omitempty"`
	NoiseFloorDB  *float32 `json:"noiseFloorDb,omitempty"`
	UptimeSeconds *int64   `json:"uptimeSeconds,omitempty"`
	QueueLength   *int32   `json:"queueLength,omitempty"`
	ReceiveErrors *int32   `json:"receiveErrors,omitempty"`
}

// ObserverTelemetry is the full telemetry response for an observer.
// Range and interval reflect the query parameters used.
type ObserverTelemetry struct {
	Range    string                   `json:"range"`
	Interval string                   `json:"interval"`
	Points   []ObserverTelemetryPoint `json:"points"`
}
