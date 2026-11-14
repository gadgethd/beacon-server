// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/hub"
	"github.com/meshcore-go/meshcore-go"
)

func TestMarkedAdvertsClearStoredAndLiveCoordinates(t *testing.T) {
	for _, withCoordinates := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "supplied"}[withCoordinates], func(t *testing.T) {
			w, db := newTestWorker()
			go w.hub.Run()
			client := w.hub.NewClient()
			defer w.hub.Remove(client)
			w.hub.AddScope(client, "redacted", hub.Scope{Events: []hub.EventType{hub.EventNodeUpdate, hub.EventObserverStatus}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			waitForSummarySubscriber(t, ctx, w.hub, client)
			data := []byte{meshcore.AdvertTypeRepeater | meshcore.AdvertNameMask}
			if withCoordinates {
				data[0] |= meshcore.AdvertLatLonMask
				data = binary.LittleEndian.AppendUint32(data, 45000000)
				data = binary.LittleEndian.AppendUint32(data, 75000000)
			}
			data = append(data, []byte("🚫 fixture")...)
			w.handlePayloadTypeSideEffects(ctx, buildAdvertPacketWithData(t, data, false), "LON", []byte{1}, RadioSettings{}, nil, nil, nil, 0, false, false)
			if db.upsertNodeCalls != 1 || !db.upsertNodeParams.ClearLocation || db.upsertNodeParams.Latitude != nil || db.upsertNodeParams.Longitude != nil {
				t.Fatalf("marked coordinates persisted: %+v", db.upsertNodeParams)
			}
			select {
			case event := <-client.Send:
				var object map[string]json.RawMessage
				if err := json.Unmarshal(event.Payload, &object); err != nil {
					t.Fatal(err)
				}
				if string(object["lat"]) != "null" || string(object["lng"]) != "null" {
					t.Fatalf("live coordinates not cleared: %s", event.Payload)
				}
			case <-ctx.Done():
				t.Fatal("no live update")
			}
		})
	}
}
