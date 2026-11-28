// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicsource

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func liveFixture(row sourceRow) string {
	value := map[string]any{"v": 1, "k": "p", "o": row.id.String(), "ip": 0, "vo": 1, "d": map[string]any{
		"time": row.at.Format(time.RFC3339Nano), "network": row.network, "iata": row.iata, "packetUid": hex.EncodeToString(row.uid),
		"identityVersion": row.version, "identityProvenance": row.provenance, "packetHash": row.alias, "packetType": row.packetType,
		"topic": row.topic, "rxNodeId": row.receiver, "srcNodeId": row.source, "pathHashes": row.paths, "pathHashSizeBytes": row.pathSize, "rawHex": row.raw}}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func TestLiveProtocolPreservesStableObservationAcrossDuplicateDelivery(t *testing.T) {
	row := observationRow()
	value := liveFixture(row)
	raw, _ := json.Marshal(map[string]any{"generation": 7, "hasMore": false, "nextCursor": "2-0", "entries": []any{
		map[string]string{"id": "1-0", "value": value}, map[string]string{"id": "2-0", "value": value}}})
	batch, err := decodeLiveBatch(raw, "0-0")
	if err != nil || !batch.CaughtUp || len(batch.Outcomes) != 2 {
		t.Fatal("valid live page rejected")
	}
	for _, out := range batch.Outcomes {
		if out.Observation == nil || out.Observation.ID != row.id || !out.Observation.Time.Equal(row.at) {
			t.Fatal("live identity/time lost")
		}
	}
	// An empty public page can still cover raw private input; EOF belongs to
	// the protected producer's hasMore, not the filtered public item count.
	for _, more := range []bool{false, true} {
		raw, _ := json.Marshal(map[string]any{"generation": 7, "hasMore": more, "nextCursor": "3-0", "entries": []any{}})
		got, err := decodeLiveBatch(raw, "2-0")
		if err != nil || got.CaughtUp == more {
			t.Fatal("filtered page invented EOF")
		}
	}
}

func TestLiveProtocolRejectsPrivateMalformedAndBackwardsInputs(t *testing.T) {
	row := observationRow()
	raw := liveFixture(row)
	var value map[string]any
	_ = json.Unmarshal([]byte(raw), &value)
	for _, field := range []string{"ip", "vo"} {
		copy := map[string]any{}
		for k, v := range value {
			copy[k] = v
		}
		copy[field] = 1
		if field == "vo" {
			copy[field] = 0
		}
		bad, _ := json.Marshal(copy)
		if _, err := decodeLiveEntry(string(bad)); err == nil {
			t.Fatal("private/unclassified live row accepted")
		}
	}
	for _, page := range []string{
		`{"generation":7,"nextCursor":"1-0","entries":[]}`, `{"generation":7,"hasMore":true,"nextCursor":"2-0","entries":[]}`,
	} {
		if _, err := decodeLiveBatch([]byte(page), "2-0"); err == nil {
			t.Fatal("backwards/stalled live cursor accepted")
		}
	}
}

func TestLiveMixedNetworksSkipWithoutStallingCursor(t *testing.T) {
	selected, other := observationRow(), observationRow()
	other.network = "another-network"
	raw, _ := json.Marshal(map[string]any{"generation": 7, "hasMore": false, "nextCursor": "2-0", "entries": []any{
		map[string]string{"id": "1-0", "value": liveFixture(selected)}, map[string]string{"id": "2-0", "value": liveFixture(other)}}})
	batch, err := decodeLiveBatch(raw, "0-0")
	if err != nil || batch.Next != "2-0" || !batch.CaughtUp || len(batch.Outcomes) != 2 {
		t.Fatal("mixed network page stalled")
	}
	if batch.Outcomes[0].Observation == nil || batch.Outcomes[1].Reason != OutsideNetwork || batch.Outcomes[1].Observation != nil {
		t.Fatal("mixed network scope leaked or discarded selected data")
	}
}
