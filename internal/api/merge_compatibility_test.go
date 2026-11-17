// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"testing"
)

func TestPublicPagesPreserveExactCursorsAndNewNodeFields(t *testing.T) {
	cursor := "exact-cursor"
	foreign := true
	pages := []any{
		ToPublicNodePage(NodePage{Page: Page[NodeSummary]{Items: []NodeSummary{{LastSeen: 42, PossiblyForeign: &foreign}}, HasMore: true}, NextPageCursor: &cursor, Sort: "name", Order: "asc"}),
		ToPublicObserverPage(ObserverPage{NextPageCursor: &cursor}),
		ToPublicPacketPage(PacketPage{NextPageCursor: &cursor}),
	}
	for _, page := range pages {
		object := jsonObject(t, page)
		if string(object["nextPageCursor"]) != `"exact-cursor"` {
			t.Fatalf("exact cursor lost: %s", object["nextPageCursor"])
		}
	}
	node := ToPublicNode(&Node{MeshMapper: &MeshMapperRepeater{IATA: "LON"}, Metadata: map[string]any{"secret": "hidden"}})
	object := jsonObject(t, node)
	if _, ok := object["meshmapper"]; !ok {
		t.Fatal("upstream repeater data lost")
	}
	assertJSONKeysAbsent(t, object, "metadata")
	var list map[string]json.RawMessage
	b, _ := json.Marshal(pages[0])
	_ = json.Unmarshal(b, &list)
	if string(list["sort"]) != `"name"` || string(list["order"]) != `"asc"` {
		t.Fatal("sort state lost")
	}
	var items []map[string]json.RawMessage
	_ = json.Unmarshal(list["items"], &items)
	if string(items[0]["lastSeen"]) != "42" || string(items[0]["possiblyForeign"]) != "true" {
		t.Fatal("new node fields lost")
	}
}
