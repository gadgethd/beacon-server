// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"
	"testing"

	sqlc "github.com/MeshCore-Beacon/beacon-server/db/sqlc"
	mockdb "github.com/MeshCore-Beacon/beacon-server/db/sqlc/mock"
	"github.com/jackc/pgx/v5"
	"go.uber.org/mock/gomock"
)

func TestUpsertRegionUnchangedReadsExistingID(t *testing.T) {
	mock := mockdb.NewMockQuerier(gomock.NewController(t))
	gomock.InOrder(
		mock.EXPECT().UpsertRegion(gomock.Any(), gomock.Any()).Return(int32(0), fmt.Errorf("unchanged: %w", pgx.ErrNoRows)),
		mock.EXPECT().GetRegionBySlug(gomock.Any(), "same").Return(sqlc.GetRegionBySlugRow{ID: 42}, nil),
	)
	id, err := (&Store{q: mock}).UpsertRegion(context.Background(), "same", "Same", "", 0, nil, nil, nil)
	if err != nil || id != 42 {
		t.Fatalf("unchanged region = %d, %v", id, err)
	}
}

func TestUpsertRegionPreservesWriteAndReadErrors(t *testing.T) {
	for _, lookup := range []bool{false, true} {
		t.Run(fmt.Sprint(lookup), func(t *testing.T) {
			mock := mockdb.NewMockQuerier(gomock.NewController(t))
			failure := errors.New("database unavailable")
			if lookup {
				gomock.InOrder(
					mock.EXPECT().UpsertRegion(gomock.Any(), gomock.Any()).Return(int32(0), pgx.ErrNoRows),
					mock.EXPECT().GetRegionBySlug(gomock.Any(), "same").Return(sqlc.GetRegionBySlugRow{}, failure),
				)
			} else {
				mock.EXPECT().UpsertRegion(gomock.Any(), gomock.Any()).Return(int32(0), failure)
			}
			_, err := (&Store{q: mock}).UpsertRegion(context.Background(), "same", "Same", "", 0, nil, nil, nil)
			if err != failure {
				t.Fatalf("error = %v, want original failure", err)
			}
		})
	}
}
