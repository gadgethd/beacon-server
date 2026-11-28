// Copyright 2026 Beacon Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicprojection

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MeshCore-Beacon/beacon-server/internal/hub"
	"github.com/MeshCore-Beacon/beacon-server/internal/publicsource"
)

type HistorySource interface {
	ReadBatch(context.Context, publicsource.Cursor, int) (publicsource.Batch, error)
}
type LiveSource interface {
	ReadBatch(context.Context, string) (publicsource.LiveBatch, error)
}

type Service struct {
	store         *PGStore
	history       HistorySource
	live          LiveSource
	authority     Authority
	hub           *hub.Hub
	syncMu        sync.Mutex
	eventCursor   int64
	eventEpoch    string
	running       atomic.Bool
	started       atomic.Bool
	baselineEpoch atomic.Value
	retentionDays int
	nextPrune     time.Time
}

func New(store *PGStore, history HistorySource, live LiveSource, authority Authority) (*Service, error) {
	if store == nil || history == nil || authority == nil {
		return nil, ErrUnavailable
	}
	return &Service{store: store, history: history, live: live, authority: authority, hub: hub.New()}, nil
}

func (s *Service) purge(cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.eventEpoch = ""
	s.baselineEpoch.Store("")
	return errors.Join(cause, s.store.reset(ctx, nil))
}

// SyncOnce is single-owner, bounded work. History and RAM/live have independent
// cursors; the same upstream UUID can cross both inputs without another row.
func (s *Service) SyncOnce(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	policy, err := s.authority.Current(ctx)
	if err != nil {
		return s.purge(err)
	}
	if policy.Network != "ukmesh" {
		return s.purge(ErrUnavailable)
	}
	if s.retentionDays > 0 && time.Now().After(s.nextPrune) {
		if err = s.store.PruneBefore(ctx, time.Now().UTC().Add(-time.Duration(s.retentionDays)*24*time.Hour)); err != nil {
			return err
		}
		s.nextPrune = time.Now().Add(time.Hour)
	}
	checkpoint, err := s.store.state(ctx)
	if err != nil {
		return err
	}
	if !checkpoint.matches(policy) {
		if err = s.store.reset(ctx, &policy); err != nil {
			return err
		}
		checkpoint, err = s.store.state(ctx)
		if err != nil {
			return err
		}
	}
	batch, err := s.history.ReadBatch(ctx, checkpoint.history, 500)
	if err != nil {
		return s.purge(err)
	}
	if batch.Next.Generation != policy.Generation {
		return s.purge(ErrUnavailable)
	}
	records := s.prepare(policy, batch.Outcomes)
	if err = s.checkPolicy(ctx, policy); err != nil {
		return s.purge(err)
	}
	historyComplete := len(batch.Outcomes) == 0
	var liveComplete *bool
	if s.live == nil {
		complete := true
		liveComplete = &complete
	}
	if err = s.store.apply(ctx, policy, checkpoint, &batch.Next, nil, &historyComplete, liveComplete, records); err != nil {
		if errors.Is(err, ErrConcurrent) {
			return err
		}
		return s.purge(err)
	}
	if s.live != nil {
		checkpoint, err = s.store.state(ctx)
		if err != nil {
			return err
		}
		live, readErr := s.live.ReadBatch(ctx, checkpoint.live)
		if readErr != nil {
			return s.purge(readErr)
		}
		if live.Generation != policy.Generation {
			return s.purge(ErrUnavailable)
		}
		if err = s.checkPolicy(ctx, policy); err != nil {
			return s.purge(err)
		}
		if err = s.store.apply(ctx, policy, checkpoint, nil, &live.Next, nil, &live.CaughtUp, s.prepare(policy, live.Outcomes)); err != nil {
			if errors.Is(err, ErrConcurrent) {
				return err
			}
			return s.purge(err)
		}
	}
	checkpoint, err = s.store.state(ctx)
	if err != nil {
		return err
	}
	if !checkpoint.ready {
		return nil
	}
	epoch := policy.Epoch() + ":" + formatGeneration(checkpoint.revision)
	if s.eventEpoch != epoch {
		s.eventCursor, err = s.store.latestEvent(ctx)
		if err != nil {
			return err
		}
		s.eventEpoch = epoch
		s.baselineEpoch.Store(epoch)
		return nil
	}
	events, err := s.store.events(ctx, policy, s.eventCursor)
	if err != nil {
		return err
	}
	for _, entry := range events {
		if err = s.checkPolicy(ctx, policy); err != nil {
			return s.purge(err)
		}
		payload, err := json.Marshal(entry.Message)
		if err != nil {
			return err
		}
		s.hub.Broadcast(hub.Event{Type: hub.EventChannelMessage, Payload: payload, IATA: entry.IATA, PayloadType: 5,
			ChannelHash: entry.Message.ChannelHash, AuthorityToken: epoch})
		s.eventCursor = entry.ID
	}
	return nil
}

func (s *Service) prepare(policy Policy, outcomes []publicsource.Outcome) []prepared {
	rows := make([]prepared, 0, len(outcomes))
	cutoff := time.Now().UTC().Add(-time.Duration(s.retentionDays) * 24 * time.Hour)
	for _, outcome := range outcomes {
		if outcome.Observation == nil {
			continue
		}
		if s.retentionDays > 0 && outcome.Observation.Time.Before(cutoff) {
			continue
		}
		record, err := authenticate(policy, outcome.Observation)
		if err == nil {
			rows = append(rows, record)
		}
	}
	return rows
}

// SetRetentionDays must match the authoritative packet lifecycle. DEV uses30.
// It is configured before starting the owned poller, not changed during reads.
func (s *Service) SetRetentionDays(days int) error {
	if days < 30 || days > 365 {
		return ErrUnavailable
	}
	if s.running.Load() {
		return ErrConcurrent
	}
	s.retentionDays, s.store.retentionDays = days, days
	return nil
}

func (s *Service) checkPolicy(ctx context.Context, expected Policy) error {
	current, err := s.authority.Current(ctx)
	if err != nil || current.Epoch() != expected.Epoch() {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) usable(ctx context.Context) (Policy, error) {
	p, _, err := s.authorized(ctx)
	return p, err
}

func (s *Service) authorized(ctx context.Context) (Policy, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !s.running.Load() {
		return Policy{}, "", ErrUnavailable
	}
	policy, err := s.authority.Current(ctx)
	if err != nil {
		return Policy{}, "", ErrUnavailable
	}
	c, err := s.store.state(ctx)
	if err != nil || !c.ready || !c.matches(policy) {
		return Policy{}, "", ErrUnavailable
	}
	epoch := policy.Epoch() + ":" + formatGeneration(c.revision)
	bound, _ := s.baselineEpoch.Load().(string)
	if epoch != bound {
		return Policy{}, "", ErrUnavailable
	}
	return policy, epoch, nil
}

func (s *Service) epoch(ctx context.Context) (string, error) {
	_, epoch, err := s.authorized(ctx)
	return epoch, err
}

// Run settles one synchronous poll at a time. A source/authority failure never
// resets a failure into readiness; another complete history pass is required.
func (s *Service) Run(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return ErrConcurrent
	}
	s.running.Store(true)
	s.baselineEpoch.Store("")
	defer s.running.Store(false)
	done := make(chan struct{})
	go func() { defer close(done); s.hub.RunContext(ctx) }()
	defer func() { <-done }()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("public projection refresh unavailable", "component", "ukmesh-public")
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
