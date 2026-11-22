package moderation

import (
	"context"
	"time"
)

type CleanupResult struct {
	ReplaysDeleted                   int `json:"replays_deleted"`
	LimitsDeleted                    int `json:"limits_deleted"`
	OutboxDeleted                    int `json:"outbox_deleted"`
	AuditDeleted                     int `json:"audit_deleted"`
	TeacherHomepageComplaintsDeleted int `json:"teacher_homepage_complaints_deleted"`
}

type HealthSnapshot struct {
	DecidedReadyCount      int        `json:"decided_ready_count"`
	OldestDecidedAt        *time.Time `json:"oldest_decided_at"`
	FailedManualCount      int        `json:"failed_manual_count"`
	OutboxPendingCount     int        `json:"outbox_pending_count"`
	OldestOutboxAt         *time.Time `json:"oldest_outbox_at"`
	FeedbackActiveCount    int        `json:"feedback_active_count"`
	FeedbackActiveBytes    int64      `json:"feedback_active_bytes"`
	FeedbackTombstoneCount int        `json:"feedback_tombstone_count"`
}

// MaintenanceRepository exposes bounded retention pruning and read-only backlog health snapshots.
type MaintenanceRepository interface {
	CleanupRetention(ctx context.Context, now time.Time, batchLimit int) (CleanupResult, error)
	HealthSnapshot(ctx context.Context, now time.Time) (HealthSnapshot, error)
}

func (s *Service) CleanupRetention(ctx context.Context, batchLimit int) (CleanupResult, error) {
	if batchLimit == 0 {
		batchLimit = 200
	}
	if batchLimit < 1 || batchLimit > 500 {
		return CleanupResult{}, ErrInput
	}
	if s == nil || s.Repo == nil {
		return CleanupResult{}, ErrUnavailable
	}
	port, ok := s.Repo.(MaintenanceRepository)
	if !ok {
		return CleanupResult{}, ErrUnavailable
	}
	return port.CleanupRetention(ctx, s.now(), batchLimit)
}

func (s *Service) HealthSnapshot(ctx context.Context) (HealthSnapshot, error) {
	if s == nil || s.Repo == nil {
		return HealthSnapshot{}, ErrUnavailable
	}
	port, ok := s.Repo.(MaintenanceRepository)
	if !ok {
		return HealthSnapshot{}, ErrUnavailable
	}
	return port.HealthSnapshot(ctx, s.now())
}

func (s *Service) Health(ctx context.Context, p Principal) (HealthSnapshot, error) {
	if err := s.auth(ctx, p, "manage", "*"); err != nil {
		return HealthSnapshot{}, err
	}
	return s.HealthSnapshot(ctx)
}
