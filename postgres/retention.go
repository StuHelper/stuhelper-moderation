package postgres

import (
	"context"
	"database/sql"
	"time"

	m "github.com/StuHelper/stuhelper-moderation"
)

var _ m.MaintenanceRepository = (*Repository)(nil)

func (r *Repository) CleanupRetention(ctx context.Context, now time.Time, batchLimit int) (m.CleanupResult, error) {
	var out m.CleanupResult
	if batchLimit == 0 {
		batchLimit = 200
	}
	if batchLimit < 1 || batchLimit > 500 {
		return out, m.ErrInput
	}
	now = now.UTC()
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, safe(err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `DELETE FROM moderation.replays WHERE key IN (
  SELECT key FROM moderation.replays WHERE until IS NOT NULL AND until <= $1::timestamptz ORDER BY until, key LIMIT $2
 )`, now, batchLimit)
	if err != nil {
		return out, safe(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return out, safe(err)
	}
	out.ReplaysDeleted = int(n)

	res, err = tx.ExecContext(ctx, `DELETE FROM moderation.submission_limits WHERE owner_key IN (
  SELECT owner_key FROM moderation.submission_limits WHERE started_at <= $1::timestamptz - interval '24 hours' ORDER BY started_at, owner_key LIMIT $2
 )`, now, batchLimit)
	if err != nil {
		return out, safe(err)
	}
	n, err = res.RowsAffected()
	if err != nil {
		return out, safe(err)
	}
	out.LimitsDeleted = int(n)

	res, err = tx.ExecContext(ctx, `DELETE FROM moderation.outbox WHERE id IN (
  SELECT id FROM moderation.outbox WHERE sent_at IS NOT NULL AND sent_at <= $1::timestamptz - interval '90 days' ORDER BY sent_at, id LIMIT $2
 )`, now, batchLimit)
	if err != nil {
		return out, safe(err)
	}
	n, err = res.RowsAffected()
	if err != nil {
		return out, safe(err)
	}
	out.OutboxDeleted = int(n)

	var canPruneAudit bool
	if err = tx.QueryRowContext(ctx, `SELECT has_function_privilege(current_user, 'moderation.cleanup_moderation_audit()', 'EXECUTE')`).Scan(&canPruneAudit); err != nil || !canPruneAudit {
		return out, m.ErrUnavailable
	}
	if err = tx.QueryRowContext(ctx, `SELECT moderation.cleanup_moderation_audit()`).Scan(&out.AuditDeleted); err != nil {
		return out, safe(err)
	}

	if err = tx.Commit(); err != nil {
		return out, safe(err)
	}
	return out, nil
}

func (r *Repository) HealthSnapshot(ctx context.Context, now time.Time) (m.HealthSnapshot, error) {
	var out m.HealthSnapshot
	now = now.UTC()
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, safe(err)
	}
	defer tx.Rollback()

	var oldestDecided, oldestOutbox sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT
  count(*) FILTER (WHERE state='decided' AND next_attempt <= $1 AND lease_until <= $1),
  min(COALESCE((data->>'decided_at')::timestamptz, (data->>'created_at')::timestamptz)) FILTER (WHERE state='decided'),
  count(*) FILTER (WHERE state='failed')
 FROM moderation.tasks`, now).Scan(&out.DecidedReadyCount, &oldestDecided, &out.FailedManualCount); err != nil {
		return out, safe(err)
	}
	if oldestDecided.Valid {
		at := oldestDecided.Time.UTC()
		out.OldestDecidedAt = &at
	}

	if err = tx.QueryRowContext(ctx, `SELECT
  count(*),
  min((data->>'time')::timestamptz)
 FROM moderation.outbox WHERE sent_at IS NULL`).Scan(&out.OutboxPendingCount, &oldestOutbox); err != nil {
		return out, safe(err)
	}
	if oldestOutbox.Valid {
		at := oldestOutbox.Time.UTC()
		out.OldestOutboxAt = &at
	}

	if err = tx.QueryRowContext(ctx, `SELECT
  count(*),
  coalesce(sum(bytes), 0),
  (SELECT count(*) FROM moderation.feedback_tombstones)
 FROM moderation.feedback`).Scan(&out.FeedbackActiveCount, &out.FeedbackActiveBytes, &out.FeedbackTombstoneCount); err != nil {
		return out, safe(err)
	}

	if err = tx.Commit(); err != nil {
		return out, safe(err)
	}
	return out, nil
}
