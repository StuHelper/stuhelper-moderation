package postgres

import (
	"database/sql"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"time"
)

func (t *transaction) LimitSubmission(owner string, now time.Time) error {
	var used int
	err := t.tx.QueryRowContext(t.ctx, `INSERT INTO moderation.submission_limits(owner_key,started_at,used) VALUES($1,$2,1) ON CONFLICT(owner_key) DO UPDATE SET started_at=CASE WHEN moderation.submission_limits.started_at <= $2-interval '1 minute' THEN $2 ELSE moderation.submission_limits.started_at END,used=CASE WHEN moderation.submission_limits.started_at <= $2-interval '1 minute' THEN 1 ELSE moderation.submission_limits.used+1 END WHERE moderation.submission_limits.started_at <= $2-interval '1 minute' OR moderation.submission_limits.used<10 RETURNING used`, owner, now).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return m.ErrRateLimited
	}
	return safe(err)
}
