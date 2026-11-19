package postgres

import (
	"database/sql"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"math"
	"time"
)

func (t *transaction) LimitSubmission(owner string, now time.Time) error {
	var used int
	err := t.tx.QueryRowContext(t.ctx, `INSERT INTO moderation.submission_limits(owner_key,started_at,used) VALUES($1,$2,1) ON CONFLICT(owner_key) DO UPDATE SET started_at=CASE WHEN moderation.submission_limits.started_at <= $2-interval '1 minute' THEN $2 ELSE moderation.submission_limits.started_at END,used=CASE WHEN moderation.submission_limits.started_at <= $2-interval '1 minute' THEN 1 ELSE moderation.submission_limits.used+1 END WHERE moderation.submission_limits.started_at <= $2-interval '1 minute' OR moderation.submission_limits.used<10 RETURNING used`, owner, now).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		var startedAt time.Time
		retryAfter := 60
		if qErr := t.tx.QueryRowContext(t.ctx, `SELECT started_at FROM moderation.submission_limits WHERE owner_key=$1`, owner).Scan(&startedAt); qErr == nil {
			rem := int(math.Ceil(startedAt.Add(time.Minute).Sub(now).Seconds()))
			if rem < 1 {
				rem = 1
			} else if rem > 60 {
				rem = 60
			}
			retryAfter = rem
		}
		return m.ReasonError{Base: m.ErrRateLimited, Reason: "submission_rate_limited", RetryAfter: retryAfter}
	}
	return safe(err)
}
