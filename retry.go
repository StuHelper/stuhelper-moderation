package moderation

import (
	"context"
	"time"
)

func (s *Service) Retry(ctx context.Context, p Principal, id, key string, revision int64) (TaskView, error) {
	var out TaskView
	if !keyOK(key) || revision < 1 {
		return out, ErrInput
	}
	rk := digest([]string{p.Subject, "retry", id, key})
	h := digest(revision)
	err := s.tx(ctx, func(t Transaction) error {
		if e := t.Lock(id); e != nil {
			return e
		}
		task, e := t.Task(id)
		if e != nil {
			return e
		}
		if e = s.auth(ctx, p, "manage", task.SchoolID); e != nil {
			return e
		}
		cached, ok, e := replay(t, rk, h, s.now())
		if e != nil {
			return e
		}
		if ok {
			out = cached
			return nil
		}
		if task.State != "failed" || task.Decision == nil || task.ErrorCode != "unavailable" {
			return withReason(ErrConflict, "retry_not_allowed")
		}
		if task.Revision != revision {
			return withReason(ErrConflict, "stale_revision")
		}
		if task.Submission.Kind == "appeal" {
			if e = s.auth(ctx, p, "review", task.SchoolID); e != nil {
				return e
			}
			prior, e := t.Task(task.Submission.PreviousTaskID)
			if e != nil {
				return e
			}
			if prior.DecidedBy == p.Subject {
				return ErrForbidden
			}
		}
		task.State = "decided"
		task.RetriedBy = p.Subject
		task.Attempts = 0
		task.NextAttempt = s.now()
		task.LeaseUntil = time.Time{}
		task.ErrorCode = ""
		now := s.now()
		task.DecidedAt = &now
		task.Revision++
		task.UpdatedAt = now
		if e = t.SaveTask(task); e != nil {
			return e
		}
		if e = s.record(t, rk, h, "retried", p, task); e != nil {
			return e
		}
		out = viewFor(p, task)
		return nil
	})
	return out, err
}
