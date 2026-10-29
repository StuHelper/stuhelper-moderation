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
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
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
		if task.Revision != revision || task.State != "failed" || task.Decision == nil {
			return ErrConflict
		}
		if task.ErrorCode != "unavailable" {
			return ErrConflict
		}
		task.State = "decided"
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
		out = view(task)
		return nil
	})
	return out, err
}
