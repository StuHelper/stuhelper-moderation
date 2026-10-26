package moderation

import (
	"context"
	"errors"
	"time"
)

// Work delivers decisions outside transactions. The content module deduplicates by decision ID.
func (s *Service) Work(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 50 {
		return 0, ErrInput
	}
	var tasks []Task
	err := s.Repo.Transaction(ctx, func(t Transaction) error { var e error; tasks, e = t.Ready(s.now(), limit); return e })
	if err != nil {
		return 0, err
	}
	done := 0
	for _, candidate := range tasks {
		var task Task
		claimed := false
		err = s.Repo.Transaction(ctx, func(t Transaction) error {
			if e := t.Lock(candidate.ID); e != nil {
				return e
			}
			var e error
			task, e = t.Task(candidate.ID)
			if e != nil {
				return e
			}
			if task.State != "decided" || task.NextAttempt.After(s.now()) || task.LeaseUntil.After(s.now()) {
				return nil
			}
			task.LeaseUntil = s.now().Add(30 * time.Second)
			task.Attempts++
			claimed = true
			return t.SaveTask(task)
		})
		if err != nil {
			return done, err
		}
		if !claimed {
			continue
		}
		if task.Decision == nil {
			return done, ErrUnavailable
		}
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		applyErr := s.Content.Apply(callCtx, Principal{Subject: task.DecidedBy}, *task.Decision)
		cancel()
		err = s.Repo.Transaction(ctx, func(t Transaction) error {
			if e := t.Lock(task.ID); e != nil {
				return e
			}
			current, e := t.Task(task.ID)
			if e != nil {
				return e
			}
			if current.Attempts != task.Attempts || current.State != "decided" {
				return nil
			}
			current.LeaseUntil = time.Time{}
			current.UpdatedAt = s.now()
			current.Revision++
			if applyErr == nil {
				current.State = "applied"
				current.ErrorCode = ""
				done++
			} else if errors.Is(applyErr, ErrConflict) || errors.Is(applyErr, ErrNotFound) || errors.Is(applyErr, ErrForbidden) {
				current.State = "failed"
				current.ErrorCode = applyErr.Error()
			} else {
				current.ErrorCode = "unavailable"
				delay := 5 * time.Second
				for i := 1; i < current.Attempts && delay < time.Hour; i++ {
					delay *= 2
				}
				if delay > time.Hour {
					delay = time.Hour
				}
				current.NextAttempt = s.now().Add(delay)
				if current.DecidedAt == nil || s.now().Sub(*current.DecidedAt) >= 24*time.Hour {
					current.State = "failed"
				}
			}
			return t.SaveTask(current)
		})
		if err != nil {
			return done, err
		}
	}
	return done, nil
}
