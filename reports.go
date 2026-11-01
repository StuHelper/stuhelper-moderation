package moderation

import (
	"context"
	"errors"
	"time"
)

// Reports first check owned local work. Only creation reads external content
// facts, so a qualification outage cannot block evidence on an existing report.
func (s *Service) submitReport(ctx context.Context, p Principal, key string, in Submission) (TaskView, error) {
	var out TaskView
	if e := s.auth(ctx, p, "submit", ""); e != nil {
		return out, e
	}
	operation := digest([]string{p.Subject, in.Kind, in.ObjectID, key})
	payload := digest(in)
	needsFacts := errors.New("report creation needs current facts")
	var object *Object
	apply := func(t Transaction) error {
		if e := t.Lock(digest([]string{p.Subject, in.Kind, in.ObjectID})); e != nil {
			return e
		}
		cached, found, e := replay(t, operation, payload, s.now())
		if e != nil {
			return e
		}
		if found {
			out = cached
			return nil
		}
		task, e := t.Active(p.Subject, in.ObjectID, "report")
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if errors.Is(e, ErrNotFound) {
			if object == nil {
				return needsFacts
			}
			task = Task{ContentOwner: object.Owner, ContentKind: object.Kind, ID: operation, SchoolID: object.SchoolID, Owner: p.Subject, Submission: in, ObjectRevision: object.Revision, State: "waiting", CreatedAt: s.now()}
		} else {
			if e = t.Lock(task.ID); e != nil {
				return e
			}
			task, e = t.Task(task.ID)
			if e != nil {
				return e
			}
			if task.State != "waiting" {
				return ErrConflict
			}
			if in.Reason != task.Submission.Reason {
				task.Submission.Evidence = append(task.Submission.Evidence, in.Reason)
			}
			task.Submission.Evidence = append(task.Submission.Evidence, in.Evidence...)
			if len(task.Submission.Evidence) > 20 {
				return ErrInput
			}
		}
		task.Revision++
		task.UpdatedAt = s.now()
		if e = t.SaveTask(task); e != nil {
			return e
		}
		if e = s.record(t, operation, payload, "submitted", p, task); e != nil {
			return e
		}
		out = viewFor(p, task)
		return nil
	}
	err := s.Repo.Transaction(ctx, apply)
	if !errors.Is(err, needsFacts) {
		return out, err
	}
	if s.Content == nil {
		return out, ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	current, e := s.Content.Inspect(call, p, in.ObjectID)
	if e != nil {
		return out, e
	}
	if !current.Visible {
		return out, ErrNotFound
	}
	if e = s.auth(call, p, "report", current.SchoolID); e != nil {
		return out, e
	}
	object = &current
	// Recheck local state under the same lock: a concurrent creation merges, and
	// a concurrent decision cannot be overwritten by late evidence.
	err = s.Repo.Transaction(ctx, apply)
	return out, err
}
