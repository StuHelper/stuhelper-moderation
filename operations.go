package moderation

import (
	"context"
	"errors"
	"slices"
	"time"
)

type TaskFilter struct {
	Owner, School, State, After, Kind, ContentKind, ObjectID string
	From, Until                                              *time.Time
	Limit                                                    int
	Admin                                                    bool
}

func (s *Service) FilteredList(ctx context.Context, p Principal, f TaskFilter) ([]TaskView, error) {
	if p.Subject == "" {
		return nil, ErrForbidden
	}
	if f.Limit < 1 || f.Limit > 100 || len(f.After) > 128 || len(f.ObjectID) > 128 || f.From != nil && f.Until != nil && !f.From.Before(*f.Until) {
		return nil, ErrInput
	}
	f.Owner = p.Subject
	if f.Kind != "" && !slices.Contains([]string{"review", "report", "edit_request", "delete_request", "appeal"}, f.Kind) {
		return nil, ErrInput
	}
	if f.ContentKind != "" && !slices.Contains([]string{"course", "mentor", "reply", "resource"}, f.ContentKind) {
		return nil, ErrInput
	}
	if f.Admin {
		if f.School == "" {
			return nil, ErrInput
		}
		if err := s.auth(ctx, p, "manage", f.School); err != nil {
			return nil, err
		}
		f.Owner = ""
	}
	out := []TaskView{}
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		tasks, e := t.FilteredTasks(f)
		if e != nil {
			return e
		}
		for _, task := range tasks {
			v := viewFor(p, task)
			if !f.Admin {
				v = recipientView(p, task)
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}

type BatchItem struct {
	ID       string   `json:"id"`
	Revision int64    `json:"revision"`
	Decision Decision `json:"decision"`
}
type BatchRequest struct {
	Items        []BatchItem `json:"items"`
	PreviewToken string      `json:"preview_token"`
}
type BatchOutcome struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Code  string `json:"code"`
}
type BatchPreview struct {
	PreviewToken string         `json:"preview_token"`
	Items        []BatchOutcome `json:"items"`
}

func batchToken(p Principal, in BatchRequest) string { return digest([]any{p.Subject, in.Items}) }
func validBatch(in BatchRequest) bool {
	if len(in.Items) < 1 || len(in.Items) > 20 {
		return false
	}
	seen := map[string]bool{}
	for _, item := range in.Items {
		if item.ID == "" || len(item.ID) > 128 || item.Revision < 1 || seen[item.ID] {
			return false
		}
		seen[item.ID] = true
	}
	return true
}
func (s *Service) PreviewBatch(ctx context.Context, p Principal, in BatchRequest) (BatchPreview, error) {
	out := BatchPreview{Items: []BatchOutcome{}}
	if !validBatch(in) {
		return out, ErrInput
	}
	out.PreviewToken = batchToken(p, in)
	mutatingObjects := map[string]bool{}
	for _, item := range in.Items {
		result := BatchOutcome{ID: item.ID, State: "ready"}
		var task Task
		e := s.Repo.Transaction(ctx, func(t Transaction) error {
			var err error
			task, err = t.Task(item.ID)
			if err != nil {
				return err
			}
			if err = s.auth(ctx, p, "manage", task.SchoolID); err != nil {
				return err
			}
			if task.Submission.Kind == "appeal" {
				if err = s.auth(ctx, p, "review", task.SchoolID); err != nil {
					return err
				}
				prior, err := t.Task(task.Submission.PreviousTaskID)
				if err != nil {
					return err
				}
				if prior.DecidedBy == p.Subject {
					return ErrForbidden
				}
			}
			return nil
		})
		if e == nil && !validateDecision(item.Decision) {
			e = ErrInput
		}
		if e == nil && !canDecideTask(task, item.Revision) {
			e = ErrConflict
		}
		var object Object
		if e == nil {
			if s.Content == nil {
				e = ErrUnavailable
			} else {
				object, e = s.Content.Inspect(ctx, p, task.Submission.ObjectID)
				if e == nil {
					e = validateDecisionTarget(object, task, item.Decision)
				}
			}
		}
		if e == nil && item.Decision.Action != "dismiss" {
			if mutatingObjects[object.ID] {
				e = ErrConflict
			} else {
				mutatingObjects[object.ID] = true
			}
		}
		if e != nil {
			result.State = "rejected"
			result.Code = errorCode(e)
		}
		out.Items = append(out.Items, result)
	}
	return out, nil
}
func errorCode(err error) string {
	for _, known := range []error{ErrInput, ErrForbidden, ErrNotFound, ErrConflict} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "unavailable"
}
func (s *Service) DecideBatch(ctx context.Context, p Principal, key string, in BatchRequest) (BatchPreview, error) {
	out := BatchPreview{Items: []BatchOutcome{}}
	if !validBatch(in) || !keyOK(key) || in.PreviewToken != batchToken(p, in) {
		return out, ErrInput
	}
	rk := digest([]string{p.Subject, "batch", key})
	hash := batchToken(p, in)
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		if e := t.Lock(rk); e != nil {
			return e
		}
		old, e := t.Replay(rk)
		if e == nil && s.now().Before(old.Until) {
			if old.Digest != hash {
				return ErrConflict
			}
			return nil
		}
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		return t.SaveReplay(rk, Replay{Digest: hash, Until: s.now().Add(24 * time.Hour)})
	})
	if err != nil {
		return out, err
	}
	out.PreviewToken = hash
	mutatingObjects := map[string]bool{}
	for _, item := range in.Items {
		if item.Decision.Action != "dismiss" && mutatingObjects[item.Decision.ObjectID] {
			var checkErr error
			_ = s.Repo.Transaction(ctx, func(t Transaction) error {
				task, e := t.Task(item.ID)
				if e != nil {
					checkErr = e
					return nil
				}
				checkErr = s.auth(ctx, p, "manage", task.SchoolID)
				return nil
			})
			code := "conflict"
			if checkErr != nil {
				code = errorCode(checkErr)
			}
			out.Items = append(out.Items, BatchOutcome{ID: item.ID, State: "rejected", Code: code})
			continue
		}
		task, e := s.Decide(ctx, p, item.ID, digest([]string{rk, item.ID}), Decide{Revision: item.Revision, Decision: item.Decision})
		result := BatchOutcome{ID: item.ID, State: task.State}
		if e != nil {
			result.State = "rejected"
			result.Code = errorCode(e)
		} else if item.Decision.Action != "dismiss" {
			mutatingObjects[item.Decision.ObjectID] = true
		}
		out.Items = append(out.Items, result)
	}
	return out, nil
}
