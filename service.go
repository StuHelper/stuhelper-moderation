package moderation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type Service struct {
	Repo    Repository
	Content Content
	Access  Access
	Clock   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func keyOK(v string) bool {
	if len(v) < 1 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
func textOK(v string, max int) bool {
	return utf8.ValidString(v) && utf8.RuneCountInString(v) <= max && !strings.ContainsRune(v, 0)
}
func view(t Task) TaskView {
	var decision *Decision
	if t.Decision != nil {
		safe := *t.Decision
		safe.Body = nil
		safe.Subject = ""
		safe.AuthorHandle = ""
		decision = &safe
	}
	return TaskView{false, t.ContentKind, t.ID, t.SchoolID, t.Submission, t.ObjectRevision, t.Revision, t.State, t.CreatedAt, t.UpdatedAt, decision, t.ErrorCode}
}
func (s *Service) auth(ctx context.Context, p Principal, action, school string) error {
	if p.Subject == "" {
		return ErrForbidden
	}
	if s.Access == nil {
		return ErrUnavailable
	}
	return s.Access.Authorize(ctx, p, action, school)
}
func replay(t Transaction, key, hash string, now time.Time) (TaskView, bool, error) {
	r, e := t.Replay(key)
	if errors.Is(e, ErrNotFound) {
		return TaskView{}, false, nil
	}
	if e != nil {
		return TaskView{}, false, e
	}
	if !now.Before(r.Until) {
		return TaskView{}, false, nil
	}
	if r.Digest != hash {
		return TaskView{}, false, ErrConflict
	}
	return r.View, true, nil
}
func (s *Service) record(t Transaction, key, hash, action string, p Principal, task Task) error {
	if e := t.Event(Event{ID: key, Type: "moderation." + action + ".v1", Subject: "task/" + task.ID, SchoolID: task.SchoolID, Actor: p.Subject, Revision: task.Revision, At: s.now()}); e != nil {
		return e
	}
	return t.SaveReplay(key, Replay{Digest: hash, TaskID: task.ID, View: view(task), Until: s.now().Add(24 * time.Hour)})
}

// Check is read-only. Pending content is handed off by the content module's outbox.
func (s *Service) Check(ctx context.Context, school, kind, title, body string) (string, error) {
	if !slices.Contains([]string{"course", "mentor", "reply"}, kind) {
		return "", ErrInput
	}
	var policy Policy
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		view, err := effectivePolicy(t, school, kind)
		policy = view.Effective
		return err
	})
	if err != nil {
		return "", err
	}
	text := strings.ToLower(title + "\n" + body)
	for _, term := range policy.BlockedTerms {
		if strings.Contains(text, strings.ToLower(term)) {
			return "blocked", nil
		}
	}
	if !slices.Contains([]string{"published", "pending", "review"}, policy.Mode) {
		return "", ErrUnavailable
	}
	return policy.Mode, nil
}
func (s *Service) Submit(ctx context.Context, p Principal, key string, in Submission) (TaskView, error) {
	var out TaskView
	if p.Subject == "" {
		return out, ErrForbidden
	}
	if !keyOK(key) || in.ObjectID == "" || len(in.ObjectID) > 128 || !slices.Contains([]string{"report", "edit_request", "delete_request", "review", "appeal"}, in.Kind) || strings.TrimSpace(in.Reason) == "" || !textOK(in.Reason, 2000) || !textOK(in.ProposedBody, 16000) || len(in.Evidence) > 5 {
		return out, ErrInput
	}
	for _, v := range in.Evidence {
		if !textOK(v, 2000) {
			return out, ErrInput
		}
	}
	object, e := s.Content.Inspect(ctx, p, in.ObjectID)
	if e != nil {
		return out, e
	}
	if in.Kind == "report" && !object.Visible {
		return out, ErrNotFound
	}
	if in.Kind != "report" && in.Kind != "review" && object.Owner != p.Subject {
		return out, ErrNotFound
	}
	if in.Kind == "edit_request" && strings.TrimSpace(in.ProposedBody) == "" {
		return out, ErrInput
	}
	if e = s.auth(ctx, p, "submit", object.SchoolID); e != nil {
		return out, e
	}
	if in.Kind == "appeal" {
		if in.PreviousTaskID == "" {
			return out, ErrInput
		}
		err := s.Repo.Transaction(ctx, func(t Transaction) error {
			previous, e := t.Task(in.PreviousTaskID)
			if e != nil {
				return e
			}
			if previous.Submission.ObjectID != in.ObjectID || previous.Decision == nil || (previous.State != "applied" && previous.State != "failed") {
				return ErrConflict
			}
			return nil
		})
		if err != nil {
			return out, err
		}
	} else if in.PreviousTaskID != "" {
		return out, ErrInput
	}
	if in.Kind == "review" {
		if e = s.auth(ctx, p, "manage", object.SchoolID); e != nil {
			return out, e
		}
	}
	rk := digest([]string{p.Subject, in.Kind, in.ObjectID, key})
	h := digest(in)
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		if e := t.Lock(digest([]string{p.Subject, in.Kind, in.ObjectID})); e != nil {
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
		task, e := t.Active(p.Subject, in.ObjectID, in.Kind)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if e == nil && task.State != "waiting" {
			return ErrConflict
		}
		if errors.Is(e, ErrNotFound) {
			task = Task{ContentOwner: object.Owner, ContentKind: object.Kind, ID: rk, SchoolID: object.SchoolID, Owner: p.Subject, Submission: in, ObjectRevision: object.Revision, State: "waiting", CreatedAt: s.now()}
		} else {
			if in.Reason != task.Submission.Reason {
				task.Submission.Evidence = append(task.Submission.Evidence, in.Reason)
			}
			task.Submission.Evidence = append(task.Submission.Evidence, in.Evidence...)
			if len(task.Submission.Evidence) > 20 {
				return ErrInput
			}
			if in.Kind == "edit_request" {
				task.Submission.ProposedBody = in.ProposedBody
			}
		}
		task.Revision++
		task.UpdatedAt = s.now()
		if e = t.SaveTask(task); e != nil {
			return e
		}
		if e = s.record(t, rk, h, "submitted", p, task); e != nil {
			return e
		}
		out = viewFor(p, task)
		return nil
	})
	return out, err
}

// Track accepts a durable content event, without copying full content into public records.
func (s *Service) Track(ctx context.Context, eventID string, object Object) (TaskView, error) {
	var out TaskView
	if eventID == "" || object.ID == "" || object.Revision < 1 {
		return out, ErrInput
	}
	id := digest([]string{"content", eventID})
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		if e := t.Lock(id); e != nil {
			return e
		}
		old, e := t.Task(id)
		if e == nil {
			if old.Submission.ObjectID != object.ID || old.ObjectRevision != object.Revision {
				return ErrConflict
			}
			out = view(old)
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		task := Task{ContentOwner: object.Owner, ContentKind: object.Kind, ID: id, SchoolID: object.SchoolID, Owner: object.Owner, Submission: Submission{ObjectID: object.ID, Kind: "review", Reason: "content_review", Evidence: []string{}}, ObjectRevision: object.Revision, Revision: 1, State: "waiting", CreatedAt: s.now(), UpdatedAt: s.now()}
		if e = t.SaveTask(task); e != nil {
			return e
		}
		out = view(task)
		return nil
	})
	return out, err
}
func (s *Service) Get(ctx context.Context, p Principal, id string) (TaskView, error) {
	var out TaskView
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		task, e := t.Task(id)
		if e != nil {
			return e
		}
		if (task.Owner != p.Subject && task.ContentOwner != p.Subject) || p.Subject == "" {
			if e = s.auth(ctx, p, "manage", task.SchoolID); e != nil {
				return ErrNotFound
			}
		}
		out = viewFor(p, task)
		if task.ContentOwner == p.Subject && task.Owner != p.Subject {
			out = recipientView(p, task)
		}
		return nil
	})
	return out, err
}
func (s *Service) List(ctx context.Context, p Principal, school, state, after string, limit int, admin bool) ([]TaskView, error) {
	return s.FilteredList(ctx, p, TaskFilter{School: school, State: state, After: after, Limit: limit, Admin: admin})
}
func (s *Service) Decide(ctx context.Context, p Principal, id, key string, in Decide) (TaskView, error) {
	var out TaskView
	d := in.Decision
	if !keyOK(key) || in.Revision < 1 || !slices.Contains([]string{"publish", "hide", "restore", "delete", "edit", "identity", "dismiss", "feature", "unfeature", "reassign"}, d.Action) || strings.TrimSpace(d.Reason) == "" || !textOK(d.Reason, 2000) || d.Body != nil && !textOK(*d.Body, 16000) {
		return out, ErrInput
	}
	rk := digest([]string{p.Subject, "decide", id, key})
	h := digest(in)
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
		if task.Revision != in.Revision || task.State != "waiting" {
			return ErrConflict
		}
		object, e := s.Content.Inspect(ctx, p, task.Submission.ObjectID)
		if e != nil {
			return e
		}
		if object.SchoolID != task.SchoolID || object.Revision != d.Revision || d.ObjectID != object.ID {
			return ErrConflict
		}
		d.ID = rk
		task.Decision = &d
		task.DecidedBy = p.Subject
		now := s.now()
		task.DecidedAt = &now
		task.State = "decided"
		if d.Action == "dismiss" {
			task.State = "applied"
		}
		task.Revision++
		task.UpdatedAt = s.now()
		task.NextAttempt = s.now()
		if e = t.SaveTask(task); e != nil {
			return e
		}
		if e = s.record(t, rk, h, "decided", p, task); e != nil {
			return e
		}
		out = viewFor(p, task)
		return nil
	})
	return out, err
}
func (s *Service) SetPolicy(ctx context.Context, p Principal, key string, policy Policy) error {
	if !keyOK(key) {
		return ErrInput
	}
	replayKey := digest([]string{p.Subject, "policy", policy.SchoolID, policy.Kind, key})
	requestHash := digest(policy)
	if policy.SchoolID == "" || !slices.Contains([]string{"course", "mentor", "reply"}, policy.Kind) || !slices.Contains([]string{"published", "pending", "review"}, policy.Mode) || len(policy.BlockedTerms) > 100 {
		return ErrInput
	}
	for _, term := range policy.BlockedTerms {
		if strings.TrimSpace(term) == "" || !textOK(term, 100) {
			return ErrInput
		}
	}
	if e := s.auth(ctx, p, "configure", policy.SchoolID); e != nil {
		return e
	}
	return s.Repo.Transaction(ctx, func(t Transaction) error {
		if e := t.Lock("policy:" + policy.SchoolID + ":" + policy.Kind); e != nil {
			return e
		}
		cached, err := t.Replay(replayKey)
		if err == nil && s.now().Before(cached.Until) {
			if cached.Digest != requestHash {
				return ErrConflict
			}
			return nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		old, e := t.Policy(policy.SchoolID, policy.Kind)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if old.Revision != policy.Revision {
			return ErrConflict
		}
		policy.Revision++
		if e = t.SavePolicy(policy); e != nil {
			return e
		}
		if e := t.Event(Event{ID: digest(policy), Type: "moderation.policy.v1", Subject: "policy/" + policy.SchoolID + "/" + policy.Kind, SchoolID: policy.SchoolID, Actor: p.Subject, Revision: policy.Revision, At: s.now()}); e != nil {
			return e
		}
		return t.SaveReplay(replayKey, Replay{Digest: requestHash, Until: s.now().Add(24 * time.Hour)})
	})
}

func viewFor(p Principal, task Task) TaskView {
	out := view(task)
	out.CanAppeal = p.Subject != "" && task.ContentOwner == p.Subject && task.Decision != nil && (task.State == "applied" || task.State == "failed")
	return out
}

func recipientView(p Principal, task Task) TaskView {
	out := viewFor(p, task)
	if task.ContentOwner == p.Subject && task.Owner != p.Subject {
		out.Submission.Reason = "content_review"
		out.Submission.Evidence = []string{}
		out.Submission.ProposedBody = ""
	}
	return out
}
