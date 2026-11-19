package moderation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Service struct {
	Repo    Repository
	Content Content
	Access  Access
	Clock   func() time.Time
}

func (s *Service) now() time.Time {
	if s != nil && s.Clock != nil {
		return s.Clock().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}
func (s *Service) tx(ctx context.Context, run func(Transaction) error) error {
	if s == nil || s.Repo == nil {
		return ErrUnavailable
	}
	return s.Repo.Transaction(ctx, run)
}
func (s *Service) inspect(ctx context.Context, p Principal, id string) (Object, error) {
	if s == nil || s.Content == nil {
		return Object{}, ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.Content.Inspect(call, p, id)
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func keyOK(v string) bool {
	if len(v) < 1 || len(v) > 128 || strings.TrimSpace(v) == "" {
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

type RelatedTaskTransaction interface {
	RelatedWaitingCounts(school string, objectIDs []string) (map[string]int, error)
	WaitingReportsByObject(school, objectID string, maxObjectRevision int64, excludeID string) ([]Task, error)
	HasDecidedTaskOnObject(school, objectID, excludeID string) (bool, error)
}

func cleanToken(v string, max int) bool {
	if len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validateDecision(d Decision) bool {
	if !keyOK(d.ObjectID) || d.Revision < 1 || !slices.Contains([]string{"approve_append", "reject_append", "publish", "hide", "restore", "delete", "edit", "identity", "dismiss", "feature", "unfeature", "reassign"}, d.Action) || strings.TrimSpace(d.Reason) == "" || !textOK(d.Reason, 2000) {
		return false
	}
	appendAction := d.Action == "approve_append" || d.Action == "reject_append"
	if appendAction != (d.AppendID != "") || (appendAction && !keyOK(d.AppendID)) {
		return false
	}
	if d.Body != nil && !textOK(*d.Body, 16000) {
		return false
	}
	if !cleanToken(d.AuthorHandle, 128) || !cleanToken(d.Subject, 256) || !cleanToken(d.EvidenceRevision, 256) || (d.TeacherID != "" && !keyOK(d.TeacherID)) {
		return false
	}
	switch d.Action {
	case "edit":
		return d.Body != nil && strings.TrimSpace(*d.Body) != ""
	case "reassign":
		return strings.TrimSpace(d.EvidenceRevision) != ""
	case "identity":
		return (strings.TrimSpace(d.Subject) != "") != (strings.TrimSpace(d.AuthorHandle) != "")
	}
	return true
}
func canDecideTask(task Task, revision int64) bool {
	if task.Revision != revision {
		return false
	}
	return task.State == "waiting" || (task.State == "failed" && (task.ErrorCode == "conflict" || task.ErrorCode == "forbidden"))
}
func validateDecisionTarget(object Object, task Task, d Decision) error {
	if task.Submission.AppendID != d.AppendID {
		return ErrInput
	}
	if object.Kind == "resource" && !slices.Contains([]string{"publish", "hide", "restore", "delete", "dismiss"}, d.Action) {
		return ErrInput
	}
	if object.SchoolID != task.SchoolID || object.Revision != d.Revision || d.ObjectID != object.ID {
		return ErrConflict
	}
	return nil
}
func publicDecision(d *Decision) *Decision {
	if d == nil {
		return nil
	}
	safe := Decision{AppendID: d.AppendID, ID: d.ID, ObjectID: d.ObjectID, Revision: d.Revision, Action: d.Action, Reason: d.Reason}
	if d.Action == "reassign" {
		safe.TeacherID = d.TeacherID
	}
	return &safe
}
func view(t Task) TaskView {
	decision := publicDecision(t.Decision)
	sub := t.Submission
	if sub.Evidence == nil {
		sub.Evidence = []string{}
	}
	return TaskView{
		PreviousTaskID: sub.PreviousTaskID,
		ContentKind:    t.ContentKind,
		ID:             t.ID,
		SchoolID:       t.SchoolID,
		Submission:     sub,
		ObjectRevision: t.ObjectRevision,
		Revision:       t.Revision,
		State:          t.State,
		CreatedAt:      t.CreatedAt,
		UpdatedAt:      t.UpdatedAt,
		Decision:       decision,
		ErrorCode:      t.ErrorCode,
	}
}

func relatedWaitingCountFor(t Transaction, task Task) (*int, error) {
	port, ok := t.(RelatedTaskTransaction)
	if !ok {
		return nil, nil
	}
	counts, err := port.RelatedWaitingCounts(task.SchoolID, []string{task.Submission.ObjectID})
	if err != nil {
		return nil, err
	}
	n := counts[task.Submission.ObjectID]
	if task.State == "waiting" && n > 0 {
		n--
	}
	return &n, nil
}

func (s *Service) resolveRelatedReports(t Transaction, primary Task) error {
	if primary.Decision == nil || primary.Submission.AppendID != "" {
		return nil
	}
	port, ok := t.(RelatedTaskTransaction)
	if !ok {
		return nil
	}
	siblings, err := port.WaitingReportsByObject(primary.SchoolID, primary.Submission.ObjectID, primary.Decision.Revision, primary.ID)
	if err != nil {
		return err
	}
	for _, candidate := range siblings {
		if err = t.Lock(candidate.ID); err != nil {
			return err
		}
		sib, err := t.Task(candidate.ID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return err
		}
		if sib.State != "waiting" || sib.Submission.Kind != "report" || sib.ObjectRevision > primary.Decision.Revision {
			continue
		}
		linked := *primary.Decision
		now := s.now()
		sib.Decision = &linked
		sib.DecidedBy = primary.DecidedBy
		sib.DecidedAt = primary.DecidedAt
		if sib.DecidedAt == nil {
			sib.DecidedAt = &now
		}
		sib.State = "applied"
		sib.ErrorCode = ""
		sib.LeaseUntil = time.Time{}
		sib.Revision++
		sib.UpdatedAt = now
		if err = t.SaveTask(sib); err != nil {
			return err
		}
		if err = s.recordResult(t, sib); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) auth(ctx context.Context, p Principal, action, school string) error {
	if p.Subject == "" {
		return ErrForbidden
	}
	if s == nil || s.Access == nil {
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
	r.View.Decision = publicDecision(r.View.Decision)
	return r.View, true, nil
}
func allocateTaskID(t Transaction, base string, now time.Time) (string, error) {
	_, e := t.Task(base)
	if errors.Is(e, ErrNotFound) {
		return base, nil
	}
	if e != nil {
		return "", e
	}
	return digest([]string{base, strconv.FormatInt(now.UnixNano(), 10)}), nil
}
func (s *Service) recordWithView(t Transaction, key, hash, action string, p Principal, task Task, v TaskView) error {
	result := "success"
	if action == "decided" {
		result = "unknown"
	}
	var data *ResultData
	if action == "decided" {
		data = resultData(task)
	}
	now := s.now()
	eventID := digest([]string{"event", key, task.ID, action, strconv.FormatInt(task.Revision, 10)})
	if e := t.Event(Event{Result: result, Data: data, ID: eventID, Type: "moderation." + action + ".v1", Subject: "task/" + task.ID, SchoolID: task.SchoolID, Actor: p.Subject, Revision: task.Revision, At: now}); e != nil {
		return e
	}
	return t.SaveReplay(key, Replay{Digest: hash, TaskID: task.ID, View: v, Until: now.Add(24 * time.Hour)})
}
func (s *Service) record(t Transaction, key, hash, action string, p Principal, task Task) error {
	return s.recordWithView(t, key, hash, action, p, task, viewFor(p, task))
}

func (s *Service) upsertSubmissionTx(t Transaction, p Principal, operation, payload string, in Submission, object *Object, missingObjectErr error, beforeSave func(Transaction) error) (TaskView, error) {
	var out TaskView
	if e := t.Lock(digest([]string{p.Subject, in.Kind, in.ObjectID})); e != nil {
		return out, e
	}
	now := s.now()
	cached, found, e := replay(t, operation, payload, now)
	if errors.Is(e, ErrConflict) && len(in.Evidence) == 0 {
		// Older receipts hashed omitted evidence as null instead of an empty array.
		legacy := in
		legacy.Evidence = nil
		cached, found, e = replay(t, operation, digest(legacy), now)
	}
	if e != nil {
		return out, e
	}
	if found {
		return cached, nil
	}
	if in.Kind == "appeal" {
		if e := t.Lock("appeal:" + in.PreviousTaskID); e != nil {
			return out, e
		}
		previous, e := t.Task(in.PreviousTaskID)
		if e != nil {
			return out, e
		}
		in.AppendID = previous.Submission.AppendID
		if previous.Submission.ObjectID != in.ObjectID || previous.Submission.Kind == "appeal" || previous.Decision == nil || previous.State != "applied" {
			return out, ErrConflict
		}
	}
	task, e := t.Active(p.Subject, in.ObjectID, in.Kind)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return out, e
	}
	if errors.Is(e, ErrNotFound) {
		if object == nil {
			return out, missingObjectErr
		}
		if in.Evidence == nil {
			in.Evidence = []string{}
		}
		if in.Kind == "appeal" {
			appealed, e := appealedTasks(t, []string{in.PreviousTaskID})
			if e != nil {
				return out, e
			}
			if appealed[in.PreviousTaskID] {
				return out, ErrConflict
			}
		}
		now := s.now()
		taskID, err := allocateTaskID(t, operation, now)
		if err != nil {
			return out, err
		}
		task = Task{
			ContentOwner:   object.Owner,
			ContentKind:    object.Kind,
			ID:             taskID,
			SchoolID:       object.SchoolID,
			Owner:          p.Subject,
			Submission:     in,
			ObjectRevision: object.Revision,
			State:          "waiting",
			CreatedAt:      now,
		}
	} else {
		if e = t.Lock(task.ID); e != nil {
			return out, e
		}
		task, e = t.Task(task.ID)
		if e != nil {
			return out, e
		}
		if task.State != "waiting" || (in.Kind == "appeal" && task.Submission.PreviousTaskID != in.PreviousTaskID) {
			return out, ErrConflict
		}
		if task.Submission.Evidence == nil {
			task.Submission.Evidence = []string{}
		}
		if in.Reason != task.Submission.Reason {
			task.Submission.Evidence = append(task.Submission.Evidence, in.Reason)
		}
		task.Submission.Evidence = append(task.Submission.Evidence, in.Evidence...)
		if len(task.Submission.Evidence) > 20 {
			return out, ErrInput
		}
		if in.Kind == "edit_request" {
			task.Submission.ProposedBody = in.ProposedBody
		}
	}
	if beforeSave != nil {
		if e = beforeSave(t); e != nil {
			return out, e
		}
	}
	task.Revision++
	task.UpdatedAt = s.now()
	if e = t.SaveTask(task); e != nil {
		return out, e
	}
	out = viewFor(p, task)
	if e = s.recordWithView(t, operation, payload, "submitted", p, task, out); e != nil {
		return out, e
	}
	return out, nil
}

type retentionRepository interface {
	Cleanup(context.Context, time.Time, int) error
}

// Cleanup removes expired idempotency replays (24h), rate-limit windows (24h),
// confirmed outbox rows (90d), and non-feedback audit records (12m) in bounded batches.
func (s *Service) Cleanup(ctx context.Context, limit int) error {
	if limit == 0 {
		limit = 200
	}
	if limit < 1 || limit > 500 {
		return ErrInput
	}
	cleaner, ok := s.Repo.(retentionRepository)
	if !ok {
		return ErrUnavailable
	}
	return cleaner.Cleanup(ctx, s.now(), limit)
}

// Check is read-only. Pending content is handed off by the content module's outbox.
func (s *Service) Check(ctx context.Context, school, kind, title, body string) (string, error) {
	if !slices.Contains([]string{"course", "mentor", "reply", "resource"}, kind) {
		return "", ErrInput
	}
	var policy Policy
	err := s.tx(ctx, func(t Transaction) error {
		view, err := effectivePolicy(t, school, kind)
		policy = view.Effective
		return err
	})
	if err != nil {
		return "", err
	}
	matched := matchedBlockedTerms(policy.BlockedTerms, title, body)
	if len(matched) > 0 {
		return "blocked", nil
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
	if in.AppendID != "" || !keyOK(key) || in.ObjectID == "" || len(in.ObjectID) > 128 || !slices.Contains([]string{"report", "edit_request", "delete_request", "review", "appeal"}, in.Kind) || strings.TrimSpace(in.Reason) == "" || !textOK(in.Reason, 2000) || !textOK(in.ProposedBody, 16000) || len(in.Evidence) > 5 {
		return out, ErrInput
	}
	for _, v := range in.Evidence {
		if !textOK(v, 2000) {
			return out, ErrInput
		}
	}
	if in.Evidence == nil {
		in.Evidence = []string{}
	}
	if in.Kind == "report" {
		if in.PreviousTaskID != "" {
			return out, ErrInput
		}
		return s.submitReport(ctx, p, key, in)
	}
	object, e := s.inspect(ctx, p, in.ObjectID)
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
		if !keyOK(in.PreviousTaskID) {
			return out, ErrInput
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
	err := s.tx(ctx, func(t Transaction) error {
		var txErr error
		out, txErr = s.upsertSubmissionTx(t, p, rk, h, in, &object, ErrUnavailable, nil)
		return txErr
	})
	return out, err
}

// Track accepts a durable content event, without copying full content into public records.
func (s *Service) Track(ctx context.Context, eventID string, object Object) (TaskView, error) {
	var out TaskView
	if !keyOK(eventID) || !keyOK(object.ID) || !keyOK(object.SchoolID) || strings.TrimSpace(object.Owner) == "" || !textOK(object.Owner, 256) || object.Revision < 1 || (object.Kind != "" && !slices.Contains([]string{"course", "mentor", "reply", "resource"}, object.Kind)) {
		return out, ErrInput
	}
	id := digest([]string{"content", eventID})
	if object.AppendID != "" {
		if !keyOK(object.AppendID) || (object.Kind != "course" && object.Kind != "mentor") {
			return out, ErrInput
		}
		id = digest([]string{"append", object.ID, object.AppendID})
	}
	err := s.tx(ctx, func(t Transaction) error {
		if e := t.Lock(id); e != nil {
			return e
		}
		old, e := t.Task(id)
		if e == nil {
			if old.Submission.ObjectID != object.ID || old.Submission.AppendID != object.AppendID || (object.AppendID == "" && old.ObjectRevision != object.Revision) {
				return ErrConflict
			}
			out = view(old)
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		task := Task{ContentOwner: object.Owner, ContentKind: object.Kind, ID: id, SchoolID: object.SchoolID, Owner: object.Owner, Submission: Submission{AppendID: object.AppendID, ObjectID: object.ID, Kind: "review", Reason: "content_review", Evidence: []string{}}, ObjectRevision: object.Revision, Revision: 1, State: "waiting", CreatedAt: s.now(), UpdatedAt: s.now()}
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
	err := s.tx(ctx, func(t Transaction) error {
		task, e := t.Task(id)
		if e != nil {
			return e
		}
		isAdmin := false
		if (task.Owner != p.Subject && task.ContentOwner != p.Subject) || p.Subject == "" {
			if e = s.auth(ctx, p, "manage", task.SchoolID); e != nil {
				return ErrNotFound
			}
			isAdmin = true
		} else if !(task.ContentOwner == p.Subject && task.Owner != p.Subject) {
			isAdmin = s.auth(ctx, p, "manage", task.SchoolID) == nil
		}
		out = viewFor(p, task)
		if task.ContentOwner == p.Subject && task.Owner != p.Subject {
			out = recipientView(p, task)
		}
		if isAdmin {
			count, err := relatedWaitingCountFor(t, task)
			if err != nil {
				return err
			}
			out.RelatedWaitingCount = count
		}
		if out.CanAppeal {
			appealed, e := appealedTasks(t, []string{task.ID})
			if e != nil {
				return e
			}
			if appealed[task.ID] {
				out.CanAppeal = false
			}
		}
		return nil
	})
	return out, err
}
func (s *Service) List(ctx context.Context, p Principal, school, state, after string, limit int, admin bool) ([]TaskView, error) {
	return s.FilteredList(ctx, p, TaskFilter{School: school, State: state, After: after, Limit: limit, Admin: admin})
}
func isSelfFavorableDecision(p Principal, task Task, objectOwner, action string) bool {
	if p.Subject == "" || (task.ContentOwner != p.Subject && objectOwner != p.Subject) {
		return false
	}
	switch action {
	case "publish", "restore", "feature", "approve_append":
		return true
	case "dismiss":
		return task.Owner != p.Subject
	default:
		return false
	}
}

func (s *Service) Decide(ctx context.Context, p Principal, id, key string, in Decide) (TaskView, error) {
	var out TaskView
	d := in.Decision
	if !keyOK(key) || in.Revision < 1 || !validateDecision(d) {
		return out, ErrInput
	}
	rk := digest([]string{p.Subject, "decide", id, key})
	h := digest(in)
	err := s.tx(ctx, func(t Transaction) error {
		initial, e := t.Task(id)
		if e != nil {
			return e
		}
		if e = t.Lock("object:" + initial.SchoolID + ":" + initial.Submission.ObjectID); e != nil {
			return e
		}
		if e = t.Lock(id); e != nil {
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
		if !canDecideTask(task, in.Revision) {
			return ErrConflict
		}
		if port, ok := t.(RelatedTaskTransaction); ok {
			inFlight, err := port.HasDecidedTaskOnObject(task.SchoolID, task.Submission.ObjectID, task.ID)
			if err != nil {
				return err
			}
			if inFlight {
				return ErrConflict
			}
		}
		object, e := s.inspect(ctx, p, task.Submission.ObjectID)
		if e != nil {
			return e
		}
		if isSelfFavorableDecision(p, task, object.Owner, d.Action) {
			if e = s.auth(ctx, p, "self_approve", "*"); e != nil {
				return e
			}
		}
		if e = validateDecisionTarget(object, task, d); e != nil {
			return e
		}
		d.ID = rk
		task.Decision = &d
		task.DecidedBy = p.Subject
		task.RetriedBy = ""
		task.ErrorCode = ""
		task.Attempts = 0
		task.LeaseUntil = time.Time{}
		now := s.now()
		task.DecidedAt = &now
		task.State = "decided"
		task.Revision++
		task.UpdatedAt = now
		task.NextAttempt = now
		if d.Action == "dismiss" {
			if e = t.Event(Event{Result: "unknown", Data: resultData(task), ID: rk, Type: "moderation.decided.v1", Subject: "task/" + task.ID, SchoolID: task.SchoolID, Actor: p.Subject, Revision: task.Revision, At: now}); e != nil {
				return e
			}
			task.State = "applied"
			task.Revision++
			if e = t.SaveTask(task); e != nil {
				return e
			}
			if e = s.recordResult(t, task); e != nil {
				return e
			}
			if task.Submission.Kind == "report" || task.Submission.Kind == "review" {
				if e = s.resolveRelatedReports(t, task); e != nil {
					return e
				}
			}
		} else if e = t.SaveTask(task); e != nil {
			return e
		}
		out = viewFor(p, task)
		count, err := relatedWaitingCountFor(t, task)
		if err != nil {
			return err
		}
		out.RelatedWaitingCount = count
		if d.Action == "dismiss" {
			return t.SaveReplay(rk, Replay{Digest: h, TaskID: task.ID, View: out, Until: now.Add(24 * time.Hour)})
		}
		if e = s.recordWithView(t, rk, h, "decided", p, task, out); e != nil {
			return e
		}
		return nil
	})
	return out, err
}
func (s *Service) SetPolicy(ctx context.Context, p Principal, key string, policy Policy) error {
	if !keyOK(key) {
		return ErrInput
	}
	legacyHash := digest(policy)
	if !keyOK(policy.SchoolID) || !slices.Contains([]string{"course", "mentor", "reply", "resource"}, policy.Kind) || !slices.Contains([]string{"published", "pending", "review"}, policy.Mode) {
		return ErrInput
	}
	normalized, err := normalizeBlockedTerms(policy.BlockedTerms)
	if err != nil {
		return err
	}
	policy.BlockedTerms = normalized
	replayKey := digest([]string{p.Subject, "policy", policy.SchoolID, policy.Kind, key})
	requestHash := digest(policy)
	if e := s.auth(ctx, p, "configure", policy.SchoolID); e != nil {
		return e
	}
	return s.tx(ctx, func(t Transaction) error {
		if e := t.Lock("policy:" + policy.SchoolID + ":" + policy.Kind); e != nil {
			return e
		}
		cached, err := t.Replay(replayKey)
		if err == nil && s.now().Before(cached.Until) {
			if cached.Digest != requestHash && cached.Digest != legacyHash {
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
		if e := t.Event(Event{Result: "success", ID: digest(policy), Type: "moderation.policy.v1", Subject: "policy/" + policy.SchoolID + "/" + policy.Kind, SchoolID: policy.SchoolID, Actor: p.Subject, Revision: policy.Revision, At: s.now()}); e != nil {
			return e
		}
		return t.SaveReplay(replayKey, Replay{Digest: requestHash, Until: s.now().Add(24 * time.Hour)})
	})
}

type appealLookupTransaction interface {
	HasAppeals([]string) (map[string]bool, error)
}

func appealedTasks(t Transaction, ids []string) (map[string]bool, error) {
	port, ok := t.(appealLookupTransaction)
	if !ok || len(ids) == 0 {
		return map[string]bool{}, nil
	}
	return port.HasAppeals(ids)
}

func viewFor(p Principal, task Task) TaskView {
	out := view(task)
	out.CanAppeal = p.Subject != "" && task.ContentOwner == p.Subject && task.Decision != nil && task.State == "applied" && task.Submission.Kind != "appeal"
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
