package moderation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

type TaskFilter struct {
	Owner, School, State, After, Order, Kind, ContentKind, ObjectID string
	From, Until, CursorAt                                           *time.Time
	CursorID                                                        string
	Limit                                                           int
	Admin                                                           bool
}

type TaskPage struct {
	Items      []TaskView `json:"items"`
	NextCursor string     `json:"next_cursor"`
}

type QueueContentCounts struct {
	Course   int `json:"course"`
	Mentor   int `json:"mentor"`
	Reply    int `json:"reply"`
	Resource int `json:"resource"`
}

type QueueRequestCounts struct {
	Review        int `json:"review"`
	Report        int `json:"report"`
	EditRequest   int `json:"edit_request"`
	DeleteRequest int `json:"delete_request"`
	Appeal        int `json:"appeal"`
}

type QueueSummary struct {
	SchoolID      string             `json:"school_id"`
	Waiting       int                `json:"waiting"`
	Decided       int                `json:"decided"`
	Failed        int                `json:"failed"`
	ByContentKind QueueContentCounts `json:"by_content_kind"`
	ByRequestKind QueueRequestCounts `json:"by_request_kind"`
}

type QueuePaginationTransaction interface {
	TaskCursorAnchor(id string) (createdAt, updatedAt time.Time, err error)
	QueueSummary(school string) (QueueSummary, error)
}

type taskCursorPayload struct {
	Order string `json:"o"`
	Micro int64  `json:"u"`
	ID    string `json:"i"`
}

func encodeTaskCursor(order string, at time.Time, id string) string {
	raw, _ := json.Marshal(taskCursorPayload{
		Order: order,
		Micro: at.UTC().Truncate(time.Microsecond).UnixMicro(),
		ID:    id,
	})
	return "t1." + base64.RawURLEncoding.EncodeToString(raw)
}

func decodeTaskCursor(token, expectedOrder string) (time.Time, string, bool, error) {
	if token == "" {
		return time.Time{}, "", false, nil
	}
	if !strings.HasPrefix(token, "t1.") {
		if !keyOK(token) {
			return time.Time{}, "", false, ErrInput
		}
		return time.Time{}, token, false, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "t1."))
	if err != nil {
		return time.Time{}, "", true, ErrInput
	}
	var p taskCursorPayload
	if err = json.Unmarshal(raw, &p); err != nil || p.Order != expectedOrder || !keyOK(p.ID) {
		return time.Time{}, "", true, ErrInput
	}
	return time.UnixMicro(p.Micro).UTC(), p.ID, true, nil
}

func (s *Service) FilteredPage(ctx context.Context, p Principal, f TaskFilter) (TaskPage, error) {
	out := TaskPage{Items: []TaskView{}}
	if p.Subject == "" {
		return out, ErrForbidden
	}
	if f.Limit < 1 || f.Limit > 100 || len(f.After) > 256 || len(f.ObjectID) > 128 || f.From != nil && f.Until != nil && !f.From.Before(*f.Until) {
		return out, ErrInput
	}
	if f.State != "" && !slices.Contains([]string{"waiting", "decided", "applied", "failed"}, f.State) {
		return out, ErrInput
	}
	if f.Order != "" && !slices.Contains([]string{"oldest", "newest", "updated_desc"}, f.Order) {
		return out, ErrInput
	}
	if f.Kind != "" && !slices.Contains([]string{"review", "report", "edit_request", "delete_request", "appeal"}, f.Kind) {
		return out, ErrInput
	}
	if f.ContentKind != "" && !slices.Contains([]string{"course", "mentor", "reply", "resource"}, f.ContentKind) {
		return out, ErrInput
	}
	f.Owner = p.Subject
	if f.Admin {
		if f.School == "" || !keyOK(f.School) {
			return out, ErrInput
		}
		if err := s.auth(ctx, p, "manage", f.School); err != nil {
			return out, err
		}
		f.Owner = ""
	}
	effectiveOrder := f.Order
	if effectiveOrder == "" {
		if f.Admin {
			effectiveOrder = "oldest"
		} else {
			effectiveOrder = "updated_desc"
		}
	}
	cursorAt, cursorID, isComposite, err := decodeTaskCursor(f.After, effectiveOrder)
	if err != nil {
		return out, err
	}
	pageLimit := f.Limit
	f.Order = effectiveOrder
	f.Limit = pageLimit + 1
	err = s.Repo.Transaction(ctx, func(t Transaction) error {
		if f.After != "" {
			if isComposite {
				at := cursorAt
				f.CursorAt = &at
				f.CursorID = cursorID
			} else if port, ok := t.(QueuePaginationTransaction); ok {
				createdAt, updatedAt, anchorErr := port.TaskCursorAnchor(cursorID)
				if errors.Is(anchorErr, ErrNotFound) {
					return ErrInput
				}
				if anchorErr != nil {
					return anchorErr
				}
				at := createdAt
				if effectiveOrder == "updated_desc" {
					at = updatedAt
				}
				f.CursorAt = &at
				f.CursorID = cursorID
			}
		}
		tasks, e := t.FilteredTasks(f)
		if e != nil {
			return e
		}
		if len(tasks) > pageLimit {
			last := tasks[pageLimit-1]
			anchorTime := last.CreatedAt
			if effectiveOrder == "updated_desc" {
				anchorTime = last.UpdatedAt
			}
			out.NextCursor = encodeTaskCursor(effectiveOrder, anchorTime, last.ID)
			tasks = tasks[:pageLimit]
		}
		for _, task := range tasks {
			v := viewFor(p, task)
			if !f.Admin {
				v = recipientView(p, task)
			}
			out.Items = append(out.Items, v)
		}
		return nil
	})
	return out, err
}

func (s *Service) FilteredList(ctx context.Context, p Principal, f TaskFilter) ([]TaskView, error) {
	page, err := s.FilteredPage(ctx, p, f)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *Service) QueueSummary(ctx context.Context, p Principal, school string) (QueueSummary, error) {
	var out QueueSummary
	if p.Subject == "" {
		return out, ErrForbidden
	}
	if !keyOK(school) {
		return out, ErrInput
	}
	if err := s.auth(ctx, p, "manage", school); err != nil {
		return out, err
	}
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		port, ok := t.(QueuePaginationTransaction)
		if !ok {
			return ErrUnavailable
		}
		var err error
		out, err = port.QueueSummary(school)
		return err
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
	for _, item := range in.Items {
		result := BatchOutcome{ID: item.ID, State: "ready"}
		task, e := s.Get(ctx, p, item.ID)
		if e == nil {
			e = s.auth(ctx, p, "manage", task.SchoolID)
		}
		if e == nil && (task.State != "waiting" || task.Revision != item.Revision) {
			e = ErrConflict
		}
		if e == nil {
			object, err := s.Content.Inspect(ctx, p, task.Submission.ObjectID)
			e = err
			if e == nil && (object.ID != item.Decision.ObjectID || object.Revision != item.Decision.Revision) {
				e = ErrConflict
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
	for _, item := range in.Items {
		task, e := s.Decide(ctx, p, item.ID, digest([]string{rk, item.ID}), Decide{Revision: item.Revision, Decision: item.Decision})
		result := BatchOutcome{ID: item.ID, State: task.State}
		if e != nil {
			result.State = "rejected"
			result.Code = errorCode(e)
		}
		out.Items = append(out.Items, result)
	}
	return out, nil
}
