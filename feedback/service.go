package feedback

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type feedbackCursorPayload struct {
	Micro int64  `json:"u"`
	ID    string `json:"i"`
}

func encodeFeedbackCursor(at time.Time, id string) string {
	raw, _ := json.Marshal(feedbackCursorPayload{
		Micro: at.UTC().Truncate(time.Microsecond).UnixMicro(),
		ID:    id,
	})
	return "f1." + base64.RawURLEncoding.EncodeToString(raw)
}

func decodeFeedbackCursor(token string) (time.Time, string, bool, error) {
	if token == "" {
		return time.Time{}, "", false, nil
	}
	if !strings.HasPrefix(token, "f1.") {
		if prefix, id, ok := strings.Cut(token, ":"); ok {
			ns, err := strconv.ParseInt(prefix, 10, 64)
			if err != nil || id == "" || !validClean(id, 128) {
				return time.Time{}, "", true, ErrInvalid
			}
			return time.Unix(0, ns).UTC(), id, true, nil
		}
		if len(token) > 128 || !validText(token, 128) || strings.TrimSpace(token) == "" {
			return time.Time{}, "", false, ErrInvalid
		}
		return time.Time{}, token, false, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "f1."))
	if err != nil {
		return time.Time{}, "", true, ErrInvalid
	}
	var p feedbackCursorPayload
	if err = json.Unmarshal(raw, &p); err != nil || p.ID == "" || len(p.ID) > 128 || !validText(p.ID, 128) {
		return time.Time{}, "", true, ErrInvalid
	}
	return time.UnixMicro(p.Micro).UTC(), p.ID, true, nil
}

func Digest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func validText(v string, max int) bool {
	return len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func validIdentifier(v string, max int) bool {
	if len(v) > max || !utf8.ValidString(v) || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func validASCIIKey(v string, max int) bool {
	if len(v) > max {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= 32 || v[i] > 126 {
			return false
		}
	}
	return true
}
func validClean(v string, max int) bool {
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
func validSubject(v string, max int) bool {
	if len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r == 0 || r == '\r' || r == '\n' || (unicode.IsControl(r) && r != '\t') {
			return false
		}
	}
	return true
}
func validState(v string) bool {
	return v == "new" || v == "processing" || v == "resolved" || v == "spam"
}

type caseLocker interface {
	LockCase(string) error
}

func lockCase(tx Tx, id string) error {
	if locker, ok := tx.(caseLocker); ok {
		return locker.LockCase(id)
	}
	return tx.Lock()
}

func validIdempotencyKey(v string) bool {
	if len(v) < 8 || len(v) > 128 || strings.TrimSpace(v) == "" {
		return false
	}
	for _, c := range v {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
func (s *Service) allowed(ctx context.Context, actor, action string) error {
	if actor == "" || s.Access == nil {
		return ErrDenied
	}
	return s.Access.Check(ctx, actor, "moderation.feedback."+action)
}

func normalizeAndValidateInput(in Input, requireParts bool) (Message, error) {
	v := in.Message
	addr, e := mail.ParseAddress(v.Sender)
	if e != nil || addr.Address == "" || !validClean(addr.Address, 320) {
		return Message{}, ErrInvalid
	}
	v.Sender = strings.ToLower(addr.Address)
	if len(v.Dedupe) != 64 || !validSubject(v.Subject, 500) || !validClean(v.MessageID, 998) || !validText(v.Body, 200000) || !validText(v.AuthenticationResults, 4096) || len(v.Attachments) > 10 || v.Bytes < 0 || v.Bytes > 12<<20 {
		return Message{}, ErrInvalid
	}
	seen := make(map[string]bool, len(v.Attachments))
	var storedBytes int64
	for _, a := range v.Attachments {
		if a.ID == "" || seen[a.ID] || !validClean(a.ID, 256) || !validClean(a.Name, 256) || !validClean(a.ContentType, 256) {
			return Message{}, ErrInvalid
		}
		seen[a.ID] = true
		switch a.Status {
		case "stored":
			if a.Size < 0 || a.Size > 5<<20 {
				return Message{}, ErrInvalid
			}
			if requireParts || in.Parts != nil {
				data, ok := in.Parts[a.ID]
				if !ok || int64(len(data)) != a.Size {
					return Message{}, ErrInvalid
				}
			}
			storedBytes += a.Size
		case "rejected":
			if a.Size < 0 || a.Size > 12<<20 {
				return Message{}, ErrInvalid
			}
		default:
			return Message{}, ErrInvalid
		}
	}
	if v.Bytes < int64(len(v.Body))+storedBytes {
		return Message{}, ErrInvalid
	}
	return v, nil
}

// Stage reserves aggregate capacity and the sender's hourly budget atomically.
// Pending ingestion is durable before the first external attachment write.
func (s *Service) Stage(ctx context.Context, in Input) (Message, error) {
	v, err := normalizeAndValidateInput(in, false)
	if err != nil {
		return Message{}, err
	}
	v.ID = Digest("feedback:" + v.Dedupe)
	v.State = "new"
	v.Revision = 1
	v.ReceivedAt = s.now()
	v.Ready = false
	v.Replies = []Reply{}
	if v.Attachments == nil {
		v.Attachments = []Attachment{}
	}
	var out Message
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		if e := tx.Lock(); e != nil {
			return e
		}
		old, e := tx.Find(v.Dedupe)
		if e == nil {
			out = old
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		if e := lockCase(tx, v.ID); e != nil {
			return e
		}
		count, bytes, sender, e := tx.Usage(v.Sender, v.ReceivedAt.Add(-time.Hour))
		if e != nil {
			return e
		}
		if count >= 100000 || bytes+v.Bytes > 2<<30 {
			return ErrLimit
		}
		if sender >= 20 {
			v.State = "spam"
			v.Body = ""
			v.Attachments = []Attachment{}
			v.Bytes = 0
			v.Ready = true
			v.Suspicious = true
			now := s.now()
			v.ClosedAt = &now
		}
		if e = tx.Save(v); e != nil {
			return e
		}
		out = v
		return tx.Audit("mailbox", "ingest", v.ID, v.ReceivedAt)
	})
	return out, e
}
func (s *Service) Ingest(ctx context.Context, in Input) (Message, error) {
	if _, err := normalizeAndValidateInput(in, true); err != nil {
		return Message{}, err
	}
	for _, a := range in.Message.Attachments {
		if a.Status == "stored" && s.Blobs == nil {
			return Message{}, ErrUnavailable
		}
	}
	v, e := s.Stage(ctx, in)
	if e != nil || v.Ready {
		return v, e
	}
	for i, a := range v.Attachments {
		if a.Status == "rejected" {
			continue
		}
		if s.Blobs == nil {
			return v, ErrUnavailable
		}
		data, ok := in.Parts[a.ID]
		if !ok || int64(len(data)) != a.Size {
			return v, ErrInvalid
		}
		object, putErr := s.Blobs.Put(ctx, v.ID+":"+a.ID, a, data)
		if object == "" {
			return v, ErrUnavailable
		}
		// Persist each object before proceeding, so retention can recover partial work.
		e = s.Repo.Transaction(ctx, func(tx Tx) error {
			if e := lockCase(tx, v.ID); e != nil {
				return e
			}
			current, e := tx.Get(v.ID)
			if e != nil {
				return e
			}
			current.Attachments[i].ObjectID = object
			v = current
			return tx.Save(current)
		})
		if e != nil {
			return v, e
		}
		if putErr != nil {
			return v, ErrUnavailable
		}
	}
	e = s.Repo.Transaction(ctx, func(tx Tx) error {
		if e := lockCase(tx, v.ID); e != nil {
			return e
		}
		current, e := tx.Get(v.ID)
		if e != nil {
			return e
		}
		current.Ready = true
		v = current
		return tx.Save(current)
	})
	return v, e
}
func (s *Service) List(ctx context.Context, actor string, f Filter) (Page, error) {
	if e := s.allowed(ctx, actor, "read"); e != nil {
		return Page{}, e
	}
	if f.Limit == 0 {
		f.Limit = 25
	}
	if f.Limit < 1 || f.Limit > 50 || len(f.After) > 256 || (f.State != "" && !validState(f.State)) {
		return Page{}, ErrInvalid
	}
	if f.Assignee != nil && (*f.Assignee != "" && !validIdentifier(*f.Assignee, 256)) {
		return Page{}, ErrInvalid
	}
	cursorAt, cursorID, isComposite, err := decodeFeedbackCursor(f.After)
	if err != nil {
		return Page{}, err
	}
	now := s.now()
	f.Now = now
	out := Page{Items: []Message{}}
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		if f.After != "" {
			if isComposite {
				at := cursorAt
				f.CursorAt = &at
				f.CursorID = cursorID
			} else {
				anchor, err := tx.Get(cursorID)
				if errors.Is(err, ErrNotFound) || (err == nil && (!anchor.Ready || expired(anchor, now))) {
					return tx.Audit(actor, "list", "mailbox", now)
				}
				if err != nil {
					return err
				}
				at := anchor.ReceivedAt.UTC().Truncate(time.Microsecond)
				f.CursorAt = &at
				f.CursorID = cursorID
			}
		}
		rows, e := tx.List(f)
		if e != nil {
			return e
		}
		if len(rows) > f.Limit {
			last := rows[f.Limit-1]
			out.NextCursor = encodeFeedbackCursor(last.ReceivedAt, last.ID)
			rows = rows[:f.Limit]
		}
		for i := range rows {
			rows[i].Body = ""
			rows[i].AuthenticationResults = ""
			rows[i].Note = ""
			rows[i].Attachments = []Attachment{}
			rows[i].Replies = []Reply{}
		}
		out.Items = rows
		return tx.Audit(actor, "list", "mailbox", now)
	})
	return out, e
}
func (s *Service) Get(ctx context.Context, actor, id string) (Message, error) {
	if e := s.allowed(ctx, actor, "read"); e != nil {
		return Message{}, e
	}
	var out Message
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		v, e := tx.Get(id)
		if e != nil {
			return e
		}
		if !v.Ready || expired(v, s.now()) {
			return ErrNotFound
		}
		out = v
		return tx.Audit(actor, "read", id, s.now())
	})
	return out, e
}
func expired(v Message, now time.Time) bool {
	if v.ClosedAt == nil {
		return false
	}
	expiry := v.ClosedAt.AddDate(1, 0, 0)
	// PostgreSQL calendar-month intervals clamp leap day to February 28.
	// Use the same boundary for detail access and cleanup eligibility.
	if expiry.Month() != v.ClosedAt.Month() {
		expiry = expiry.AddDate(0, 0, -1)
	}
	return !expiry.After(now)
}
func (s *Service) Update(ctx context.Context, actor, id, key string, u Update) (Message, error) {
	if e := s.allowed(ctx, actor, "manage"); e != nil {
		return Message{}, e
	}
	if !validState(u.State) || u.Revision < 1 || !validText(u.Note, 10000) || !validIdempotencyKey(key) {
		return Message{}, ErrInvalid
	}
	if u.Assignee != nil && *u.Assignee != "" && !validIdentifier(*u.Assignee, 256) {
		return Message{}, ErrInvalid
	}
	if u.RelatedTaskID != nil && *u.RelatedTaskID != "" && !validASCIIKey(*u.RelatedTaskID, 128) {
		return Message{}, ErrInvalid
	}
	if u.RelatedObjectID != nil && *u.RelatedObjectID != "" && !validASCIIKey(*u.RelatedObjectID, 128) {
		return Message{}, ErrInvalid
	}
	request, _ := json.Marshal(u)
	hash := Digest(string(request))
	rk := Digest(actor + ":update:" + id + ":" + key)
	var out Message
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		if e := lockCase(tx, id); e != nil {
			return e
		}
		b, e := tx.Replay(rk, hash)
		if e == nil {
			return json.Unmarshal(b, &out)
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		v, e := tx.Get(id)
		if e != nil {
			return e
		}
		if !v.Ready || expired(v, s.now()) {
			return ErrNotFound
		}
		if v.Revision != u.Revision {
			return ErrConflict
		}
		v.State = u.State
		v.Note = u.Note
		if u.Assignee != nil {
			v.Assignee = *u.Assignee
		} else if v.Assignee == "" {
			v.Assignee = actor
		}
		if u.RelatedTaskID != nil {
			v.RelatedTaskID = *u.RelatedTaskID
		}
		if u.RelatedObjectID != nil {
			v.RelatedObjectID = *u.RelatedObjectID
		}
		v.Revision++
		if v.State == "resolved" || v.State == "spam" {
			if v.ClosedAt == nil {
				now := s.now()
				v.ClosedAt = &now
			}
		} else {
			v.ClosedAt = nil
		}
		if e = tx.Save(v); e != nil {
			return e
		}
		if e = tx.Audit(actor, "update", id, s.now()); e != nil {
			return e
		}
		out = v
		b, e = json.Marshal(out)
		if e != nil {
			return e
		}
		return tx.Receipt(rk, hash, id, b, s.now())
	})
	return out, e
}
func (s *Service) DownloadAttachment(ctx context.Context, actor, id, part string, w io.Writer) (Attachment, error) {
	if e := s.allowed(ctx, actor, "read"); e != nil {
		return Attachment{}, e
	}
	if part == "" {
		return Attachment{}, ErrNotFound
	}
	var found Attachment
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		v, e := tx.Get(id)
		if e != nil {
			return e
		}
		if !v.Ready || expired(v, s.now()) {
			return ErrNotFound
		}
		for _, a := range v.Attachments {
			if a.ID == part && a.Status == "stored" && a.ObjectID != "" {
				found = a
				if s.Blobs == nil {
					return ErrUnavailable
				}
				return tx.Audit(actor, "download", id, s.now())
			}
		}
		return ErrNotFound
	})
	if e != nil {
		return Attachment{}, e
	}
	return found, s.Blobs.Download(ctx, found.ObjectID, w)
}
func (s *Service) Download(ctx context.Context, actor, id, part string, w io.Writer) error {
	_, err := s.DownloadAttachment(ctx, actor, id, part, w)
	return err
}
