package feedback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

func Digest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func validText(v string, max int) bool {
	return len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func validState(v string) bool {
	return v == "new" || v == "processing" || v == "resolved" || v == "spam"
}
func (s *Service) allowed(ctx context.Context, actor, action string) error {
	if actor == "" || s.Access == nil {
		return ErrDenied
	}
	return s.Access.Check(ctx, actor, "moderation.feedback."+action)
}

// Stage reserves aggregate capacity and the sender's hourly budget atomically.
// Pending ingestion is durable before the first external attachment write.
func (s *Service) Stage(ctx context.Context, in Input) (Message, error) {
	v := in.Message
	if _, e := mail.ParseAddress(v.Sender); e != nil {
		return Message{}, ErrInvalid
	}
	if len(v.Dedupe) != 64 || !validText(v.Subject, 500) || !validText(v.Body, 200000) || !validText(v.AuthenticationResults, 4096) || len(v.Attachments) > 10 || v.Bytes < 0 || v.Bytes > 12<<20 {
		return Message{}, ErrInvalid
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
			if e := tx.Lock(); e != nil {
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
		if e := tx.Lock(); e != nil {
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
	if f.Limit < 1 || f.Limit > 50 || len(f.After) > 64 || (f.State != "" && !validState(f.State)) {
		return Page{}, ErrInvalid
	}
	out := Page{Items: []Message{}}
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		rows, e := tx.List(f)
		if e != nil {
			return e
		}
		if len(rows) > f.Limit {
			out.NextCursor = rows[f.Limit-1].ID
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
		return tx.Audit(actor, "list", "mailbox", s.now())
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
	if !validState(u.State) || u.Revision < 1 || !validText(u.Note, 10000) || len(key) < 8 || len(key) > 128 {
		return Message{}, ErrInvalid
	}
	request, _ := json.Marshal(u)
	hash := Digest(string(request))
	rk := Digest(actor + ":update:" + id + ":" + key)
	var out Message
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		if e := tx.Lock(); e != nil {
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
		v.Assignee = actor
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
func (s *Service) Download(ctx context.Context, actor, id, part string, w io.Writer) error {
	v, e := s.Get(ctx, actor, id)
	if e != nil {
		return e
	}
	for _, a := range v.Attachments {
		if a.ID == part && a.Status == "stored" && a.ObjectID != "" {
			if s.Blobs == nil {
				return ErrUnavailable
			}
			return s.Blobs.Download(ctx, a.ObjectID, w)
		}
	}
	return ErrNotFound
}
