package feedback

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

func (s *Service) Reply(ctx context.Context, actor, id, key, body string) (Reply, error) {
	if e := s.allowed(ctx, actor, "reply"); e != nil {
		return Reply{}, e
	}
	if s.Sender == nil {
		return Reply{}, ErrUnavailable
	}
	if body == "" || !validText(body, 20000) || !validIdempotencyKey(key) {
		return Reply{}, ErrInvalid
	}
	rk := Digest(actor + ":reply:" + id + ":" + key)
	hash := Digest(body)
	var out Reply
	var message Message
	send := false
	e := s.Repo.Transaction(ctx, func(tx Tx) error {
		if e := lockCase(tx, id); e != nil {
			return e
		}
		v, e := tx.Get(id)
		if e != nil {
			return e
		}
		if !v.Ready || expired(v, s.now()) {
			return ErrNotFound
		}
		message = v
		b, e := tx.Replay(rk, hash)
		if e == nil {
			if e = json.Unmarshal(b, &out); e != nil {
				return ErrUnavailable
			}
			for _, r := range v.Replies {
				if r.ID == out.ID {
					out = r
					return nil
				}
			}
			return ErrUnavailable
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		for _, previous := range v.Replies {
			if previous.ID == rk {
				if previous.Body != body {
					return ErrConflict
				}
				out = previous
				return nil
			}
		}
		if v.State == "spam" {
			return ErrConflict
		}
		if len(v.Replies) >= 100 {
			return ErrLimit
		}
		// The durable sending record prevents replay after a crash or ambiguous DATA.
		out = Reply{ID: rk, Body: body, Actor: actor, State: "sending", CreatedAt: s.now()}
		v.Replies = append(v.Replies, out)
		v.Revision++
		if e = tx.Save(v); e != nil {
			return e
		}
		if e = tx.Audit(actor, "reply_attempt", id, s.now()); e != nil {
			return e
		}
		b, e = json.Marshal(out)
		if e != nil {
			return e
		}
		if e = tx.Receipt(rk, hash, id, b, s.now()); e != nil {
			return e
		}
		send = true
		return nil
	})
	if e != nil || !send {
		return out, e
	}
	call, stop := context.WithTimeout(ctx, 30*time.Second)
	state, sendErr := s.Sender.Send(call, out.ID, message.Sender, message.Subject, message.MessageID, body)
	stop()
	if state != "sent" && state != "failed" {
		state = "unknown"
	}
	if sendErr != nil && state == "sent" {
		state = "unknown"
	}
	// Persist the outcome even if the browser disconnected during SMTP.
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	e = s.Repo.Transaction(persist, func(tx Tx) error {
		if e := lockCase(tx, id); e != nil {
			return e
		}
		v, e := tx.Get(id)
		if e != nil {
			return e
		}
		for i, r := range v.Replies {
			if r.ID == out.ID {
				v.Replies[i].State = state
				out = v.Replies[i]
			}
		}
		v.Revision++
		if e = tx.Save(v); e != nil {
			return e
		}
		return tx.Audit(actor, "reply_"+state, id, s.now())
	})
	return out, e
}

// Cleanup removes only closed cases older than twelve calendar months. External
// deletion is repeatable and runs outside DB transactions so slow object storage
// cannot block active mailbox or operator workflows. Each run is bounded.
func (s *Service) Cleanup(ctx context.Context) error {
	var rows []Message
	e := s.Repo.Transaction(ctx, func(tx Tx) error { var e error; rows, e = tx.Expired(s.now(), 50); return e })
	if e != nil {
		return e
	}
	for _, v := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		var objects []string
		eligible := false
		e = s.Repo.Transaction(ctx, func(tx Tx) error {
			if e := lockCase(tx, v.ID); e != nil {
				return e
			}
			current, e := tx.Get(v.ID)
			if errors.Is(e, ErrNotFound) {
				return nil
			}
			if e != nil {
				return e
			}
			if !expired(current, s.now()) {
				return nil
			}
			eligible = true
			for _, a := range current.Attachments {
				if a.ObjectID != "" {
					objects = append(objects, a.ObjectID)
				}
			}
			return nil
		})
		if e != nil {
			return e
		}
		if !eligible {
			continue
		}
		for _, objectID := range objects {
			if s.Blobs == nil {
				return ErrUnavailable
			}
			delCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			delErr := s.Blobs.Delete(delCtx, objectID)
			cancel()
			if delErr != nil {
				return ErrUnavailable
			}
		}
		e = s.Repo.Transaction(ctx, func(tx Tx) error {
			if e := lockCase(tx, v.ID); e != nil {
				return e
			}
			current, e := tx.Get(v.ID)
			if errors.Is(e, ErrNotFound) {
				return nil
			}
			if e != nil {
				return e
			}
			if !expired(current, s.now()) {
				return nil
			}
			if e = tx.Delete(v.ID); e != nil {
				return e
			}
			return tx.Audit("retention", "delete", v.ID, s.now())
		})
		if e != nil {
			return e
		}
	}
	return s.Repo.Transaction(ctx, func(tx Tx) error { return tx.Prune(s.now(), 100) })
}
