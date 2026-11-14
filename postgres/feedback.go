package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	"github.com/google/uuid"
	"time"
)

type FeedbackRepository struct{ DB *sql.DB }
type feedbackTx struct {
	ctx context.Context
	tx  *sql.Tx
}
type storedFeedback struct {
	Message   f.Message         `json:"message"`
	Dedupe    string            `json:"dedupe"`
	MessageID string            `json:"message_id"`
	Ready     bool              `json:"ready"`
	Bytes     int64             `json:"bytes"`
	Objects   map[string]string `json:"objects"`
}

func feedbackError(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, sql.ErrNoRows) {
		return f.ErrNotFound
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return e
	}
	return f.ErrUnavailable
}
func (r *FeedbackRepository) Transaction(ctx context.Context, run func(f.Tx) error) error {
	tx, e := r.DB.BeginTx(ctx, nil)
	if e != nil {
		return feedbackError(e)
	}
	defer tx.Rollback()
	// Calendar retention must match the UTC timestamps used by the service,
	// independently of the deployment database/session timezone.
	if _, e = tx.ExecContext(ctx, "SET LOCAL TIME ZONE 'UTC'"); e != nil {
		return feedbackError(e)
	}
	if e = run(&feedbackTx{ctx, tx}); e != nil {
		return e
	}
	return feedbackError(tx.Commit())
}
func (t *feedbackTx) Lock() error {
	_, e := t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended('moderation:feedback',0))`)
	return feedbackError(e)
}
func decodeFeedback(b []byte) (f.Message, error) {
	var v storedFeedback
	if json.Unmarshal(b, &v) != nil {
		return f.Message{}, f.ErrUnavailable
	}
	v.Message.Dedupe = v.Dedupe
	v.Message.MessageID = v.MessageID
	v.Message.Ready = v.Ready
	v.Message.Bytes = v.Bytes
	for i, a := range v.Message.Attachments {
		v.Message.Attachments[i].ObjectID = v.Objects[a.ID]
	}
	return v.Message, nil
}
func (t *feedbackTx) one(q string, args ...any) (f.Message, error) {
	var b []byte
	e := t.tx.QueryRowContext(t.ctx, q, args...).Scan(&b)
	if e != nil {
		return f.Message{}, feedbackError(e)
	}
	return decodeFeedback(b)
}
func (t *feedbackTx) Get(id string) (f.Message, error) {
	return t.one(`SELECT data FROM moderation.feedback WHERE id=$1`, id)
}
func (t *feedbackTx) Find(key string) (f.Message, error) {
	v, e := t.one(`SELECT data FROM moderation.feedback WHERE dedupe=$1`, key)
	if !errors.Is(e, f.ErrNotFound) {
		return v, e
	}
	var id string
	e = t.tx.QueryRowContext(t.ctx, `SELECT id FROM moderation.feedback_tombstones WHERE dedupe=$1`, key).Scan(&id)
	return f.Message{ID: id, Ready: true}, feedbackError(e)
}
func (t *feedbackTx) Save(v f.Message) error {
	objects := map[string]string{}
	for _, a := range v.Attachments {
		objects[a.ID] = a.ObjectID
	}
	b, e := json.Marshal(storedFeedback{v, v.Dedupe, v.MessageID, v.Ready, v.Bytes, objects})
	if e != nil {
		return f.ErrInvalid
	}
	_, e = t.tx.ExecContext(t.ctx, `INSERT INTO moderation.feedback(id,dedupe,sender,state,ready,received_at,closed_at,bytes,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET state=excluded.state,ready=excluded.ready,closed_at=excluded.closed_at,data=excluded.data`, v.ID, v.Dedupe, v.Sender, v.State, v.Ready, v.ReceivedAt, v.ClosedAt, v.Bytes, string(b))
	return feedbackError(e)
}
func (t *feedbackTx) many(q string, args ...any) ([]f.Message, error) {
	rows, e := t.tx.QueryContext(t.ctx, q, args...)
	if e != nil {
		return nil, feedbackError(e)
	}
	defer rows.Close()
	out := []f.Message{}
	for rows.Next() {
		var b []byte
		if rows.Scan(&b) != nil {
			return nil, f.ErrUnavailable
		}
		v, e := decodeFeedback(b)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, feedbackError(rows.Err())
}
func (t *feedbackTx) List(v f.Filter) ([]f.Message, error) {
	return t.many(`SELECT data FROM moderation.feedback WHERE ready AND id>$1 AND ($2='' OR state=$2) AND (closed_at IS NULL OR closed_at+interval '12 months'>now()) ORDER BY id LIMIT $3`, v.After, v.State, v.Limit+1)
}
func (t *feedbackTx) Usage(sender string, since time.Time) (int, int64, int, error) {
	var count, rate int
	var bytes int64
	e := t.tx.QueryRowContext(t.ctx, `SELECT CASE WHEN (SELECT count(*) FROM moderation.feedback_tombstones)>=1000000 THEN 100000 ELSE count(*) END,coalesce(sum(bytes),0),count(*) FILTER(WHERE sender=$1 AND received_at>=$2) FROM moderation.feedback`, sender, since).Scan(&count, &bytes, &rate)
	return count, bytes, rate, feedbackError(e)
}
func (t *feedbackTx) Audit(actor, action, id string, now time.Time) error {
	data, _ := json.Marshal(map[string]any{"actor": actor, "action": "feedback." + action, "target": id, "time": now})
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO moderation.audit(id,time,data,actor,target,action,school,result) VALUES($1,$2,$3,$4,$5,$6,'*','success')`, uuid.NewString(), now, string(data), actor, id, "feedback."+action)
	return feedbackError(e)
}
func (t *feedbackTx) Replay(key, hash string) ([]byte, error) {
	var b []byte
	var h string
	e := t.tx.QueryRowContext(t.ctx, `SELECT hash,data FROM moderation.feedback_receipts WHERE key=$1`, key).Scan(&h, &b)
	if e != nil {
		return nil, feedbackError(e)
	}
	if h != hash {
		return nil, f.ErrConflict
	}
	return b, nil
}
func (t *feedbackTx) Receipt(key, hash, target string, b []byte, now time.Time) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO moderation.feedback_receipts(key,hash,target,data,created_at) VALUES($1,$2,$3,$4,$5)`, key, hash, target, string(b), now)
	return feedbackError(e)
}
func (t *feedbackTx) Expired(now time.Time, limit int) ([]f.Message, error) {
	return t.many(`SELECT data FROM moderation.feedback WHERE closed_at+interval '12 months'<=$1 ORDER BY closed_at,id LIMIT $2`, now, limit)
}
func (t *feedbackTx) Delete(id string) error {
	_, e := t.tx.ExecContext(t.ctx, `INSERT INTO moderation.feedback_tombstones(id,dedupe) SELECT id,dedupe FROM moderation.feedback WHERE id=$1 ON CONFLICT DO NOTHING`, id)
	if e != nil {
		return feedbackError(e)
	}
	_, e = t.tx.ExecContext(t.ctx, `DELETE FROM moderation.feedback WHERE id=$1`, id)
	return feedbackError(e)
}
func (t *feedbackTx) Prune(now time.Time, limit int) error {
	// Reply receipts retain idempotence for the whole case lifetime without keeping
	// a second copy of personal content beyond the retention deadline.
	_, e := t.tx.ExecContext(t.ctx, `DELETE FROM moderation.feedback_receipts WHERE key IN (SELECT key FROM moderation.feedback_receipts WHERE created_at<$1::timestamptz-interval '12 months' ORDER BY created_at LIMIT $2)`, now, limit)
	if e != nil {
		return feedbackError(e)
	}
	_, e = t.tx.ExecContext(t.ctx, `SELECT moderation.cleanup_feedback_audit()`)
	return feedbackError(e)
}

// Cursor belongs to the mailbox consumer, not to request authorization.
func (r *FeedbackRepository) Cursor(ctx context.Context, mailbox string, validity uint32) (uint32, error) {
	var stored uint32
	var uid uint32
	e := r.DB.QueryRowContext(ctx, `SELECT validity,uid FROM moderation.feedback_cursors WHERE mailbox=$1`, mailbox).Scan(&stored, &uid)
	if errors.Is(e, sql.ErrNoRows) || e == nil && stored != validity {
		return 0, nil
	}
	return uid, feedbackError(e)
}
func (r *FeedbackRepository) Advance(ctx context.Context, mailbox string, validity, uid uint32) error {
	_, e := r.DB.ExecContext(ctx, `INSERT INTO moderation.feedback_cursors(mailbox,validity,uid) VALUES($1,$2,$3) ON CONFLICT(mailbox) DO UPDATE SET validity=excluded.validity,uid=CASE WHEN feedback_cursors.validity=excluded.validity THEN greatest(feedback_cursors.uid,excluded.uid) ELSE excluded.uid END`, mailbox, validity, uid)
	return feedbackError(e)
}
