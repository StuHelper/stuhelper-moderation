// Package postgres owns moderation storage and migrations.
package postgres

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"time"
)

//go:embed schema.sql
var Schema string

type Repository struct{ DB *sql.DB }
type transaction struct {
	tx  *sql.Tx
	ctx context.Context
}

func safe(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, sql.ErrNoRows) {
		return m.ErrNotFound
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return e
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) && (pg.Code == "23505" || pg.Code == "40001" || pg.Code == "40P01") {
		return m.ErrConflict
	}
	return m.ErrUnavailable
}
func (r *Repository) Transaction(ctx context.Context, run func(m.Transaction) error) error {
	tx, e := r.DB.BeginTx(ctx, nil)
	if e != nil {
		return safe(e)
	}
	defer tx.Rollback()
	if e = run(&transaction{tx, ctx}); e != nil {
		return e
	}
	return safe(tx.Commit())
}
func (t *transaction) Lock(key string) error {
	_, e := t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "moderation:"+key)
	return safe(e)
}
func read[T any](t *transaction, q string, args ...any) (T, error) {
	var v T
	var b []byte
	if e := t.tx.QueryRowContext(t.ctx, q, args...).Scan(&b); e != nil {
		return v, safe(e)
	}
	if json.Unmarshal(b, &v) != nil {
		return v, m.ErrUnavailable
	}
	return v, nil
}
func list[T any](t *transaction, q string, args ...any) ([]T, error) {
	rows, e := t.tx.QueryContext(t.ctx, q, args...)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var b []byte
		var v T
		if rows.Scan(&b) != nil || json.Unmarshal(b, &v) != nil {
			return nil, m.ErrUnavailable
		}
		out = append(out, v)
	}
	return out, safe(rows.Err())
}
func (t *transaction) save(q string, v any, args ...any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return m.ErrInput
	}
	args = append(args, string(b))
	_, e = t.tx.ExecContext(t.ctx, q, args...)
	return safe(e)
}
func (t *transaction) Task(id string) (m.Task, error) {
	return read[m.Task](t, `SELECT data FROM moderation.tasks WHERE id=$1`, id)
}
func (t *transaction) Active(owner, object, kind string) (m.Task, error) {
	return read[m.Task](t, `SELECT data FROM moderation.tasks WHERE owner=$1 AND object_id=$2 AND kind=$3 AND state IN ('waiting','decided')`, owner, object, kind)
}
func (t *transaction) SaveTask(v m.Task) error {
	return t.save(`INSERT INTO moderation.tasks(id,owner,school_id,object_id,kind,state,next_attempt,lease_until,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET state=excluded.state,next_attempt=excluded.next_attempt,lease_until=excluded.lease_until,data=excluded.data`, v, v.ID, v.Owner, v.SchoolID, v.Submission.ObjectID, v.Submission.Kind, v.State, v.NextAttempt, v.LeaseUntil)
}
func (t *transaction) List(owner, school, state, after string, limit int) ([]m.Task, error) {
	return list[m.Task](t, `SELECT data FROM moderation.tasks WHERE ($1='' OR owner=$1) AND ($2='' OR school_id=$2) AND ($3='' OR state=$3) AND id>$4 ORDER BY id LIMIT $5`, owner, school, state, after, limit)
}
func (t *transaction) Ready(now time.Time, limit int) ([]m.Task, error) {
	return list[m.Task](t, `SELECT data FROM moderation.tasks WHERE state='decided' AND next_attempt<=$1 AND lease_until<=$1 ORDER BY next_attempt,id LIMIT $2`, now, limit)
}
func (t *transaction) Policy(school, kind string) (m.Policy, error) {
	return read[m.Policy](t, `SELECT data FROM moderation.policies WHERE school_id=$1 AND kind=$2`, school, kind)
}
func (t *transaction) SavePolicy(v m.Policy) error {
	return t.save(`INSERT INTO moderation.policies(school_id,kind,data) VALUES($1,$2,$3) ON CONFLICT(school_id,kind) DO UPDATE SET data=excluded.data`, v, v.SchoolID, v.Kind)
}
func (t *transaction) Replay(key string) (m.Replay, error) {
	return read[m.Replay](t, `SELECT data FROM moderation.replays WHERE key=$1`, key)
}
func (t *transaction) SaveReplay(key string, v m.Replay) error {
	return t.save(`INSERT INTO moderation.replays(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=excluded.data`, v, key)
}
func (t *transaction) Event(v m.Event) error {
	if e := t.save(`INSERT INTO moderation.audit(id,data) VALUES($1,$2)`, v, v.ID); e != nil {
		return e
	}
	return t.save(`INSERT INTO moderation.outbox(id,data) VALUES($1,$2)`, map[string]any{"specversion": "1.0", "id": v.ID, "source": "moderation", "type": v.Type, "subject": v.Subject, "time": v.At, "schoolid": v.SchoolID, "datacontenttype": "application/json", "data": map[string]any{"revision": v.Revision}}, v.ID)
}
