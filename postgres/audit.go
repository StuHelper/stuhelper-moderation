package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	m "github.com/StuHelper/stuhelper-moderation"
)

var _ m.AuditReader = (*Repository)(nil)

func auditClean(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func auditQueryValid(q m.AuditRequest) bool {
	if q.Limit < 1 || q.Limit > 101 || q.Until.IsZero() || (!q.From.IsZero() && !q.From.Before(q.Until)) || len(q.Snapshot) > 256 || !auditClean(q.Principal, 2048) || len(q.Scopes) > 256 {
		return false
	}
	for _, scope := range q.Scopes {
		if !auditClean(scope.School, 128) || !auditClean(scope.Group, 128) || !auditClean(scope.Module, 128) {
			return false
		}
	}
	for _, f := range []struct {
		s string
		n int
	}{{q.Actor, 2048}, {q.Target, 2048}, {q.Action, 128}} {
		if f.s != "" && !auditClean(f.s, f.n) {
			return false
		}
	}
	return q.Before == nil || (!q.Before.Time.IsZero() && auditClean(q.Before.Source, 64) && auditClean(q.Before.ID, 256))
}

// ReadAudit pins committed membership in a repeatable-read transaction. Cleanup
// changes the epoch, so subsequent pages cannot silently omit removed records.
func (r *Repository) ReadAudit(ctx context.Context, q m.AuditRequest) (m.AuditBatch, error) {
	out := m.AuditBatch{Records: []m.AuditRecord{}}
	if !auditQueryValid(q) {
		return out, m.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, safe(err)
	}
	defer tx.Rollback()
	var epoch int64
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT revision,transaction_timestamp() FROM moderation.audit_retention WHERE singleton`).Scan(&epoch, &now); err != nil {
		return out, safe(err)
	}
	var visibility string
	expires := now.Add(15 * time.Minute).Unix()
	if q.Snapshot == "" {
		if err = tx.QueryRowContext(ctx, `SELECT pg_current_snapshot()::text`).Scan(&visibility); err != nil {
			return out, safe(err)
		}
	} else {
		parts := strings.Split(q.Snapshot, "|")
		if len(parts) != 3 || parts[0] != strconv.FormatInt(epoch, 10) {
			return out, m.ErrUnavailable
		}
		expires, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil || expires <= now.Unix() || expires > now.Add(15*time.Minute).Unix() {
			return out, m.ErrUnavailable
		}
		visibility = parts[2]
	}
	out.Snapshot = strconv.FormatInt(epoch, 10) + "|" + strconv.FormatInt(expires, 10) + "|" + visibility
	if len(out.Snapshot) > 256 {
		return m.AuditBatch{}, m.ErrUnavailable
	}
	if q.Scopes == nil {
		q.Scopes = []m.AuditScope{}
	}
	scopes, err := json.Marshal(q.Scopes)
	if err != nil {
		return out, m.ErrInput
	}
	var from, before any
	if !q.From.IsZero() {
		from = q.From
	}
	source, id := "", ""
	if q.Before != nil {
		before = q.Before.Time
		source = q.Before.Source
		id = q.Before.ID
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,actor,target,action,school,group_id,module,reason,result,time
 FROM moderation.audit a WHERE pg_visible_in_snapshot(recorded_xid,$1::pg_snapshot)
 AND EXISTS(SELECT 1 FROM jsonb_to_recordset($2::jsonb) AS s(school text,"group" text,module text)
 WHERE (s.school='*' OR a.school=s.school) AND (s."group"='*' OR a.group_id=s."group") AND (s.module='*' OR a.module=s.module))
 AND ($3='' OR actor=$3) AND ($4='' OR target=$4) AND ($5='' OR action=$5)
 AND ($6::timestamptz IS NULL OR time >= $6) AND time < $7
 AND ($8::timestamptz IS NULL OR (time,'moderation' COLLATE "C",id COLLATE "C") < ($8,$9::text COLLATE "C",$10::text COLLATE "C"))
 ORDER BY time DESC,id COLLATE "C" DESC LIMIT $11`, visibility, scopes, q.Actor, q.Target, q.Action, from, q.Until, before, source, id, q.Limit)
	if err != nil {
		return out, safe(err)
	}
	defer rows.Close()
	for rows.Next() {
		record := m.AuditRecord{Source: "moderation"}
		if err = rows.Scan(&record.ID, &record.Actor, &record.Target, &record.Action, &record.Scope.School, &record.Scope.Group, &record.Scope.Module, &record.Reason, &record.Result, &record.CreatedAt); err != nil {
			return out, safe(err)
		}
		out.Records = append(out.Records, record)
	}
	if err = rows.Err(); err != nil {
		return out, safe(err)
	}
	if err = rows.Close(); err != nil {
		return out, safe(err)
	}
	return out, safe(tx.Commit())
}

func (t *transaction) saveAudit(e m.Event) error {
	result := e.Result
	if result == "" {
		result = "unknown"
	}
	if result != "success" && result != "failed" && result != "denied" && result != "unknown" {
		return m.ErrInput
	}
	if e.Reason != "" && !auditClean(e.Reason, 512) {
		return m.ErrInput
	}
	school, actor := e.SchoolID, e.Actor
	if school == "" {
		school = "*"
	}
	if actor == "" {
		actor = "unknown"
	}
	return t.save(`INSERT INTO moderation.audit(id,time,actor,target,action,school,reason,result,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, e, e.ID, e.At, actor, e.Subject, e.Type, school, e.Reason, result)
}
