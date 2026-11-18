package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"strings"
	"time"
)

func buildTaskQuery(f m.TaskFilter, hasCursor bool, cursorTime time.Time) (string, []any) {
	args := []any{}
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	extraConds := []string{}
	if f.School != "" {
		extraConds = append(extraConds, "school_id="+add(f.School))
	}
	if f.State != "" {
		extraConds = append(extraConds, "state="+add(f.State))
	}
	if f.Kind != "" {
		extraConds = append(extraConds, "kind="+add(f.Kind))
	}
	if f.ContentKind != "" {
		extraConds = append(extraConds, "content_kind="+add(f.ContentKind))
	}
	if f.ObjectID != "" {
		extraConds = append(extraConds, "object_id="+add(f.ObjectID))
	}
	if f.From != nil {
		extraConds = append(extraConds, "created_at>="+add(*f.From))
	}
	if f.Until != nil {
		extraConds = append(extraConds, "created_at<"+add(*f.Until))
	}

	if f.Owner != "" {
		ownerArg := add(f.Owner)
		if hasCursor {
			ctArg := add(cursorTime)
			idArg := add(f.After)
			extraConds = append(extraConds, fmt.Sprintf("(created_at<=%s AND (created_at,id)<(%s,%s))", ctArg, ctArg, idArg))
		}
		limitArg := add(f.Limit)
		suffix := ""
		if len(extraConds) > 0 {
			suffix = " AND " + strings.Join(extraConds, " AND ")
		}
		q := fmt.Sprintf(`SELECT t.data FROM (
 (SELECT id,created_at FROM moderation.tasks WHERE owner=%s%s ORDER BY created_at DESC,id DESC LIMIT %s)
 UNION
 (SELECT id,created_at FROM moderation.tasks WHERE content_owner=%s%s ORDER BY created_at DESC,id DESC LIMIT %s)
) ids JOIN moderation.tasks t ON t.id=ids.id ORDER BY ids.created_at DESC,ids.id DESC LIMIT %s`,
			ownerArg, suffix, limitArg, ownerArg, suffix, limitArg, limitArg)
		return q, args
	}

	if hasCursor {
		ctArg := add(cursorTime)
		idArg := add(f.After)
		extraConds = append(extraConds, fmt.Sprintf("(created_at>=%s AND (created_at,id)>(%s,%s))", ctArg, ctArg, idArg))
	}
	limitArg := add(f.Limit)
	where := ""
	if len(extraConds) > 0 {
		where = " WHERE " + strings.Join(extraConds, " AND ")
	}
	return fmt.Sprintf(`SELECT data FROM moderation.tasks%s ORDER BY created_at ASC,id ASC LIMIT %s`, where, limitArg), args
}

func (t *transaction) FilteredTasks(f m.TaskFilter) ([]m.Task, error) {
	var cursorTime time.Time
	hasCursor := false
	if f.After != "" {
		if e := t.tx.QueryRowContext(t.ctx, `SELECT created_at FROM moderation.tasks WHERE id=$1`, f.After).Scan(&cursorTime); e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				return []m.Task{}, nil
			}
			return nil, safe(e)
		}
		hasCursor = true
	}
	q, args := buildTaskQuery(f, hasCursor, cursorTime)
	return list[m.Task](t, q, args...)
}
