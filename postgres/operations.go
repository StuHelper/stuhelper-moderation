package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"strings"
	"time"
)

// Match the expression index in schema.sql so the queue can seek by category.
const taskCategorySQL = `COALESCE(NULLIF(data#>>'{decision,category}',''),NULLIF(data#>>'{submission,category}',''))`

func buildTaskQuery(f m.TaskFilter, hasCursor bool, cursorTime time.Time) (string, []any) {
	args := []any{}
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	extraConds := []string{}
	if !f.IncludeTeacherHomepage && f.ContentKind != m.TeacherHomepageContentKind {
		extraConds = append(extraConds, "content_kind <> 'teacher_homepage'")
	}
	if f.School != "" {
		extraConds = append(extraConds, "school_id="+add(f.School))
	}
	if f.State != "" {
		extraConds = append(extraConds, "state="+add(f.State))
	}
	if f.Kind != "" {
		extraConds = append(extraConds, "kind="+add(f.Kind))
	}
	if f.Category != "" {
		extraConds = append(extraConds, taskCategorySQL+"="+add(f.Category))
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

	column, direction, cmp := "created_at", "ASC", ">"
	if f.Order == "updated_desc" || (f.Order == "" && f.Owner != "") {
		column, direction, cmp = "updated_at", "DESC", "<"
	} else if f.Order == "newest" {
		direction, cmp = "DESC", "<"
	}
	// Only the fixed order choices above enter SQL. All filter values are parameters.
	order := column + " " + direction + ", id COLLATE \"C\" " + direction
	if hasCursor {
		at, id := add(cursorTime), add(f.CursorID)
		extraConds = append(extraConds, fmt.Sprintf("(%s,id COLLATE \"C\") %s (%s,%s)", column, cmp, at, id))
	}
	limitArg := add(f.Limit)
	if f.Owner != "" {
		owner := add(f.Owner)
		suffix := ""
		if len(extraConds) > 0 {
			suffix = " AND " + strings.Join(extraConds, " AND ")
		}
		branch := func(ownerColumn string) string {
			return fmt.Sprintf("(SELECT id,%s FROM moderation.tasks WHERE %s=%s%s ORDER BY %s LIMIT %s)", column, ownerColumn, owner, suffix, order, limitArg)
		}
		q := fmt.Sprintf(`SELECT t.data || jsonb_build_object('created_at', t.created_at, 'updated_at', t.updated_at) FROM (%s UNION %s) ids JOIN moderation.tasks t ON t.id=ids.id ORDER BY ids.%s %s, ids.id COLLATE "C" %s LIMIT %s`, branch("owner"), branch("content_owner"), column, direction, direction, limitArg)
		return q, args
	}
	where := ""
	if len(extraConds) > 0 {
		where = " WHERE " + strings.Join(extraConds, " AND ")
	}
	return "SELECT data || jsonb_build_object('created_at', created_at, 'updated_at', updated_at) FROM moderation.tasks" + where + " ORDER BY " + order + " LIMIT " + limitArg, args
}

func (t *transaction) FilteredTasks(f m.TaskFilter) ([]m.Task, error) {
	var cursorTime time.Time
	if f.CursorAt != nil {
		cursorTime = *f.CursorAt
	}
	if f.After != "" && f.CursorAt == nil {
		created, updated, err := t.TaskCursorAnchor(f.After)
		if errors.Is(err, m.ErrNotFound) {
			return []m.Task{}, nil
		}
		if err != nil {
			return nil, err
		}
		cursorTime = created
		if f.Order == "updated_desc" || (f.Order == "" && f.Owner != "") {
			cursorTime = updated
		}
		f.CursorAt = &cursorTime
		f.CursorID = f.After
	}
	q, args := buildTaskQuery(f, f.CursorAt != nil, cursorTime)
	return list[m.Task](t, q, args...)
}

func (t *transaction) TaskCursorAnchor(id string) (time.Time, time.Time, error) {
	var createdAt, updatedAt time.Time
	err := t.tx.QueryRowContext(t.ctx, `SELECT created_at, updated_at FROM moderation.tasks WHERE id=$1`, id).Scan(&createdAt, &updatedAt)
	return createdAt.UTC(), updatedAt.UTC(), safe(err)
}

func (t *transaction) QueueSummary(school string) (m.QueueSummary, error) {
	return t.queueSummary(school, false)
}

func (t *transaction) QueueSummaryIncludingTeacherHomepage(school string) (m.QueueSummary, error) {
	return t.queueSummary(school, true)
}

func (t *transaction) queueSummary(school string, includeTeacherHomepage bool) (m.QueueSummary, error) {
	out := m.QueueSummary{SchoolID: school}
	var counts []byte
	err := t.tx.QueryRowContext(t.ctx, `SELECT
 count(*) FILTER (WHERE state='waiting'),
 count(*) FILTER (WHERE state='decided'),
 count(*) FILTER (WHERE state='failed'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='course'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='mentor'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='reply'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='resource'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='teacher_homepage'),
 count(*) FILTER (WHERE state='waiting' AND kind='review'),
 count(*) FILTER (WHERE state='waiting' AND kind='report'),
 count(*) FILTER (WHERE state='waiting' AND kind='edit_request'),
 count(*) FILTER (WHERE state='waiting' AND kind='delete_request'),
 count(*) FILTER (WHERE state='waiting' AND kind='appeal'),
 (SELECT COALESCE(jsonb_object_agg(category, total), '{}'::jsonb) FROM (
   SELECT `+taskCategorySQL+` AS category, count(*) AS total
   FROM moderation.tasks WHERE school_id=$1 AND ($2 OR content_kind<>'teacher_homepage')
     AND state='waiting' AND `+taskCategorySQL+` IS NOT NULL
   GROUP BY category
 ) AS category_counts)
 FROM moderation.tasks WHERE school_id=$1 AND ($2 OR content_kind<>'teacher_homepage')`, school, includeTeacherHomepage).Scan(
		&out.Waiting,
		&out.Decided,
		&out.Failed,
		&out.ByContentKind.Course,
		&out.ByContentKind.Mentor,
		&out.ByContentKind.Reply,
		&out.ByContentKind.Resource,
		&out.ByContentKind.TeacherHomepage,
		&out.ByRequestKind.Review,
		&out.ByRequestKind.Report,
		&out.ByRequestKind.EditRequest,
		&out.ByRequestKind.DeleteRequest,
		&out.ByRequestKind.Appeal,
		&counts,
	)
	if err != nil {
		return out, safe(err)
	}
	if err := json.Unmarshal(counts, &out.ByCategory); err != nil {
		return out, m.ErrUnavailable
	}
	return out, nil
}

func (t *transaction) RelatedWaitingCounts(school string, objectIDs []string) (map[string]int, error) {
	out := map[string]int{}
	if len(objectIDs) == 0 {
		return out, nil
	}
	rows, err := t.tx.QueryContext(t.ctx, `SELECT object_id, count(*) FROM moderation.tasks WHERE school_id=$1 AND state='waiting' AND object_id=ANY($2::text[]) GROUP BY object_id`, school, objectIDs)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	for rows.Next() {
		var objectID string
		var count int
		if err = rows.Scan(&objectID, &count); err != nil {
			return nil, safe(err)
		}
		out[objectID] = count
	}
	return out, safe(rows.Err())
}

func (t *transaction) WaitingReportsByObject(school, objectID string, maxObjectRevision int64, excludeID string) ([]m.Task, error) {
	return list[m.Task](t, `SELECT data FROM moderation.tasks WHERE school_id=$1 AND object_id=$2 AND kind='report' AND state='waiting' AND id<>$3 AND CASE WHEN content_kind='teacher_homepage' THEN (data->>'object_revision')::bigint=$4
     ELSE COALESCE((data->>'object_revision')::bigint,0)<=$4 END ORDER BY id ASC`, school, objectID, excludeID, maxObjectRevision)
}

func (t *transaction) HasDecidedTaskOnObject(school, objectID, excludeID string) (bool, error) {
	var exists bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM moderation.tasks WHERE school_id=$1 AND object_id=$2 AND state='decided' AND id<>$3)`, school, objectID, excludeID).Scan(&exists)
	return exists, safe(err)
}
