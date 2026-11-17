package postgres

import (
	"time"

	m "github.com/StuHelper/stuhelper-moderation"
)

func (t *transaction) FilteredTasks(f m.TaskFilter) ([]m.Task, error) {
	baseWhere := `WHERE ($1='' OR owner=$1 OR content_owner=$1)
 AND ($2='' OR school_id=$2)
 AND ($3='' OR state=$3)
 AND ($4='' OR kind=$4)
 AND ($5='' OR content_kind=$5)
 AND ($6='' OR object_id=$6)
 AND ($7::timestamptz IS NULL OR created_at>=$7)
 AND ($8::timestamptz IS NULL OR created_at<$8)`

	var query string
	switch f.Order {
	case "newest":
		query = `SELECT data FROM moderation.tasks ` + baseWhere + `
 AND ($9::timestamptz IS NULL OR (created_at, id COLLATE "C") < ($9, $10::text COLLATE "C"))
 ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $11`
	case "updated_desc":
		query = `SELECT data FROM moderation.tasks ` + baseWhere + `
 AND ($9::timestamptz IS NULL OR (updated_at, id COLLATE "C") < ($9, $10::text COLLATE "C"))
 ORDER BY updated_at DESC, id COLLATE "C" DESC LIMIT $11`
	default:
		query = `SELECT data FROM moderation.tasks ` + baseWhere + `
 AND ($9::timestamptz IS NULL OR (created_at, id COLLATE "C") > ($9, $10::text COLLATE "C"))
 ORDER BY created_at ASC, id COLLATE "C" ASC LIMIT $11`
	}
	return list[m.Task](t, query, f.Owner, f.School, f.State, f.Kind, f.ContentKind, f.ObjectID, f.From, f.Until, f.CursorAt, f.CursorID, f.Limit)
}

func (t *transaction) TaskCursorAnchor(id string) (time.Time, time.Time, error) {
	var createdAt, updatedAt time.Time
	err := t.tx.QueryRowContext(t.ctx, `SELECT created_at, updated_at FROM moderation.tasks WHERE id=$1`, id).Scan(&createdAt, &updatedAt)
	return createdAt.UTC(), updatedAt.UTC(), safe(err)
}

func (t *transaction) QueueSummary(school string) (m.QueueSummary, error) {
	out := m.QueueSummary{SchoolID: school}
	err := t.tx.QueryRowContext(t.ctx, `SELECT
 count(*) FILTER (WHERE state='waiting'),
 count(*) FILTER (WHERE state='decided'),
 count(*) FILTER (WHERE state='failed'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='course'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='mentor'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='reply'),
 count(*) FILTER (WHERE state='waiting' AND content_kind='resource'),
 count(*) FILTER (WHERE state='waiting' AND kind='review'),
 count(*) FILTER (WHERE state='waiting' AND kind='report'),
 count(*) FILTER (WHERE state='waiting' AND kind='edit_request'),
 count(*) FILTER (WHERE state='waiting' AND kind='delete_request'),
 count(*) FILTER (WHERE state='waiting' AND kind='appeal')
 FROM moderation.tasks WHERE school_id=$1`, school).Scan(
		&out.Waiting,
		&out.Decided,
		&out.Failed,
		&out.ByContentKind.Course,
		&out.ByContentKind.Mentor,
		&out.ByContentKind.Reply,
		&out.ByContentKind.Resource,
		&out.ByRequestKind.Review,
		&out.ByRequestKind.Report,
		&out.ByRequestKind.EditRequest,
		&out.ByRequestKind.DeleteRequest,
		&out.ByRequestKind.Appeal,
	)
	return out, safe(err)
}
