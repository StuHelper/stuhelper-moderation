package postgres

import m "github.com/StuHelper/stuhelper-moderation"

func (t *transaction) FilteredTasks(f m.TaskFilter) ([]m.Task, error) {
	return list[m.Task](t, `SELECT data FROM moderation.tasks WHERE ($1='' OR owner=$1 OR data->>'content_owner'=$1) AND ($2='' OR school_id=$2) AND ($3='' OR state=$3) AND id>$4 AND ($6='' OR kind=$6) AND ($7='' OR data->>'content_kind'=$7) AND ($8='' OR object_id=$8) AND ($9::timestamptz IS NULL OR (data->>'created_at')::timestamptz>=$9) AND ($10::timestamptz IS NULL OR (data->>'created_at')::timestamptz<$10) ORDER BY id LIMIT $5`, f.Owner, f.School, f.State, f.After, f.Limit, f.Kind, f.ContentKind, f.ObjectID, f.From, f.Until)
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
	return list[m.Task](t, `SELECT data FROM moderation.tasks WHERE school_id=$1 AND object_id=$2 AND kind='report' AND state='waiting' AND id<>$3 AND COALESCE((data->>'object_revision')::bigint,0)<=$4 ORDER BY id ASC`, school, objectID, excludeID, maxObjectRevision)
}

func (t *transaction) HasDecidedTaskOnObject(school, objectID, excludeID string) (bool, error) {
	var exists bool
	err := t.tx.QueryRowContext(t.ctx, `SELECT EXISTS(SELECT 1 FROM moderation.tasks WHERE school_id=$1 AND object_id=$2 AND state='decided' AND id<>$3)`, school, objectID, excludeID).Scan(&exists)
	return exists, safe(err)
}
