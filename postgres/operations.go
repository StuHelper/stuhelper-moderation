package postgres

import m "github.com/StuHelper/stuhelper-moderation"

func (t *transaction) FilteredTasks(f m.TaskFilter) ([]m.Task, error) {
	return list[m.Task](t, `SELECT data FROM moderation.tasks WHERE ($1='' OR owner=$1 OR data->>'content_owner'=$1) AND ($2='' OR school_id=$2) AND ($3='' OR state=$3) AND id>$4 AND ($6='' OR kind=$6) AND ($7='' OR data->>'content_kind'=$7) AND ($8='' OR object_id=$8) AND ($9::timestamptz IS NULL OR (data->>'created_at')::timestamptz>=$9) AND ($10::timestamptz IS NULL OR (data->>'created_at')::timestamptz<$10) ORDER BY id LIMIT $5`, f.Owner, f.School, f.State, f.After, f.Limit, f.Kind, f.ContentKind, f.ObjectID, f.From, f.Until)
}

func (t *transaction) AppealedTaskIDs(ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := t.tx.QueryContext(t.ctx, `SELECT DISTINCT data->'submission'->>'previous_task_id' FROM moderation.tasks WHERE kind='appeal' AND (data->'submission'->>'previous_task_id') = ANY($1::text[])`, ids)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	for rows.Next() {
		var prev string
		if err = rows.Scan(&prev); err != nil {
			return nil, safe(err)
		}
		out[prev] = true
	}
	return out, safe(rows.Err())
}
