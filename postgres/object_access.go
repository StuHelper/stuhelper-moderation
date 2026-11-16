package postgres

import m "github.com/StuHelper/stuhelper-moderation"

func (t *transaction) TaskAccessReferences(ids []string) ([]m.TaskAccessReference, error) {
	return list[m.TaskAccessReference](t, `SELECT jsonb_build_object('ID',id,'SchoolID',school_id,'Owner',owner,'ContentOwner',COALESCE(data->>'content_owner','')) FROM moderation.tasks WHERE id=ANY($1::text[]) ORDER BY id`, ids)
}
