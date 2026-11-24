package postgres

import "context"

// PendingResourceComplaintPurges exposes only IDs of complaints whose evidence
// was deleted at the verified deadline. The destination acknowledges after commit.
func (r *Repository) PendingResourceComplaintPurges(ctx context.Context, limit int) ([]string, error) {
	rows, err := r.DB.QueryContext(ctx, "SELECT task_id FROM moderation.resource_complaint_purges ORDER BY task_id LIMIT least(greatest($1,0),100)", limit)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, safe(err)
		}
		ids = append(ids, id)
	}
	return ids, safe(rows.Err())
}
func (r *Repository) AcknowledgeResourceComplaintPurge(ctx context.Context, id string) error {
	_, err := r.DB.ExecContext(ctx, "DELETE FROM moderation.resource_complaint_purges WHERE task_id=$1", id)
	return safe(err)
}
