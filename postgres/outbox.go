package postgres

import (
	"context"
	m "github.com/StuHelper/stuhelper-moderation"
)

const pendingOutboxQuery = `SELECT data FROM moderation.outbox WHERE sent_at IS NULL AND NOT (data->>'subject' = ANY($2::text[])) ORDER BY data->>'subject', (data->'data'->>'revision')::bigint, id LIMIT $1`

var _ m.OutboxReader = (*Repository)(nil)

func (r *Repository) PendingOutbox(ctx context.Context, limit int, excludeSubjects []string) ([]m.Envelope, error) {
	if limit < 1 || limit > 100 || len(excludeSubjects) > 1000 {
		return nil, m.ErrInput
	}
	if excludeSubjects == nil {
		excludeSubjects = []string{}
	}
	var out []m.Envelope
	err := r.Transaction(ctx, func(tx m.Transaction) error {
		var err error
		out, err = list[m.Envelope](tx.(*transaction), pendingOutboxQuery, limit, excludeSubjects)
		return err
	})
	return out, err
}
func (r *Repository) ConfirmOutbox(ctx context.Context, id string) error {
	result, err := r.DB.ExecContext(ctx, `UPDATE moderation.outbox SET sent_at=COALESCE(sent_at,now()), delivered=true WHERE id=$1`, id)
	if err != nil {
		return safe(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return safe(err)
	}
	if n == 0 {
		return m.ErrNotFound
	}
	return nil
}
