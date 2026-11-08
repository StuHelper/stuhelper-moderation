package postgres

import (
	"context"
	m "github.com/StuHelper/stuhelper-moderation"
)

var _ m.OutboxReader = (*Repository)(nil)

func (r *Repository) PendingOutbox(ctx context.Context, limit int) ([]m.Envelope, error) {
	if limit < 1 || limit > 100 {
		return nil, m.ErrInput
	}
	var out []m.Envelope
	err := r.Transaction(ctx, func(tx m.Transaction) error {
		var err error
		out, err = list[m.Envelope](tx.(*transaction), `SELECT data FROM moderation.outbox WHERE sent_at IS NULL ORDER BY data->>'subject', (data->'data'->>'revision')::bigint, id LIMIT $1`, limit)
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
