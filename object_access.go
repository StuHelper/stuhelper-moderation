package moderation

import (
	"context"
	"errors"
)

type TaskAccessReference struct{ ID, SchoolID, Owner, ContentOwner string }
type TaskAccessTransaction interface {
	TaskAccessReferences([]string) ([]TaskAccessReference, error)
}

// AccessibleTasks batches current receipt access without exposing report text,
// reporter identity, or evidence to the consuming module.
func (s *Service) AccessibleTasks(ctx context.Context, p Principal, ids []string) ([]string, error) {
	if p.Subject == "" {
		return nil, ErrUnauthenticated
	}
	if len(ids) < 1 || len(ids) > 100 {
		return nil, ErrInput
	}
	for _, id := range ids {
		if !keyOK(id) {
			return nil, ErrInput
		}
	}
	var rows []TaskAccessReference
	read := func() error {
		return s.Repo.Transaction(ctx, func(tx Transaction) error {
			port, ok := tx.(TaskAccessTransaction)
			if !ok {
				return ErrUnavailable
			}
			var err error
			rows, err = port.TaskAccessReferences(ids)
			return err
		})
	}
	if err := read(); err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, row := range rows {
		if row.Owner == p.Subject || row.ContentOwner == p.Subject {
			continue
		}
		if _, checked := allowed[row.SchoolID]; !checked {
			err := s.auth(ctx, p, "manage", row.SchoolID)
			if err != nil && !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrUnauthenticated) {
				return nil, err
			}
			allowed[row.SchoolID] = err == nil
		}
	}
	if err := read(); err != nil {
		return nil, err
	}
	out := []string{}
	for _, row := range rows {
		if row.Owner == p.Subject || row.ContentOwner == p.Subject || allowed[row.SchoolID] {
			out = append(out, row.ID)
		}
	}
	return out, nil
}
