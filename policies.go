package moderation

import (
	"context"
	"errors"
	"slices"
)

func effectivePolicy(t Transaction, school, kind string) (PolicyView, error) {
	out := PolicyView{Source: "default", Effective: Policy{SchoolID: school, Kind: kind, Mode: "published", BlockedTerms: []string{}}}
	if kind == "resource" {
		out.Effective.Mode = "pending"
	}
	local, err := t.Policy(school, kind)
	if err == nil {
		if local.BlockedTerms == nil {
			local.BlockedTerms = []string{}
		}
		out.Configured = &local
		out.Effective = local
		out.Source = "school"
		if school == "*" {
			out.Source = "global"
		}
		return out, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return out, err
	}
	global, err := t.Policy("*", kind)
	if err == nil {
		if global.BlockedTerms == nil {
			global.BlockedTerms = []string{}
		}
		out.Effective = global
		out.Source = "global"
		return out, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return out, err
	}
	return out, nil
}
func (s *Service) GetPolicy(ctx context.Context, p Principal, school, kind string) (PolicyView, error) {
	var out PolicyView
	if !keyOK(school) || !slices.Contains([]string{"course", "mentor", "reply", "resource"}, kind) {
		return out, ErrInput
	}
	if err := s.auth(ctx, p, "configure", school); err != nil {
		return out, err
	}
	err := s.Repo.Transaction(ctx, func(t Transaction) error { var err error; out, err = effectivePolicy(t, school, kind); return err })
	return out, err
}
