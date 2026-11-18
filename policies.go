package moderation

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type PolicyPreviewInput struct {
	SchoolID     string   `json:"school_id"`
	Kind         string   `json:"kind"`
	Title        string   `json:"title,omitempty"`
	Body         string   `json:"body"`
	Mode         *string  `json:"mode,omitempty"`
	BlockedTerms []string `json:"blocked_terms,omitempty"`
}

type PolicyPreview struct {
	Result        string   `json:"result"`
	MatchedTerms  []string `json:"matched_terms"`
	EffectiveMode string   `json:"effective_mode"`
	Source        string   `json:"source"`
}

func normalizeBlockedTerms(terms []string) ([]string, error) {
	if len(terms) > 100 {
		return nil, ErrInput
	}
	out := make([]string, 0, len(terms))
	seen := map[string]bool{}
	for _, raw := range terms {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || !textOK(raw, 100) || !textOK(trimmed, 100) {
			return nil, ErrInput
		}
		lowered := strings.ToLower(trimmed)
		if !seen[lowered] {
			seen[lowered] = true
			out = append(out, lowered)
		}
	}
	return out, nil
}

func matchedBlockedTerms(terms []string, title, body string) []string {
	text := strings.ToLower(title + "\n" + body)
	matched := []string{}
	for _, raw := range terms {
		term := strings.ToLower(strings.TrimSpace(raw))
		if term != "" && strings.Contains(text, term) && !slices.Contains(matched, term) {
			matched = append(matched, term)
		}
	}
	return matched
}

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
	err := s.tx(ctx, func(t Transaction) error { var err error; out, err = effectivePolicy(t, school, kind); return err })
	return out, err
}

func (s *Service) PreviewPolicy(ctx context.Context, p Principal, in PolicyPreviewInput) (PolicyPreview, error) {
	out := PolicyPreview{MatchedTerms: []string{}}
	if !keyOK(in.SchoolID) || !slices.Contains([]string{"course", "mentor", "reply", "resource"}, in.Kind) || !textOK(in.Title, 500) || !textOK(in.Body, 16000) {
		return out, ErrInput
	}
	if in.Mode != nil && !slices.Contains([]string{"published", "pending", "review"}, *in.Mode) {
		return out, ErrInput
	}
	var candidateTerms []string
	if in.BlockedTerms != nil {
		var err error
		candidateTerms, err = normalizeBlockedTerms(in.BlockedTerms)
		if err != nil {
			return out, err
		}
	}
	if err := s.auth(ctx, p, "configure", in.SchoolID); err != nil {
		return out, err
	}
	var view PolicyView
	err := s.Repo.Transaction(ctx, func(t Transaction) error {
		var err error
		view, err = effectivePolicy(t, in.SchoolID, in.Kind)
		return err
	})
	if err != nil {
		return out, err
	}
	mode := view.Effective.Mode
	terms := view.Effective.BlockedTerms
	source := view.Source
	if in.Mode != nil {
		mode = *in.Mode
		source = "candidate"
	}
	if in.BlockedTerms != nil {
		terms = candidateTerms
		source = "candidate"
	}
	if !slices.Contains([]string{"published", "pending", "review"}, mode) {
		return out, ErrUnavailable
	}
	matched := matchedBlockedTerms(terms, in.Title, in.Body)
	out.MatchedTerms = matched
	out.EffectiveMode = mode
	out.Source = source
	out.Result = mode
	if len(matched) > 0 {
		out.Result = "blocked"
	}
	return out, nil
}
