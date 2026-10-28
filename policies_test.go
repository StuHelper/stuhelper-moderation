package moderation_test

import (
	"context"
	"errors"
	"testing"

	m "github.com/StuHelper/stuhelper-moderation"
)

func TestEffectivePolicyAndAdminInitiatedReviewAreScoped(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}
	view, err := s.GetPolicy(ctx, admin, "school", "course")
	if err != nil || view.Configured != nil || view.Source != "default" || view.Effective.Mode != "published" || view.Effective.BlockedTerms == nil {
		t.Fatal(view, err)
	}
	if _, err = s.GetPolicy(ctx, m.Principal{Subject: "author"}, "school", "course"); !errors.Is(err, m.ErrForbidden) {
		t.Fatal("policy leaked", err)
	}
	if err = s.SetPolicy(ctx, admin, "change", m.Policy{SchoolID: "school", Kind: "course", Mode: "pending", BlockedTerms: []string{}}); err != nil {
		t.Fatal(err)
	}
	view, err = s.GetPolicy(ctx, admin, "school", "course")
	if err != nil || view.Configured == nil || view.Configured.Revision != 1 || view.Source != "school" || view.Effective.Mode != "pending" {
		t.Fatal(view, err)
	}
	request := m.Submission{ObjectID: "review", Kind: "review", Reason: "Moderator initiated inspection", Evidence: []string{}}
	if _, err = s.Submit(ctx, m.Principal{Subject: "author"}, "init", request); !errors.Is(err, m.ErrForbidden) {
		t.Fatal("ordinary author opened an admin task", err)
	}
	task, err := s.Submit(ctx, admin, "init", request)
	if err != nil || task.State != "waiting" || task.Submission.Kind != "review" {
		t.Fatal(task, err)
	}
	retry, err := s.Submit(ctx, admin, "init", request)
	if err != nil || retry.ID != task.ID || retry.Revision != task.Revision {
		t.Fatal("task retry duplicated", retry, err)
	}
	if _, err = s.GetPolicy(ctx, admin, "other-school", "course"); !errors.Is(err, m.ErrForbidden) {
		t.Fatal("policy school boundary missing", err)
	}
}
