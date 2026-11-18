package moderation_test

import (
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"slices"
	"testing"
)

func TestNotificationTaskBatchKeepsReceiptPermissions(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	task, err := s.Submit(ctx, m.Principal{Subject: "reporter"}, "report", m.Submission{Kind: "report", ObjectID: "review", Reason: "Private reason", Evidence: []string{"Private evidence"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"reporter", "author", "admin", "other"} {
		got, err := s.AccessibleTasks(ctx, m.Principal{Subject: user}, []string{task.ID, "missing", task.ID})
		if err != nil {
			t.Fatal(err)
		}
		if (user != "other") != slices.Contains(got, task.ID) || len(got) > 1 {
			t.Fatal("receipt scope or duplicate", user, got)
		}
	}
	if _, err = s.AccessibleTasks(ctx, m.Principal{}, []string{task.ID}); !errors.Is(err, m.ErrUnauthenticated) {
		t.Fatal(err)
	}
	for _, ids := range [][]string{nil, make([]string, 101), {""}} {
		if _, err = s.AccessibleTasks(ctx, m.Principal{Subject: "reporter"}, ids); !errors.Is(err, m.ErrInput) {
			t.Fatal("bounds", err)
		}
	}
	if err = s.Repo.Transaction(ctx, func(tx m.Transaction) error {
		v, e := tx.Task(task.ID)
		if e != nil {
			return e
		}
		v.Owner = "new-reporter"
		v.ContentOwner = "new-author"
		return tx.SaveTask(v)
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.AccessibleTasks(ctx, m.Principal{Subject: "author"}, []string{task.ID})
	if err != nil || len(got) != 0 {
		t.Fatal("stale content author", got, err)
	}
	gotReporter, err := s.AccessibleTasks(ctx, m.Principal{Subject: "reporter"}, []string{task.ID})
	if err != nil || len(gotReporter) != 0 {
		t.Fatal("stale reporter owner column", gotReporter, err)
	}
}
