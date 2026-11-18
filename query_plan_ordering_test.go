package moderation_test

import (
	"context"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"testing"
	"time"
)

func TestTasksAndFeedbackUseTimeOrderedPaginationWithoutMissingNewArrivals(t *testing.T) {
	repo, _ := database(t)
	now := time.Date(2026, 11, 18, 7, 0, 0, 0, time.UTC)
	c := &content{revision: 1, applied: map[string]bool{}}
	s := &m.Service{Repo: repo, Content: c, Access: access{}, Clock: func() time.Time { return now }}
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}

	// Create 6 reports at strictly increasing timestamps. SHA-256 IDs will not match chronological order.
	var createdIDs []string
	for i := 0; i < 6; i++ {
		now = now.Add(time.Minute)
		user := m.Principal{Subject: fmt.Sprintf("student-%d", i)}
		task, err := s.Submit(ctx, user, fmt.Sprintf("k-%d", i), m.Submission{
			ObjectID: "review",
			Kind:     "report",
			Reason:   fmt.Sprintf("reason-%d", i),
			Evidence: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		createdIDs = append(createdIDs, task.ID)
	}

	// 1. Admin queue must return FIFO (oldest first: createdIDs[0..5]) across pages, and a new arrival during pagination is visited on the tail page.
	page1, err := s.FilteredList(ctx, admin, m.TaskFilter{School: "school", State: "waiting", Admin: true, Limit: 3})
	if err != nil || len(page1) != 3 {
		t.Fatalf("admin page1: %+v %v", page1, err)
	}
	for i := 0; i < 3; i++ {
		if page1[i].ID != createdIDs[i] {
			t.Fatalf("admin queue out of FIFO order at %d: got %s, want %s", i, page1[i].ID, createdIDs[i])
		}
	}
	// New report arrives while admin is viewing page 1 (even if its SHA-256 ID is smaller than page1[2].ID!).
	now = now.Add(time.Minute)
	lateTask, err := s.Submit(ctx, m.Principal{Subject: "student-late"}, "k-late", m.Submission{ObjectID: "review", Kind: "report", Reason: "late", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	createdIDs = append(createdIDs, lateTask.ID)

	page2, err := s.FilteredList(ctx, admin, m.TaskFilter{School: "school", State: "waiting", Admin: true, After: page1[2].ID, Limit: 10})
	if err != nil || len(page2) != 4 {
		t.Fatalf("admin page2 missed items: got %d (%+v), err=%v", len(page2), page2, err)
	}
	for i := 0; i < 4; i++ {
		if page2[i].ID != createdIDs[3+i] {
			t.Fatalf("admin page2 out of FIFO order at %d: got %s, want %s", i, page2[i].ID, createdIDs[3+i])
		}
	}

	// 2. Content author ("author") personal list returns newest first (createdIDs[6] down to createdIDs[0]) across pages.
	authorPage1, err := s.FilteredList(ctx, m.Principal{Subject: "author"}, m.TaskFilter{Limit: 4})
	if err != nil || len(authorPage1) != 4 {
		t.Fatalf("author page1: %+v %v", authorPage1, err)
	}
	for i := 0; i < 4; i++ {
		want := createdIDs[len(createdIDs)-1-i]
		if authorPage1[i].ID != want {
			t.Fatalf("student personal list out of newest-first order at %d: got %s, want %s", i, authorPage1[i].ID, want)
		}
	}
	authorPage2, err := s.FilteredList(ctx, m.Principal{Subject: "author"}, m.TaskFilter{After: authorPage1[3].ID, Limit: 10})
	if err != nil || len(authorPage2) != 3 {
		t.Fatalf("author page2: %+v %v", authorPage2, err)
	}
	for i := 0; i < 3; i++ {
		want := createdIDs[2-i]
		if authorPage2[i].ID != want {
			t.Fatalf("student personal page2 out of newest-first order at %d: got %s, want %s", i, authorPage2[i].ID, want)
		}
	}

	// 3. Feedback inbox returns newest received messages first across cursor pagination.
	fbSvc := &f.Service{
		Repo:   &pg.FeedbackRepository{DB: repo.DB},
		Access: &feedbackAccess{},
		Blobs:  &feedbackBlobs{values: map[string][]byte{}},
		Now:    func() time.Time { return now },
	}
	var msgIDs []string
	for i := 0; i < 5; i++ {
		now = now.Add(time.Minute)
		msg, err := fbSvc.Ingest(ctx, feedbackInput(fmt.Sprintf("mail-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		msgIDs = append(msgIDs, msg.ID)
	}
	fbPage1, err := fbSvc.List(ctx, "operator", f.Filter{Limit: 3})
	if err != nil || len(fbPage1.Items) != 3 || fbPage1.NextCursor == "" {
		t.Fatalf("feedback page1: %+v %v", fbPage1, err)
	}
	for i := 0; i < 3; i++ {
		want := msgIDs[len(msgIDs)-1-i]
		if fbPage1.Items[i].ID != want {
			t.Fatalf("feedback list out of newest-first order at %d: got %s, want %s", i, fbPage1.Items[i].ID, want)
		}
	}
	fbPage2, err := fbSvc.List(ctx, "operator", f.Filter{After: fbPage1.NextCursor, Limit: 3})
	if err != nil || len(fbPage2.Items) != 2 || fbPage2.NextCursor != "" {
		t.Fatalf("feedback page2: %+v %v", fbPage2, err)
	}
	if fbPage2.Items[0].ID != msgIDs[1] || fbPage2.Items[1].ID != msgIDs[0] {
		t.Fatalf("feedback page2 wrong items: %+v", fbPage2.Items)
	}
}
