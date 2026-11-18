package moderation_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"testing"
)

func TestRelatedWaitingCountAndLinkedReportResolution(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}

	var tasks []m.TaskView
	for i := 1; i <= 3; i++ {
		reporter := m.Principal{Subject: fmt.Sprintf("reporter-%d", i)}
		task, err := s.Submit(ctx, reporter, fmt.Sprintf("report-%d", i), m.Submission{
			ObjectID: "review",
			Kind:     "report",
			Reason:   fmt.Sprintf("Report reason %d", i),
			Evidence: []string{fmt.Sprintf("Evidence %d", i)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if task.RelatedWaitingCount != nil {
			t.Fatalf("reporter view leaked related_waiting_count: %+v", task)
		}
		tasks = append(tasks, task)
	}

	ownGet, err := s.Get(ctx, m.Principal{Subject: "reporter-1"}, tasks[0].ID)
	if err != nil || ownGet.RelatedWaitingCount != nil {
		t.Fatalf("student get exposed related_waiting_count: %+v %v", ownGet, err)
	}
	ownList, err := s.FilteredList(ctx, m.Principal{Subject: "author"}, m.TaskFilter{Limit: 20})
	if err != nil || len(ownList) != 3 {
		t.Fatalf("author list: %+v %v", ownList, err)
	}
	for _, item := range ownList {
		raw, _ := json.Marshal(item)
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		if _, exists := decoded["related_waiting_count"]; exists {
			t.Fatalf("author list leaked related_waiting_count: %s", raw)
		}
	}

	adminDetail, err := s.Get(ctx, admin, tasks[0].ID)
	if err != nil || adminDetail.RelatedWaitingCount == nil || *adminDetail.RelatedWaitingCount != 2 {
		t.Fatalf("admin detail related_waiting_count: %+v %v", adminDetail, err)
	}
	adminList, err := s.FilteredList(ctx, admin, m.TaskFilter{School: "school", State: "waiting", Admin: true, Limit: 20})
	if err != nil || len(adminList) != 3 {
		t.Fatalf("admin list: %+v %v", adminList, err)
	}
	for _, item := range adminList {
		if item.RelatedWaitingCount == nil || *item.RelatedWaitingCount != 2 {
			t.Fatalf("admin list related_waiting_count: %+v", item)
		}
	}

	preview, err := s.PreviewBatch(ctx, admin, m.BatchRequest{
		Items: []m.BatchItem{
			{ID: tasks[0].ID, Revision: tasks[0].Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Violation"}},
			{ID: tasks[1].ID, Revision: tasks[1].Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Violation"}},
		},
	})
	if err != nil || preview.Items[0].State != "ready" || preview.Items[1].State != "rejected" || preview.Items[1].Code != "conflict" {
		t.Fatalf("batch preview same-object dedupe: %+v %v", preview, err)
	}

	decided, err := s.Decide(ctx, admin, tasks[0].ID, "decide-hide", m.Decide{
		Revision: tasks[0].Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Confirmed violation"},
	})
	if err != nil || decided.State != "decided" || decided.RelatedWaitingCount == nil || *decided.RelatedWaitingCount != 2 {
		t.Fatalf("primary decide: %+v %v", decided, err)
	}
	if _, err = s.Decide(ctx, admin, tasks[1].ID, "decide-second", m.Decide{
		Revision: tasks[1].Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Duplicate"},
	}); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("expected conflict while sibling decision is in flight, got %v", err)
	}

	if n, err := s.Work(ctx, 10); err != nil || n != 1 || c.calls != 1 {
		t.Fatalf("work delivery: n=%d calls=%d err=%v", n, c.calls, err)
	}

	for i, orig := range tasks {
		reporter := m.Principal{Subject: fmt.Sprintf("reporter-%d", i+1)}
		got, err := s.Get(ctx, reporter, orig.ID)
		if err != nil || got.State != "applied" || got.Decision == nil || got.Decision.ID != decided.Decision.ID || got.Decision.Action != "hide" {
			t.Fatalf("reporter %d receipt not linked-resolved: %+v %v", i+1, got, err)
		}
	}
	afterWork, err := s.Get(ctx, admin, tasks[0].ID)
	if err != nil || afterWork.RelatedWaitingCount == nil || *afterWork.RelatedWaitingCount != 0 {
		t.Fatalf("expected 0 remaining waiting tasks: %+v %v", afterWork, err)
	}

	events, err := s.Repo.(m.OutboxReader).PendingOutbox(ctx, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	resultsByOwner := map[string]m.Envelope{}
	for _, ev := range events {
		if ev.Type == "moderation.result.v1" {
			resultsByOwner[ev.Data.Owner] = ev
		}
	}
	for i, orig := range tasks {
		owner := fmt.Sprintf("reporter-%d", i+1)
		ev, ok := resultsByOwner[owner]
		if !ok || ev.Data.TaskID != orig.ID || ev.Data.DecisionID != decided.Decision.ID || ev.Data.Action != "hide" || ev.Data.State != "applied" {
			t.Fatalf("missing or wrong result event for %s: %+v", owner, ev)
		}
	}
}

func TestDismissCascadesOnlyForReportOrReviewAndRespectsObjectRevision(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}

	r1, err := s.Submit(ctx, m.Principal{Subject: "reporter-a"}, "r1", m.Submission{
		ObjectID: "review",
		Kind:     "report",
		Reason:   "First report",
		Evidence: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	editReq, err := s.Submit(ctx, m.Principal{Subject: "author"}, "edit-1", m.Submission{
		ObjectID:     "review",
		Kind:         "edit_request",
		Reason:       "Author typo fix",
		ProposedBody: "Updated text",
		Evidence:     []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Dismissing the author's edit_request must NOT auto-dismiss pending reports.
	if _, err = s.Decide(ctx, admin, editReq.ID, "dismiss-edit", m.Decide{
		Revision: editReq.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Keep original"},
	}); err != nil {
		t.Fatal(err)
	}
	stillWaiting, err := s.Get(ctx, m.Principal{Subject: "reporter-a"}, r1.ID)
	if err != nil || stillWaiting.State != "waiting" {
		t.Fatalf("edit_request dismiss closed unrelated report: %+v %v", stillWaiting, err)
	}

	// Add a second report at revision 1, and a third report after bumping object revision to 2.
	r2, err := s.Submit(ctx, m.Principal{Subject: "reporter-b"}, "r2", m.Submission{
		ObjectID: "review",
		Kind:     "report",
		Reason:   "Second report",
		Evidence: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.revision = 2
	c.mu.Unlock()
	rNewer, err := s.Submit(ctx, m.Principal{Subject: "reporter-c"}, "r3", m.Submission{
		ObjectID: "review",
		Kind:     "report",
		Reason:   "Report on revision 2",
		Evidence: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Reset object revision to 1 to test dismissing r1 at revision 1 while rNewer recorded object_revision=2.
	c.mu.Lock()
	c.revision = 1
	c.mu.Unlock()
	dismissed, err := s.Decide(ctx, admin, r1.ID, "dismiss-r1", m.Decide{
		Revision: r1.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "No violation in rev 1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotR2, err := s.Get(ctx, m.Principal{Subject: "reporter-b"}, r2.ID)
	if err != nil || gotR2.State != "applied" || gotR2.Decision == nil || gotR2.Decision.ID != dismissed.Decision.ID {
		t.Fatalf("r2 at rev 1 should be linked-dismissed: %+v %v", gotR2, err)
	}
	gotNewer, err := s.Get(ctx, m.Principal{Subject: "reporter-c"}, rNewer.ID)
	if err != nil || gotNewer.State != "waiting" {
		t.Fatalf("rNewer at rev 2 must remain waiting: %+v %v", gotNewer, err)
	}
}
