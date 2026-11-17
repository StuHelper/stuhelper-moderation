package moderation_test

import (
	"context"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"github.com/StuHelper/stuhelper-moderation/sdk"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTimeOrderedTaskPaginationAndQueueSummary(t *testing.T) {
	s, _, now := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}
	*now = time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)

	createdOrder := []string{}
	for i := 0; i < 5; i++ {
		if i != 2 {
			// Give i=1 and i=2 the exact same microsecond timestamp to exercise tie-breaking by ID.
			*now = now.Add(time.Minute)
		}
		reporter := m.Principal{Subject: fmt.Sprintf("student-%d", i)}
		task, err := s.Submit(ctx, reporter, fmt.Sprintf("k-%d", i), m.Submission{
			ObjectID: "review",
			Kind:     "report",
			Reason:   fmt.Sprintf("Reason %d", i),
			Evidence: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		createdOrder = append(createdOrder, task.ID)
	}
	if createdOrder[1] > createdOrder[2] {
		createdOrder[1], createdOrder[2] = createdOrder[2], createdOrder[1]
	}

	// Admin default order is oldest (FIFO: created_at ASC, id ASC).
	seenAsc := []string{}
	cursor := ""
	pages := 0
	for {
		pages++
		page, err := s.FilteredPage(ctx, admin, m.TaskFilter{
			School: "school",
			Admin:  true,
			After:  cursor,
			Limit:  2,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			seenAsc = append(seenAsc, item.ID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if pages != 3 || len(seenAsc) != 5 {
		t.Fatalf("unexpected pages=%d items=%d", pages, len(seenAsc))
	}
	for i := range createdOrder {
		if seenAsc[i] != createdOrder[i] {
			t.Fatalf("FIFO order mismatch at %d: got %v want %v", i, seenAsc, createdOrder)
		}
	}

	// Exact page boundary (limit == 5 for 5 rows) must return empty next_cursor.
	exactPage, err := s.FilteredPage(ctx, admin, m.TaskFilter{School: "school", Admin: true, Limit: 5})
	if err != nil || len(exactPage.Items) != 5 || exactPage.NextCursor != "" {
		t.Fatalf("exact limit should have empty next_cursor: %+v %v", exactPage, err)
	}

	// Switching order with a cursor from another order must fail with ErrInput.
	firstTwo, err := s.FilteredPage(ctx, admin, m.TaskFilter{School: "school", Admin: true, Order: "oldest", Limit: 2})
	if err != nil || firstTwo.NextCursor == "" {
		t.Fatal(firstTwo, err)
	}
	if _, err = s.FilteredPage(ctx, admin, m.TaskFilter{School: "school", Admin: true, Order: "newest", After: firstTwo.NextCursor, Limit: 2}); !errors.Is(err, m.ErrInput) {
		t.Fatalf("mismatched cursor order accepted: %v", err)
	}

	// Admin newest order (created_at DESC, id DESC).
	newestPage, err := s.FilteredPage(ctx, admin, m.TaskFilter{School: "school", Admin: true, Order: "newest", Limit: 5})
	if err != nil || len(newestPage.Items) != 5 || newestPage.Items[0].ID != createdOrder[4] || newestPage.Items[4].ID != createdOrder[0] {
		t.Fatalf("newest order mismatch: %+v %v", newestPage, err)
	}

	// Legacy bare-ID after cursor compatibility.
	legacyNext, err := s.FilteredList(ctx, admin, m.TaskFilter{School: "school", Admin: true, After: createdOrder[1], Limit: 10})
	if err != nil || len(legacyNext) != 3 || legacyNext[0].ID != createdOrder[2] {
		t.Fatalf("legacy bare ID cursor failed: %+v %v", legacyNext, err)
	}

	// Add a pending resource review and decide one report to verify student updated_desc and QueueSummary.
	*now = now.Add(time.Minute)
	if _, err = s.Track(ctx, "res-upload", m.Object{ID: "resource:v1", Kind: "resource", SchoolID: "school", Owner: "author", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if _, err = s.Decide(ctx, admin, createdOrder[0], "decide-oldest", m.Decide{
		Revision: 1,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Confirmed"},
	}); err != nil {
		t.Fatal(err)
	}

	// Author list defaults to updated_desc: createdOrder[0] was just decided so it must appear first!
	authorPage, err := s.FilteredPage(ctx, m.Principal{Subject: "author"}, m.TaskFilter{Limit: 10})
	if err != nil || len(authorPage.Items) != 6 || authorPage.Items[0].ID != createdOrder[0] {
		t.Fatalf("student updated_desc order failed: %+v %v", authorPage, err)
	}

	// Verify QueueSummary and HTTP SDK endpoints.
	if _, err = s.QueueSummary(ctx, m.Principal{Subject: "author"}, "school"); !errors.Is(err, m.ErrForbidden) {
		t.Fatalf("non-admin accessed queue summary: %v", err)
	}
	if _, err = s.QueueSummary(ctx, admin, "other-school"); !errors.Is(err, m.ErrForbidden) {
		t.Fatalf("cross-school queue summary allowed: %v", err)
	}

	srv := httptest.NewServer(httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (m.Principal, error) {
			return m.Principal{Subject: r.Header.Get("X-Test-Actor")}, nil
		},
	}.Routes())
	defer srv.Close()

	client, err := sdk.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	asAdmin := func(_ context.Context, r *http.Request) error {
		r.Header.Set("X-Test-Actor", "admin")
		return nil
	}

	summaryResp, err := client.GetQueueSummaryWithResponse(ctx, &sdk.GetQueueSummaryParams{SchoolId: "school"}, asAdmin)
	if err != nil || summaryResp.StatusCode() != 200 || summaryResp.JSON200 == nil {
		t.Fatalf("getQueueSummary failed: %v %+v", err, summaryResp)
	}
	gotSummary := summaryResp.JSON200
	if gotSummary.Waiting != 5 || gotSummary.Decided != 1 || gotSummary.Failed != 0 ||
		gotSummary.ByContentKind.Course != 4 || gotSummary.ByContentKind.Resource != 1 ||
		gotSummary.ByRequestKind.Report != 4 || gotSummary.ByRequestKind.Review != 1 {
		t.Fatalf("unexpected queue summary: %+v", gotSummary)
	}

	limit := 2
	adminFlag := "true"
	schoolID := "school"
	listResp, err := client.ListTasksWithResponse(ctx, &sdk.ListTasksParams{SchoolId: &schoolID, Admin: &adminFlag, Limit: &limit}, asAdmin)
	if err != nil || listResp.StatusCode() != 200 || listResp.JSON200 == nil || len(*listResp.JSON200) != 2 || listResp.HTTPResponse.Header.Get("X-Next-Cursor") == "" {
		t.Fatalf("listTasks X-Next-Cursor failed: %v %+v", err, listResp)
	}

	pageResp, err := client.ListTaskPageWithResponse(ctx, &sdk.ListTaskPageParams{SchoolId: &schoolID, Admin: &adminFlag, Limit: &limit}, asAdmin)
	if err != nil || pageResp.StatusCode() != 200 || pageResp.JSON200 == nil || pageResp.JSON200.NextCursor == "" || len(pageResp.JSON200.Items) != 2 {
		t.Fatalf("listTaskPage failed: %v %+v", err, pageResp)
	}
}

func TestFeedbackTimeOrderedCursorPagination(t *testing.T) {
	repo, _ := database(t)
	clock := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	svc := &f.Service{
		Repo:   &pg.FeedbackRepository{DB: repo.DB},
		Access: &feedbackAccess{},
		Blobs:  &feedbackBlobs{values: map[string][]byte{}},
		Now:    func() time.Time { return clock },
	}
	ctx := context.Background()

	ingested := []string{}
	for i := 0; i < 4; i++ {
		clock = clock.Add(time.Minute)
		msg, err := svc.Ingest(ctx, feedbackInput(fmt.Sprintf("mail-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		ingested = append(ingested, msg.ID)
	}

	// Feedback inbox defaults to received_at DESC, id DESC (newest mail first).
	seen := []string{}
	cursor := ""
	for {
		page, err := svc.List(ctx, "operator", f.Filter{After: cursor, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			seen = append(seen, item.ID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	want := []string{ingested[3], ingested[2], ingested[1], ingested[0]}
	if len(seen) != 4 {
		t.Fatalf("got %v want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("feedback order mismatch at %d: got %v want %v", i, seen, want)
		}
	}
	if _, err := svc.List(ctx, "operator", f.Filter{After: "f1.invalid", Limit: 2}); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("invalid feedback cursor accepted: %v", err)
	}
}
