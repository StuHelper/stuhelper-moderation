package moderation_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
	"github.com/StuHelper/stuhelper-moderation/postgres"
	"github.com/StuHelper/stuhelper-moderation/sdk"
)

func TestFixedCategoriesAndRequiredOtherReason(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	server := httptest.NewServer(httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (m.Principal, error) {
			return m.Principal{Subject: r.Header.Get("X-Actor")}, nil
		},
	}.Routes())
	defer server.Close()
	client, err := sdk.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	submit := func(category sdk.ViolationCategory, reason string) (*sdk.SubmitTaskResponse, error) {
		return client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "report"}, sdk.Submission{
			ObjectId: "review",
			Kind:     sdk.SubmissionKindReport,
			Category: &category,
			Reason:   reason,
			Evidence: []string{},
		}, func(_ context.Context, r *http.Request) error {
			r.Header.Set("X-Actor", "reporter-"+string(category))
			return nil
		})
	}

	other := sdk.ViolationCategoryOther
	for _, reason := range []string{"", "  \t\u3000", strings.Repeat("说", 2001)} {
		resp, err := submit(other, reason)
		if err != nil || resp.JSON400 == nil || resp.JSON400.Reason == nil || *resp.JSON400.Reason != sdk.InvalidParameter {
			t.Fatalf("other reason of length %d: expected invalid_parameter, got %v %+v", len(reason), err, resp)
		}
	}
	unknown := sdk.ViolationCategory("obsolete")
	bad, err := submit(unknown, "补充说明")
	if err != nil || bad.JSON400 == nil || bad.JSON400.Reason == nil || *bad.JSON400.Reason != sdk.InvalidCategory {
		t.Fatalf("expected invalid_category, got %v %+v", err, bad)
	}

	categories := []sdk.ViolationCategory{
		"illegal_content", "pornography", "gambling_drugs", "fraud", "violence_threat", "minors_harm",
		"personal_attack", "harassment_discrimination", "defamation_rumor", "privacy_leak", "impersonation",
		"copyright", "other_ip", "academic_integrity", "leaked_exam", "fake_review", "wrong_teacher", "wrong_info",
		"spam", "malware", "duplicate", "low_quality", "author_update", other,
	}
	for _, category := range categories {
		resp, err := submit(category, strings.Repeat("说", 2000))
		if err != nil || resp.JSON200 == nil || resp.JSON200.Submission.Category == nil || *resp.JSON200.Submission.Category != category {
			t.Fatalf("category %q at the Unicode limit: %v %+v", category, err, resp)
		}
	}

	summary, err := s.QueueSummary(ctx, m.Principal{Subject: "admin"}, "school")
	if err != nil || summary.Waiting != len(categories) || len(summary.ByCategory) != len(categories) {
		t.Fatalf("invalid submissions changed the queue: %+v, %v", summary, err)
	}
	admin := func(_ context.Context, r *http.Request) error {
		r.Header.Set("X-Actor", "admin")
		return nil
	}
	school := "school"
	adminQuery := "true"
	page, err := client.ListTaskPageWithResponse(ctx, &sdk.ListTaskPageParams{Category: &other, SchoolId: &school, Admin: &adminQuery}, admin)
	if err != nil || page.JSON200 == nil || len(page.JSON200.Items) != 1 {
		t.Fatalf("filter via generated client: %v %+v", err, page)
	}
	task := page.JSON200.Items[0]
	badDecision, err := client.DecideTaskWithResponse(ctx, task.Id, &sdk.DecideTaskParams{IdempotencyKey: "bad-other-decision"}, sdk.Decide{
		Revision: task.Revision,
		Decision: sdk.DecisionInput{ObjectId: "review", Action: "dismiss", Revision: task.ObjectRevision, Category: &other, Reason: "  "},
	}, admin)
	if err != nil || badDecision.JSON400 == nil || badDecision.JSON400.Reason == nil || *badDecision.JSON400.Reason != sdk.InvalidParameter {
		t.Fatalf("decision with other requires a reason: %v %+v", err, badDecision)
	}
	unchanged, err := s.Get(ctx, m.Principal{Subject: "admin"}, task.Id)
	if err != nil || unchanged.Revision != task.Revision || unchanged.State != "waiting" || unchanged.Decision != nil {
		t.Fatalf("invalid decision changed task: %+v, %v", unchanged, err)
	}
}

func TestFixedCategoryMigrationQueueAndComplaintReplay(t *testing.T) {
	repo, migration := database(t)
	ctx := context.Background()
	if _, err := repo.DB.ExecContext(ctx, `INSERT INTO moderation.schema_migrations(name) VALUES ('runtime_write')`); err == nil {
		t.Fatal("runtime role can write migration history")
	}
	// The fixture installs the latest schema. Remove the migration record before
	// seeding rows that represent the original schema's data.
	if _, err := migration.ExecContext(ctx, `DELETE FROM moderation.schema_migrations WHERE name='fixed_violation_categories'`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := &m.Service{Repo: repo, Access: access{}, Clock: func() time.Time { return now }}
	admin := m.Principal{Subject: "admin"}
	reporter := m.Principal{Subject: "reporter"}
	object := m.Object{ID: "resource:legacy", Kind: "resource", SchoolID: "school", Owner: "author", Revision: 1}

	digest := func(v any) string {
		sum := sha256.Sum256(mustJSON(t, v))
		return hex.EncodeToString(sum[:])
	}
	oldSubmission := m.Submission{ObjectID: object.ID, Kind: "report", Reason: "Original complaint", Evidence: []string{"Evidence", "Contact"}}
	key := "legacy-delivery"
	operation := digest([]string{reporter.Subject, "report", object.ID, key})
	original := m.Task{
		ID: operation, Owner: reporter.Subject, ContentOwner: object.Owner, ContentKind: object.Kind, SchoolID: object.SchoolID,
		Submission: oldSubmission, ObjectRevision: 1, Revision: 1, State: "waiting", CreatedAt: now, UpdatedAt: now,
	}
	if err := repo.Transaction(ctx, func(tx m.Transaction) error {
		if err := tx.SaveTask(original); err != nil {
			return err
		}
		oldView := m.TaskView{
			ID: original.ID, ContentKind: original.ContentKind, SchoolID: original.SchoolID, Submission: oldSubmission,
			State: original.State, Revision: original.Revision, ObjectRevision: original.ObjectRevision, CreatedAt: now, UpdatedAt: now,
		}
		if err := tx.SaveReplay(operation, m.Replay{TaskID: original.ID, Digest: digest(oldSubmission), View: oldView, Until: now.Add(time.Hour)}); err != nil {
			return err
		}
		for _, task := range []m.Task{
			{ID: "same-category", State: "waiting", Submission: m.Submission{Category: "copyright"}},
			{ID: "no-category", State: "waiting"},
			{ID: "unknown-category", State: "waiting", Submission: m.Submission{Category: "old_label"}},
			{ID: "decision-overrides", State: "applied", Submission: m.Submission{Category: "spam"}, Decision: &m.Decision{Category: "old_decision", Reason: "Original decision"}},
			{ID: "foreign-category", State: "waiting", SchoolID: "other-school", Submission: m.Submission{Category: "copyright"}},
		} {
			task.Owner = task.ID
			task.ContentKind = "course"
			if task.SchoolID == "" {
				task.SchoolID = "school"
			}
			task.Submission.ObjectID = task.ID
			task.Submission.Kind = "report"
			task.Submission.Reason = "Original report"
			task.CreatedAt = now
			if err := tx.SaveTask(task); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.ExecContext(ctx, postgres.Schema); err != nil {
		t.Fatal(err)
	}

	currentObject := m.Object{ID: "resource:current", Kind: "resource", SchoolID: "school", Owner: "author", Revision: 1, Visible: true}
	s.Content = complaintTarget{object: currentObject}
	currentSubmission := m.Submission{ObjectID: currentObject.ID, Kind: "report", Reason: "Uncategorized public report"}
	const newKey = "generic-resource-report"
	current, err := s.Submit(ctx, reporter, newKey, currentSubmission)
	if err != nil || current.Submission.Category != "" {
		t.Fatalf("new generic report should start uncategorized: %+v, %v", current, err)
	}
	if _, err := migration.ExecContext(ctx, postgres.Schema); err != nil {
		t.Fatal(err)
	}
	task, err := s.Get(ctx, reporter, current.ID)
	if err != nil || task.Submission.Category != "" {
		t.Fatalf("rerunning migration changed the new report: %+v, %v", task, err)
	}
	currentReplay, err := s.Submit(ctx, reporter, newKey, currentSubmission)
	if err != nil || currentReplay.ID != current.ID || currentReplay.Revision != current.Revision || currentReplay.Submission.Category != "" {
		t.Fatalf("rerunning migration changed the new report receipt: %+v, %v", currentReplay, err)
	}

	updated := oldSubmission
	updated.Category = "other"
	replayed, err := s.SubmitResourceComplaint(ctx, reporter, key, updated, object)
	if err != nil || replayed.ID != original.ID || replayed.Revision != 1 || len(replayed.Submission.Evidence) != 2 || replayed.Submission.Category != "other" || replayed.Submission.Reason != oldSubmission.Reason {
		t.Fatalf("migration did not recover the original complaint: %+v, %v", replayed, err)
	}
	changed := updated
	changed.Reason = "Changed complaint"
	if _, err = s.SubmitResourceComplaint(ctx, reporter, key, changed, object); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("same key with changed content must conflict: %v", err)
	}
	changed = updated
	changed.Category = "copyright"
	if _, err = s.SubmitResourceComplaint(ctx, reporter, key, changed, object); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("same key with changed category must conflict: %v", err)
	}
	if err := repo.Transaction(ctx, func(tx m.Transaction) error {
		receipt, err := tx.Replay(operation)
		if err == nil && receipt.Digest != digest(oldSubmission) {
			t.Fatal("migration changed the original idempotency digest")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	summary, err := s.QueueSummary(ctx, admin, "school")
	if err != nil || summary.Waiting != 5 || !maps.Equal(summary.ByCategory, map[string]int{"copyright": 1, "other": 2}) {
		t.Fatalf("unexpected category queue summary: %+v, %v", summary, err)
	}
	filter := m.TaskFilter{School: "school", Admin: true, Category: "other", Limit: 100}
	tasks, err := s.FilteredList(ctx, admin, filter)
	if err != nil || len(tasks) != 3 {
		t.Fatalf("category filter did not use the new values: %+v, %v", tasks, err)
	}
	for _, task := range tasks {
		if task.ID == "decision-overrides" && (task.Submission.Category != "spam" || task.Decision == nil || task.Decision.Category != "other" || task.Decision.Reason != "Original decision") {
			t.Fatalf("migration changed the decision's original facts: %+v", task)
		}
	}
	filter.Category = "spam"
	tasks, err = s.FilteredList(ctx, admin, filter)
	if err != nil || len(tasks) != 0 {
		t.Fatalf("decision category did not override submission category: %+v, %v", tasks, err)
	}

	t.Run("merged_resource_complaints", checkMergedResourceComplaintCategories)
}

func checkMergedResourceComplaintCategories(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}
	reporter := m.Principal{Subject: "reporter"}
	for _, tc := range []struct {
		objectID, initial, supplement, want string
	}{
		{"resource:classified", "copyright", "spam", "copyright"},
		{"resource:uncategorized", "", "other_ip", "other_ip"},
	} {
		object := m.Object{ID: tc.objectID, Kind: "resource", SchoolID: "school", Owner: "author", Revision: 1, Visible: true}
		first := m.Submission{
			Kind: "report", ObjectID: object.ID, Category: tc.initial,
			Reason: "Original report", Evidence: []string{"Original evidence", "Original contact"},
		}
		var original m.TaskView
		var err error
		if tc.initial == "" {
			s.Content = complaintTarget{object: object}
			original, err = s.Submit(ctx, reporter, "initial", first)
		} else {
			original, err = s.SubmitResourceComplaint(ctx, reporter, "initial", first, object)
		}
		if err != nil || original.Submission.Category != tc.initial {
			t.Fatalf("%s: initial submission: %+v, %v", tc.objectID, original, err)
		}

		later := m.Submission{
			Kind: "report", ObjectID: object.ID, Category: tc.supplement,
			Reason: "Supplementary explanation", Evidence: []string{"Additional evidence", "Updated contact"},
		}
		merged, err := s.SubmitResourceComplaint(ctx, reporter, "supplement", later, object)
		wantEvidence := []string{"Original evidence", "Original contact", "Supplementary explanation", "Additional evidence", "Updated contact"}
		if err != nil || merged.ID != original.ID || merged.Revision != original.Revision+1 ||
			merged.Submission.Category != tc.want || merged.Submission.Reason != first.Reason || !slices.Equal(merged.Submission.Evidence, wantEvidence) {
			t.Fatalf("%s: complaint must merge into the original task: %+v, %v", tc.objectID, merged, err)
		}
		replayed, err := s.SubmitResourceComplaint(ctx, reporter, "supplement", later, object)
		if err != nil || replayed.ID != merged.ID || replayed.Revision != merged.Revision ||
			replayed.Submission.Category != tc.want || !slices.Equal(replayed.Submission.Evidence, wantEvidence) {
			t.Fatalf("%s: complaint replay must preserve the merged task: %+v, %v", tc.objectID, replayed, err)
		}
		filter := m.TaskFilter{School: "school", Admin: true, Limit: 10, Category: tc.want}
		tasks, err := s.FilteredList(ctx, admin, filter)
		if err != nil || len(tasks) != 1 || tasks[0].ID != original.ID || !slices.Equal(tasks[0].Submission.Evidence, wantEvidence) {
			t.Fatalf("%s: expected one persisted task under %q: %+v, %v", tc.objectID, tc.want, tasks, err)
		}
	}

	filter := m.TaskFilter{School: "school", Admin: true, Limit: 10, Category: "spam"}
	tasks, err := s.FilteredList(ctx, admin, filter)
	if err != nil || len(tasks) != 0 {
		t.Fatalf("replacement category appeared in the filter: %+v, %v", tasks, err)
	}
	summary, err := s.QueueSummary(ctx, admin, "school")
	if err != nil || summary.Waiting != 2 || !maps.Equal(summary.ByCategory, map[string]int{"copyright": 1, "other_ip": 1}) {
		t.Fatalf("unexpected merged complaint counts: %+v, %v", summary, err)
	}
}
