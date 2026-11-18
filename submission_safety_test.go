package moderation_test

import (
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/StuHelper/stuhelper-moderation/postgres"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
	"time"
)

func TestAuthorRequestSupplementCannotOverwriteConcurrentDecision(t *testing.T) {
	s, _, _ := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	author := m.Principal{Subject: "author"}
	in := m.Submission{ObjectID: "review", Kind: "edit_request", Reason: "Fix typo", Evidence: []string{"v1"}, ProposedBody: "First draft"}
	task, err := s.Submit(ctx, author, "edit-initial", in)
	if err != nil {
		t.Fatal(err)
	}
	barrier := &decisionBarrier{Content: s.Content, entered: make(chan struct{}), release: make(chan struct{})}
	s.Content = barrier
	decided := make(chan error, 1)
	go func() {
		_, e := s.Decide(ctx, m.Principal{Subject: "admin"}, task.ID, "decide-edit", m.Decide{
			Revision: task.Revision,
			Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Keep original"},
		})
		decided <- e
	}()
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	in.ProposedBody = "Late draft"
	in.Evidence = []string{"v2"}
	supplemented := make(chan error, 1)
	go func() {
		_, e := s.Submit(ctx, author, "edit-late", in)
		supplemented <- e
	}()
	select {
	case early := <-supplemented:
		close(barrier.release)
		<-decided
		t.Fatalf("author supplement bypassed active decision lock: %v", early)
	case <-time.After(50 * time.Millisecond):
	}
	close(barrier.release)
	if e := <-decided; e != nil {
		t.Fatal(e)
	}
	if e := <-supplemented; !errors.Is(e, m.ErrConflict) {
		t.Fatalf("expected conflict on late author supplement, got: %v", e)
	}
	current, err := s.Get(ctx, author, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != "applied" || current.Decision == nil || current.Submission.ProposedBody != "First draft" || len(current.Submission.Evidence) != 1 {
		t.Fatalf("decision or original request overwritten: %+v", current)
	}
}

func TestAppealEnforcesSingleAppealAppliedStateAndRecusal(t *testing.T) {
	s, c, now := fixture(t)
	s.Access = reviewAccess{}
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}
	reviewer := m.Principal{Subject: "reviewer"}
	author := m.Principal{Subject: "author"}

	// 1. Failed tasks (not yet applied) cannot be appealed and do not advertise CanAppeal.
	failedReq, err := s.Submit(ctx, author, "del-1", m.Submission{ObjectID: "review", Kind: "delete_request", Reason: "Remove", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	c.loseResult = true
	if _, err = s.Decide(ctx, admin, failedReq.ID, "dec-fail", m.Decide{Revision: failedReq.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"}}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(25 * time.Hour)
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	failedView, err := s.Get(ctx, author, failedReq.ID)
	if err != nil || failedView.State != "failed" {
		t.Fatalf("expected failed task, got %+v %v", failedView, err)
	}
	if failedView.CanAppeal {
		t.Fatal("failed task must not set can_appeal")
	}
	if _, err = s.Submit(ctx, author, "appeal-on-failed", m.Submission{ObjectID: "review", Kind: "appeal", PreviousTaskID: failedReq.ID, Reason: "Appeal failed delivery", Evidence: []string{}}); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("appeal on failed task must conflict, got: %v", err)
	}
	c.loseResult = false

	// 2. Two applied tasks on the same object: an active appeal on task A rejects merging an appeal for task B.
	firstTask, err := s.Submit(ctx, admin, "rev-1", m.Submission{ObjectID: "review", Kind: "review", Reason: "Check 1", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	firstTask, err = s.Decide(ctx, admin, firstTask.ID, "dec-1", m.Decide{Revision: firstTask.Revision, Decision: m.Decision{ObjectID: "review", Revision: 2, Action: "dismiss", Reason: "Dismissed 1"}})
	if err != nil {
		t.Fatal(err)
	}
	secondTask, err := s.Submit(ctx, admin, "rev-2", m.Submission{ObjectID: "review", Kind: "review", Reason: "Check 2", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	secondTask, err = s.Decide(ctx, admin, secondTask.ID, "dec-2", m.Decide{Revision: secondTask.Revision, Decision: m.Decision{ObjectID: "review", Revision: 2, Action: "dismiss", Reason: "Dismissed 2"}})
	if err != nil {
		t.Fatal(err)
	}

	appeal1, err := s.Submit(ctx, author, "appeal-1", m.Submission{ObjectID: "review", Kind: "appeal", PreviousTaskID: firstTask.ID, Reason: "Reconsider first", Evidence: []string{"ev1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Submit(ctx, author, "appeal-mismatched-prev", m.Submission{ObjectID: "review", Kind: "appeal", PreviousTaskID: secondTask.ID, Reason: "Different prior", Evidence: []string{"ev2"}}); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("expected conflict when active appeal has different previous_task_id, got: %v", err)
	}

	// Same previous_task_id while waiting can still supplement evidence.
	appeal1, err = s.Submit(ctx, author, "appeal-1-supp", m.Submission{ObjectID: "review", Kind: "appeal", PreviousTaskID: firstTask.ID, Reason: "Reconsider first", Evidence: []string{"ev2"}})
	if err != nil || len(appeal1.Submission.Evidence) != 2 {
		t.Fatalf("expected supplement on waiting appeal, got: %+v %v", appeal1, err)
	}

	// 3. Once appeal1 is decided (applied), neither appeal1 itself nor firstTask can be appealed again.
	appeal1, err = s.Decide(ctx, reviewer, appeal1.ID, "decide-appeal-1", m.Decide{Revision: appeal1.Revision, Decision: m.Decision{ObjectID: "review", Revision: 2, Action: "dismiss", Reason: "Upheld"}})
	if err != nil {
		t.Fatal(err)
	}
	if appeal1.CanAppeal {
		t.Fatal("completed appeal must not allow chained appeal")
	}
	reloadedFirst, err := s.Get(ctx, author, firstTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedFirst.CanAppeal {
		t.Fatal("already-appealed task must not advertise can_appeal")
	}
	if _, err = s.Submit(ctx, author, "appeal-1-duplicate", m.Submission{ObjectID: "review", Kind: "appeal", PreviousTaskID: firstTask.ID, Reason: "Appeal again", Evidence: []string{}}); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("duplicate appeal for same previous_task_id must conflict, got: %v", err)
	}
	if _, err = s.Submit(ctx, author, "appeal-of-appeal", m.Submission{ObjectID: "review", Kind: "appeal", PreviousTaskID: appeal1.ID, Reason: "Chained appeal", Evidence: []string{}}); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("chained appeal on appeal task must conflict, got: %v", err)
	}
}

type strictOutageAccess struct {
	allUnavailable bool
	allForbidden   bool
}

func (a *strictOutageAccess) Authorize(ctx context.Context, p m.Principal, action, school string) error {
	if a.allUnavailable {
		return m.ErrUnavailable
	}
	if a.allForbidden {
		return m.ErrForbidden
	}
	return (access{}).Authorize(ctx, p, action, school)
}

func TestReportSupplementBypassesSubmitOutageAndTrustedPortsValidateObject(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	gate := &strictOutageAccess{}
	s.Access = gate
	source := &reportContent{Content: s.Content}
	s.Content = source

	reporter := m.Principal{Subject: "reporter"}
	in := m.Submission{Kind: "report", ObjectID: "review", Reason: "Spam", Evidence: []string{"ev-1"}}
	original, err := s.Submit(ctx, reporter, "rep-init", in)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate full Access outage (including action="submit") and Content outage.
	gate.allUnavailable = true
	source.unavailable = true

	replayed, err := s.Submit(ctx, reporter, "rep-init", in)
	if err != nil || replayed.ID != original.ID {
		t.Fatalf("replay failed under Access outage: %+v %v", replayed, err)
	}
	in.Evidence = []string{"ev-2"}
	supplemented, err := s.Submit(ctx, reporter, "rep-supp-1", in)
	if err != nil || supplemented.ID != original.ID || len(supplemented.Submission.Evidence) != 2 {
		t.Fatalf("own waiting report supplement failed under Access outage: %+v %v", supplemented, err)
	}

	// Simulate expired qualification (Access returns ErrForbidden even for "submit").
	gate.allUnavailable = false
	gate.allForbidden = true
	in.Evidence = []string{"ev-3"}
	supplemented, err = s.Submit(ctx, reporter, "rep-supp-2", in)
	if err != nil || len(supplemented.Submission.Evidence) != 3 {
		t.Fatalf("own waiting report supplement failed after qualification expiry: %+v %v", supplemented, err)
	}

	// Trusted SubmitResourceComplaint port works without user "submit" admission, and validates SchoolID.
	validObj := m.Object{ID: "resource:v1", Kind: "resource", SchoolID: "school", Owner: "uploader", Revision: 1, Visible: true}
	compIn := m.Submission{Kind: "report", ObjectID: validObj.ID, Reason: "Copyright", Evidence: []string{"Proof", "contact@example.test"}}
	if _, err = s.SubmitResourceComplaint(ctx, m.Principal{Subject: "rightsholder"}, "comp-ok", compIn, validObj); err != nil {
		t.Fatalf("trusted complaint port blocked by user qualification gate: %v", err)
	}

	noSchool := validObj
	noSchool.SchoolID = ""
	if _, err = s.SubmitResourceComplaint(ctx, m.Principal{Subject: "rightsholder"}, "comp-bad-school", compIn, noSchool); !errors.Is(err, m.ErrInput) {
		t.Fatalf("expected ErrInput for empty SchoolID in SubmitResourceComplaint, got: %v", err)
	}

	for _, badTrack := range []struct {
		eventID string
		obj     m.Object
	}{
		{"", m.Object{ID: "review", SchoolID: "school", Owner: "author", Revision: 1}},
		{"ev-bad-1", m.Object{ID: "review", SchoolID: "", Owner: "author", Revision: 1}},
		{"ev-bad-2", m.Object{ID: "review", SchoolID: "school", Owner: "", Revision: 1}},
		{"ev-bad-3", m.Object{ID: "review", SchoolID: "school", Kind: "invalid_kind", Owner: "author", Revision: 1}},
	} {
		if _, err = s.Track(ctx, badTrack.eventID, badTrack.obj); !errors.Is(err, m.ErrInput) {
			t.Fatalf("expected ErrInput for invalid Track(%q, %+v), got: %v", badTrack.eventID, badTrack.obj, err)
		}
	}
}

func TestAppealMigrationPreservesHistoricalDuplicates(t *testing.T) {
	_, db := database(t)
	if _, err := db.Exec("DROP INDEX moderation.moderation_appeal_previous"); err != nil {
		t.Fatal(err)
	}
	const insert = `INSERT INTO moderation.tasks(id,owner,school_id,object_id,kind,state,next_attempt,lease_until,data)
		VALUES($1,'author','school','object','appeal','applied',now(),now(),jsonb_build_object('submission',jsonb_build_object('previous_task_id','previous'),'history',$1::text))`
	for _, id := range []string{"appeal-a", "appeal-b"} {
		if _, err := db.Exec(insert, id); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(postgres.Schema); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM moderation.tasks WHERE state='applied' AND data->'submission'->>'previous_task_id'='previous' AND data->>'history'=id").Scan(&count); err != nil || count != 2 {
		t.Fatal("historical appeals", count, err)
	}
	_, err := db.Exec(insert, "appeal-c")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatal("new duplicate", err)
	}
}
