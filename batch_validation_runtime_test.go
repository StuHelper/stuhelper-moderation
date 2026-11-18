package moderation_test

import (
	"bytes"
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"io"
	"strings"
	"testing"
	"time"
)

type revocableModerators struct {
	revoked map[string]bool
}

func (r *revocableModerators) Authorize(_ context.Context, p m.Principal, action, school string) error {
	if p.Subject == "" {
		return m.ErrForbidden
	}
	if action == "submit" || action == "report" {
		return nil
	}
	if r.revoked[p.Subject] {
		return m.ErrForbidden
	}
	if (p.Subject == "mod-a" || p.Subject == "mod-b") && school == "school" {
		return nil
	}
	return m.ErrForbidden
}

type authCheckingContent struct {
	*content
	auth *revocableModerators
	kind string
}

func (c *authCheckingContent) Inspect(ctx context.Context, p m.Principal, id string) (m.Object, error) {
	obj, err := c.content.Inspect(ctx, p, id)
	if c.kind != "" {
		obj.Kind = c.kind
	}
	return obj, err
}

func (c *authCheckingContent) Apply(ctx context.Context, p m.Principal, d m.Decision) error {
	if c.auth != nil && c.auth.revoked[p.Subject] {
		return m.ErrForbidden
	}
	return c.content.Apply(ctx, p, d)
}

func TestBatchValidationSameObjectConflictRedecideAndRevokedModeratorRetry(t *testing.T) {
	s, base, now := fixture(t)
	auth := &revocableModerators{revoked: map[string]bool{}}
	customContent := &authCheckingContent{content: base, auth: auth, kind: "resource"}
	s.Access = auth
	s.Content = customContent
	ctx := context.Background()
	modA := m.Principal{Subject: "mod-a"}
	modB := m.Principal{Subject: "mod-b"}

	// 1. PreviewBatch rejects resource-disallowed action ("feature") and duplicate mutating actions on same ObjectID.
	r1, err := s.Submit(ctx, m.Principal{Subject: "u1"}, "r1", m.Submission{ObjectID: "review", Kind: "report", Reason: "R1", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Submit(ctx, m.Principal{Subject: "u2"}, "r2", m.Submission{ObjectID: "review", Kind: "report", Reason: "R2", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}

	previewBadAction, err := s.PreviewBatch(ctx, modA, m.BatchRequest{
		Items: []m.BatchItem{{ID: r1.ID, Revision: r1.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "feature", Reason: "Invalid for resource"}}},
	})
	if err != nil || previewBadAction.Items[0].State != "rejected" || previewBadAction.Items[0].Code != "invalid_input" {
		t.Fatalf("PreviewBatch accepted resource-disallowed action: %+v %v", previewBadAction, err)
	}

	batchSameObj := m.BatchRequest{
		Items: []m.BatchItem{
			{ID: r1.ID, Revision: r1.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide 1"}},
			{ID: r2.ID, Revision: r2.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide 2"}},
		},
	}
	previewSameObj, err := s.PreviewBatch(ctx, modA, batchSameObj)
	if err != nil || previewSameObj.Items[0].State != "ready" || previewSameObj.Items[1].State != "rejected" || previewSameObj.Items[1].Code != "conflict" {
		t.Fatalf("PreviewBatch did not flag duplicate mutating action on same ObjectID: %+v %v", previewSameObj, err)
	}

	// A second decision cannot race an in-flight one. An external content edit
	// can still invalidate the first decision before its delivery.
	customContent.kind = "course"
	if _, err = s.Decide(ctx, modA, r1.ID, "dec-r1", m.Decide{Revision: r1.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, modA, r2.ID, "dec-r2", m.Decide{Revision: r2.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"}}); !errors.Is(err, m.ErrConflict) {
		t.Fatalf("second in-flight decision: %v", err)
	}
	base.mu.Lock()
	base.revision++
	base.mu.Unlock()
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	conflicted, err := s.Get(ctx, modA, r1.ID)
	if err != nil || conflicted.State != "failed" || conflicted.ErrorCode != "conflict" {
		t.Fatalf("stale decision: %+v %v", conflicted, err)
	}
	resolved, err := s.Decide(ctx, modB, conflicted.ID, "redecide-conflicted", m.Decide{
		Revision: conflicted.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 2, Action: "dismiss", Reason: "Already hidden by earlier report"},
	})
	if err != nil || resolved.State != "applied" || resolved.ErrorCode != "" {
		t.Fatalf("failed(conflict) task could not be re-decided: %+v %v", resolved, err)
	}

	// 3. Retry by modB after modA is revoked executes Apply under modB instead of revoked modA.
	r3, err := s.Submit(ctx, m.Principal{Subject: "u3"}, "r3", m.Submission{ObjectID: "review", Kind: "report", Reason: "R3", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	base.loseResult = true
	if _, err = s.Decide(ctx, modA, r3.ID, "dec-r3", m.Decide{Revision: r3.Revision, Decision: m.Decision{ObjectID: "review", Revision: 2, Action: "restore", Reason: "Restore"}}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(25 * time.Hour)
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	r3Failed, err := s.Get(ctx, modB, r3.ID)
	if err != nil || r3Failed.State != "failed" {
		t.Fatalf("expected r3 failed(unavailable), got: %+v %v", r3Failed, err)
	}
	base.loseResult = false
	// Reset revision in mock because loseResult incremented mock revision before returning ErrUnavailable.
	base.revision = 2
	base.applied = map[string]bool{}
	auth.revoked["mod-a"] = true

	if _, err = s.Retry(ctx, modB, r3.ID, "retry-r3", r3Failed.Revision); err != nil {
		t.Fatalf("Retry by modB failed: %v", err)
	}
	done, err := s.Work(ctx, 10)
	if err != nil || done != 1 {
		t.Fatalf("Work after Retry failed due to stale revoked modA principal: done=%d err=%v", done, err)
	}
	r3Applied, err := s.Get(ctx, modB, r3.ID)
	if err != nil || r3Applied.State != "applied" {
		t.Fatalf("expected r3 applied after modB Retry, got: %+v %v", r3Applied, err)
	}
}

type applyCallback struct {
	m.Content
	run func() error
}

func (c applyCallback) Apply(context.Context, m.Principal, m.Decision) error { return c.run() }

func TestReplacedDecisionRejectsStaleWorkerResult(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}
	task, err := s.Submit(ctx, m.Principal{Subject: "reporter"}, "submit-stale", m.Submission{ObjectID: "review", Kind: "report", Reason: "review"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Decide(ctx, admin, task.ID, "decide-stale", m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "check"}})
	if err != nil {
		t.Fatal(err)
	}
	// Model the persisted state after a failure, a replacement decision, and its
	// first claim. The original network call then returns its obsolete result.
	s.Content = applyCallback{c, func() error {
		err := s.Repo.Transaction(ctx, func(tx m.Transaction) error {
			v, err := tx.Task(task.ID)
			if err != nil {
				return err
			}
			v.Decision.ID = "replacement"
			v.Revision += 2
			v.Attempts = 1
			return tx.SaveTask(v)
		})
		if err != nil {
			t.Fatal(err)
		}
		return nil
	}}
	_, err = s.Work(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.Get(ctx, admin, task.ID)
	if err != nil || view.State != "decided" || view.Decision.ID != "replacement" {
		t.Fatal("stale worker changed replacement", view.State, err)
	}
}

func TestInputValidationFeedbackClockDownloadAuditAndCheckRuntime(t *testing.T) {
	repo, migration := database(t)
	now := time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC)
	c := &content{revision: 1, applied: map[string]bool{}}
	s := &m.Service{Repo: repo, Content: c, Access: access{}, Clock: func() time.Time { return now }}
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}

	task, err := s.Submit(ctx, m.Principal{Subject: "reporter"}, "rep-val", m.Submission{ObjectID: "review", Kind: "report", Reason: "Check", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Whitespace-only idempotency key, invalid SetPolicy SchoolID, edit with nil Body, reassign without EvidenceRevision, overlong AuthorHandle.
	if _, err = s.Submit(ctx, m.Principal{Subject: "reporter"}, "   ", m.Submission{ObjectID: "review", Kind: "report", Reason: "Check", Evidence: []string{}}); !errors.Is(err, m.ErrInput) {
		t.Fatalf("whitespace-only idempotency key accepted: %v", err)
	}
	if err = s.SetPolicy(ctx, admin, "pol-1", m.Policy{SchoolID: strings.Repeat("s", 129), Kind: "course", Mode: "pending"}); !errors.Is(err, m.ErrInput) {
		t.Fatalf("SetPolicy accepted invalid overlong SchoolID: %v", err)
	}
	for _, badDecision := range []m.Decision{
		{ObjectID: "review", Revision: 1, Action: "edit", Body: nil, Reason: "Missing body"},
		{ObjectID: "review", Revision: 1, Action: "reassign", TeacherID: "t1", EvidenceRevision: "", Reason: "Missing evidence_revision"},
		{ObjectID: "review", Revision: 1, Action: "identity", AuthorHandle: strings.Repeat("h", 129), Reason: "Overlong handle"},
		{ObjectID: "review", Revision: 1, Action: "identity", Reason: "Missing both handle and subject"},
	} {
		if _, err = s.Decide(ctx, admin, task.ID, "bad-dec", m.Decide{Revision: task.Revision, Decision: badDecision}); !errors.Is(err, m.ErrInput) {
			t.Fatalf("expected ErrInput for bad decision %+v, got: %v", badDecision, err)
		}
	}
	// Reassign with empty TeacherID ("noTeacher") + valid EvidenceRevision IS valid.
	validClearTeacher := m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "reassign", TeacherID: "", EvidenceRevision: "ev-rev-1", Reason: "Clear wrong teacher"}}
	if _, err = s.Decide(ctx, admin, task.ID, "ok-reassign", validClearTeacher); err != nil {
		t.Fatalf("reassign with empty TeacherID and valid EvidenceRevision rejected: %v", err)
	}

	// 2. Feedback clock alignment in List, Download audit isolation, and feedback key validation.
	blobs := &feedbackBlobs{values: map[string][]byte{}}
	fbSvc := &f.Service{Repo: &pg.FeedbackRepository{DB: repo.DB}, Access: &feedbackAccess{}, Blobs: blobs, Now: func() time.Time { return now }}
	msg, err := fbSvc.Ingest(ctx, feedbackInput("clock-case"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fbSvc.Update(ctx, "operator", msg.ID, "        ", f.Update{Revision: msg.Revision, State: "processing"}); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("feedback Update accepted whitespace-only idempotency key: %v", err)
	}
	if _, err = fbSvc.Update(ctx, "operator", msg.ID, "bad\x00key123", f.Update{Revision: msg.Revision, State: "processing"}); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("feedback Update accepted control-char idempotency key: %v", err)
	}

	// Missing attachment download must NOT write false feedback.read or feedback.download audit.
	if err = fbSvc.Download(ctx, "operator", msg.ID, "non-existent", io.Discard); !errors.Is(err, f.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing attachment, got: %v", err)
	}
	var readAudits int
	if err = migration.QueryRow(`SELECT count(*) FROM moderation.audit WHERE action IN ('feedback.read','feedback.download')`).Scan(&readAudits); err != nil || readAudits != 0 {
		t.Fatalf("missing attachment wrote false audit: count=%d err=%v", readAudits, err)
	}
	if err = fbSvc.Download(ctx, "operator", msg.ID, "one", io.Discard); err != nil {
		t.Fatalf("valid attachment download failed: %v", err)
	}
	var downloadAudits int
	if err = migration.QueryRow(`SELECT count(*) FROM moderation.audit WHERE action='feedback.download'`).Scan(&downloadAudits); err != nil || downloadAudits != 1 {
		t.Fatalf("expected 1 feedback.download audit, got %d (%v)", downloadAudits, err)
	}

	// Deny the audit write and verify the attachment never reaches the caller.
	if _, err = migration.Exec(`ALTER TABLE moderation.audit ADD CONSTRAINT fixture_deny_download CHECK (action <> 'feedback.download') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err = fbSvc.Download(ctx, "operator", msg.ID, "one", &buf); err == nil || buf.Len() != 0 {
		t.Fatal("bytes released before audit committed", buf.Len(), err)
	}
	if _, err = migration.Exec("ALTER TABLE moderation.audit DROP CONSTRAINT fixture_deny_download"); err != nil {
		t.Fatal(err)
	}
	// Close case and advance injected clock past 12 months: List must immediately exclude it just like Get.
	msg, err = fbSvc.Update(ctx, "operator", msg.ID, "close-clock-case", f.Update{Revision: msg.Revision, State: "resolved"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.AddDate(1, 0, 1)
	page, err := fbSvc.List(ctx, "operator", f.Filter{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("feedback.List returned expired message due to SQL now() mismatch: %+v %v", page, err)
	}

	// 3. CheckRuntime verifies runtime role lacks UPDATE/DELETE/TRUNCATE on moderation.audit.
	if err = repo.CheckRuntime(ctx); err != nil {
		t.Fatalf("CheckRuntime failed on properly restricted runtime role: %v", err)
	}
	var runtimeRole string
	if err = repo.DB.QueryRow(`SELECT current_user`).Scan(&runtimeRole); err != nil {
		t.Fatal(err)
	}
	if _, err = migration.Exec(`GRANT DELETE ON moderation.audit TO ` + runtimeRole); err != nil {
		t.Fatal(err)
	}
	if err = repo.CheckRuntime(ctx); !errors.Is(err, m.ErrUnavailable) {
		t.Fatalf("CheckRuntime failed to reject runtime role with DELETE privilege on moderation.audit: %v", err)
	}
	if _, err = migration.Exec(`REVOKE DELETE ON moderation.audit FROM ` + runtimeRole); err != nil {
		t.Fatal(err)
	}
}
