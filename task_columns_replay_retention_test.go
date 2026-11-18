package moderation_test

import (
	"context"
	m "github.com/StuHelper/stuhelper-moderation"
	"testing"
	"time"
)

func TestSaveTaskSyncsColumnsReplayPreservesCanAppealAndExpiredKeyDoesNotCollide(t *testing.T) {
	repo, migration := database(t)
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	c := &content{revision: 1, applied: map[string]bool{}}
	s := &m.Service{Repo: repo, Content: c, Access: access{}, Clock: func() time.Time { return now }}
	ctx := context.Background()

	// 1. SaveTask ON CONFLICT DO UPDATE must update relational columns (owner, school_id, object_id, kind).
	task, err := s.Submit(ctx, m.Principal{Subject: "reporter"}, "rep-col", m.Submission{ObjectID: "review", Kind: "report", Reason: "R", Evidence: []string{"e1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Transaction(ctx, func(tx m.Transaction) error {
		v, e := tx.Task(task.ID)
		if e != nil {
			return e
		}
		v.Owner = "new-reporter"
		v.SchoolID = "new-school"
		v.Submission.ObjectID = "new-object"
		v.Submission.Kind = "review"
		return tx.SaveTask(v)
	}); err != nil {
		t.Fatal(err)
	}
	gotOldReporter, err := s.AccessibleTasks(ctx, m.Principal{Subject: "reporter"}, []string{task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotOldReporter) != 0 {
		t.Fatalf("SaveTask left stale relational owner column accessible to old reporter: %v", gotOldReporter)
	}
	var dbSchool, dbObj, dbKind string
	if err = migration.QueryRow(`SELECT school_id,object_id,kind FROM moderation.tasks WHERE id=$1`, task.ID).Scan(&dbSchool, &dbObj, &dbKind); err != nil {
		t.Fatal(err)
	}
	if dbSchool != "new-school" || dbObj != "new-object" || dbKind != "review" {
		t.Fatalf("SaveTask did not sync relational columns: school=%q obj=%q kind=%q", dbSchool, dbObj, dbKind)
	}

	// 2. SaveReplay must preserve viewFor (including CanAppeal when moderator is also ContentOwner in fixture or replayed response).
	authorMod := &m.Service{
		Repo:    repo,
		Content: c,
		Access:  authorAdminAccess{},
		Clock:   func() time.Time { return now },
	}
	authorTask, err := authorMod.Submit(ctx, m.Principal{Subject: "author"}, "del-author", m.Submission{ObjectID: "review", Kind: "delete_request", Reason: "Del", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	decIn := m.Decide{Revision: authorTask.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Dismissed"}}
	firstDec, err := authorMod.Decide(ctx, m.Principal{Subject: "author"}, authorTask.ID, "dec-replay", decIn)
	if err != nil || !firstDec.CanAppeal {
		t.Fatalf("expected CanAppeal=true on initial response: %+v %v", firstDec, err)
	}
	replayedDec, err := authorMod.Decide(ctx, m.Principal{Subject: "author"}, authorTask.ID, "dec-replay", decIn)
	if err != nil || !replayedDec.CanAppeal {
		t.Fatalf("SaveReplay lost CanAppeal on idempotent replay: %+v %v", replayedDec, err)
	}

	// 3. Reusing an Idempotency-Key after 24h replay expiry must NOT hit audit_pkey/outbox_pkey conflict or overwrite closed task.
	r1, err := s.Submit(ctx, m.Principal{Subject: "user-24h"}, "reused-key", m.Submission{ObjectID: "review", Kind: "report", Reason: "First report", Evidence: []string{"ev1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, m.Principal{Subject: "admin"}, r1.ID, "close-r1", m.Decide{Revision: r1.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Closed"}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	r2, err := s.Submit(ctx, m.Principal{Subject: "user-24h"}, "reused-key", m.Submission{ObjectID: "review", Kind: "report", Reason: "Second report after 25h", Evidence: []string{"ev2"}})
	if err != nil {
		t.Fatalf("post-24h reuse of expired Idempotency-Key failed with conflict: %v", err)
	}
	if r2.ID == r1.ID {
		t.Fatalf("post-24h reuse overwrote historical closed task %s", r1.ID)
	}
	oldClosed, err := s.Get(ctx, m.Principal{Subject: "user-24h"}, r1.ID)
	if err != nil || oldClosed.State != "applied" {
		t.Fatalf("historical closed task corrupted: %+v %v", oldClosed, err)
	}

	// 4. Bounded retention cleanup removes expired replays (24h), submission_limits (24h), confirmed outbox (90d), and non-feedback audit (12m), while preserving unexpired/pending rows.
	cleaner, ok := any(s).(interface {
		Cleanup(context.Context, int) error
	})
	if !ok {
		t.Fatal("Service does not implement bounded Cleanup(ctx, limit)")
	}
	// Confirm one outbox event at current `now`, then advance 91 days (so replays, limits, and confirmed outbox expire, while unconfirmed outbox and <12m audit stay).
	events, err := repo.PendingOutbox(ctx, 100, nil)
	if err != nil || len(events) == 0 {
		t.Fatalf("expected pending outbox events: %v", err)
	}
	confirmedID := events[0].ID
	if err = repo.ConfirmOutbox(ctx, confirmedID); err != nil {
		t.Fatal(err)
	}
	if _, err = migration.Exec(`UPDATE moderation.outbox SET sent_at=$1 WHERE id=$2`, now, confirmedID); err != nil {
		t.Fatal(err)
	}

	now = now.Add(91 * 24 * time.Hour)
	if err = cleaner.Cleanup(ctx, 200); err != nil {
		t.Fatalf("Cleanup at +91d failed: %v", err)
	}

	var replayCount, limitCount, confirmedRemaining, unconfirmedRemaining, auditRemaining int
	_ = migration.QueryRow(`SELECT count(*) FROM moderation.replays`).Scan(&replayCount)
	_ = migration.QueryRow(`SELECT count(*) FROM moderation.submission_limits`).Scan(&limitCount)
	_ = migration.QueryRow(`SELECT count(*) FROM moderation.outbox WHERE id=$1`, confirmedID).Scan(&confirmedRemaining)
	_ = migration.QueryRow(`SELECT count(*) FROM moderation.outbox WHERE sent_at IS NULL`).Scan(&unconfirmedRemaining)
	_ = migration.QueryRow(`SELECT count(*) FROM moderation.audit`).Scan(&auditRemaining)
	if replayCount != 0 || limitCount != 0 || confirmedRemaining != 0 || unconfirmedRemaining == 0 || auditRemaining == 0 {
		t.Fatalf("unexpected +91d retention counts: replays=%d limits=%d confirmed=%d unconfirmed=%d audit=%d", replayCount, limitCount, confirmedRemaining, unconfirmedRemaining, auditRemaining)
	}

	// Advance past 12 months total: non-feedback audit rows older than 12 months are cleaned up.
	now = now.Add(280 * 24 * time.Hour)
	if err = cleaner.Cleanup(ctx, 200); err != nil {
		t.Fatalf("Cleanup at +12m failed: %v", err)
	}
	_ = migration.QueryRow(`SELECT count(*) FROM moderation.audit WHERE action NOT LIKE 'feedback.%'`).Scan(&auditRemaining)
	if auditRemaining != 0 {
		t.Fatalf("expected expired non-feedback audit rows cleaned up, remaining=%d", auditRemaining)
	}
}

type authorAdminAccess struct{}

func (authorAdminAccess) Authorize(_ context.Context, p m.Principal, _, _ string) error {
	if p.Subject == "" {
		return m.ErrForbidden
	}
	return nil
}
