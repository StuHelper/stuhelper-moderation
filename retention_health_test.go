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

type globalHealthAccess struct{}

func (globalHealthAccess) Authorize(ctx context.Context, p m.Principal, action, school string) error {
	if p.Subject == "platform-admin" {
		return nil
	}
	return (access{}).Authorize(ctx, p, action, school)
}

func TestNonFeedbackRetentionBoundedCleanupAndAuditSnapshotSafety(t *testing.T) {
	repo, migration := database(t)
	baseNow := time.Now().UTC().Truncate(time.Second)
	now := baseNow
	c := &content{revision: 1, applied: map[string]bool{}}
	s := &m.Service{Repo: repo, Content: c, Access: globalHealthAccess{}, Clock: func() time.Time { return now }}
	ctx := context.Background()

	// Seed 3 expired replays (>24h ago) and 1 active replay (<24h).
	err := repo.Transaction(ctx, func(tx m.Transaction) error {
		for i := 0; i < 3; i++ {
			if err := tx.SaveReplay(fmt.Sprintf("exp-replay-%d", i), m.Replay{
				Digest: "d",
				Until:  now.Add(-time.Hour - time.Duration(i)*time.Minute),
			}); err != nil {
				return err
			}
		}
		if err := tx.SaveReplay("fresh-replay", m.Replay{
			Digest: "d",
			Until:  now.Add(12 * time.Hour),
		}); err != nil {
			return err
		}
		// Seed 1 old audit (>12 months) and 1 recent audit, plus outbox events.
		if err := tx.Event(m.Event{
			ID:       "old-audit-outbox",
			Actor:    "admin",
			SchoolID: "school",
			Type:     "moderation.policy.v1",
			Subject:  "policy/school/course",
			Revision: 1,
			Result:   "success",
			At:       now.AddDate(-1, 0, -5),
		}); err != nil {
			return err
		}
		return tx.Event(m.Event{
			ID:       "pending-outbox",
			Actor:    "admin",
			SchoolID: "school",
			Type:     "moderation.policy.v1",
			Subject:  "policy/school/mentor",
			Revision: 1,
			Result:   "success",
			At:       now.Add(-10 * time.Minute),
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	// Confirm old-audit-outbox and set sent_at to 91 days ago; add a recently confirmed outbox (10 days ago); keep pending-outbox unconfirmed!
	if err = repo.ConfirmOutbox(ctx, "old-audit-outbox"); err != nil {
		t.Fatal(err)
	}
	if _, err = migration.Exec(`UPDATE moderation.outbox SET sent_at=$1 WHERE id='old-audit-outbox'`, now.Add(-91*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = migration.Exec(`INSERT INTO moderation.outbox(id,data,delivered,sent_at) VALUES('recent-sent','{"subject":"policy/school/reply","data":{"revision":1}}'::jsonb,true,$1)`, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Seed 2 expired submission_limits (>24h ago) and 1 active limit (<24h).
	if _, err = migration.Exec(`INSERT INTO moderation.submission_limits(owner_key,started_at,used) VALUES
 ('exp-u1',$1,3),
 ('exp-u2',$2,5),
 ('active-u3',$3,1)`, now.Add(-26*time.Hour), now.Add(-25*time.Hour), now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	// Run bounded cleanup with batchLimit=2: should delete 2 of 3 expired replays, 2 expired limits, 1 expired outbox, 1 expired audit.
	res1, err := s.CleanupRetention(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res1.ReplaysDeleted != 2 || res1.LimitsDeleted != 2 || res1.OutboxDeleted != 1 || res1.AuditDeleted != 1 {
		t.Fatalf("unexpected first cleanup counts: %+v", res1)
	}

	// Capture an audit snapshot after the old audit was cleaned, then run Cleanup again when 0 audit rows are expired -> snapshot MUST remain valid!
	auditPage1, err := repo.ReadAudit(ctx, m.AuditRequest{
		Principal: "viewer",
		Scopes:    []m.AuditScope{{School: "*", Group: "*", Module: "*"}},
		Until:     now.Add(time.Minute),
		Limit:     10,
	})
	if err != nil || len(auditPage1.Records) != 1 || auditPage1.Records[0].ID != "pending-outbox" {
		t.Fatalf("unexpected remaining audit records: %+v %v", auditPage1, err)
	}

	res2, err := s.CleanupRetention(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res2.ReplaysDeleted != 1 || res2.LimitsDeleted != 0 || res2.OutboxDeleted != 0 || res2.AuditDeleted != 0 {
		t.Fatalf("unexpected second cleanup counts: %+v", res2)
	}

	// Verify ReadAudit snapshot was NOT invalidated by a 0-row audit cleanup run!
	auditPage2, err := repo.ReadAudit(ctx, m.AuditRequest{
		Principal: "viewer",
		Scopes:    []m.AuditScope{{School: "*", Group: "*", Module: "*"}},
		Until:     now.Add(time.Minute),
		Snapshot:  auditPage1.Snapshot,
		Limit:     10,
	})
	if err != nil || len(auditPage2.Records) != 1 {
		t.Fatalf("empty audit cleanup invalidated active ReadAudit snapshot: %+v %v", auditPage2, err)
	}

	// Verify fresh replay, active submission_limit, recent sent outbox, and unconfirmed pending outbox are all preserved.
	var replayCount, limitCount, outboxTotal, outboxPending int
	if err = migration.QueryRow(`SELECT count(*) FROM moderation.replays`).Scan(&replayCount); err != nil || replayCount != 1 {
		t.Fatalf("replays remaining=%d err=%v", replayCount, err)
	}
	if err = migration.QueryRow(`SELECT count(*) FROM moderation.submission_limits`).Scan(&limitCount); err != nil || limitCount != 1 {
		t.Fatalf("limits remaining=%d err=%v", limitCount, err)
	}
	if err = migration.QueryRow(`SELECT count(*), count(*) FILTER (WHERE sent_at IS NULL) FROM moderation.outbox`).Scan(&outboxTotal, &outboxPending); err != nil || outboxTotal != 2 || outboxPending != 1 {
		t.Fatalf("outbox total=%d pending=%d err=%v", outboxTotal, outboxPending, err)
	}
}

func TestModerationHealthSnapshotAndHTTPAuthorization(t *testing.T) {
	repo, _ := database(t)
	now := time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC)
	c := &content{revision: 1, applied: map[string]bool{}}
	s := &m.Service{Repo: repo, Content: c, Access: globalHealthAccess{}, Clock: func() time.Time { return now }}
	fbSvc := &f.Service{
		Repo:   &pg.FeedbackRepository{DB: repo.DB},
		Access: &feedbackAccess{},
		Blobs:  &feedbackBlobs{values: map[string][]byte{}},
		Now:    func() time.Time { return now },
	}
	ctx := context.Background()

	// Create 1 decided-ready task and 1 failed-manual task.
	t1, err := s.Submit(ctx, m.Principal{Subject: "reporter-1"}, "h-r1", m.Submission{
		ObjectID: "review",
		Kind:     "report",
		Reason:   "First",
		Evidence: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, m.Principal{Subject: "admin"}, t1.ID, "h-d1", m.Decide{
		Revision: t1.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"},
	}); err != nil {
		t.Fatal(err)
	}

	// An external content edit makes the first decision stale before delivery.
	c.mu.Lock()
	c.revision++
	c.mu.Unlock()
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	decidedAt := now
	t3, err := s.Submit(ctx, m.Principal{Subject: "reporter-3"}, "h-r3", m.Submission{
		ObjectID: "review",
		Kind:     "report",
		Reason:   "Third",
		Evidence: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, m.Principal{Subject: "admin"}, t3.ID, "h-d3", m.Decide{
		Revision: t3.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 2, Action: "hide", Reason: "Hide rev 2"},
	}); err != nil {
		t.Fatal(err)
	}

	// Ingest 2 feedback messages (1 closed & expired -> cleaned into tombstone, 1 active).
	expiredMail, err := fbSvc.Ingest(ctx, feedbackInput("exp-mail"))
	if err != nil {
		t.Fatal(err)
	}
	expiredMail, err = fbSvc.Update(ctx, "operator", expiredMail.ID, "close-exp-mail", f.Update{Revision: expiredMail.Revision, State: "resolved"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.AddDate(1, 0, 1)
	if err = fbSvc.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	activeIn := feedbackInput("active-mail")
	activeIn.Message.Bytes = 512
	if _, err = fbSvc.Ingest(ctx, activeIn); err != nil {
		t.Fatal(err)
	}

	snap, err := s.HealthSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.DecidedReadyCount != 1 || snap.OldestDecidedAt == nil || !snap.OldestDecidedAt.Equal(decidedAt) ||
		snap.FailedManualCount != 1 || snap.OutboxPendingCount < 5 || snap.OldestOutboxAt == nil ||
		snap.FeedbackActiveCount != 1 || snap.FeedbackActiveBytes != 512 || snap.FeedbackTombstoneCount != 1 {
		t.Fatalf("unexpected health snapshot: %+v", snap)
	}

	// School-only admin is denied HTTP /health (403); platform-admin succeeds (200).
	if _, err = s.Health(ctx, m.Principal{Subject: "admin"}); !errors.Is(err, m.ErrForbidden) {
		t.Fatalf("school-only admin accessed global health: %v", err)
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
	forbiddenResp, err := client.GetModerationHealthWithResponse(ctx, func(_ context.Context, r *http.Request) error {
		r.Header.Set("X-Test-Actor", "admin")
		return nil
	})
	if err != nil || forbiddenResp.StatusCode() != 403 {
		t.Fatalf("expected 403 for school-only admin, got %v %+v", err, forbiddenResp)
	}
	okResp, err := client.GetModerationHealthWithResponse(ctx, func(_ context.Context, r *http.Request) error {
		r.Header.Set("X-Test-Actor", "platform-admin")
		return nil
	})
	if err != nil || okResp.StatusCode() != 200 || okResp.JSON200 == nil || okResp.JSON200.DecidedReadyCount != 1 || okResp.JSON200.FailedManualCount != 1 || okResp.JSON200.FeedbackActiveBytes != 512 {
		t.Fatalf("getModerationHealth failed: %v %+v", err, okResp)
	}
}
