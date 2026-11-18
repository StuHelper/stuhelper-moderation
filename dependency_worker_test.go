package moderation_test

import (
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"testing"
	"time"
)

func TestMissingDependenciesReturnUnavailableWithoutPanic(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	author := m.Principal{Subject: "author"}
	admin := m.Principal{Subject: "admin"}

	report, err := s.Submit(ctx, m.Principal{Subject: "reporter"}, "rep-1", m.Submission{ObjectID: "review", Kind: "report", Reason: "Check", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}

	s.Content = nil
	if _, err = s.Submit(ctx, author, "edit-nil", m.Submission{ObjectID: "review", Kind: "edit_request", Reason: "Edit", Evidence: []string{}, ProposedBody: "Updated"}); !errors.Is(err, m.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable from Submit with nil Content, got: %v", err)
	}
	if _, err = s.Decide(ctx, admin, report.ID, "dec-nil", m.Decide{Revision: report.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"}}); !errors.Is(err, m.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable from Decide with nil Content, got: %v", err)
	}
	preview, err := s.PreviewBatch(ctx, admin, m.BatchRequest{Items: []m.BatchItem{{ID: report.ID, Revision: report.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"}}}})
	if err != nil || len(preview.Items) != 1 || preview.Items[0].State != "rejected" || preview.Items[0].Code != "unavailable" {
		t.Fatalf("expected unavailable batch preview item, got: %+v %v", preview, err)
	}

	emptySvc := &m.Service{Access: access{}}
	if _, err = emptySvc.Check(ctx, "school", "course", "t", "b"); !errors.Is(err, m.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable from Check with nil Repo, got: %v", err)
	}
	if _, err = emptySvc.Get(ctx, admin, report.ID); !errors.Is(err, m.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable from Get with nil Repo, got: %v", err)
	}
}

type inspectDeadlineContent struct {
	m.Content
	hasDeadline bool
	remaining   time.Duration
}

func (c *inspectDeadlineContent) Inspect(ctx context.Context, p m.Principal, id string) (m.Object, error) {
	d, ok := ctx.Deadline()
	c.hasDeadline = ok
	if ok {
		c.remaining = time.Until(d)
	}
	return c.Content.Inspect(ctx, p, id)
}

type cancelDuringApplyContent struct {
	m.Content
	cancel context.CancelFunc
}

func (c *cancelDuringApplyContent) Apply(ctx context.Context, p m.Principal, d m.Decision) error {
	err := c.Content.Apply(ctx, p, d)
	c.cancel()
	return err
}

func TestWorkerShutdownPersistsAppliedResultInspectHasTimeoutAndRetryResetsBackoff(t *testing.T) {
	s, base, now := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}

	// 1. Inspect calls carry a bounded <= 3s deadline even when caller ctx has none.
	probe := &inspectDeadlineContent{Content: base}
	s.Content = probe
	task, err := s.Submit(ctx, m.Principal{Subject: "author"}, "del-req", m.Submission{ObjectID: "review", Kind: "delete_request", Reason: "Delete", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if !probe.hasDeadline || probe.remaining > 3*time.Second+100*time.Millisecond {
		t.Fatalf("Submit Inspect missing 3s timeout: hasDeadline=%v remaining=%v", probe.hasDeadline, probe.remaining)
	}
	probe.hasDeadline = false
	task, err = s.Decide(ctx, admin, task.ID, "dec-1", m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"}})
	if err != nil {
		t.Fatal(err)
	}
	if !probe.hasDeadline || probe.remaining > 3*time.Second+100*time.Millisecond {
		t.Fatalf("Decide Inspect missing 3s timeout: hasDeadline=%v remaining=%v", probe.hasDeadline, probe.remaining)
	}

	// 2. Work persists applied state even if worker context is canceled right after Content.Apply succeeds.
	workCtx, cancelWork := context.WithCancel(ctx)
	s.Content = &cancelDuringApplyContent{Content: base, cancel: cancelWork}
	done, err := s.Work(workCtx, 10)
	if err != nil || done != 1 {
		t.Fatalf("Work lost applied outcome on shutdown: done=%d err=%v", done, err)
	}
	applied, err := s.Get(ctx, admin, task.ID)
	if err != nil || applied.State != "applied" {
		t.Fatalf("expected persisted applied state after shutdown, got: %+v %v", applied, err)
	}

	// 3. Manual Retry resets backoff so a transient failure retries in 5s rather than 1h.
	s.Content = base
	second, err := s.Submit(ctx, admin, "rev-2", m.Submission{ObjectID: "review", Kind: "review", Reason: "Check", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	second, err = s.Decide(ctx, admin, second.ID, "dec-2", m.Decide{Revision: second.Revision, Decision: m.Decision{ObjectID: "review", Revision: 2, Action: "restore", Reason: "Restore"}})
	if err != nil {
		t.Fatal(err)
	}
	s.Content = nil
	for i := 0; i < 12; i++ {
		if _, err = s.Work(ctx, 10); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(time.Hour)
	}
	*now = now.Add(13 * time.Hour)
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	failed, err := s.Get(ctx, admin, second.ID)
	if err != nil || failed.State != "failed" || failed.ErrorCode != "unavailable" {
		t.Fatalf("expected failed(unavailable), got: %+v %v", failed, err)
	}

	retried, err := s.Retry(ctx, admin, second.ID, "manual-retry", failed.Revision)
	if err != nil || retried.State != "decided" {
		t.Fatalf("Retry failed: %+v %v", retried, err)
	}
	// First attempt after manual retry fails transiently (s.Content == nil).
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	// After 6 seconds (< 1 hour!), Content recovers and Work must claim and apply it.
	s.Content = base
	*now = now.Add(6 * time.Second)
	done, err = s.Work(ctx, 10)
	if err != nil || done != 1 {
		t.Fatalf("expected 5s initial backoff after manual Retry, got done=%d err=%v", done, err)
	}
	recovered, err := s.Get(ctx, admin, second.ID)
	if err != nil || recovered.State != "applied" {
		t.Fatalf("expected applied after 6s retry, got: %+v %v", recovered, err)
	}
}
