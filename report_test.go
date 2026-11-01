package moderation_test

import (
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"sync"
	"testing"
	"time"
)

type reportGate struct{ denied, unavailable bool }

func (g *reportGate) Authorize(ctx context.Context, p m.Principal, action, school string) error {
	if action == "report" {
		if g.unavailable {
			return m.ErrUnavailable
		}
		if g.denied {
			return m.ErrForbidden
		}
		return nil
	}
	return (access{}).Authorize(ctx, p, action, school)
}

type reportContent struct {
	m.Content
	unavailable bool
}

func (c *reportContent) Inspect(ctx context.Context, p m.Principal, id string) (m.Object, error) {
	if c.unavailable {
		return m.Object{}, m.ErrUnavailable
	}
	return c.Content.Inspect(ctx, p, id)
}
func TestNewReportsRequireAdmissionButOwnPendingEvidenceRemainsAvailable(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	gate := &reportGate{denied: true}
	s.Access = gate
	source := &reportContent{Content: s.Content}
	s.Content = source
	reporter := m.Principal{Subject: "reporter"}
	in := m.Submission{Kind: "report", ObjectID: "review", Reason: "Initial reason", Evidence: []string{"Initial evidence"}}
	if _, e := s.Submit(ctx, reporter, "denied", in); !errors.Is(e, m.ErrForbidden) {
		t.Fatal("new report bypassed admission", e)
	}
	tasks, e := s.List(ctx, reporter, "", "", "", 20, false)
	if e != nil || len(tasks) != 0 {
		t.Fatal("denied report persisted", tasks, e)
	}
	gate.unavailable = true
	if _, e := s.Submit(ctx, reporter, "unknown", in); !errors.Is(e, m.ErrUnavailable) {
		t.Fatal("unknown admission allowed report", e)
	}
	gate.unavailable = false
	gate.denied = false
	original, e := s.Submit(ctx, reporter, "first", in)
	if e != nil {
		t.Fatal(e)
	}
	gate.denied = true
	gate.unavailable = true
	source.unavailable = true
	in.Evidence = []string{"Additional evidence"}
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, e := s.Submit(ctx, reporter, "supplement", in)
			if e == nil && (result.ID != original.ID || len(result.Submission.Evidence) != 2) {
				e = errors.New("replayed evidence duplicated or changed report")
			}
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	for e := range results {
		if e != nil {
			t.Fatal("own supplement blocked", e)
		}
	}
	current, e := s.Get(ctx, reporter, original.ID)
	if e != nil || current.Revision != 2 || len(current.Submission.Evidence) != 2 {
		t.Fatal(current, e)
	}
	if _, e = s.Get(ctx, m.Principal{Subject: "other"}, original.ID); !errors.Is(e, m.ErrNotFound) {
		t.Fatal("other user read report", e)
	}
	changed := in
	changed.Evidence = []string{"Changed retry"}
	if _, e = s.Submit(ctx, reporter, "supplement", changed); !errors.Is(e, m.ErrConflict) {
		t.Fatal("changed idempotency payload accepted", e)
	}
	source.unavailable = false
	gate.unavailable = false
	if _, e = s.Submit(ctx, m.Principal{Subject: "other"}, "hijack", in); !errors.Is(e, m.ErrForbidden) {
		t.Fatal("other user bypassed admission", e)
	}
	decision := m.Decide{Revision: current.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Closed"}}
	if _, e = s.Decide(ctx, m.Principal{Subject: "admin"}, current.ID, "close", decision); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Work(ctx, 10); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Submit(ctx, reporter, "new-after-close", in); !errors.Is(e, m.ErrForbidden) {
		t.Fatal("closed report bypassed admission", e)
	}
	tasks, e = s.List(ctx, reporter, "", "", "", 20, false)
	if e != nil || len(tasks) != 1 {
		t.Fatal("new report written after close", tasks, e)
	}
}

type decisionBarrier struct {
	m.Content
	entered, release chan struct{}
}

func (c *decisionBarrier) Inspect(ctx context.Context, p m.Principal, id string) (m.Object, error) {
	if p.Subject == "admin" {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return m.Object{}, ctx.Err()
		}
	}
	return c.Content.Inspect(ctx, p, id)
}
func TestPendingEvidenceCannotOverwriteConcurrentDecision(t *testing.T) {
	s, _, _ := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reporter := m.Principal{Subject: "reporter"}
	in := m.Submission{ObjectID: "review", Kind: "report", Reason: "Reason", Evidence: []string{"Original"}}
	task, e := s.Submit(ctx, reporter, "original", in)
	if e != nil {
		t.Fatal(e)
	}
	barrier := &decisionBarrier{Content: s.Content, entered: make(chan struct{}), release: make(chan struct{})}
	s.Content = barrier
	decided := make(chan error, 1)
	go func() {
		_, e := s.Decide(ctx, m.Principal{Subject: "admin"}, task.ID, "decide", m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Final"}})
		decided <- e
	}()
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	in.Evidence = []string{"Late evidence"}
	supplemented := make(chan error, 1)
	go func() { _, e := s.Submit(ctx, reporter, "late", in); supplemented <- e }()
	var early error
	returned := false
	select {
	case early = <-supplemented:
		returned = true
	case <-time.After(50 * time.Millisecond):
	}
	close(barrier.release)
	if e := <-decided; e != nil {
		t.Fatal(e)
	}
	if returned {
		t.Fatal("evidence ran through a pending decision", early)
	}
	if e := <-supplemented; !errors.Is(e, m.ErrConflict) {
		t.Fatal("late evidence did not conflict", e)
	}
	current, e := s.Get(ctx, reporter, task.ID)
	if e != nil || current.State != "applied" || current.Decision == nil || len(current.Submission.Evidence) != 1 {
		t.Fatal("decision overwritten", current, e)
	}
}
