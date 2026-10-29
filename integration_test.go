package moderation_test

import (
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"sync"
	"testing"
	"time"
)

type content struct {
	mu         sync.Mutex
	revision   int64
	applied    map[string]bool
	calls      int
	loseResult bool
}

func (c *content) Inspect(context.Context, m.Principal, string) (m.Object, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return m.Object{ID: "review", Kind: "course", SchoolID: "school", Owner: "author", Revision: c.revision, Visible: true}, nil
}
func (c *content) Apply(_ context.Context, _ m.Principal, d m.Decision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.applied[d.ID] {
		return nil
	}
	if d.Revision != c.revision {
		return m.ErrConflict
	}
	c.applied[d.ID] = true
	c.revision++
	if c.loseResult {
		return m.ErrUnavailable
	}
	return nil
}

type access struct{}

func (access) Authorize(_ context.Context, p m.Principal, action, school string) error {
	if p.Subject == "" {
		return m.ErrForbidden
	}
	if action == "submit" {
		return nil
	}
	if p.Subject == "admin" && school == "school" {
		return nil
	}
	return m.ErrForbidden
}
func fixture(t *testing.T) (*m.Service, *content, *time.Time) {
	repo, _ := database(t)
	c := &content{revision: 1, applied: map[string]bool{}}
	now := time.Now().UTC()
	s := &m.Service{Repo: repo, Content: c, Access: access{}, Clock: func() time.Time { return now }}
	return s, c, &now
}
func TestPendingReportMergesEvidenceAndAuthorRequestsAreScoped(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	p := m.Principal{Subject: "reporter"}
	in := m.Submission{ObjectID: "review", Kind: "report", Reason: "Reason", Evidence: []string{"Evidence"}}
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	ids := make(chan string, 10)
	for range 10 {
		wg.Go(func() { v, e := s.Submit(ctx, p, "same", in); errs <- e; ids <- v.ID })
	}
	wg.Wait()
	close(errs)
	close(ids)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	id := ""
	for v := range ids {
		if id != "" && id != v {
			t.Fatal("duplicate report")
		}
		id = v
	}
	in.Evidence = []string{"New evidence"}
	merged, e := s.Submit(ctx, p, "supplement", in)
	if e != nil || merged.ID != id || len(merged.Submission.Evidence) != 2 {
		t.Fatal("report did not merge", merged, e)
	}
	if _, e = s.Get(ctx, m.Principal{Subject: "unrelated"}, id); !errors.Is(e, m.ErrNotFound) {
		t.Fatal("other reporter leaked")
	}
	in.Kind = "edit_request"
	in.ProposedBody = "Edited"
	if _, e = s.Submit(ctx, p, "edit", in); !errors.Is(e, m.ErrNotFound) {
		t.Fatal("non-author requested edit")
	}
	if _, e = s.Submit(ctx, m.Principal{Subject: "author"}, "edit", in); e != nil {
		t.Fatal(e)
	}
}
func TestDecisionDeliveryRecoversUnknownResultAndRejectsStaleRevision(t *testing.T) {
	s, c, now := fixture(t)
	ctx := context.Background()
	task, e := s.Submit(ctx, m.Principal{Subject: "reporter"}, "report", m.Submission{ObjectID: "review", Kind: "report", Reason: "Report", Evidence: []string{}})
	if e != nil {
		t.Fatal(e)
	}
	d := m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Confirmed"}}
	if _, e = s.Decide(ctx, m.Principal{Subject: "reporter"}, task.ID, "decision", d); !errors.Is(e, m.ErrForbidden) {
		t.Fatal("reporter moderated")
	}
	decided, e := s.Decide(ctx, m.Principal{Subject: "admin"}, task.ID, "decision", d)
	if e != nil || decided.State != "decided" {
		t.Fatal(e)
	}
	c.loseResult = true
	if n, e := s.Work(ctx, 10); e != nil || n != 0 {
		t.Fatal("unknown result not retained", n, e)
	}
	pending, e := s.Get(ctx, m.Principal{Subject: "admin"}, task.ID)
	if e != nil || pending.State != "decided" {
		t.Fatal("premature success", pending, e)
	}
	*now = now.Add(6 * time.Second)
	if n, e := s.Work(ctx, 10); e != nil || n != 1 {
		t.Fatal("delivery retry", n, e)
	}
	if c.revision != 2 || len(c.applied) != 1 || c.calls != 2 {
		t.Fatal("duplicate content effect")
	}
	second, e := s.Submit(ctx, m.Principal{Subject: "reporter"}, "new-facts", m.Submission{ObjectID: "review", Kind: "report", Reason: "New facts", Evidence: []string{}})
	if e != nil {
		t.Fatal(e)
	}
	d.Revision = second.Revision
	if _, e = s.Decide(ctx, m.Principal{Subject: "admin"}, second.ID, "stale", d); !errors.Is(e, m.ErrConflict) {
		t.Fatal("stale content decision accepted")
	}
}
func TestPolicyScopeReplayAndPrivateDecisionProjection(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	policy := m.Policy{SchoolID: "school", Kind: "course", Mode: "pending", BlockedTerms: []string{"blocked phrase"}}
	if e := s.SetPolicy(ctx, m.Principal{Subject: "admin"}, "policy", policy); e != nil {
		t.Fatal(e)
	}
	if e := s.SetPolicy(ctx, m.Principal{Subject: "admin"}, "policy", policy); e != nil {
		t.Fatal("policy replay", e)
	}
	mode, e := s.Check(ctx, "school", "course", "Title", "Body")
	if e != nil || mode != "pending" {
		t.Fatal(mode, e)
	}
	mode, e = s.Check(ctx, "other", "course", "Title", "Body")
	if e != nil || mode != "published" {
		t.Fatal("policy crossed school", mode, e)
	}
	mode, e = s.Check(ctx, "school", "course", "Title", "BLOCKED PHRASE")
	if e != nil || mode != "blocked" {
		t.Fatal(mode, e)
	}
	policy.Revision = 1
	policy.Mode = "published"
	if e = s.SetPolicy(ctx, m.Principal{Subject: "admin"}, "policy", policy); !errors.Is(e, m.ErrConflict) {
		t.Fatal("policy key reused")
	}
	object := m.Object{ID: "review", SchoolID: "school", Owner: "author", Revision: 1}
	task, e := s.Track(ctx, "event", object)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.Track(ctx, "event", object)
	if e != nil || again.ID != task.ID {
		t.Fatal("event duplicated")
	}
	body := "Private edited text"
	d := m.Decide{Revision: 1, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "edit", Body: &body, Subject: "anonymous-account", Reason: "Correction"}}
	decided, e := s.Decide(ctx, m.Principal{Subject: "admin"}, task.ID, "decide", d)
	if e != nil {
		t.Fatal(e)
	}
	if decided.Decision.Body != nil || decided.Decision.Subject != "" {
		t.Fatal("decision leaked private identity or gated body")
	}
}
