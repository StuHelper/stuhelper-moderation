package moderation_test

import (
	"context"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"sync"
	"testing"
	"time"
)

type complaintTarget struct {
	m.Content
	object m.Object
}

func (c complaintTarget) Inspect(context.Context, m.Principal, string) (m.Object, error) {
	return c.object, nil
}
func TestResourceComplaintPortPreservesLegacyReplayAndRejectsPublicBypass(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	p := m.Principal{Subject: "reporter"}
	object := m.Object{ID: "resource:version", Kind: "resource", SchoolID: "school", Owner: "uploader", Revision: 1, Visible: true}
	s.Content = complaintTarget{Content: s.Content, object: object}
	in := m.Submission{Kind: "report", ObjectID: object.ID, Reason: "Complaint", Evidence: []string{"Rights evidence", "Contact"}}
	legacy, e := s.Submit(ctx, p, "ambiguous", in)
	if e != nil {
		t.Fatal(e)
	}
	gate := &reportGate{denied: true, unavailable: true}
	s.Access = gate
	if _, e = s.Submit(ctx, m.Principal{Subject: "other"}, "public", in); !errors.Is(e, m.ErrUnavailable) {
		t.Fatal("public report bypass", e)
	}
	s.Content = nil
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, e := s.SubmitResourceComplaint(ctx, p, "ambiguous", in, object)
			if e == nil && (got.ID != legacy.ID || len(got.Submission.Evidence) != 2) {
				e = errors.New("legacy report duplicated")
			}
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	for e := range results {
		if e != nil {
			t.Fatal(e)
		}
	}
	fresh, e := s.SubmitResourceComplaint(ctx, m.Principal{Subject: "new-reporter"}, "fresh", in, object)
	if e != nil || fresh.ID == legacy.ID {
		t.Fatal(fresh, e)
	}
	if _, e = s.Get(ctx, m.Principal{Subject: "other"}, fresh.ID); !errors.Is(e, m.ErrNotFound) {
		t.Fatal("foreign complaint receipt", e)
	}
	bad := object
	bad.Kind = "course"
	if _, e = s.SubmitResourceComplaint(ctx, p, "bad", in, bad); !errors.Is(e, m.ErrInput) {
		t.Fatal("non-resource trusted port", e)
	}
	if _, e = s.SubmitResourceComplaint(ctx, m.Principal{}, "anon", in, object); !errors.Is(e, m.ErrUnauthenticated) {
		t.Fatal(e)
	}
	missing := in
	missing.Evidence = []string{"Contact only"}
	if _, e = s.SubmitResourceComplaint(ctx, p, "missing", missing, object); !errors.Is(e, m.ErrInput) {
		t.Fatal(e)
	}
}

func TestComplaintRateLimitIsPerAccountAndReplayDoesNotConsumeQuota(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	s.Clock = func() time.Time { return now }
	p := m.Principal{Subject: "reporter"}
	submit := func(i int, key string, who m.Principal) error {
		object := m.Object{ID: fmt.Sprintf("resource-%d", i), Kind: "resource", SchoolID: "school", Owner: "uploader", Revision: 1}
		_, e := s.SubmitResourceComplaint(ctx, who, key, m.Submission{Kind: "report", ObjectID: object.ID, Reason: "Complaint", Evidence: []string{"Evidence", "Contact"}}, object)
		return e
	}
	for i := 0; i < 10; i++ {
		if e := submit(i, fmt.Sprint(i), p); e != nil {
			t.Fatal(e)
		}
	}
	if e := submit(0, "0", p); e != nil {
		t.Fatal("replay consumed quota", e)
	}
	if e := submit(11, "blocked", p); !errors.Is(e, m.ErrRateLimited) {
		t.Fatal(e)
	}
	if e := submit(11, "other", m.Principal{Subject: "other"}); e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	if e := submit(11, "recovered", p); e != nil {
		t.Fatal(e)
	}
}
