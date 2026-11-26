package moderation_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"strings"
	"testing"
	"time"
)

type captureDecisionContent struct {
	m.Content
	lastApplied m.Decision
	applyErr    error
}

func (c *captureDecisionContent) Apply(ctx context.Context, p m.Principal, d m.Decision) error {
	c.lastApplied = d
	if c.applyErr != nil {
		return c.applyErr
	}
	return c.Content.Apply(ctx, p, d)
}

func TestDecisionProjectionHidesEnrollmentEvidenceAndSignedState(t *testing.T) {
	s, base, _ := fixture(t)
	capture := &captureDecisionContent{Content: base}
	s.Content = capture
	ctx := context.Background()
	reporter := m.Principal{Subject: "reporter"}
	admin := m.Principal{Subject: "admin"}

	rep1, err := s.Submit(ctx, reporter, "rep-reassign", m.Submission{ObjectID: "review", Kind: "report", Reason: "Wrong teacher", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	decided1, err := s.Decide(ctx, admin, rep1.ID, "dec-reassign", m.Decide{
		Revision: rep1.Revision,
		Decision: m.Decision{
			ObjectID:         "review",
			Revision:         1,
			Action:           "reassign",
			TeacherIDs:       []string{"teacher-two", "teacher-public"},
			EvidenceRevision: "secret-enrollment-rev-42",
			Signed:           true,
			AuthorHandle:     "author-local",
			Subject:          "private-subject",
			Reason:           "Reassigned to verified teacher",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range []m.TaskView{decided1} {
		raw, _ := json.Marshal(view)
		if strings.Contains(string(raw), "secret-enrollment-rev-42") || strings.Contains(string(raw), `"signed"`) {
			t.Fatalf("TaskView leaked enrollment evidence or signed flag: %s", raw)
		}
		if view.Decision == nil || len(view.Decision.TeacherIDs) != 2 || view.Decision.TeacherIDs[0] != "teacher-public" || view.Decision.TeacherIDs[1] != "teacher-two" || view.Decision.EvidenceRevision != "" || view.Decision.Signed {
			t.Fatalf("unexpected public decision projection: %+v", view.Decision)
		}
	}
	receipt, err := s.Get(ctx, reporter, rep1.ID)
	if err != nil {
		t.Fatal(err)
	}
	rawReceipt, _ := json.Marshal(receipt)
	if strings.Contains(string(rawReceipt), "secret-enrollment-rev-42") || strings.Contains(string(rawReceipt), `"signed"`) {
		t.Fatalf("reporter Get leaked enrollment evidence or signed flag: %s", rawReceipt)
	}

	// Internal delivery must still receive full EvidenceRevision and Signed from persisted Task.
	if n, err := s.Work(ctx, 10); err != nil || n != 1 {
		t.Fatalf("Work failed: %d %v", n, err)
	}
	if capture.lastApplied.EvidenceRevision != "secret-enrollment-rev-42" || !capture.lastApplied.Signed || len(capture.lastApplied.TeacherIDs) != 2 || capture.lastApplied.TeacherIDs[0] != "teacher-public" || capture.lastApplied.TeacherIDs[1] != "teacher-two" {
		t.Fatalf("internal Work lost private Decision fields: %+v", capture.lastApplied)
	}
}

func TestWorkNormalizesWrappedAndMultilineErrorsWithoutPoisonLoop(t *testing.T) {
	s, base, _ := fixture(t)
	capture := &captureDecisionContent{
		Content:  base,
		applyErr: errors.Join(fmt.Errorf("student 21370001 enrollment check failed\ndetail: %w", m.ErrForbidden), errors.New("extra diagnostic line")),
	}
	s.Content = capture
	ctx := context.Background()
	reporter := m.Principal{Subject: "reporter"}
	admin := m.Principal{Subject: "admin"}

	task, err := s.Submit(ctx, reporter, "rep-err", m.Submission{ObjectID: "review", Kind: "report", Reason: "Check", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, admin, task.ID, "dec-err", m.Decide{
		Revision: task.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Hide"},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatalf("Work failed to commit multiline wrapped error: %v", err)
	}
	got, err := s.Get(ctx, reporter, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "failed" || got.ErrorCode != "forbidden" {
		t.Fatalf("expected failed with normalized error_code='forbidden', got state=%q error_code=%q", got.State, got.ErrorCode)
	}
	audits, err := s.Repo.(m.AuditReader).ReadAudit(ctx, m.AuditRequest{
		Principal: "auditor",
		Scopes:    []m.AuditScope{{School: "*", Group: "*", Module: "moderation"}},
		Action:    "moderation.result.v1",
		Until:     time.Now().UTC().Add(time.Minute),
		Limit:     10,
	})
	if err != nil || len(audits.Records) != 1 || audits.Records[0].Reason != "forbidden" || audits.Records[0].Result != "failed" {
		t.Fatalf("unexpected result audit record: %+v %v", audits, err)
	}
}

func TestDismissEmitsStrictlyIncreasingRevisionsInOrder(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	relay := s.Repo.(m.OutboxReader)
	reporter := m.Principal{Subject: "reporter"}
	admin := m.Principal{Subject: "admin"}

	task, err := s.Submit(ctx, reporter, "rep-dismiss", m.Submission{ObjectID: "review", Kind: "report", Reason: "Report", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	decided, err := s.Decide(ctx, admin, task.ID, "dec-dismiss", m.Decide{
		Revision: task.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "No violation"},
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := relay.PendingOutbox(ctx, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	var subjectEvents []m.Envelope
	for _, ev := range events {
		if ev.Subject == "task/"+task.ID {
			subjectEvents = append(subjectEvents, ev)
		}
	}
	if len(subjectEvents) != 3 {
		t.Fatalf("expected 3 events (submitted, decided, result), got %d: %+v", len(subjectEvents), subjectEvents)
	}
	wantTypes := []string{"moderation.submitted.v1", "moderation.decided.v1", "moderation.result.v1"}
	var prevRev int64
	for i, ev := range subjectEvents {
		if ev.Type != wantTypes[i] {
			t.Fatalf("event[%d] type=%q, want %q (all: %+v)", i, ev.Type, wantTypes[i], subjectEvents)
		}
		if ev.Data.Revision <= prevRev {
			t.Fatalf("non-monotonic event revision at %d: %d <= %d (all: %+v)", i, ev.Data.Revision, prevRev, subjectEvents)
		}
		prevRev = ev.Data.Revision
	}
	if decided.Revision != prevRev || decided.State != "applied" {
		t.Fatalf("decided TaskView mismatch: %+v (last event rev=%d)", decided, prevRev)
	}
}

func TestDecisionAndBatchReplayWireCompatibility(t *testing.T) {
	decision := m.Decision{ObjectID: "doc", Revision: 1, Action: "hide", Reason: "review"}
	const oldDecision = `{"id":"","object_id":"doc","revision":1,"action":"hide","signed":false,"reason":"review"}`
	for _, tc := range []struct {
		value any
		want  string
	}{
		{m.Decide{Revision: 2, Decision: decision}, `{"revision":2,"decision":` + oldDecision + `}`},
		{[]any{"admin", []m.BatchItem{{ID: "task", Revision: 2, Decision: decision}}}, `["admin",[{"id":"task","revision":2,"decision":` + oldDecision + `}]]`},
	} {
		got, err := json.Marshal(tc.value)
		if err != nil || string(got) != tc.want {
			t.Fatalf("request digest input changed: %s, %v", got, err)
		}
	}
}
