package moderation_test

import (
	"context"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"testing"
)

type reviewAccess struct{}

func (reviewAccess) Authorize(ctx context.Context, p m.Principal, action, school string) error {
	if p.Subject == "reviewer" && school == "school" {
		return nil
	}
	return (access{}).Authorize(ctx, p, action, school)
}
func TestAppealRequiresContentOwnerAndAnotherReviewer(t *testing.T) {
	s, _, _ := fixture(t)
	s.Access = reviewAccess{}
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}
	author := m.Principal{Subject: "author"}
	task, err := s.Submit(ctx, author, "request", m.Submission{ObjectID: "review", Kind: "delete_request", Reason: "Author request", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	task, err = s.Decide(ctx, admin, task.ID, "dismiss", m.Decide{Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Rejected"}})
	if err != nil {
		t.Fatal(err)
	}
	request := m.Submission{ObjectID: "review", Kind: "appeal", Reason: "Please reconsider", PreviousTaskID: task.ID, Evidence: []string{}}
	if _, err = s.Submit(ctx, m.Principal{Subject: "other"}, "appeal", request); !errors.Is(err, m.ErrNotFound) {
		t.Fatal("another user appealed", err)
	}
	appeal, err := s.Submit(ctx, author, "appeal", request)
	if err != nil {
		t.Fatal(err)
	}
	decision := m.Decide{Revision: appeal.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Reviewed separately"}}
	if _, err = s.Decide(ctx, admin, appeal.ID, "same-reviewer", decision); !errors.Is(err, m.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, m.Principal{Subject: "reviewer"}, appeal.ID, "second-reviewer", decision); err != nil {
		t.Fatal(err)
	}
	records, err := s.FilteredList(ctx, admin, m.TaskFilter{School: "school", Admin: true, ObjectID: "review", ContentKind: "course", Kind: "appeal", Limit: 20})
	if err != nil || len(records) != 1 || records[0].Submission.PreviousTaskID != task.ID {
		t.Fatal(records, err)
	}
}
func TestBatchPreviewAndRetryPreservePerItemResults(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	admin := m.Principal{Subject: "admin"}
	task, err := s.Submit(ctx, admin, "inspect", m.Submission{ObjectID: "review", Kind: "review", Reason: "Inspection", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	in := m.BatchRequest{Items: []m.BatchItem{{ID: task.ID, Revision: task.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Batch review"}}, {ID: "missing", Revision: 1, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "hide", Reason: "Missing task"}}}}
	preview, err := s.PreviewBatch(ctx, admin, in)
	if err != nil || preview.Items[0].State != "ready" || preview.Items[1].Code != "not_found" {
		t.Fatal(preview, err)
	}
	in.PreviewToken = preview.PreviewToken
	result, err := s.DecideBatch(ctx, admin, "batch", in)
	if err != nil || result.Items[0].State != "decided" || result.Items[1].Code != "not_found" {
		t.Fatal(result, err)
	}
	result, err = s.DecideBatch(ctx, admin, "batch", in)
	if err != nil || result.Items[0].State != "decided" {
		t.Fatal(result, err)
	}
	in.Items[0].Decision.Reason = "Different request"
	preview, _ = s.PreviewBatch(ctx, admin, in)
	in.PreviewToken = preview.PreviewToken
	if _, err = s.DecideBatch(ctx, admin, "batch", in); !errors.Is(err, m.ErrConflict) {
		t.Fatal("changed batch replay accepted", err)
	}
}

func TestAffectedAuthorSeesDecisionWithoutReportersPrivateEvidence(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	report, err := s.Submit(ctx, m.Principal{Subject: "reporter"}, "report", m.Submission{ObjectID: "review", Kind: "report", Reason: "Private reporter account detail", Evidence: []string{"Private contact information"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Decide(ctx, m.Principal{Subject: "admin"}, report.ID, "decide", m.Decide{Revision: report.Revision, Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Public decision feedback"}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.FilteredList(ctx, m.Principal{Subject: "author"}, m.TaskFilter{Limit: 20})
	if err != nil || len(rows) != 1 || !rows[0].CanAppeal {
		t.Fatal(rows, err)
	}
	if rows[0].Submission.Reason != "content_review" || len(rows[0].Submission.Evidence) != 0 || rows[0].Decision.Reason != "Public decision feedback" {
		t.Fatal("private report leaked", rows)
	}
	own, err := s.Get(ctx, m.Principal{Subject: "reporter"}, report.ID)
	if err != nil || len(own.Submission.Evidence) != 1 {
		t.Fatal("reporter lost own evidence", own, err)
	}
}
