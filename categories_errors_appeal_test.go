package moderation_test

import (
	"context"
	"encoding/json"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
	"github.com/StuHelper/stuhelper-moderation/sdk"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClosedCategoriesErrorReasonsRetryAfterAndCanAppeal(t *testing.T) {
	s, c, now := fixture(t)
	s.Access = reviewAccess{}
	*now = time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	ctx := context.Background()

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
	asActor := func(actor string) sdk.RequestEditorFn {
		return func(_ context.Context, r *http.Request) error {
			r.Header.Set("X-Test-Actor", actor)
			return nil
		}
	}

	// 1. Invalid category rejected with 400 and reason="invalid_category".
	badCat := sdk.ViolationCategory("unknown_category")
	badResp, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "bad-cat"}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReport,
		Category: &badCat,
		Reason:   "Test",
		Evidence: []string{},
	}, asActor("reporter"))
	if err != nil || badResp.StatusCode() != 400 || badResp.JSON400 == nil || badResp.JSON400.Reason == nil || string(*badResp.JSON400.Reason) != "invalid_category" {
		t.Fatalf("expected invalid_category 400, got: %v %+v", err, badResp)
	}

	// 2. Cross-origin Origin rejected with 403 and reason="cross_origin_forbidden".
	crossReq, _ := http.NewRequest("POST", srv.URL+"/api/v1/moderation/tasks", strings.NewReader(`{}`))
	crossReq.Header.Set("Origin", "https://evil.example")
	crossReq.Header.Set("X-Test-Actor", "reporter")
	crossResp, err := http.DefaultClient.Do(crossReq)
	if err != nil {
		t.Fatal(err)
	}
	defer crossResp.Body.Close()
	var errBody map[string]string
	_ = json.NewDecoder(crossResp.Body).Decode(&errBody)
	if crossResp.StatusCode != 403 || errBody["reason"] != "cross_origin_forbidden" {
		t.Fatalf("expected cross_origin_forbidden 403, got %d %v", crossResp.StatusCode, errBody)
	}

	// 3. Favorable publish decision on pending review -> can_appeal == false, appeal rejected with appeal_not_allowed.
	pendingTask, err := s.Track(ctx, "upload-1", m.Object{ID: "review", Kind: "course", SchoolID: "school", Owner: "author", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(ctx, m.Principal{Subject: "admin"}, pendingTask.ID, "pub-1", m.Decide{
		Revision: pendingTask.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "publish", Reason: "Approved"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	pubView, err := s.Get(ctx, m.Principal{Subject: "author"}, pendingTask.ID)
	if err != nil || pubView.CanAppeal {
		t.Fatalf("published task must not be appealable: %+v %v", pubView, err)
	}
	appealOnPublished, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "appeal-pub"}, sdk.Submission{
		ObjectId:       "review",
		Kind:           sdk.SubmissionKindAppeal,
		Reason:         "Why appeal approved?",
		Evidence:       []string{},
		PreviousTaskId: &pendingTask.ID,
	}, asActor("author"))
	if err != nil || appealOnPublished.StatusCode() != 409 || appealOnPublished.JSON409 == nil || appealOnPublished.JSON409.Reason == nil || string(*appealOnPublished.JSON409.Reason) != "appeal_not_allowed" {
		t.Fatalf("expected appeal_not_allowed 409, got %v %+v", err, appealOnPublished)
	}

	// 4. Adverse hide decision -> can_appeal == true before appeal, false after first appeal; second appeal rejected with already_appealed; appeal task itself has can_appeal == false.
	catAttack := sdk.ViolationCategory("personal_attack")
	reportResp, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "rep-1"}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReport,
		Category: &catAttack,
		Reason:   "Abusive remark",
		Evidence: []string{"Screenshot"},
	}, asActor("reporter-1"))
	if err != nil || reportResp.StatusCode() != 200 || reportResp.JSON200 == nil {
		t.Fatalf("submit report failed: %v %+v", err, reportResp)
	}
	reportID := reportResp.JSON200.Id

	// Idempotency key payload mismatch returns 409 idempotency_mismatch.
	mismatchResp, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "rep-1"}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReport,
		Category: &catAttack,
		Reason:   "Different reason",
		Evidence: []string{},
	}, asActor("reporter-1"))
	if err != nil || mismatchResp.StatusCode() != 409 || mismatchResp.JSON409 == nil || mismatchResp.JSON409.Reason == nil || string(*mismatchResp.JSON409.Reason) != "idempotency_mismatch" {
		t.Fatalf("expected idempotency_mismatch 409, got %v %+v", err, mismatchResp)
	}

	c.mu.Lock()
	curRev := c.revision
	c.mu.Unlock()
	if _, err = s.Decide(ctx, m.Principal{Subject: "admin"}, reportID, "hide-rep-1", m.Decide{
		Revision: 1,
		Decision: m.Decision{ObjectID: "review", Revision: curRev, Action: "hide", Category: "personal_attack", Reason: "Hidden for personal attack"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}

	beforeAppeal, err := s.Get(ctx, m.Principal{Subject: "author"}, reportID)
	if err != nil || !beforeAppeal.CanAppeal {
		t.Fatalf("expected CanAppeal=true on hidden report: %+v %v", beforeAppeal, err)
	}

	appealResp, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "appeal-1"}, sdk.Submission{
		ObjectId:       "review",
		Kind:           sdk.SubmissionKindAppeal,
		Category:       &catAttack,
		Reason:         "Context was misunderstood",
		Evidence:       []string{},
		PreviousTaskId: &reportID,
	}, asActor("author"))
	if err != nil || appealResp.StatusCode() != 200 || appealResp.JSON200 == nil {
		t.Fatalf("appeal submit failed: %v %+v", err, appealResp)
	}
	appealID := appealResp.JSON200.Id

	afterAppeal, err := s.Get(ctx, m.Principal{Subject: "author"}, reportID)
	if err != nil || afterAppeal.CanAppeal {
		t.Fatalf("expected CanAppeal=false after appeal created: %+v %v", afterAppeal, err)
	}

	dupAppealResp, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "appeal-2"}, sdk.Submission{
		ObjectId:       "review",
		Kind:           sdk.SubmissionKindAppeal,
		Reason:         "Second appeal on same task",
		Evidence:       []string{},
		PreviousTaskId: &reportID,
	}, asActor("author"))
	if err != nil || dupAppealResp.StatusCode() != 409 || dupAppealResp.JSON409 == nil || dupAppealResp.JSON409.Reason == nil || string(*dupAppealResp.JSON409.Reason) != "already_appealed" {
		t.Fatalf("expected already_appealed 409, got %v %+v", err, dupAppealResp)
	}

	// Original moderator deciding appeal returns 403 self_review_forbidden.
	c.mu.Lock()
	curRev = c.revision
	c.mu.Unlock()
	selfRevResp, err := client.DecideTaskWithResponse(ctx, appealID, &sdk.DecideTaskParams{IdempotencyKey: "self-rev"}, sdk.Decide{
		Revision: 1,
		Decision: sdk.Decision{Id: "", ObjectId: "review", Revision: int(curRev), Action: sdk.DecisionAction("dismiss"), Reason: "Self review"},
	}, asActor("admin"))
	if err != nil || selfRevResp.StatusCode() != 403 || selfRevResp.JSON403 == nil || selfRevResp.JSON403.Reason == nil || string(*selfRevResp.JSON403.Reason) != "self_review_forbidden" {
		t.Fatalf("expected self_review_forbidden 403, got %v %+v", err, selfRevResp)
	}

	// Second reviewer dismisses appeal -> appeal task itself must still have CanAppeal=false.
	if _, err = s.Decide(ctx, m.Principal{Subject: "reviewer"}, appealID, "rev-decide", m.Decide{
		Revision: 1,
		Decision: m.Decision{ObjectID: "review", Revision: curRev, Action: "dismiss", Reason: "Upheld original decision"},
	}); err != nil {
		t.Fatal(err)
	}
	appealDone, err := s.Get(ctx, m.Principal{Subject: "author"}, appealID)
	if err != nil || appealDone.CanAppeal {
		t.Fatalf("appeal task itself must never have CanAppeal=true: %+v %v", appealDone, err)
	}

	// 5. Rate limit 429 includes Retry-After header and reason="submission_rate_limited".
	*now = now.Add(20 * time.Second)
	for i := 0; i < 10; i++ {
		if _, err = s.SubmitResourceComplaint(ctx, m.Principal{Subject: "flood-user"}, fmt.Sprintf("flood-%d", i), m.Submission{
			Kind:     "report",
			ObjectID: fmt.Sprintf("res-%d", i),
			Category: "copyright",
			Reason:   "Copyright notice",
			Evidence: []string{"Proof", "Contact"},
		}, m.Object{ID: fmt.Sprintf("res-%d", i), Kind: "resource", SchoolID: "school", Owner: "uploader", Revision: 1}); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(15 * time.Second)
	rateResp, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "flood-11"}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReport,
		Reason:   "Over quota",
		Evidence: []string{},
	}, asActor("flood-user"))
	if err != nil || rateResp.StatusCode() != 429 || rateResp.JSON429 == nil || rateResp.JSON429.Reason == nil || string(*rateResp.JSON429.Reason) != "submission_rate_limited" {
		t.Fatalf("expected 429 submission_rate_limited, got %v %+v", err, rateResp)
	}
	retryHeader := rateResp.HTTPResponse.Header.Get("Retry-After")
	secs, convErr := strconv.Atoi(retryHeader)
	if convErr != nil || secs != 45 {
		t.Fatalf("expected Retry-After=45, got %q (%v)", retryHeader, convErr)
	}
}
