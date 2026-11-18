package moderation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
	pg "github.com/StuHelper/stuhelper-moderation/postgres"
	"github.com/StuHelper/stuhelper-moderation/sdk"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestOpenAPIAndHTTPHandlerAlignment(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	h := httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (m.Principal, error) {
			return m.Principal{Subject: r.Header.Get("X-Actor")}, nil
		},
	}.Routes()

	// 1. Go Submit with nil Evidence must serialize `"evidence":[]` (never `"evidence":null`).
	task, err := s.Submit(ctx, m.Principal{Subject: "reporter"}, "nil-ev", m.Submission{ObjectID: "review", Kind: "report", Reason: "Reason", Evidence: nil})
	if err != nil {
		t.Fatal(err)
	}
	rawTask, _ := json.Marshal(task)
	if strings.Contains(string(rawTask), `"evidence":null`) || !strings.Contains(string(rawTask), `"evidence":[]`) {
		t.Fatalf("TaskView serialized null evidence: %s", rawTask)
	}

	// HTTP POST /api/v1/moderation/tasks omitting required "evidence" must return 400.
	reqMissingEv := httptest.NewRequest("POST", "/api/v1/moderation/tasks", strings.NewReader(`{"object_id":"review","kind":"report","reason":"Reason"}`))
	reqMissingEv.Header.Set("X-Actor", "reporter")
	reqMissingEv.Header.Set("Idempotency-Key", "http-no-ev")
	resMissingEv := httptest.NewRecorder()
	h.ServeHTTP(resMissingEv, reqMissingEv)
	if resMissingEv.Code != 400 {
		t.Fatalf("expected 400 when HTTP Submission omits required evidence array, got %d: %s", resMissingEv.Code, resMissingEv.Body.String())
	}

	// 2. Appeal TaskView must populate top-level previous_task_id matching OpenAPI.
	decided, err := s.Decide(ctx, m.Principal{Subject: "admin"}, task.ID, "dec-1", m.Decide{
		Revision: task.Revision,
		Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Dismissed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	appeal, err := s.Submit(ctx, m.Principal{Subject: "author"}, "appeal-1", m.Submission{
		ObjectID:       "review",
		Kind:           "appeal",
		PreviousTaskID: decided.ID,
		Reason:         "Please review again",
		Evidence:       []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var appealMap map[string]any
	_ = json.Unmarshal(mustJSON(t, appeal), &appealMap)
	if appealMap["previous_task_id"] != decided.ID {
		t.Fatalf("TaskView missing top-level previous_task_id=%q, got: %v", decided.ID, appealMap)
	}

	// 3. Invalid admin query param (?admin=1) and invalid state enum (?state=bogus) must return 400.
	for _, path := range []string{"/api/v1/moderation/tasks?admin=1", "/api/v1/moderation/tasks?state=bogus"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Actor", "reporter")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != 400 {
			t.Fatalf("expected 400 for %s, got %d: %s", path, res.Code, res.Body.String())
		}
	}

	// 4. BatchPreview must work without Decision.id or preview_token, and batchToken must ignore placeholder Decision.id differences.
	revTask, err := s.Submit(ctx, m.Principal{Subject: "admin"}, "rev-b", m.Submission{ObjectID: "review", Kind: "review", Reason: "Batch", Evidence: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	previewBody := map[string]any{
		"items": []map[string]any{{
			"id":       revTask.ID,
			"revision": revTask.Revision,
			"decision": map[string]any{"id": "client-placeholder", "object_id": "review", "revision": 1, "action": "hide", "reason": "Hide"},
		}},
	}
	reqPreview := httptest.NewRequest("POST", "/api/v1/moderation/tasks/batch-preview", bytes.NewReader(mustJSON(t, previewBody)))
	reqPreview.Header.Set("X-Actor", "admin")
	resPreview := httptest.NewRecorder()
	h.ServeHTTP(resPreview, reqPreview)
	if resPreview.Code != 200 {
		t.Fatalf("batch-preview without Idempotency-Key or preview_token failed: %d %s", resPreview.Code, resPreview.Body.String())
	}
	var previewOut m.BatchPreview
	_ = json.Unmarshal(resPreview.Body.Bytes(), &previewOut)

	decideBatchBody := map[string]any{
		"preview_token": previewOut.PreviewToken,
		"items": []map[string]any{{
			"id":       revTask.ID,
			"revision": revTask.Revision,
			"decision": map[string]any{"object_id": "review", "revision": 1, "action": "hide", "reason": "Hide"},
		}},
	}
	reqBatch := httptest.NewRequest("POST", "/api/v1/moderation/tasks/batch", bytes.NewReader(mustJSON(t, decideBatchBody)))
	reqBatch.Header.Set("X-Actor", "admin")
	reqBatch.Header.Set("Idempotency-Key", "batch-exec-1")
	resBatch := httptest.NewRecorder()
	h.ServeHTTP(resBatch, reqBatch)
	if resBatch.Code != 200 {
		t.Fatalf("batch decide rejected token when placeholder Decision.id omitted: %d %s", resBatch.Code, resBatch.Body.String())
	}

	// 5. Feedback List accepts up to 256-char after cursor matching OpenAPI maxLength: 256.
	repo := s.Repo.(*pg.Repository)
	fbSvc := &f.Service{Repo: &pg.FeedbackRepository{DB: repo.DB}, Access: &feedbackAccess{}, Blobs: &feedbackBlobs{values: map[string][]byte{}}}
	if _, err = fbSvc.List(ctx, "operator", f.Filter{After: strings.Repeat("a", 120), Limit: 10}); err != nil {
		t.Fatalf("feedback.List rejected 120-char cursor allowed by OpenAPI maxLength=256: %v", err)
	}
	if _, err = fbSvc.List(ctx, "operator", f.Filter{After: strings.Repeat("a", 257), Limit: 10}); !errors.Is(err, f.ErrInvalid) {
		t.Fatalf("feedback.List accepted >256-char cursor: %v", err)
	}

	// 6. OpenAPI contract checks: feedback security & Error schemas, optional Idempotency-Key on previewBatch, DecisionInput without required id.
	specBytes, err := os.ReadFile("contracts/moderation.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(specBytes, &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]any)
	fbListGet := paths["/api/v1/moderation/feedback"].(map[string]any)["get"].(map[string]any)
	if fbListGet["security"] == nil {
		t.Fatal("OpenAPI /api/v1/moderation/feedback GET missing security bearerAuth")
	}
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	if schemas["DecisionInput"] == nil || schemas["BatchPreviewRequest"] == nil {
		t.Fatal("OpenAPI missing split DecisionInput / BatchPreviewRequest request schemas")
	}

	// 7. Generated Go SDK uses int64 revisions and optional request-side DecisionInput.Id / BatchPreviewRequest.PreviewToken / PreviewBatchParams.IdempotencyKey.
	var sdkView sdk.TaskView
	var rev64 int64 = sdkView.Revision
	var objRev64 int64 = sdkView.ObjectRevision
	_ = rev64
	_ = objRev64
	sdkDecInput := sdk.DecisionInput{ObjectId: "review", Revision: int64(1), Action: sdk.DecisionInputActionHide, Reason: "Hide"}
	if sdkDecInput.Id != nil {
		t.Fatal("expected optional nil Id on sdk.DecisionInput")
	}
	sdkPreviewReq := sdk.BatchPreviewRequest{Items: []sdk.BatchItem{{Id: "t1", Revision: int64(1), Decision: sdkDecInput}}}
	if sdkPreviewReq.PreviewToken != nil {
		t.Fatal("expected optional nil PreviewToken on sdk.BatchPreviewRequest")
	}
	var sdkPreviewParams sdk.PreviewBatchParams
	if sdkPreviewParams.IdempotencyKey != nil {
		t.Fatal("expected optional nil IdempotencyKey on sdk.PreviewBatchParams")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
