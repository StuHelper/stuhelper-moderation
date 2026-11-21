package moderation_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/StuHelper/stuhelper-moderation/httpapi"
	"github.com/StuHelper/stuhelper-moderation/sdk"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGeneratedAppealSubmissionPreservesRequestFields(t *testing.T) {
	input := []byte(`{"object_id":"review","kind":"appeal","reason":"Please reconsider","evidence":[],"previous_task_id":"previous-task"}`)
	var generated sdk.Submission
	if err := json.Unmarshal(input, &generated); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	var actual m.Submission
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Kind != "appeal" || actual.PreviousTaskID != "previous-task" {
		t.Fatalf("generated client dropped appeal request data: %s", encoded)
	}
	bytes, err := os.ReadFile("contracts/moderation.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(bytes, &document); err != nil {
		t.Fatal(err)
	}
	shape := document.Components.Schemas["Submission"]
	if _, ok := shape.Properties["previous_task_id"]; !ok {
		t.Fatal("strict request schema rejects previous task")
	}
	allowed := false
	for _, kind := range shape.Properties["kind"].Enum {
		if kind == "appeal" {
			allowed = true
		}
	}
	if !allowed {
		t.Fatal("strict request schema rejects appeal")
	}
}

func TestConvergedEditRequestCannotOverwriteConcurrentDecision(t *testing.T) {
	s, _, _ := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	author := m.Principal{Subject: "author"}
	in := m.Submission{
		ObjectID:     "review",
		Kind:         "edit_request",
		Reason:       "Initial edit reason",
		ProposedBody: "Proposed v1",
		Evidence:     nil,
	}
	task, err := s.Submit(ctx, author, "edit-orig", in)
	if err != nil {
		t.Fatal(err)
	}
	if task.Submission.Evidence == nil {
		t.Fatal("expected non-nil Evidence slice in TaskView")
	}

	barrier := &decisionBarrier{Content: s.Content, entered: make(chan struct{}), release: make(chan struct{})}
	s.Content = barrier
	decided := make(chan error, 1)
	go func() {
		_, err := s.Decide(ctx, m.Principal{Subject: "admin"}, task.ID, "decide-edit", m.Decide{
			Revision: task.Revision,
			Decision: m.Decision{ObjectID: "review", Revision: 1, Action: "dismiss", Reason: "Rejected"},
		})
		decided <- err
	}()
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	in.ProposedBody = "Proposed v2"
	supplemented := make(chan error, 1)
	go func() {
		_, err := s.Submit(ctx, author, "edit-late", in)
		supplemented <- err
	}()
	select {
	case early := <-supplemented:
		t.Fatalf("edit_request supplement bypassed pending decision lock: %v", early)
	case <-time.After(50 * time.Millisecond):
	}
	close(barrier.release)
	if err := <-decided; err != nil {
		t.Fatal(err)
	}
	if err := <-supplemented; !errors.Is(err, m.ErrConflict) {
		t.Fatalf("expected conflict on late edit_request update, got %v", err)
	}
	current, err := s.Get(ctx, author, task.ID)
	if err != nil || current.State != "applied" || current.Decision == nil || current.Submission.ProposedBody != "Proposed v1" {
		t.Fatalf("concurrent edit_request overwrote admin decision: %+v %v", current, err)
	}
}

type openAPIDoc struct {
	Components struct {
		Schemas map[string]openAPISchema `json:"schemas"`
	} `json:"components"`
}

type openAPISchema struct {
	Ref                  string                      `json:"$ref"`
	Type                 string                      `json:"type"`
	Nullable             bool                        `json:"nullable"`
	AdditionalProperties openAPIAdditionalProperties `json:"additionalProperties"`
	Required             []string                    `json:"required"`
	Enum                 []string                    `json:"enum"`
	Properties           map[string]openAPISchema    `json:"properties"`
	Items                *openAPISchema              `json:"items"`
	Minimum              *float64                    `json:"minimum"`
}

type openAPIAdditionalProperties struct {
	Forbidden bool
	Schema    *openAPISchema
}

func (p *openAPIAdditionalProperties) UnmarshalJSON(raw []byte) error {
	switch string(raw) {
	case "true", "false":
		*p = openAPIAdditionalProperties{Forbidden: string(raw) == "false"}
		return nil
	default:
		var schema *openAPISchema
		if err := json.Unmarshal(raw, &schema); err != nil {
			return err
		}
		if schema == nil {
			return errors.New("additionalProperties requires a boolean or schema")
		}
		*p = openAPIAdditionalProperties{Schema: schema}
		return nil
	}
}

func loadOpenAPIDoc(t *testing.T) openAPIDoc {
	t.Helper()
	raw, err := os.ReadFile("contracts/moderation.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc openAPIDoc
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func assertConformsSchema(t *testing.T, doc openAPIDoc, schema openAPISchema, val any, path string) {
	t.Helper()
	if schema.Ref != "" {
		name := strings.TrimPrefix(schema.Ref, "#/components/schemas/")
		resolved, ok := doc.Components.Schemas[name]
		if !ok {
			t.Fatalf("%s: unknown schema ref %s", path, schema.Ref)
		}
		assertConformsSchema(t, doc, resolved, val, path)
		return
	}
	if val == nil {
		if !schema.Nullable {
			t.Fatalf("%s: unexpected null for non-nullable schema", path)
		}
		return
	}
	switch schema.Type {
	case "object":
		obj, ok := val.(map[string]any)
		if !ok {
			t.Fatalf("%s: expected object, got %T", path, val)
		}
		for _, req := range schema.Required {
			if _, exists := obj[req]; !exists {
				t.Fatalf("%s: missing required field %q in %v", path, req, obj)
			}
		}
		for k, v := range obj {
			propSchema, declared := schema.Properties[k]
			switch {
			case declared:
				assertConformsSchema(t, doc, propSchema, v, path+"."+k)
			case schema.AdditionalProperties.Forbidden:
				t.Fatalf("%s: undeclared field %q in strict schema", path, k)
			case schema.AdditionalProperties.Schema != nil:
				assertConformsSchema(t, doc, *schema.AdditionalProperties.Schema, v, path+"."+k)
			}
		}
	case "array":
		arr, ok := val.([]any)
		if !ok {
			t.Fatalf("%s: expected non-null array, got %T (%v)", path, val, val)
		}
		if schema.Items != nil {
			for i, elem := range arr {
				assertConformsSchema(t, doc, *schema.Items, elem, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	case "string":
		str, ok := val.(string)
		if !ok {
			t.Fatalf("%s: expected string, got %T", path, val)
		}
		if len(schema.Enum) > 0 && !slices.Contains(schema.Enum, str) {
			t.Fatalf("%s: value %q not in enum %v", path, str, schema.Enum)
		}
	case "integer":
		num, ok := val.(float64)
		if !ok || num != float64(int64(num)) {
			t.Fatalf("%s: expected integer, got %v (%T)", path, val, val)
		}
		if schema.Minimum != nil && num < *schema.Minimum {
			t.Fatalf("%s: expected at least %v, got %v", path, *schema.Minimum, num)
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			t.Fatalf("%s: expected boolean, got %T", path, val)
		}
	}
}

func validateJSONBytes(t *testing.T, doc openAPIDoc, schemaRef string, raw []byte) {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("invalid JSON (%s): %v", raw, err)
	}
	if schemaRef == "TaskView[]" {
		itemSchema := openAPISchema{Ref: "#/components/schemas/TaskView"}
		assertConformsSchema(t, doc, openAPISchema{Type: "array", Items: &itemSchema}, decoded, "TaskView[]")
		return
	}
	assertConformsSchema(t, doc, openAPISchema{Ref: "#/components/schemas/" + schemaRef}, decoded, schemaRef)
}

func TestGeneratedSDKAllRoutesAndOpenAPISchemaConformance(t *testing.T) {
	doc := loadOpenAPIDoc(t)
	s, c, now := fixture(t)
	s.Access = reviewAccess{}
	*now = time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)
	ctx := context.Background()

	var authErr error
	srv := httptest.NewServer(httpapi.Handler{
		Service: s,
		Authenticate: func(r *http.Request) (m.Principal, error) {
			if authErr != nil {
				return m.Principal{}, authErr
			}
			actor := r.Header.Get("X-Test-Actor")
			if actor == "" {
				return m.Principal{}, m.ErrUnauthenticated
			}
			return m.Principal{Subject: actor}, nil
		},
	}.Routes())
	defer srv.Close()

	client, err := sdk.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	asActor := func(actor string) sdk.RequestEditorFn {
		return func(_ context.Context, r *http.Request) error {
			if actor != "" {
				r.Header.Set("X-Test-Actor", actor)
			}
			return nil
		}
	}

	// 401 & 503 via SDK
	unauthResp, err := client.ListTasksWithResponse(ctx, &sdk.ListTasksParams{})
	if err != nil || unauthResp.StatusCode() != 401 {
		t.Fatalf("expected 401, got %v %+v", err, unauthResp)
	}
	validateJSONBytes(t, doc, "Error", unauthResp.Body)

	authErr = m.ErrUnavailable
	unavailResp, err := client.ListTasksWithResponse(ctx, &sdk.ListTasksParams{}, asActor("admin"))
	authErr = nil
	if err != nil || unavailResp.StatusCode() != 503 {
		t.Fatalf("expected 503, got %v %+v", err, unavailResp)
	}
	validateJSONBytes(t, doc, "Error", unavailResp.Body)

	// Policies GET (default), PUT (200), GET (configured), 403, 409, 400
	polGet0, err := client.GetPolicyWithResponse(ctx, &sdk.GetPolicyParams{SchoolId: "school", Kind: "course"}, asActor("admin"))
	if err != nil || polGet0.StatusCode() != 200 {
		t.Fatalf("getPolicy default failed: %v %+v", err, polGet0)
	}
	validateJSONBytes(t, doc, "PolicyView", polGet0.Body)

	polPut, err := client.SetPolicyWithResponse(ctx, &sdk.SetPolicyParams{IdempotencyKey: "pol-1"}, sdk.Policy{
		SchoolId:     "school",
		Kind:         "course",
		Mode:         sdk.PolicyMode("published"),
		BlockedTerms: []string{"spamword"},
		Revision:     0,
	}, asActor("admin"))
	if err != nil || polPut.StatusCode() != 200 {
		t.Fatalf("setPolicy failed: %v %+v", err, polPut)
	}
	validateJSONBytes(t, doc, "Saved", polPut.Body)

	polGet1, err := client.GetPolicyWithResponse(ctx, &sdk.GetPolicyParams{SchoolId: "school", Kind: "course"}, asActor("admin"))
	if err != nil || polGet1.StatusCode() != 200 {
		t.Fatalf("getPolicy configured failed: %v %+v", err, polGet1)
	}
	validateJSONBytes(t, doc, "PolicyView", polGet1.Body)

	pol403, err := client.GetPolicyWithResponse(ctx, &sdk.GetPolicyParams{SchoolId: "school", Kind: "course"}, asActor("reporter"))
	if err != nil || pol403.StatusCode() != 403 {
		t.Fatalf("expected 403 on policy, got %v %+v", err, pol403)
	}
	validateJSONBytes(t, doc, "Error", pol403.Body)

	pol409, err := client.SetPolicyWithResponse(ctx, &sdk.SetPolicyParams{IdempotencyKey: "pol-1"}, sdk.Policy{
		SchoolId:     "school",
		Kind:         "course",
		Mode:         sdk.PolicyMode("pending"),
		BlockedTerms: []string{},
		Revision:     1,
	}, asActor("admin"))
	if err != nil || pol409.StatusCode() != 409 {
		t.Fatalf("expected 409 on policy idempotency conflict, got %v %+v", err, pol409)
	}
	validateJSONBytes(t, doc, "Error", pol409.Body)

	// SubmitTask (200, 400, 404, 409) & GetTask (200, 404) & ListTasks (200)
	category := sdk.ViolationCategorySpam
	sub200, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "sub-1"}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReport,
		Reason:   "Contract report",
		Evidence: []string{"item-1"},
		Category: &category,
	}, asActor("reporter"))
	if err != nil || sub200.StatusCode() != 200 || sub200.JSON200 == nil {
		t.Fatalf("submitTask 200 failed: %v %+v", err, sub200)
	}
	validateJSONBytes(t, doc, "TaskView", sub200.Body)
	taskID := sub200.JSON200.Id

	sub400, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: ""}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReport,
		Reason:   "Missing key",
		Evidence: []string{},
	}, asActor("reporter"))
	if err != nil || sub400.StatusCode() != 400 {
		t.Fatalf("expected 400 on empty Idempotency-Key, got %v %+v", err, sub400)
	}
	validateJSONBytes(t, doc, "Error", sub400.Body)

	get200, err := client.GetTaskWithResponse(ctx, taskID, asActor("reporter"))
	if err != nil || get200.StatusCode() != 200 {
		t.Fatalf("getTask 200 failed: %v %+v", err, get200)
	}
	validateJSONBytes(t, doc, "TaskView", get200.Body)

	get404, err := client.GetTaskWithResponse(ctx, "missing-task-id", asActor("reporter"))
	if err != nil || get404.StatusCode() != 404 {
		t.Fatalf("expected 404 on missing task, got %v %+v", err, get404)
	}
	validateJSONBytes(t, doc, "Error", get404.Body)

	schoolID := "school"
	adminTrue := "true"
	list200, err := client.ListTasksWithResponse(ctx, &sdk.ListTasksParams{SchoolId: &schoolID, Admin: &adminTrue}, asActor("admin"))
	if err != nil || list200.StatusCode() != 200 {
		t.Fatalf("listTasks 200 failed: %v %+v", err, list200)
	}
	validateJSONBytes(t, doc, "TaskView[]", list200.Body)

	summary, err := client.GetQueueSummaryWithResponse(ctx, &sdk.GetQueueSummaryParams{SchoolId: schoolID}, asActor("admin"))
	if err != nil || summary.JSON200 == nil || summary.JSON200.ByCategory[string(category)] != 1 {
		t.Fatalf("getQueueSummary did not count the categorized task: %v %+v", err, summary)
	}
	validateJSONBytes(t, doc, "QueueSummary", summary.Body)

	// PreviewBatch & DecideBatch (200)
	batchReq := sdk.BatchRequest{
		PreviewToken: "",
		Items: []sdk.BatchItem{{
			Id:       taskID,
			Revision: 1,
			Decision: sdk.DecisionInput{ObjectId: "review", Revision: 1, Action: sdk.DecisionInputAction("hide"), Reason: "Batch hide"},
		}},
	}
	prev200, err := client.PreviewBatchWithResponse(ctx, &sdk.PreviewBatchParams{}, sdk.BatchPreviewRequest{Items: batchReq.Items}, asActor("admin"))
	if err != nil || prev200.StatusCode() != 200 || prev200.JSON200 == nil {
		t.Fatalf("previewBatch 200 failed: %v %+v", err, prev200)
	}
	validateJSONBytes(t, doc, "BatchPreview", prev200.Body)

	batchReq.PreviewToken = prev200.JSON200.PreviewToken
	batch200, err := client.DecideBatchWithResponse(ctx, &sdk.DecideBatchParams{IdempotencyKey: "batch-1"}, batchReq, asActor("admin"))
	if err != nil || batch200.StatusCode() != 200 {
		t.Fatalf("decideBatch 200 failed: %v %+v", err, batch200)
	}
	validateJSONBytes(t, doc, "BatchPreview", batch200.Body)

	// Simulate 24h temporary failure -> RetryTask (200 & 409)
	c.loseResult = true
	*now = now.Add(25 * time.Hour)
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	failedView, err := s.Get(ctx, m.Principal{Subject: "admin"}, taskID)
	if err != nil || failedView.State != "failed" {
		t.Fatalf("expected failed state, got %+v %v", failedView, err)
	}

	retry200, err := client.RetryTaskWithResponse(ctx, taskID, &sdk.RetryTaskParams{IdempotencyKey: "retry-1"}, sdk.RetryTaskJSONRequestBody{
		Revision: failedView.Revision,
	}, asActor("admin"))
	if err != nil || retry200.StatusCode() != 200 {
		t.Fatalf("retryTask 200 failed: %v %+v", err, retry200)
	}
	validateJSONBytes(t, doc, "TaskView", retry200.Body)

	retry409, err := client.RetryTaskWithResponse(ctx, taskID, &sdk.RetryTaskParams{IdempotencyKey: "retry-stale"}, sdk.RetryTaskJSONRequestBody{
		Revision: failedView.Revision,
	}, asActor("admin"))
	if err != nil || retry409.StatusCode() != 409 {
		t.Fatalf("expected 409 on retry of decided task, got %v %+v", err, retry409)
	}
	validateJSONBytes(t, doc, "Error", retry409.Body)

	// Single DecideTask (200 & 403)
	c.loseResult = false
	if _, err = s.Work(ctx, 10); err != nil {
		t.Fatal(err)
	}
	reviewTask, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "rev-task"}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReview,
		Reason:   "Routine review",
		Evidence: []string{},
	}, asActor("admin"))
	if err != nil || reviewTask.StatusCode() != 200 || reviewTask.JSON200 == nil {
		t.Fatalf("submit review failed: %v %+v", err, reviewTask)
	}
	c.mu.Lock()
	curRev := c.revision
	c.mu.Unlock()
	dec403, err := client.DecideTaskWithResponse(ctx, reviewTask.JSON200.Id, &sdk.DecideTaskParams{IdempotencyKey: "dec-403"}, sdk.Decide{
		Revision: 1,
		Decision: sdk.DecisionInput{ObjectId: "review", Revision: curRev, Action: sdk.DecisionInputAction("dismiss"), Reason: "Denied"},
	}, asActor("reporter"))
	if err != nil || dec403.StatusCode() != 403 {
		t.Fatalf("expected 403 on decideTask, got %v %+v", err, dec403)
	}
	validateJSONBytes(t, doc, "Error", dec403.Body)

	dec200, err := client.DecideTaskWithResponse(ctx, reviewTask.JSON200.Id, &sdk.DecideTaskParams{IdempotencyKey: "dec-200"}, sdk.Decide{
		Revision: 1,
		Decision: sdk.DecisionInput{ObjectId: "review", Revision: curRev, Action: sdk.DecisionInputAction("dismiss"), Reason: "Closed"},
	}, asActor("admin"))
	if err != nil || dec200.StatusCode() != 200 {
		t.Fatalf("decideTask 200 failed: %v %+v", err, dec200)
	}
	validateJSONBytes(t, doc, "TaskView", dec200.Body)

	// 429 via SDK
	*now = now.Add(2 * time.Minute)
	for i := 0; i < 10; i++ {
		if _, err = s.SubmitResourceComplaint(ctx, m.Principal{Subject: "rate-actor"}, fmt.Sprintf("rk-%d", i), m.Submission{
			Kind:     "report",
			ObjectID: fmt.Sprintf("res-%d", i),
			Category: "copyright",
			Reason:   "Complaint",
			Evidence: []string{"E1", "E2"},
		}, m.Object{ID: fmt.Sprintf("res-%d", i), Kind: "resource", SchoolID: "school", Owner: "uploader", Revision: 1}); err != nil {
			t.Fatal(err)
		}
	}
	rate429, err := client.SubmitTaskWithResponse(ctx, &sdk.SubmitTaskParams{IdempotencyKey: "rk-over"}, sdk.Submission{
		ObjectId: "review",
		Kind:     sdk.SubmissionKindReport,
		Reason:   "Over limit",
		Evidence: []string{},
	}, asActor("rate-actor"))
	if err != nil || rate429.StatusCode() != 429 {
		t.Fatalf("expected 429 via SDK, got %v %+v", err, rate429)
	}
	validateJSONBytes(t, doc, "Error", rate429.Body)
}
