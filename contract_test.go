package moderation_test

import (
	"encoding/json"
	"os"
	"testing"

	m "github.com/StuHelper/stuhelper-moderation"
	"github.com/StuHelper/stuhelper-moderation/sdk"
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
