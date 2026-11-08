package moderation

import (
	"context"
	"strconv"
	"time"
)

const OutboxChannel = "moderation_outbox"

// OutboxReader is a trusted relay port. Confirm only after durable consumption.
type OutboxReader interface {
	PendingOutbox(context.Context, int) ([]Envelope, error)
	ConfirmOutbox(context.Context, string) error
}

type Envelope struct {
	SpecVersion     string     `json:"specversion"`
	ID              string     `json:"id"`
	Source          string     `json:"source"`
	Type            string     `json:"type"`
	Subject         string     `json:"subject"`
	Time            time.Time  `json:"time"`
	SchoolID        string     `json:"schoolid"`
	DataContentType string     `json:"datacontenttype"`
	Data            ResultData `json:"data"`
}

type ResultData struct {
	Revision     int64  `json:"revision"`
	TaskID       string `json:"task_id,omitempty"`
	Owner        string `json:"owner,omitempty"`
	ContentOwner string `json:"content_owner,omitempty"`
	ObjectID     string `json:"object_id,omitempty"`
	ContentKind  string `json:"content_kind,omitempty"`
	RequestKind  string `json:"request_kind,omitempty"`
	DecisionID   string `json:"decision_id,omitempty"`
	Action       string `json:"action,omitempty"`
	State        string `json:"state,omitempty"`
}

func resultData(task Task) *ResultData {
	return &ResultData{Revision: task.Revision, TaskID: task.ID, Owner: task.Owner, ContentOwner: task.ContentOwner, ObjectID: task.Submission.ObjectID, ContentKind: task.ContentKind, RequestKind: task.Submission.Kind, DecisionID: task.Decision.ID, Action: task.Decision.Action, State: task.State}
}
func (s *Service) recordResult(t Transaction, task Task) error {
	result := "unknown"
	if task.State == "applied" {
		result = "success"
	} else if task.State == "failed" {
		result = "failed"
	}
	return t.Event(Event{Result: result, Reason: task.ErrorCode, Actor: task.DecidedBy, ID: digest([]string{"result", task.Decision.ID, strconv.FormatInt(task.Revision, 10)}), Type: "moderation.result.v1", Subject: "task/" + task.ID, SchoolID: task.SchoolID, Revision: task.Revision, At: s.now(), Data: resultData(task)})
}
