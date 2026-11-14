// Package feedback owns the private operator mailbox and its retention policy.
package feedback

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	ErrInvalid     = errors.New("invalid_request")
	ErrDenied      = errors.New("forbidden")
	ErrConflict    = errors.New("conflict")
	ErrNotFound    = errors.New("not_found")
	ErrUnavailable = errors.New("unavailable")
	ErrLimit       = errors.New("capacity_exceeded")
)

type Attachment struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Status      string `json:"status"`
	ObjectID    string `json:"-"`
}
type Reply struct {
	ID        string    `json:"id"`
	Body      string    `json:"body"`
	Actor     string    `json:"actor"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}
type Message struct {
	ID                    string       `json:"id"`
	Sender                string       `json:"sender"`
	Subject               string       `json:"subject"`
	Body                  string       `json:"body"`
	AuthenticationResults string       `json:"authentication_results"`
	Suspicious            bool         `json:"suspicious"`
	State                 string       `json:"state"`
	Assignee              string       `json:"assignee"`
	Note                  string       `json:"note"`
	Revision              int64        `json:"revision"`
	ReceivedAt            time.Time    `json:"received_at"`
	ClosedAt              *time.Time   `json:"closed_at"`
	Attachments           []Attachment `json:"attachments"`
	Replies               []Reply      `json:"replies"`
	// Ingestion metadata is never returned by the management API.
	Dedupe    string `json:"-"`
	MessageID string `json:"-"`
	Ready     bool   `json:"-"`
	Bytes     int64  `json:"-"`
}
type Input struct {
	Message Message
	Parts   map[string][]byte
}
type Filter struct {
	After, State string
	Limit        int
}
type Page struct {
	Items      []Message `json:"items"`
	NextCursor string    `json:"next_cursor"`
}
type Update struct {
	Revision int64  `json:"revision"`
	State    string `json:"state"`
	Note     string `json:"note"`
}
type Tx interface {
	Lock() error
	Get(string) (Message, error)
	Find(string) (Message, error)
	Save(Message) error
	List(Filter) ([]Message, error)
	Usage(string, time.Time) (int, int64, int, error)
	Audit(string, string, string, time.Time) error
	Replay(string, string) ([]byte, error)
	Receipt(string, string, string, []byte, time.Time) error
	Expired(time.Time, int) ([]Message, error)
	Delete(string) error
	Prune(time.Time, int) error
}
type Repository interface {
	Transaction(context.Context, func(Tx) error) error
}
type Access interface {
	Check(context.Context, string, string) error
}

// Blobs must implement idempotent writes under a stable message/part key.
// Failed writes must remain discoverable for retry or cleanup.
type Blobs interface {
	Put(context.Context, string, Attachment, []byte) (string, error)
	Download(context.Context, string, io.Writer) error
	Delete(context.Context, string) error
}

// Sender reports unknown once DATA may have been accepted; callers never retry
// an unknown SMTP result automatically.
type Sender interface {
	Send(context.Context, string, string, string, string, string) (string, error)
}
type Service struct {
	Repo   Repository
	Access Access
	Blobs  Blobs
	Sender Sender
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
