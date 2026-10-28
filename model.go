// Package moderation owns reports, author requests and durable moderation decisions.
package moderation

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrInput           = errors.New("invalid_input")
	ErrNotFound        = errors.New("not_found")
	ErrForbidden       = errors.New("forbidden")
	ErrConflict        = errors.New("conflict")
	ErrUnavailable     = errors.New("unavailable")
)

type Principal struct{ Subject string }
type Object struct {
	ID, Kind, SchoolID, Owner string
	Revision                  int64
	Visible                   bool
}
type Content interface {
	Inspect(context.Context, Principal, string) (Object, error)
	Apply(context.Context, Principal, Decision) error
}
type Access interface {
	Authorize(context.Context, Principal, string, string) error
}
type Policy struct {
	SchoolID     string   `json:"school_id"`
	Kind         string   `json:"kind"`
	Mode         string   `json:"mode"`
	BlockedTerms []string `json:"blocked_terms"`
	Revision     int64    `json:"revision"`
}
type PolicyView struct {
	Configured *Policy `json:"configured"`
	Effective  Policy  `json:"effective"`
	Source     string  `json:"source"`
}
type Submission struct {
	ObjectID     string   `json:"object_id"`
	Kind         string   `json:"kind"`
	Reason       string   `json:"reason"`
	Evidence     []string `json:"evidence"`
	ProposedBody string   `json:"proposed_body,omitempty"`
}
type Decision struct {
	ID           string  `json:"id"`
	ObjectID     string  `json:"object_id"`
	Revision     int64   `json:"revision"`
	Action       string  `json:"action"`
	Body         *string `json:"body,omitempty"`
	Subject      string  `json:"subject,omitempty"`
	AuthorHandle string  `json:"author_handle,omitempty"`
	Signed       bool    `json:"signed"`
	Reason       string  `json:"reason"`
}
type Task struct {
	ID             string     `json:"id"`
	SchoolID       string     `json:"school_id"`
	Owner          string     `json:"owner"`
	Submission     Submission `json:"submission"`
	ObjectRevision int64      `json:"object_revision"`
	Revision       int64      `json:"revision"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Decision       *Decision  `json:"decision,omitempty"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	Attempts       int        `json:"attempts"`
	NextAttempt    time.Time  `json:"next_attempt"`
	LeaseUntil     time.Time  `json:"lease_until"`
	ErrorCode      string     `json:"error_code,omitempty"`
}
type TaskView struct {
	ID             string     `json:"id"`
	SchoolID       string     `json:"school_id"`
	Submission     Submission `json:"submission"`
	ObjectRevision int64      `json:"object_revision"`
	Revision       int64      `json:"revision"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Decision       *Decision  `json:"decision,omitempty"`
	ErrorCode      string     `json:"error_code,omitempty"`
}
type Decide struct {
	Revision int64    `json:"revision"`
	Decision Decision `json:"decision"`
}
type Replay struct {
	Digest string
	TaskID string
	View   TaskView
	Until  time.Time
}
type Event struct {
	ID, Type, Subject, SchoolID, Actor string
	Revision                           int64
	At                                 time.Time
}
type Repository interface {
	Transaction(context.Context, func(Transaction) error) error
}
type Transaction interface {
	Lock(string) error
	Task(string) (Task, error)
	Active(owner, object, kind string) (Task, error)
	SaveTask(Task) error
	List(owner, school, state, after string, limit int) ([]Task, error)
	Ready(time.Time, int) ([]Task, error)
	Policy(school, kind string) (Policy, error)
	SavePolicy(Policy) error
	Replay(string) (Replay, error)
	SaveReplay(string, Replay) error
	Event(Event) error
}
