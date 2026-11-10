package moderation

import (
	"context"
	"time"
)

// AuditReader is a trusted adapter port; Scopes must come from current authorization.
// The platform adapter binds Principal, filters and Scopes to its outer cursor.
type AuditReader interface {
	ReadAudit(context.Context, AuditRequest) (AuditBatch, error)
}
type AuditScope struct {
	School string `json:"school"`
	Group  string `json:"group"`
	Module string `json:"module"`
}
type AuditPosition struct {
	Time       time.Time
	Source, ID string
}
type AuditRequest struct {
	Principal             string
	Scopes                []AuditScope
	Actor, Target, Action string
	From, Until           time.Time
	Before                *AuditPosition
	Snapshot              string
	Limit                 int
}
type AuditRecord struct {
	ID        string     `json:"id"`
	Source    string     `json:"source"`
	Target    string     `json:"target"`
	Actor     string     `json:"actor"`
	CreatedAt time.Time  `json:"created_at"`
	Action    string     `json:"action"`
	Reason    string     `json:"reason"`
	Result    string     `json:"result"`
	Scope     AuditScope `json:"scope"`
}
type AuditBatch struct {
	Records  []AuditRecord
	Snapshot string
}
