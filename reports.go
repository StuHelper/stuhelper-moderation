package moderation

import (
	"context"
	"errors"
	"time"
)

// Reports first check owned local work. Only creation reads external content
// facts, so a qualification outage cannot block evidence on an existing report.
func (s *Service) submitReport(ctx context.Context, p Principal, key string, in Submission) (TaskView, error) {
	return s.saveReport(ctx, p, key, in, nil)
}

func (s *Service) saveReport(ctx context.Context, p Principal, key string, in Submission, object *Object) (TaskView, error) {
	return s.saveReportUsing(ctx, p, key, in, object, func(call context.Context) (Object, error) {
		if s.Content == nil {
			return Object{}, ErrUnavailable
		}
		current, err := s.Content.Inspect(call, p, in.ObjectID)
		if err != nil {
			return Object{}, err
		}
		if !current.Visible {
			return Object{}, ErrNotFound
		}
		return current, s.auth(call, p, "report", current.SchoolID)
	})
}

func (s *Service) saveReportUsing(ctx context.Context, p Principal, key string, in Submission, object *Object, load func(context.Context) (Object, error)) (TaskView, error) {
	var out TaskView
	if p.Subject == "" {
		return out, ErrForbidden
	}
	if in.Evidence == nil {
		in.Evidence = []string{}
	}
	in.Kind = "report"
	operation := digest([]string{p.Subject, in.Kind, in.ObjectID, key})
	payload := digest(in)
	var migratedComplaintHash string
	if object != nil && in.Category == "other" {
		// The resources migration classifies old complaints as other. Verify the
		// original payload for an existing receipt when delivery lost its result.
		original := in
		original.Category = ""
		migratedComplaintHash = digest(original)
	}
	needsFacts := errors.New("report creation needs current facts")
	checkRateLimit := func(t Transaction) error {
		limiter, ok := t.(interface{ LimitSubmission(string, time.Time) error })
		if !ok {
			return ErrUnavailable
		}
		return limiter.LimitSubmission(p.Subject, s.now())
	}
	apply := func(t Transaction) error {
		var txErr error
		out, txErr = s.upsertSubmissionTx(t, p, operation, payload, migratedComplaintHash, in, object, needsFacts, checkRateLimit)
		return txErr
	}
	err := s.tx(ctx, apply)
	if !errors.Is(err, needsFacts) {
		return out, err
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	current, e := load(call)
	if e != nil {
		return out, e
	}
	object = &current
	// Recheck local state under the same lock: a concurrent creation merges, and
	// a concurrent decision cannot be overwritten by late evidence.
	err = s.tx(ctx, apply)
	return out, err
}
