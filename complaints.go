package moderation

import (
	"context"
	"strings"
)

// SubmitResourceComplaint is a trusted module port, never an HTTP route. The
// resources module authenticates and persists the complaint, then supplies
// verified target metadata. Retries use the same request key and payload.
func (s *Service) SubmitResourceComplaint(ctx context.Context, p Principal, key string, in Submission, object Object) (TaskView, error) {
	if p.Subject == "" {
		return TaskView{}, ErrUnauthenticated
	}
	if !keyOK(key) || in.Kind != "report" || in.PreviousTaskID != "" || in.ProposedBody != "" || object.Kind != "resource" || object.ID != in.ObjectID || object.ID == "" || len(object.ID) > 128 || object.Revision < 1 || object.Owner == "" || strings.TrimSpace(in.Reason) == "" || !textOK(in.Reason, 2000) || len(in.Evidence) < 2 || len(in.Evidence) > 5 {
		return TaskView{}, ErrInput
	}
	for _, value := range in.Evidence {
		if strings.TrimSpace(value) == "" || !textOK(value, 2000) {
			return TaskView{}, ErrInput
		}
	}
	return s.saveReport(ctx, p, key, in, &object)
}
