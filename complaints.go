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
	if in.Category == "" || !validCategory(in.Category) {
		return TaskView{}, withReason(ErrInput, "invalid_category")
	}
	if !keyOK(key) || in.Kind != "report" || in.PreviousTaskID != "" || in.ProposedBody != "" || object.Kind != "resource" || object.ID != in.ObjectID || !keyOK(object.ID) || !keyOK(object.SchoolID) || object.Revision < 1 || strings.TrimSpace(object.Owner) == "" || !textOK(object.Owner, 256) || !validReason(in.Reason) || len(in.Evidence) < 2 || len(in.Evidence) > 5 {
		return TaskView{}, withReason(ErrInput, "invalid_parameter")
	}
	for _, value := range in.Evidence {
		if strings.TrimSpace(value) == "" || !textOK(value, 2000) {
			return TaskView{}, withReason(ErrInput, "invalid_parameter")
		}
	}
	return s.saveReport(ctx, p, key, in, &object)
}
