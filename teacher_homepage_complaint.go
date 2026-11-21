package moderation

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	TeacherHomepageContentKind  = "teacher_homepage"
	teacherHomepageObjectPrefix = "teacher-homepage:"
)

// TeacherHomepageContent receives a canonical directory ID instead of the
// namespaced moderation object ID. Its reader supplies metadata only.
type TeacherHomepageContent interface {
	InspectTeacherHomepage(context.Context, Principal, string) (Object, error)
	ApplyTeacherHomepageDecision(context.Context, Principal, Decision) error
}

type TeacherHomepageComplaint struct {
	Category string   `json:"category"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence"`
}

type TeacherHomepageComplaintTarget struct {
	ObjectID string `json:"object_id"`
	SchoolID string `json:"school_id"`
	Revision int64  `json:"revision"`
	Visible  bool   `json:"visible"`
}

func validTeacherHomepageID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-_.:", char)) {
			return false
		}
	}
	return true
}

func teacherHomepageObjectID(id string) bool {
	return strings.HasPrefix(id, teacherHomepageObjectPrefix)
}

func validModerationObjectID(id string) bool {
	if teacherHomepageObjectID(id) {
		return validTeacherHomepageID(strings.TrimPrefix(id, teacherHomepageObjectPrefix))
	}
	return keyOK(id)
}

func (s *Service) SubmitTeacherHomepageComplaint(ctx context.Context, p Principal, key, teacherID string, in TeacherHomepageComplaint) (TaskView, error) {
	if p.Subject == "" {
		return TaskView{}, ErrUnauthenticated
	}
	if in.Category == "" || !validCategory(in.Category) {
		return TaskView{}, withReason(ErrInput, "invalid_category")
	}
	if !keyOK(key) || !validTeacherHomepageID(teacherID) || !validReason(in.Reason) || in.Evidence == nil || len(in.Evidence) > 5 {
		return TaskView{}, withReason(ErrInput, "invalid_parameter")
	}
	for _, evidence := range in.Evidence {
		if strings.TrimSpace(evidence) == "" || !textOK(evidence, 2000) {
			return TaskView{}, withReason(ErrInput, "invalid_parameter")
		}
	}
	submission := Submission{ObjectID: teacherHomepageObjectPrefix + teacherID, Kind: "report", Category: in.Category, Reason: in.Reason, Evidence: in.Evidence}
	return s.saveReportUsing(ctx, p, key, submission, nil, func(call context.Context) (Object, error) {
		// The content port uses the current hosted school and checks the
		// directory ID. Filing a complaint requires an authenticated account.
		return s.inspectTeacherHomepage(call, p, teacherID)
	})
}

func (s *Service) GetTeacherHomepageComplaintTarget(ctx context.Context, p Principal, teacherID string) (TeacherHomepageComplaintTarget, error) {
	if p.Subject == "" {
		return TeacherHomepageComplaintTarget{}, ErrUnauthenticated
	}
	if !validTeacherHomepageID(teacherID) {
		return TeacherHomepageComplaintTarget{}, ErrInput
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	object, err := s.inspectTeacherHomepage(call, p, teacherID)
	if err != nil {
		return TeacherHomepageComplaintTarget{}, err
	}
	if err := s.auth(call, p, "manage", object.SchoolID); err != nil {
		return TeacherHomepageComplaintTarget{}, err
	}
	return TeacherHomepageComplaintTarget{ObjectID: object.ID, SchoolID: object.SchoolID, Revision: object.Revision, Visible: object.Visible}, nil
}

func (s *Service) inspectTeacherHomepage(ctx context.Context, p Principal, teacherID string) (Object, error) {
	if s == nil || s.TeacherHomepageContent == nil {
		return Object{}, ErrUnavailable
	}
	object, err := s.TeacherHomepageContent.InspectTeacherHomepage(ctx, p, teacherID)
	if err != nil {
		return Object{}, err
	}
	// Reserved IDs represent a current canonical record. A stale alias cannot
	// route old complaints or decisions to a different teacher after a merge.
	if object.ID != teacherID {
		return Object{}, ErrNotFound
	}
	if object.Kind != TeacherHomepageContentKind || !keyOK(object.SchoolID) || object.Revision < 1 || object.Revision > 1<<53-1 || object.AppendID != "" {
		return Object{}, ErrUnavailable
	}
	object.ID = teacherHomepageObjectPrefix + object.ID
	object.Owner = ""
	return object, nil
}

func (s *Service) inspectDecisionTarget(ctx context.Context, p Principal, task Task, d Decision) (Object, error) {
	object, err := s.inspect(ctx, p, task.Submission.ObjectID)
	if errors.Is(err, ErrNotFound) && task.ContentKind == TeacherHomepageContentKind && d.Action == "dismiss" {
		// A removed or merged teacher can leave a pending complaint. The school
		// administrator can close that receipt without mutating another record.
		return Object{ID: task.Submission.ObjectID, SchoolID: task.SchoolID, Kind: task.ContentKind, Revision: task.ObjectRevision}, nil
	}
	return object, err
}

func (s *Service) applyDecision(ctx context.Context, task Task, actor Principal) error {
	if task.ContentKind == TeacherHomepageContentKind {
		if s.TeacherHomepageContent == nil {
			return ErrUnavailable
		}
		if !teacherHomepageObjectID(task.Decision.ObjectID) || task.Decision.Action != "hide" {
			return ErrInput
		}
		decision := *task.Decision
		decision.ObjectID = strings.TrimPrefix(decision.ObjectID, teacherHomepageObjectPrefix)
		return s.TeacherHomepageContent.ApplyTeacherHomepageDecision(ctx, actor, decision)
	}
	if s.Content == nil {
		return ErrUnavailable
	}
	return s.Content.Apply(ctx, actor, *task.Decision)
}
