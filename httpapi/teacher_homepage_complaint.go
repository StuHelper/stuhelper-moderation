package httpapi

import (
	"net/http"

	m "github.com/StuHelper/stuhelper-moderation"
)

func includeTeacherHomepage(r *http.Request) (bool, error) {
	switch r.URL.Query().Get("include_teacher_homepage") {
	case "true":
		return true, nil
	case "false", "":
		return false, nil
	default:
		return false, m.ErrInput
	}
}

func (h Handler) submitTeacherHomepageComplaint(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var in m.TeacherHomepageComplaint
	if err := decode(w, r, &in); err != nil {
		respond(w, nil, err)
		return
	}
	v, err := h.Service.SubmitTeacherHomepageComplaint(r.Context(), p, r.Header.Get("Idempotency-Key"), r.PathValue("teacher_id"), in)
	respond(w, v, err)
}

func (h Handler) teacherHomepageComplaintTarget(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	v, err := h.Service.GetTeacherHomepageComplaintTarget(r.Context(), p, r.PathValue("teacher_id"))
	respond(w, v, err)
}
