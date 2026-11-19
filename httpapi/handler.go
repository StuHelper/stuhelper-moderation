package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Authenticate func(*http.Request) (m.Principal, error)
type Handler struct {
	Service      *m.Service
	Feedback     *f.Service
	Authenticate Authenticate
}

func (h Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	h.batchRoutes(mux)
	if h.Feedback != nil {
		(FeedbackHandler{Service: h.Feedback, Authenticate: h.Authenticate}).registerRoutes(mux)
	}
	mux.HandleFunc("GET /api/v1/moderation/tasks", h.list)
	mux.HandleFunc("GET /api/v1/moderation/tasks/page", h.listPage)
	mux.HandleFunc("GET /api/v1/moderation/tasks/summary", h.summary)
	mux.HandleFunc("POST /api/v1/moderation/tasks", h.submit)
	mux.HandleFunc("GET /api/v1/moderation/tasks/{id}", h.get)
	mux.HandleFunc("POST /api/v1/moderation/tasks/{id}/decisions", h.decide)
	mux.HandleFunc("POST /api/v1/moderation/tasks/{id}/retry", h.retry)
	mux.HandleFunc("PUT /api/v1/moderation/policies", h.policy)
	mux.HandleFunc("GET /api/v1/moderation/health", h.health)
	mux.HandleFunc("POST /api/v1/moderation/policies/preview", h.previewPolicy)
	mux.HandleFunc("GET /api/v1/moderation/policies", func(w http.ResponseWriter, r *http.Request) {
		p, ok := h.principal(w, r)
		if !ok {
			return
		}
		v, e := h.Service.GetPolicy(r.Context(), p, r.URL.Query().Get("school_id"), r.URL.Query().Get("kind"))
		respond(w, v, e)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" && r.Header.Get("Origin") != "" {
			u, e := url.Parse(r.Header.Get("Origin"))
			if e != nil || u.Host != r.Host {
				respond(w, nil, m.ReasonError{Base: m.ErrForbidden, Reason: "cross_origin_forbidden"})
				return
			}
		}
		timeout := 15 * time.Second
		if strings.HasPrefix(r.URL.Path, "/api/v1/moderation/feedback") {
			timeout = 40 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func respond(w http.ResponseWriter, v any, e error) {
	w.Header().Set("Content-Type", "application/json")
	if e != nil {
		status := 503
		code := "unavailable"
		for _, x := range []struct {
			e error
			s int
		}{{m.ErrRateLimited, 429}, {m.ErrUnauthenticated, 401}, {m.ErrInput, 400}, {m.ErrForbidden, 403}, {m.ErrNotFound, 404}, {m.ErrConflict, 409}} {
			if errors.Is(e, x.e) {
				status = x.s
				code = x.e.Error()
			}
		}
		var re m.ReasonError
		hasReason := errors.As(e, &re)
		if status == 429 {
			retryAfter := 60
			if hasReason && re.RetryAfter >= 1 {
				retryAfter = re.RetryAfter
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		}
		w.WriteHeader(status)
		body := map[string]string{"code": code}
		if hasReason && re.Reason != "" {
			body["reason"] = re.Reason
		}
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return m.ErrInput
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return m.ErrInput
	}
	return nil
}
func (h Handler) principal(w http.ResponseWriter, r *http.Request) (m.Principal, bool) {
	if h.Authenticate == nil || h.Service == nil {
		respond(w, nil, m.ErrUnavailable)
		return m.Principal{}, false
	}
	p, e := h.Authenticate(r)
	if e != nil {
		respond(w, nil, e)
		return p, false
	}
	if p.Subject == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "unauthenticated"})
		return p, false
	}
	if h.Service == nil {
		respond(w, nil, m.ErrUnavailable)
		return p, false
	}
	return p, true
}
func parseTaskFilter(r *http.Request) (m.TaskFilter, error) {
	q := r.URL.Query()
	n := 20
	if q.Get("limit") != "" {
		var e error
		n, e = strconv.Atoi(q.Get("limit"))
		if e != nil {
			return m.TaskFilter{}, m.ErrInput
		}
	}
	rawAdmin := q.Get("admin")
	if rawAdmin != "" && rawAdmin != "true" && rawAdmin != "false" {
		return m.TaskFilter{}, m.ErrInput
	}
	filter := m.TaskFilter{
		School:      q.Get("school_id"),
		State:       q.Get("state"),
		After:       q.Get("after"),
		Order:       q.Get("order"),
		Limit:       n,
		Admin:       rawAdmin == "true",
		Kind:        q.Get("kind"),
		ContentKind: q.Get("content_kind"),
		ObjectID:    q.Get("object_id"),
	}
	for key, dest := range map[string]**time.Time{"from": &filter.From, "until": &filter.Until} {
		if q.Get(key) != "" {
			v, e := time.Parse(time.RFC3339, q.Get(key))
			if e != nil {
				return m.TaskFilter{}, m.ErrInput
			}
			*dest = &v
		}
	}
	return filter, nil
}
func (h Handler) list(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	filter, err := parseTaskFilter(r)
	if err != nil {
		respond(w, nil, err)
		return
	}
	page, e := h.Service.FilteredPage(r.Context(), p, filter)
	if e == nil && page.NextCursor != "" {
		w.Header().Set("X-Next-Cursor", page.NextCursor)
	}
	respond(w, page.Items, e)
}
func (h Handler) listPage(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	filter, err := parseTaskFilter(r)
	if err != nil {
		respond(w, nil, err)
		return
	}
	page, e := h.Service.FilteredPage(r.Context(), p, filter)
	respond(w, page, e)
}
func (h Handler) summary(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	v, e := h.Service.QueueSummary(r.Context(), p, r.URL.Query().Get("school_id"))
	respond(w, v, e)
}
func (h Handler) get(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	v, e := h.Service.Get(r.Context(), p, r.PathValue("id"))
	respond(w, v, e)
}
func (h Handler) submit(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var in m.Submission
	if e := decode(w, r, &in); e != nil {
		respond(w, nil, e)
		return
	}
	if in.Evidence == nil {
		respond(w, nil, m.ErrInput)
		return
	}
	v, e := h.Service.Submit(r.Context(), p, r.Header.Get("Idempotency-Key"), in)
	respond(w, v, e)
}
func (h Handler) decide(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var in m.Decide
	if e := decode(w, r, &in); e != nil {
		respond(w, nil, e)
		return
	}
	v, e := h.Service.Decide(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), in)
	respond(w, v, e)
}
func (h Handler) retry(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var in struct {
		Revision int64 `json:"revision"`
	}
	if e := decode(w, r, &in); e != nil {
		respond(w, nil, e)
		return
	}
	v, e := h.Service.Retry(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), in.Revision)
	respond(w, v, e)
}
func (h Handler) policy(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var in m.Policy
	if e := decode(w, r, &in); e != nil {
		respond(w, nil, e)
		return
	}
	e := h.Service.SetPolicy(r.Context(), p, r.Header.Get("Idempotency-Key"), in)
	respond(w, map[string]bool{"ok": e == nil}, e)
}
func (h Handler) health(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	v, e := h.Service.Health(r.Context(), p)
	respond(w, v, e)
}
func (h Handler) previewPolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	var in m.PolicyPreviewInput
	if e := decode(w, r, &in); e != nil {
		respond(w, nil, e)
		return
	}
	v, e := h.Service.PreviewPolicy(r.Context(), p, in)
	respond(w, v, e)
}
