package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Authenticate func(*http.Request) (m.Principal, error)
type Handler struct {
	Service      *m.Service
	Authenticate Authenticate
}

func (h Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/moderation/tasks", h.list)
	mux.HandleFunc("POST /api/v1/moderation/tasks", h.submit)
	mux.HandleFunc("GET /api/v1/moderation/tasks/{id}", h.get)
	mux.HandleFunc("POST /api/v1/moderation/tasks/{id}/decisions", h.decide)
	mux.HandleFunc("POST /api/v1/moderation/tasks/{id}/retry", h.retry)
	mux.HandleFunc("PUT /api/v1/moderation/policies", h.policy)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" && r.Header.Get("Origin") != "" {
			u, e := url.Parse(r.Header.Get("Origin"))
			if e != nil || u.Host != r.Host {
				respond(w, nil, m.ErrForbidden)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
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
		}{{m.ErrInput, 400}, {m.ErrForbidden, 403}, {m.ErrNotFound, 404}, {m.ErrConflict, 409}} {
			if errors.Is(e, x.e) {
				status = x.s
				code = x.e.Error()
			}
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
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
	if h.Authenticate == nil {
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
	return p, true
}
func (h Handler) list(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	n := 20
	if q.Get("limit") != "" {
		var e error
		n, e = strconv.Atoi(q.Get("limit"))
		if e != nil {
			respond(w, nil, m.ErrInput)
			return
		}
	}
	admin := q.Get("admin") == "true"
	v, e := h.Service.List(r.Context(), p, q.Get("school_id"), q.Get("state"), q.Get("after"), n, admin)
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
