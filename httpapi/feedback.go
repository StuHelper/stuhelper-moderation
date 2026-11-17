package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	m "github.com/StuHelper/stuhelper-moderation"
	f "github.com/StuHelper/stuhelper-moderation/feedback"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type FeedbackHandler struct {
	Service      *f.Service
	Authenticate Authenticate
}

func (h FeedbackHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	h.registerRoutes(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" && r.Header.Get("Origin") != "" {
			u, e := url.Parse(r.Header.Get("Origin"))
			if e != nil || u.Host != r.Host {
				respondFeedback(w, nil, f.ErrDenied)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h FeedbackHandler) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/moderation/feedback", h.list)
	mux.HandleFunc("GET /api/v1/moderation/feedback/{id}", h.get)
	mux.HandleFunc("PATCH /api/v1/moderation/feedback/{id}", h.update)
	mux.HandleFunc("POST /api/v1/moderation/feedback/{id}/replies", h.reply)
	mux.HandleFunc("GET /api/v1/moderation/feedback/{id}/attachments/{attachment}", h.download)
}

func (h FeedbackHandler) actor(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.Authenticate == nil || h.Service == nil {
		respondFeedback(w, nil, f.ErrUnavailable)
		return "", false
	}
	p, err := h.Authenticate(r)
	if err != nil {
		respond(w, nil, err)
		return "", false
	}
	if p.Subject == "" {
		respond(w, nil, m.ErrUnauthenticated)
		return "", false
	}
	return p.Subject, true
}

func respondFeedback(w http.ResponseWriter, v any, e error) {
	if e != nil {
		status := 503
		code := "unavailable"
		switch {
		case errors.Is(e, m.ErrUnauthenticated):
			status = 401
			code = "unauthenticated"
		case errors.Is(e, f.ErrInvalid) || errors.Is(e, m.ErrInput):
			status = 400
			code = "invalid_request"
		case errors.Is(e, f.ErrDenied) || errors.Is(e, m.ErrForbidden):
			status = 403
			code = "forbidden"
		case errors.Is(e, f.ErrNotFound) || errors.Is(e, m.ErrNotFound):
			status = 404
			code = "not_found"
		case errors.Is(e, f.ErrConflict) || errors.Is(e, m.ErrConflict):
			status = 409
			code = "conflict"
		case errors.Is(e, f.ErrLimit) || errors.Is(e, m.ErrRateLimited):
			status = 429
			code = "capacity_exceeded"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func presentFeedbackOutcome(value any, now time.Time) any {
	normalizeReply := func(v f.Reply) f.Reply {
		if v.State == "sending" && !v.CreatedAt.Add(time.Minute).After(now) {
			v.State = "unknown"
		}
		return v
	}
	switch v := value.(type) {
	case f.Reply:
		return normalizeReply(v)
	case f.Message:
		v.Replies = append([]f.Reply{}, v.Replies...)
		for i := range v.Replies {
			v.Replies[i] = normalizeReply(v.Replies[i])
		}
		return v
	default:
		return value
	}
}

func (h FeedbackHandler) now() time.Time {
	if h.Service != nil && h.Service.Now != nil {
		return h.Service.Now().UTC()
	}
	return time.Now().UTC()
}

func (h FeedbackHandler) list(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 25
	if raw := q.Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			respondFeedback(w, nil, f.ErrInvalid)
			return
		}
	}
	filter := f.Filter{
		After: q.Get("after"),
		State: q.Get("state"),
		Limit: limit,
	}
	if q.Has("assignee") {
		v := q.Get("assignee")
		filter.Assignee = &v
	}
	if q.Has("suspicious") {
		raw := q.Get("suspicious")
		if raw != "true" && raw != "false" {
			respondFeedback(w, nil, f.ErrInvalid)
			return
		}
		b := raw == "true"
		filter.Suspicious = &b
	}
	out, err := h.Service.List(r.Context(), actor, filter)
	respondFeedback(w, out, err)
}

func (h FeedbackHandler) get(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	out, err := h.Service.Get(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		respondFeedback(w, nil, err)
		return
	}
	respondFeedback(w, presentFeedbackOutcome(out, h.now()), nil)
}

func (h FeedbackHandler) update(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	var u f.Update
	if err := decode(w, r, &u); err != nil {
		respondFeedback(w, nil, f.ErrInvalid)
		return
	}
	out, err := h.Service.Update(r.Context(), actor, r.PathValue("id"), r.Header.Get("Idempotency-Key"), u)
	if err != nil {
		respondFeedback(w, nil, err)
		return
	}
	respondFeedback(w, presentFeedbackOutcome(out, h.now()), nil)
}

func (h FeedbackHandler) reply(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	var in struct {
		Body string `json:"body"`
	}
	if err := decode(w, r, &in); err != nil {
		respondFeedback(w, nil, f.ErrInvalid)
		return
	}
	out, err := h.Service.Reply(r.Context(), actor, r.PathValue("id"), r.Header.Get("Idempotency-Key"), in.Body)
	if err != nil {
		respondFeedback(w, nil, err)
		return
	}
	respondFeedback(w, presentFeedbackOutcome(out, h.now()), nil)
}

type attachmentStreamWriter struct {
	w           http.ResponseWriter
	wroteHeader bool
}

func (s *attachmentStreamWriter) applySecurityHeaders() {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	s.w.Header().Set("Cache-Control", "no-store")
	s.w.Header().Set("Content-Type", "application/octet-stream")
	s.w.Header().Set("Content-Disposition", `attachment; filename="feedback-attachment"`)
	s.w.Header().Set("X-Content-Type-Options", "nosniff")
	s.w.Header().Set("Content-Security-Policy", "sandbox")
	s.w.WriteHeader(http.StatusOK)
}

func (s *attachmentStreamWriter) Write(p []byte) (int, error) {
	s.applySecurityHeaders()
	return s.w.Write(p)
}

func (h FeedbackHandler) download(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	stream := &attachmentStreamWriter{w: w}
	_, err := h.Service.DownloadAttachment(r.Context(), actor, r.PathValue("id"), r.PathValue("attachment"), stream)
	if err != nil {
		if !stream.wroteHeader {
			respondFeedback(w, nil, err)
		}
		return
	}
	stream.applySecurityHeaders()
}
