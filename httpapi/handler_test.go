package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	m "github.com/StuHelper/stuhelper-moderation"
)

func TestAuthenticationFailureKeepsItsStatus(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{{m.ErrUnauthenticated, 401, "unauthenticated"}, {m.ErrUnavailable, 503, "unavailable"}} {
		h := Handler{
			Service:      &m.Service{},
			Authenticate: func(*http.Request) (m.Principal, error) { return m.Principal{}, test.err },
		}
		response := httptest.NewRecorder()
		h.Routes().ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/moderation/tasks", nil))
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != test.status || body["code"] != test.code {
			t.Fatalf("authentication response: %d %v", response.Code, body)
		}
	}
	h := Handler{Authenticate: func(*http.Request) (m.Principal, error) { return m.Principal{Subject: "user"}, nil }}
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/moderation/tasks", nil))
	if response.Code != 503 {
		t.Fatalf("expected 503 when Handler.Service is nil, got: %d %s", response.Code, response.Body.String())
	}
}

func TestHTTPBoundaryGuardsOriginBodySizeUnknownFieldsAndQueryValidation(t *testing.T) {
	// 1. Nil Service fails safely with 503 rather than panicking.
	nilSvcHandler := Handler{
		Authenticate: func(*http.Request) (m.Principal, error) { return m.Principal{Subject: "user"}, nil },
	}.Routes()
	rec := httptest.NewRecorder()
	nilSvcHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/moderation/tasks", nil))
	if rec.Code != 503 {
		t.Fatalf("expected 503 on nil Service, got %d", rec.Code)
	}

	// 2. Empty subject returns 401 unauthenticated.
	anonHandler := Handler{
		Service:      &m.Service{},
		Authenticate: func(*http.Request) (m.Principal, error) { return m.Principal{}, nil },
	}.Routes()
	rec = httptest.NewRecorder()
	anonHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/moderation/tasks", nil))
	if rec.Code != 401 {
		t.Fatalf("expected 401 on empty subject, got %d", rec.Code)
	}

	routes := Handler{
		Service:      &m.Service{},
		Authenticate: func(*http.Request) (m.Principal, error) { return m.Principal{Subject: "user"}, nil },
	}.Routes()

	// 3. Cross-origin Origin on mutating request returns 403 and security headers.
	req := httptest.NewRequest("POST", "http://moderation.local/api/v1/moderation/tasks", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://attacker.example")
	rec = httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != 403 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected 403 cross-origin rejection with security headers, got %d %+v", rec.Code, rec.Header())
	}

	// 4. Unknown JSON field, trailing JSON object, and >128 KiB body all return 400.
	for name, payload := range map[string][]byte{
		"unknown-field": []byte(`{"object_id":"x","kind":"report","reason":"r","evidence":[],"extra":1}`),
		"trailing-json": []byte(`{"object_id":"x","kind":"report","reason":"r","evidence":[]}{}`),
		"oversized":     bytes.Repeat([]byte("a"), (128<<10)+64),
	} {
		req := httptest.NewRequest("POST", "http://moderation.local/api/v1/moderation/tasks", bytes.NewReader(payload))
		req.Header.Set("Origin", "http://moderation.local")
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("%s: expected 400, got %d (%s)", name, rec.Code, rec.Body.String())
		}
	}

	// 5. Invalid query parameters on list return 400.
	for _, query := range []string{"?limit=notanint", "?from=bad-timestamp", "?until=bad-timestamp"} {
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/moderation/tasks"+query, nil))
		if rec.Code != 400 {
			t.Fatalf("query %s: expected 400, got %d", query, rec.Code)
		}
	}
}
