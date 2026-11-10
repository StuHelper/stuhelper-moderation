package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	m "github.com/StuHelper/stuhelper-moderation"
)

func TestAuthenticationFailureKeepsItsStatus(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{{m.ErrUnauthenticated, 401, "unauthenticated"}, {m.ErrUnavailable, 503, "unavailable"}} {
		h := Handler{Authenticate: func(*http.Request) (m.Principal, error) { return m.Principal{}, test.err }}
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
}
