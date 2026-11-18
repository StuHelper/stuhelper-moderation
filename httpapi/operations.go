package httpapi

import (
	m "github.com/StuHelper/stuhelper-moderation"
	"net/http"
	"strings"
)

func validOptionalHeaderKey(v string) bool {
	if len(v) > 128 || strings.TrimSpace(v) == "" {
		return false
	}
	for _, c := range v {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func (h Handler) batchRoutes(mux *http.ServeMux) {
	for _, operation := range []string{"batch-preview", "batch"} {
		mux.HandleFunc("POST /api/v1/moderation/tasks/"+operation, func(w http.ResponseWriter, r *http.Request) {
			p, ok := h.principal(w, r)
			if !ok {
				return
			}
			var in m.BatchRequest
			if e := decode(w, r, &in); e != nil {
				respond(w, nil, e)
				return
			}
			if operation == "batch-preview" {
				if key := r.Header.Get("Idempotency-Key"); key != "" && !validOptionalHeaderKey(key) {
					respond(w, nil, m.ErrInput)
					return
				}
				v, e := h.Service.PreviewBatch(r.Context(), p, in)
				respond(w, v, e)
			} else {
				v, e := h.Service.DecideBatch(r.Context(), p, r.Header.Get("Idempotency-Key"), in)
				respond(w, v, e)
			}
		})
	}
}
