package httpapi

import (
	m "github.com/StuHelper/stuhelper-moderation"
	"net/http"
)

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
				v, e := h.Service.PreviewBatch(r.Context(), p, in)
				respond(w, v, e)
			} else {
				v, e := h.Service.DecideBatch(r.Context(), p, r.Header.Get("Idempotency-Key"), in)
				respond(w, v, e)
			}
		})
	}
}
