package httpapi

import (
	"net/http"
	"strconv"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
)

func (s *Server) registerAuditRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/audit", s.listAudit)
	mux.HandleFunc("GET /v1/audit/verify", s.verifyAudit)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if !s.authorize(w, r, namespace, "/", policydomain.CapabilityList) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.audit.List(r.Context(), auditdomain.ListFilter{
		Namespace: namespace,
		Path:      r.URL.Query().Get("path"),
		Actor:     r.URL.Query().Get("actor"),
		Action:    r.URL.Query().Get("action"),
		Limit:     limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordSuccess(r, namespace, "/", "audit.list", map[string]string{"count": itoa(len(events))})
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/", policydomain.CapabilityRead) {
		return
	}
	ok, count, err := s.audit.Verify(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordSuccess(r, "*", "/", "audit.verify", map[string]string{"events": itoa(count)})
	writeJSON(w, http.StatusOK, map[string]interface{}{"valid": ok, "events": count})
}
