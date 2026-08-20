package httpapi

import (
	"net/http"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
)

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, namespace, path string, capability policyCapability) bool {
	allowed, err := s.policy.Authorize(r.Context(), policyAuthorizationRequest(actorFromContext(r.Context()), namespace, path, capability, r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}
	if !allowed {
		s.recordAudit(r, namespace, path, string(capability), "denied", map[string]string{"actor": actorFromContext(r.Context())})
		writeError(w, http.StatusForbidden, errForbidden)
		return false
	}
	return true
}

func (s *Server) recordAudit(r *http.Request, namespace, path, action, result string, metadata map[string]string) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Record(r.Context(), auditdomain.RecordInput{
		Actor:     actorFromContext(r.Context()),
		Namespace: namespace,
		Path:      path,
		Action:    action,
		Result:    result,
		Metadata:  metadata,
	})
}

func (s *Server) recordSuccess(r *http.Request, namespace, path, action string, metadata map[string]string) {
	s.recordAudit(r, namespace, path, action, "success", metadata)
}
