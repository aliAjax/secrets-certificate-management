package httpapi

import (
	"net/http"

	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

func (s *Server) registerNamespaceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/namespaces", s.createNamespace)
	mux.HandleFunc("GET /v1/namespaces", s.listNamespaces)
}

func (s *Server) createNamespace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, req.Name, "/", policydomain.CapabilityCreate) {
		return
	}
	ns, err := s.secret.CreateNamespace(r.Context(), req.Name, req.Description)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, ns.Name, "/", "namespace.create", map[string]string{"namespace": ns.Name})
	writeJSON(w, http.StatusCreated, ns)
}

func (s *Server) listNamespaces(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/", policydomain.CapabilityList) {
		return
	}
	namespaces, err := s.secret.ListNamespaces(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordSuccess(r, "*", "/", "namespace.list", map[string]string{"count": itoa(len(namespaces))})
	writeJSON(w, http.StatusOK, namespaces)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

var _ = secretdomain.SecretTypeKV
