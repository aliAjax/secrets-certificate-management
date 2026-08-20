package httpapi

import (
	"net/http"
	"strings"

	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
)

func requestConditions(values map[string]string) map[string]string {
	return policydomain.CloneConditions(values)
}

func (s *Server) registerPolicyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/policies", s.createPolicy)
	mux.HandleFunc("GET /v1/policies", s.listPolicies)
	mux.HandleFunc("GET /v1/policies/{name}", s.getPolicy)
	mux.HandleFunc("DELETE /v1/policies/{name}", s.deletePolicy)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string            `json:"name"`
		Namespace    string            `json:"namespace"`
		PathPrefix   string            `json:"path_prefix"`
		Identity     string            `json:"identity"`
		Capabilities []string          `json:"capabilities"`
		Conditions   map[string]string `json:"conditions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, req.Namespace, "/", policydomain.CapabilityCreate) {
		return
	}
	caps := make([]policydomain.Capability, 0, len(req.Capabilities))
	for _, c := range req.Capabilities {
		cap, err := policydomain.ValidateCapability(c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		caps = append(caps, cap)
	}
	policy, err := s.policy.Create(r.Context(), policydomain.CreateInput{
		Name:         req.Name,
		Namespace:    req.Namespace,
		PathPrefix:   cleanWildcardPath(req.PathPrefix),
		Identity:     req.Identity,
		Capabilities: caps,
		Conditions:   requestConditions(req.Conditions),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, req.Namespace, "/", "policy.create", map[string]string{"policy": policy.Name})
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "*"
	}
	if !s.authorize(w, r, namespace, "/", policydomain.CapabilityList) {
		return
	}
	policies, err := s.policy.List(r.Context(), namespace)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, "/", "policy.list", map[string]string{"count": itoa(len(policies))})
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	policy, err := s.policy.Get(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, policy.Namespace, "/", policydomain.CapabilityRead) {
		return
	}
	s.recordSuccess(r, policy.Namespace, "/", "policy.read", map[string]string{"policy": policy.Name})
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	policy, err := s.policy.Get(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, policy.Namespace, "/", policydomain.CapabilityDelete) {
		return
	}
	if err := s.policy.Delete(r.Context(), name); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, policy.Namespace, "/", "policy.delete", map[string]string{"policy": policy.Name})
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

var _ = strings.TrimSpace
