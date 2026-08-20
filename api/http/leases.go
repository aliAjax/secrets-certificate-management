package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	leasedomain "github.com/example/secrets-cert-platform/internal/lease/domain"
	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
)

func (s *Server) registerLeaseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/leases", s.createLease)
	mux.HandleFunc("GET /v1/leases/{id}", s.getLease)
	mux.HandleFunc("POST /v1/leases/{id}/renew", s.renewLease)
	mux.HandleFunc("POST /v1/leases/{id}/revoke", s.revokeLease)
}

func (s *Server) createLease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Namespace string            `json:"namespace"`
		Path      string            `json:"path"`
		TTL       string            `json:"ttl"`
		Renewable bool              `json:"renewable"`
		Metadata  map[string]string `json:"metadata"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	path := cleanWildcardPath(req.Path)
	ttl, _ := time.ParseDuration(req.TTL)
	if !s.authorize(w, r, req.Namespace, path, policydomain.CapabilityCreate) {
		return
	}
	lease, err := s.lease.Create(r.Context(), leasedomain.CreateInput{
		Namespace: req.Namespace,
		Path:      path,
		TTL:       ttl,
		Renewable: req.Renewable,
		Metadata:  req.Metadata,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.metrics.Leases.Inc()
	s.recordSuccess(r, req.Namespace, path, "lease.create", map[string]string{"lease_id": lease.ID.String()})
	writeJSON(w, http.StatusCreated, lease)
}

func (s *Server) getLease(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	lease, err := s.lease.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, lease.Namespace, lease.Path, policydomain.CapabilityRead) {
		return
	}
	s.recordSuccess(r, lease.Namespace, lease.Path, "lease.read", map[string]string{"lease_id": lease.ID.String()})
	writeJSON(w, http.StatusOK, lease)
}

func (s *Server) renewLease(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	lease, err := s.lease.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, lease.Namespace, lease.Path, policydomain.CapabilityUpdate) {
		return
	}
	var req struct {
		TTL string `json:"ttl"`
	}
	_ = decodeJSON(r, &req)
	ttl, _ := time.ParseDuration(req.TTL)
	renewed, err := s.lease.Renew(r.Context(), id, ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, renewed.Namespace, renewed.Path, "lease.renew", map[string]string{"lease_id": renewed.ID.String()})
	writeJSON(w, http.StatusOK, renewed)
}

func (s *Server) revokeLease(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	lease, err := s.lease.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, lease.Namespace, lease.Path, policydomain.CapabilityDelete) {
		return
	}
	revoked, err := s.lease.Revoke(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.metrics.Leases.Dec()
	s.recordSuccess(r, revoked.Namespace, revoked.Path, "lease.revoke", map[string]string{"lease_id": revoked.ID.String()})
	writeJSON(w, http.StatusOK, revoked)
}

var _ = strconv.Itoa
