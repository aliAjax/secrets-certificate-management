package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

func (s *Server) registerSecretRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/namespaces/{namespace}/secrets", s.createSecret)
	mux.HandleFunc("GET /v1/namespaces/{namespace}/secrets", s.listSecrets)
	mux.HandleFunc("GET /v1/secrets/{namespace}/{path...}", s.getSecret)
	mux.HandleFunc("PUT /v1/secrets/{namespace}/{path...}", s.putSecret)
	mux.HandleFunc("GET /v1/versions/{namespace}/{path...}", s.listVersions)
	mux.HandleFunc("DELETE /v1/versions/{namespace}/delete/{path...}", s.softDeleteVersion)
	mux.HandleFunc("POST /v1/versions/{namespace}/restore/{path...}", s.restoreVersion)
	mux.HandleFunc("POST /v1/versions/{namespace}/destroy/{path...}", s.destroyVersion)
	mux.HandleFunc("POST /v1/versions/{namespace}/rollback/{path...}", s.rollbackVersion)
}

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	var req struct {
		Path  string `json:"path"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	path := cleanWildcardPath(req.Path)
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityCreate) {
		return
	}
	metadata, err := s.secret.PutSecret(r.Context(), secretdomain.PutSecretInput{
		Namespace: namespace,
		Path:      path,
		Type:      secretdomain.SecretType(req.Type),
		Value:     []byte(req.Value),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.create", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	writeJSON(w, http.StatusCreated, metadata)
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	if !s.authorize(w, r, namespace, "/", policydomain.CapabilityList) {
		return
	}
	secrets, err := s.secret.ListSecrets(r.Context(), namespace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordSuccess(r, namespace, "/", "secret.list", map[string]string{"count": itoa(len(secrets))})
	writeJSON(w, http.StatusOK, secrets)
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	namespace, path := s.secretRouteParams(r)
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityRead) {
		return
	}
	version := queryVersion(r)
	plaintext, metadata, err := s.secret.GetSecret(r.Context(), namespace, path, version)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.read", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"value":   string(plaintext),
		"version": metadata.Version,
		"state":   metadata.State,
	})
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	namespace, path := s.secretRouteParams(r)
	var req struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityUpdate) {
		return
	}
	metadata, err := s.secret.PutSecret(r.Context(), secretdomain.PutSecretInput{
		Namespace: namespace,
		Path:      path,
		Type:      secretdomain.SecretType(req.Type),
		Value:     []byte(req.Value),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.update", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	writeJSON(w, http.StatusOK, metadata)
}

func (s *Server) listVersions(w http.ResponseWriter, r *http.Request) {
	namespace, path := s.secretRouteParams(r)
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityRead) {
		return
	}
	versions, err := s.secret.ListVersions(r.Context(), namespace, path)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.versions.list", map[string]string{"count": itoa(len(versions))})
	writeJSON(w, http.StatusOK, versions)
}

func (s *Server) softDeleteVersion(w http.ResponseWriter, r *http.Request) {
	namespace, path := s.secretRouteParams(r)
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityDelete) {
		return
	}
	version := queryVersion(r)
	metadata, err := s.secret.SoftDeleteVersion(r.Context(), namespace, path, version)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.version.delete", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	writeJSON(w, http.StatusOK, metadata)
}

func (s *Server) restoreVersion(w http.ResponseWriter, r *http.Request) {
	namespace, path := s.secretRouteParams(r)
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityUpdate) {
		return
	}
	version := queryVersion(r)
	metadata, err := s.secret.RestoreVersion(r.Context(), namespace, path, version)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.version.restore", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	writeJSON(w, http.StatusOK, metadata)
}

func (s *Server) destroyVersion(w http.ResponseWriter, r *http.Request) {
	namespace, path := s.secretRouteParams(r)
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityDelete) {
		return
	}
	version := queryVersion(r)
	if err := s.secret.DestroyVersion(r.Context(), namespace, path, version); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.version.destroy", map[string]string{"version": strconv.FormatInt(version, 10)})
	writeJSON(w, http.StatusOK, map[string]bool{"destroyed": true})
}

func (s *Server) rollbackVersion(w http.ResponseWriter, r *http.Request) {
	namespace, path := s.secretRouteParams(r)
	if !s.authorize(w, r, namespace, path, policydomain.CapabilityUpdate) {
		return
	}
	version := queryVersion(r)
	metadata, err := s.secret.Rollback(r.Context(), namespace, path, version)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, path, "secret.version.rollback", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	writeJSON(w, http.StatusOK, metadata)
}

func (s *Server) secretRouteParams(r *http.Request) (string, string) {
	path := r.PathValue("path")
	return r.PathValue("namespace"), cleanWildcardPath(path)
}

func cleanWildcardPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "/" + strings.Trim(path, "/")
}

func queryVersion(r *http.Request) int64 {
	value := r.URL.Query().Get("version")
	if value == "" {
		return 0
	}
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}
