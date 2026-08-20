package httpapi

import (
	"net/http"
	"time"

	pkidomain "github.com/example/secrets-cert-platform/internal/pki/domain"
	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
)

func certificateEnvelope(cert *pkidomain.Certificate) map[string]interface{} {
	if cert == nil {
		return map[string]interface{}{"serial": "", "status": "unavailable"}
	}
	return map[string]interface{}{"serial": cert.SerialNumber, "status": cert.Status}
}

func (s *Server) registerPKIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/pki/cas/root", s.createRootCA)
	mux.HandleFunc("POST /v1/pki/cas/intermediate", s.createIntermediateCA)
	mux.HandleFunc("GET /v1/pki/cas", s.listCAs)
	mux.HandleFunc("GET /v1/pki/cas/{name}", s.getCA)
	mux.HandleFunc("GET /v1/pki/cas/{name}/crl", s.getCRL)
	mux.HandleFunc("GET /v1/pki/cas/{name}/ocsp/{serial}", s.getOCSP)
	mux.HandleFunc("POST /v1/pki/issue", s.issueCertificate)
	mux.HandleFunc("POST /v1/pki/renew", s.renewCertificate)
	mux.HandleFunc("POST /v1/pki/revoke", s.revokeCertificate)
	mux.HandleFunc("GET /v1/pki/certificates", s.listCertificates)
	mux.HandleFunc("GET /v1/pki/certificates/{serial}", s.getCertificate)
}

func (s *Server) createRootCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		Namespace  string   `json:"namespace"`
		CommonName string   `json:"common_name"`
		TTL        string   `json:"ttl"`
		MaxPathLen int      `json:"max_path_len"`
		DNSDomains []string `json:"dns_domains"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, req.Namespace, "/", policydomain.CapabilityCreate) {
		return
	}
	ttl, _ := time.ParseDuration(req.TTL)
	ca, err := s.pki.CreateRoot(r.Context(), pkidomain.CreateCAInput{
		Name:       req.Name,
		Namespace:  req.Namespace,
		CommonName: req.CommonName,
		TTL:        ttl,
		MaxPathLen: req.MaxPathLen,
		DNSDomains: req.DNSDomains,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, req.Namespace, "/", "pki.ca.root.create", map[string]string{"ca": ca.Name})
	writeJSON(w, http.StatusCreated, ca)
}

func (s *Server) createIntermediateCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		Namespace  string   `json:"namespace"`
		ParentName string   `json:"parent_name"`
		CommonName string   `json:"common_name"`
		TTL        string   `json:"ttl"`
		MaxPathLen int      `json:"max_path_len"`
		DNSDomains []string `json:"dns_domains"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, req.Namespace, "/", policydomain.CapabilityCreate) {
		return
	}
	ttl, _ := time.ParseDuration(req.TTL)
	ca, err := s.pki.CreateIntermediate(r.Context(), pkidomain.CreateCAInput{
		Name:       req.Name,
		Namespace:  req.Namespace,
		ParentName: req.ParentName,
		CommonName: req.CommonName,
		TTL:        ttl,
		MaxPathLen: req.MaxPathLen,
		DNSDomains: req.DNSDomains,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, req.Namespace, "/", "pki.ca.intermediate.create", map[string]string{"ca": ca.Name})
	writeJSON(w, http.StatusCreated, ca)
}

func (s *Server) listCAs(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "*"
	}
	if !s.authorize(w, r, namespace, "/", policydomain.CapabilityList) {
		return
	}
	cas, err := s.pki.ListCAs(r.Context(), namespace)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, "/", "pki.ca.list", map[string]string{"count": itoa(len(cas))})
	writeJSON(w, http.StatusOK, cas)
}

func (s *Server) getCA(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ca, err := s.pki.GetCA(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, ca.Namespace, "/", policydomain.CapabilityRead) {
		return
	}
	s.recordSuccess(r, ca.Namespace, "/", "pki.ca.read", map[string]string{"ca": ca.Name})
	writeJSON(w, http.StatusOK, ca)
}

func (s *Server) getCRL(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ca, err := s.pki.GetCA(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, ca.Namespace, "/", policydomain.CapabilityRead) {
		return
	}
	crl, err := s.pki.CRL(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, ca.Namespace, "/", "pki.crl.read", map[string]string{"ca": name})
	writeJSON(w, http.StatusOK, map[string]string{"crl": crl})
}

func (s *Server) getOCSP(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	serial := r.PathValue("serial")
	ca, err := s.pki.GetCA(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, ca.Namespace, "/", policydomain.CapabilityRead) {
		return
	}
	ocspResponse, err := s.pki.OCSP(r.Context(), name, serial)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, ca.Namespace, "/", "pki.ocsp.read", map[string]string{"ca": name, "serial": serial})
	writeJSON(w, http.StatusOK, map[string]string{"ocsp_response": ocspResponse})
}

func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CAName     string   `json:"ca_name"`
		CommonName string   `json:"common_name"`
		DNSNames   []string `json:"dns_names"`
		TTL        string   `json:"ttl"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ca, err := s.pki.GetCA(r.Context(), req.CAName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, ca.Namespace, "/", policydomain.CapabilityCreate) {
		return
	}
	ttl, _ := time.ParseDuration(req.TTL)
	cert, err := s.pki.Issue(r.Context(), pkidomain.IssueInput{
		CAName:     req.CAName,
		CommonName: req.CommonName,
		DNSNames:   req.DNSNames,
		TTL:        ttl,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, cert.Namespace, "/", "pki.certificate.issue", map[string]string{"serial": cert.SerialNumber})
	writeJSON(w, http.StatusCreated, cert)
}

func (s *Server) renewCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SerialNumber string `json:"serial_number"`
		TTL          string `json:"ttl"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cert, err := s.pki.GetCertificate(r.Context(), r.URL.Query().Get("namespace"), req.SerialNumber)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, cert.Namespace, "/", policydomain.CapabilityUpdate) {
		return
	}
	ttl, _ := time.ParseDuration(req.TTL)
	renewed, err := s.pki.Renew(r.Context(), pkidomain.RenewInput{SerialNumber: req.SerialNumber, TTL: ttl})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, renewed.Namespace, "/", "pki.certificate.renew", map[string]string{"serial": renewed.SerialNumber})
	writeJSON(w, http.StatusOK, renewed)
}

func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SerialNumber string `json:"serial_number"`
		Reason       string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cert, err := s.pki.GetCertificate(r.Context(), r.URL.Query().Get("namespace"), req.SerialNumber)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, cert.Namespace, "/", policydomain.CapabilityDelete) {
		return
	}
	revocation, err := s.pki.Revoke(r.Context(), pkidomain.RevokeInput{SerialNumber: req.SerialNumber, Reason: req.Reason})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, cert.Namespace, "/", "pki.certificate.revoke", map[string]string{"serial": req.SerialNumber, "reason": req.Reason})
	writeJSON(w, http.StatusOK, revocation)
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "*"
	}
	if !s.authorize(w, r, namespace, "/", policydomain.CapabilityList) {
		return
	}
	certs, err := s.pki.ListCertificates(r.Context(), namespace)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, namespace, "/", "pki.certificate.list", map[string]string{"count": itoa(len(certs))})
	writeJSON(w, http.StatusOK, certs)
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	namespace := r.URL.Query().Get("namespace")
	cert, err := s.pki.GetCertificate(r.Context(), namespace, serial)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !s.authorize(w, r, cert.Namespace, "/", policydomain.CapabilityRead) {
		return
	}
	s.recordSuccess(r, cert.Namespace, "/", "pki.certificate.read", map[string]string{"serial": serial})
	writeJSON(w, http.StatusOK, cert)
}
