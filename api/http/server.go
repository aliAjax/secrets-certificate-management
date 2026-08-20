package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	auditapplication "github.com/example/secrets-cert-platform/internal/audit/application"
	cryptoapplication "github.com/example/secrets-cert-platform/internal/crypto/application"
	leaseapplication "github.com/example/secrets-cert-platform/internal/lease/application"
	pkiapplication "github.com/example/secrets-cert-platform/internal/pki/application"
	"github.com/example/secrets-cert-platform/internal/platform/config"
	"github.com/example/secrets-cert-platform/internal/platform/metrics"
	policyapplication "github.com/example/secrets-cert-platform/internal/policy/application"
	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
	secretapplication "github.com/example/secrets-cert-platform/internal/secret/application"
)

type policyCapability = policydomain.Capability

type Server struct {
	config    config.Config
	logger    *slog.Logger
	metrics   *metrics.Metrics
	secret    *secretapplication.Service
	lease     *leaseapplication.Service
	policy    *policyapplication.Service
	audit     *auditapplication.Service
	pki       *pkiapplication.Service
	crypto    *cryptoapplication.Service
	startedAt time.Time
}

func NewServer(
	cfg config.Config,
	logger *slog.Logger,
	m *metrics.Metrics,
	secret *secretapplication.Service,
	lease *leaseapplication.Service,
	policy *policyapplication.Service,
	audit *auditapplication.Service,
	pki *pkiapplication.Service,
	crypto *cryptoapplication.Service,
) *Server {
	return &Server{
		config:    cfg,
		logger:    logger,
		metrics:   m,
		secret:    secret,
		lease:     lease,
		policy:    policy,
		audit:     audit,
		pki:       pki,
		crypto:    crypto,
		startedAt: time.Now().UTC(),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.Handle("GET /metrics", s.metrics.Handler())

	s.registerNamespaceRoutes(mux)
	s.registerSecretRoutes(mux)
	s.registerLeaseRoutes(mux)
	s.registerPolicyRoutes(mux)
	s.registerAuditRoutes(mux)
	s.registerPKIRoutes(mux)
	s.registerCryptoRoutes(mux)

	return s.withMiddleware(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":         "ready",
		"uptime_seconds": time.Since(s.startedAt).String(),
	})
}

func policyAuthorizationRequest(actor, namespace, path string, capability policyCapability, r *http.Request) policydomain.AuthorizationRequest {
	return policydomain.AuthorizationRequest{
		Identity:   actor,
		Namespace:  namespace,
		Path:       path,
		Capability: capability,
		Context: map[string]string{
			"ip":     clientIP(r),
			"method": r.Method,
		},
	}
}
