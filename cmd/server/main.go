package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	grpcserver "github.com/example/secrets-cert-platform/api/grpc"
	httpapi "github.com/example/secrets-cert-platform/api/http"
	auditapplication "github.com/example/secrets-cert-platform/internal/audit/application"
	auditpostgres "github.com/example/secrets-cert-platform/internal/audit/infrastructure/postgres"
	backendadapter "github.com/example/secrets-cert-platform/internal/backend/adapter"
	cryptoapplication "github.com/example/secrets-cert-platform/internal/crypto/application"
	leaseapplication "github.com/example/secrets-cert-platform/internal/lease/application"
	leasepostgres "github.com/example/secrets-cert-platform/internal/lease/infrastructure/postgres"
	pkiapplication "github.com/example/secrets-cert-platform/internal/pki/application"
	pkipostgres "github.com/example/secrets-cert-platform/internal/pki/infrastructure/postgres"
	"github.com/example/secrets-cert-platform/internal/platform/config"
	"github.com/example/secrets-cert-platform/internal/platform/database"
	"github.com/example/secrets-cert-platform/internal/platform/logging"
	"github.com/example/secrets-cert-platform/internal/platform/metrics"
	"github.com/example/secrets-cert-platform/internal/platform/migrate"
	policyapplication "github.com/example/secrets-cert-platform/internal/policy/application"
	policypostgres "github.com/example/secrets-cert-platform/internal/policy/infrastructure/postgres"
	secretapplication "github.com/example/secrets-cert-platform/internal/secret/application"
	secretpostgres "github.com/example/secrets-cert-platform/internal/secret/infrastructure/postgres"
)

func main() {
	configPath := flag.String("config", envOr("SCP_CONFIG", "configs/config.yaml"), "path to YAML config")
	logLevel := flag.String("log-level", envOr("SCP_LOG_LEVEL", "info"), "log level")
	flag.Parse()

	logger := logging.New(*logLevel)
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config failed", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, cfg.Database.DSN, cfg.Database.MaxConnections)
	if err != nil {
		logger.Error("open database failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := migrate.Run(ctx, pool, cfg.Database.MigrationsDir); err != nil {
		logger.Error("run migrations failed", "error", err)
		os.Exit(1)
	}

	provider := backendadapter.NewSoftwareProvider(cfg.Crypto.MasterKey, cfg.Crypto.AuditKey)
	cryptoService := cryptoapplication.NewService(provider, cfg.Crypto.EncryptionAAD)

	secretRepo := secretpostgres.NewRepository(pool)
	leaseRepo := leasepostgres.NewRepository(pool)
	policyRepo := policypostgres.NewRepository(pool)
	auditRepo := auditpostgres.NewRepository(pool)
	pkiRepo := pkipostgres.NewRepository(pool)

	secretService := secretapplication.NewService(secretRepo, cryptoService, cfg.Defaults.VersionDeletionTTL)
	leaseService := leaseapplication.NewService(leaseRepo, secretRepo, cfg.Defaults.LeaseDefaultTTL, cfg.Defaults.LeaseMaxTTL)
	policyService := policyapplication.NewService(policyRepo, "admin")
	auditService := auditapplication.NewService(auditRepo, cryptoService)
	pkiService := pkiapplication.NewService(pkiRepo, cryptoService, 24*time.Hour)

	metricsRegistry := metrics.New()
	httpServer := httpapi.NewServer(cfg, logger, metricsRegistry, secretService, leaseService, policyService, auditService, pkiService, cryptoService)
	grpcServer := grpcserver.NewServer(cfg, logger, secretService, leaseService, policyService, auditService, pkiService, cryptoService)

	expiryCtx, cancelExpiry := context.WithCancel(context.Background())
	defer cancelExpiry()
	go leaseExpiryLoop(expiryCtx, leaseService, logger)

	httpListener, err := net.Listen("tcp", cfg.Server.HTTPAddr)
	if err != nil {
		logger.Error("listen http failed", "error", err)
		os.Exit(1)
	}
	grpcListener, err := net.Listen("tcp", cfg.Server.GRPCAddr)
	if err != nil {
		logger.Error("listen grpc failed", "error", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Handler:           httpServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.Server.RequestTimeout,
		WriteTimeout:      cfg.Server.RequestTimeout,
		IdleTimeout:       60 * time.Second,
	}

	tlsConfig, err := buildTLSConfig(cfg.TLS)
	if err != nil {
		logger.Error("build tls config failed", "error", err)
		os.Exit(1)
	}

	httpErr := make(chan error, 1)
	grpcErr := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", cfg.Server.HTTPAddr, "tls", cfg.TLS.Enabled)
		if tlsConfig != nil {
			httpErr <- httpSrv.Serve(tls.NewListener(httpListener, tlsConfig))
		} else {
			httpErr <- httpSrv.Serve(httpListener)
		}
	}()

	grpcSrv := grpcServer.Build()
	go func() {
		logger.Info("grpc server listening", "addr", cfg.Server.GRPCAddr)
		if err := grpcSrv.Serve(grpcListener); err != nil && !errors.Is(err, net.ErrClosed) {
			grpcErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-httpErr:
		logger.Error("http server stopped", "error", err)
	case err := <-grpcErr:
		logger.Error("grpc server stopped", "error", err)
	}

	cancelExpiry()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancelShutdown()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown failed", "error", err)
	}
	grpcSrv.GracefulStop()
	logger.Info("servers stopped")
}

func leaseExpiryLoop(ctx context.Context, service *leaseapplication.Service, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			count, err := service.ExpireDue(ctx, now)
			if err != nil {
				logger.Error("expire due leases failed", "error", err)
				continue
			}
			if count > 0 {
				logger.Info("expired dynamic leases", "count", count)
			}
		}
	}
}

func buildTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("tls cert_file and key_file are required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls keypair: %w", err)
	}
	minVersion, err := parseTLSVersion(cfg.MinVersion)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
	}
	if cfg.RequireClientCert {
		pool := x509.NewCertPool()
		data, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client ca: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("failed to append client ca")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConfig, nil
}

func parseTLSVersion(value string) (uint16, error) {
	switch value {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported tls min_version %q", value)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
