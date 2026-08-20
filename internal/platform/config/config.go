package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	TLS      TLSConfig      `yaml:"tls"`
	Crypto   CryptoConfig   `yaml:"crypto"`
	Auth     AuthConfig     `yaml:"auth"`
	Limits   LimitsConfig   `yaml:"limits"`
	Defaults DefaultsConfig `yaml:"defaults"`
}

type ServerConfig struct {
	HTTPAddr        string        `yaml:"http_addr"`
	GRPCAddr        string        `yaml:"grpc_addr"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
}

type DatabaseConfig struct {
	DSN            string `yaml:"dsn"`
	MigrationsDir  string `yaml:"migrations_dir"`
	MaxConnections int32  `yaml:"max_connections"`
}

type TLSConfig struct {
	Enabled           bool   `yaml:"enabled"`
	CertFile          string `yaml:"cert_file"`
	KeyFile           string `yaml:"key_file"`
	ClientCAFile      string `yaml:"client_ca_file"`
	RequireClientCert bool   `yaml:"require_client_cert"`
	MinVersion        string `yaml:"min_version"`
}

type CryptoConfig struct {
	MasterKey     string `yaml:"master_key"`
	AuditKey      string `yaml:"audit_key"`
	EncryptionAAD string `yaml:"encryption_aad"`
}

type AuthConfig struct {
	AdminToken     string `yaml:"admin_token"`
	IdentityHeader string `yaml:"identity_header"`
	TokenHeader    string `yaml:"token_header"`
}

type LimitsConfig struct {
	MaxBodyBytes  int64 `yaml:"max_body_bytes"`
	RatePerSecond int   `yaml:"rate_per_second"`
	RateBurst     int   `yaml:"rate_burst"`
}

type DefaultsConfig struct {
	LeaseDefaultTTL    time.Duration `yaml:"lease_default_ttl"`
	LeaseMaxTTL        time.Duration `yaml:"lease_max_ttl"`
	VersionDeletionTTL time.Duration `yaml:"version_deletion_ttl"`
}

func Load(path string) (Config, error) {
	cfg := Config{
		Server: ServerConfig{
			HTTPAddr:        ":8080",
			GRPCAddr:        ":9090",
			ShutdownTimeout: 10 * time.Second,
			RequestTimeout:  15 * time.Second,
		},
		Database: DatabaseConfig{
			DSN:            "postgres://secrets:secrets@localhost:55432/secrets?sslmode=disable",
			MigrationsDir:  "migrations",
			MaxConnections: 20,
		},
		Crypto: CryptoConfig{
			MasterKey:     "development-master-key-change-me",
			AuditKey:      "development-audit-key-change-me",
			EncryptionAAD: "secrets-cert-platform",
		},
		Auth: AuthConfig{
			AdminToken:     "dev-admin-token",
			IdentityHeader: "X-Auth-Identity",
			TokenHeader:    "X-Auth-Token",
		},
		Limits: LimitsConfig{
			MaxBodyBytes:  1 << 20,
			RatePerSecond: 100,
			RateBurst:     200,
		},
		Defaults: DefaultsConfig{
			LeaseDefaultTTL:    time.Hour,
			LeaseMaxTTL:        24 * time.Hour,
			VersionDeletionTTL: 72 * time.Hour,
		},
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnv(&cfg)
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	setString := func(target *string, key string) {
		if v := os.Getenv(key); v != "" {
			*target = v
		}
	}
	setBool := func(target *bool, key string) {
		if v := os.Getenv(key); v != "" {
			*target = strings.EqualFold(v, "true") || v == "1"
		}
	}
	setInt := func(target *int, key string) {
		if v := os.Getenv(key); v != "" {
			fmt.Sscanf(v, "%d", target)
		}
	}
	setInt32 := func(target *int32, key string) {
		if v := os.Getenv(key); v != "" {
			var n int
			fmt.Sscanf(v, "%d", &n)
			*target = int32(n)
		}
	}
	setDuration := func(target *time.Duration, key string) {
		if v := os.Getenv(key); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				*target = d
			}
		}
	}

	setString(&cfg.Server.HTTPAddr, "SCP_HTTP_ADDR")
	setString(&cfg.Server.GRPCAddr, "SCP_GRPC_ADDR")
	setDuration(&cfg.Server.ShutdownTimeout, "SCP_SHUTDOWN_TIMEOUT")
	setDuration(&cfg.Server.RequestTimeout, "SCP_REQUEST_TIMEOUT")
	setString(&cfg.Database.DSN, "SCP_DATABASE_DSN")
	setString(&cfg.Database.MigrationsDir, "SCP_MIGRATIONS_DIR")
	setInt32(&cfg.Database.MaxConnections, "SCP_DATABASE_MAX_CONNECTIONS")
	setBool(&cfg.TLS.Enabled, "SCP_TLS_ENABLED")
	setString(&cfg.TLS.CertFile, "SCP_TLS_CERT_FILE")
	setString(&cfg.TLS.KeyFile, "SCP_TLS_KEY_FILE")
	setString(&cfg.TLS.ClientCAFile, "SCP_TLS_CLIENT_CA_FILE")
	setBool(&cfg.TLS.RequireClientCert, "SCP_TLS_REQUIRE_CLIENT_CERT")
	setString(&cfg.TLS.MinVersion, "SCP_TLS_MIN_VERSION")
	setString(&cfg.Crypto.MasterKey, "SCP_CRYPTO_MASTER_KEY")
	setString(&cfg.Crypto.AuditKey, "SCP_CRYPTO_AUDIT_KEY")
	setString(&cfg.Crypto.EncryptionAAD, "SCP_CRYPTO_ENCRYPTION_AAD")
	setString(&cfg.Auth.AdminToken, "SCP_AUTH_ADMIN_TOKEN")
	setString(&cfg.Auth.IdentityHeader, "SCP_AUTH_IDENTITY_HEADER")
	setString(&cfg.Auth.TokenHeader, "SCP_AUTH_TOKEN_HEADER")
	setInt64(&cfg.Limits.MaxBodyBytes, "SCP_MAX_BODY_BYTES")
	setInt(&cfg.Limits.RatePerSecond, "SCP_RATE_PER_SECOND")
	setInt(&cfg.Limits.RateBurst, "SCP_RATE_BURST")
	setDuration(&cfg.Defaults.LeaseDefaultTTL, "SCP_LEASE_DEFAULT_TTL")
	setDuration(&cfg.Defaults.LeaseMaxTTL, "SCP_LEASE_MAX_TTL")
	setDuration(&cfg.Defaults.VersionDeletionTTL, "SCP_VERSION_DELETION_TTL")
}

func setInt64(target *int64, key string) {
	if v := os.Getenv(key); v != "" {
		var n int64
		fmt.Sscanf(v, "%d", &n)
		*target = n
	}
}

func (c Config) validate() error {
	if c.Server.HTTPAddr == "" {
		return fmt.Errorf("server.http_addr is required")
	}
	if c.Server.GRPCAddr == "" {
		return fmt.Errorf("server.grpc_addr is required")
	}
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	if len(c.Crypto.MasterKey) < 16 {
		return fmt.Errorf("crypto.master_key must be at least 16 characters")
	}
	if len(c.Crypto.AuditKey) < 16 {
		return fmt.Errorf("crypto.audit_key must be at least 16 characters")
	}
	return nil
}
