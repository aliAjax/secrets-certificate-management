#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

export SCP_HTTP_ADDR="${SCP_HTTP_ADDR:-:8080}"
export SCP_GRPC_ADDR="${SCP_GRPC_ADDR:-:9090}"
export SCP_DATABASE_DSN="${SCP_DATABASE_DSN:-postgres://secrets:secrets@localhost:55432/secrets?sslmode=disable}"
export SCP_CRYPTO_MASTER_KEY="${SCP_CRYPTO_MASTER_KEY:-development-master-key-change-me}"
export SCP_CRYPTO_AUDIT_KEY="${SCP_CRYPTO_AUDIT_KEY:-development-audit-key-change-me}"
export SCP_AUTH_ADMIN_TOKEN="${SCP_AUTH_ADMIN_TOKEN:-dev-admin-token}"

exec go run ./cmd/server
