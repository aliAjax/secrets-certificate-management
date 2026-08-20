# Secrets and Certificate Lifecycle Platform

This repository contains a pure Go service for centralized secret management, dynamic credential leases, path-based access policies, tamper-evident audit, PKI issuance, certificate revocation, CRL, and OCSP. It exposes REST, gRPC, and a CLI management client. It does not contain a web frontend.

## Architecture

```text
cmd/
  server/                 HTTP/gRPC server entrypoint
  cli/                    CLI management entrypoint
api/
  http/                   REST routes, auth, policy, audit, metrics middleware
  grpc/                   JSON-codec gRPC gateway with auth interceptor
internal/
  secret/                 namespaces, secret paths, encrypted multi-version values
  lease/                  dynamic secret leases, renewal, revocation, expiry
  policy/                 identity/path/capability policies and conditions
  audit/                  hash-chained tamper-evident events
  pki/                    root/intermediate CA, CSR-style issue, renew, revoke, CRL, OCSP
  crypto/                 encryption, signing, verification, key derivation
  backend/                crypto provider abstraction with software and stub HSM adapters
  platform/               config, logging, database, migrations, metrics
configs/                  YAML configuration and examples
migrations/               PostgreSQL schema migrations
deploy/                   Docker Compose and Dockerfile
scripts/                  development startup script
```

Each business domain follows a layered structure:

- `domain`: models, invariants, repository interfaces
- `application`: use cases and transaction orchestration
- `adapter`: interfaces to external capability providers
- `infrastructure`: PostgreSQL implementations and provider registries

Dependencies are injected through constructors. Every request carries `context.Context`. Errors are wrapped with `fmt.Errorf` and sensitive values are never written to audit events or API responses in plaintext.

## Quick Start

Requirements: Go 1.22 or newer, Docker with Compose.

```bash
make docker-up
make run
```

The server listens on:

- HTTP: `http://localhost:8080`
- gRPC: `localhost:9090`

Use the development admin token:

```bash
export TOKEN='dev-admin-token'
```

## Configuration

The service reads `configs/config.yaml` and overlays environment variables. Important environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCP_CONFIG` | `configs/config.yaml` | Config file path |
| `SCP_HTTP_ADDR` | `:8080` | HTTP bind address |
| `SCP_GRPC_ADDR` | `:9090` | gRPC bind address |
| `SCP_DATABASE_DSN` | local Compose DSN | PostgreSQL connection string |
| `SCP_CRYPTO_MASTER_KEY` | development key | Key used to derive encryption keys |
| `SCP_CRYPTO_AUDIT_KEY` | development key | Audit HMAC key |
| `SCP_AUTH_ADMIN_TOKEN` | `dev-admin-token` | Admin token |
| `SCP_LEASE_DEFAULT_TTL` | `1h` | Default dynamic lease TTL |
| `SCP_LEASE_MAX_TTL` | `24h` | Maximum dynamic lease TTL |

For production, change both crypto keys and the admin token. TLS and mutual TLS can be enabled in the `tls` section.

## REST API Examples

Authentication uses `X-Auth-Token` for admin or `X-Auth-Identity` for policy-controlled identities.

Create a namespace:

```bash
curl -H 'Content-Type: application/json' -H "X-Auth-Token: $TOKEN" \
  -X POST http://localhost:8080/v1/namespaces \
  -d '{"name":"tenant-a","description":"example tenant"}'
```

Create a secret:

```bash
curl -H 'Content-Type: application/json' -H "X-Auth-Token: $TOKEN" \
  -X POST http://localhost:8080/v1/namespaces/tenant-a/secrets \
  -d '{"path":"/db/password","type":"kv","value":"s3cr3t"}'
```

Read a secret:

```bash
curl -H "X-Auth-Token: $TOKEN" \
  'http://localhost:8080/v1/secrets/tenant-a/db/password'
```

Create a policy:

```bash
curl -H 'Content-Type: application/json' -H "X-Auth-Token: $TOKEN" \
  -X POST http://localhost:8080/v1/policies \
  -d '{"name":"alice-read-db","namespace":"tenant-a","path_prefix":"/db","identity":"alice","capabilities":["read","list"],"conditions":{}}'
```

Read as a policy-controlled identity:

```bash
curl -H 'X-Auth-Identity: alice' \
  'http://localhost:8080/v1/secrets/tenant-a/db/password'
```

Create a dynamic secret lease:

```bash
curl -H 'Content-Type: application/json' -H "X-Auth-Token: $TOKEN" \
  -X POST http://localhost:8080/v1/leases \
  -d '{"namespace":"tenant-a","path":"/db/dynamic","ttl":"2m","renewable":true}'
```

Create a root CA and issue a certificate:

```bash
curl -H 'Content-Type: application/json' -H "X-Auth-Token: $TOKEN" \
  -X POST http://localhost:8080/v1/pki/cas/root \
  -d '{"name":"root-a","namespace":"tenant-a","common_name":"Root A","ttl":"8760h","max_path_len":1}'

curl -H 'Content-Type: application/json' -H "X-Auth-Token: $TOKEN" \
  -X POST http://localhost:8080/v1/pki/issue \
  -d '{"ca_name":"root-a","common_name":"svc.example.internal","ttl":"2h","dns_names":["svc.example.internal"]}'
```

Verify the audit chain:

```bash
curl -H "X-Auth-Token: $TOKEN" http://localhost:8080/v1/audit/verify
```

## CLI Examples

```bash
go run ./cmd/cli --server http://localhost:8080 --token dev-admin-token namespace list
go run ./cmd/cli --server http://localhost:8080 --token dev-admin-token secret put tenant-a /db/password s3cr3t
go run ./cmd/cli --server http://localhost:8080 --token dev-admin-token secret get tenant-a /db/password
go run ./cmd/cli --server http://localhost:8080 --token dev-admin-token audit verify
```

Run `go run ./cmd/cli --help` for all commands.

## Verification

The standard verification sequence is:

1. Start PostgreSQL with `make docker-up`.
2. Start the server with `make run`.
3. Check `GET /healthz`, `GET /readyz`, and `GET /metrics`.
4. Exercise namespace, secret, version, lease, policy, PKI, crypto, and audit endpoints.
5. Run `go run ./cmd/cli audit verify` and confirm `"valid":true`.

## Build and Test

```bash
make tidy
make build
make test
```

The repository contains no frontend and intentionally keeps test source separate from runtime source.
