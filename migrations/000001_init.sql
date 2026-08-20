CREATE TABLE IF NOT EXISTS namespaces (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS secrets (
    id UUID PRIMARY KEY,
    namespace TEXT NOT NULL,
    path TEXT NOT NULL,
    type TEXT NOT NULL,
    current_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(namespace, path)
);

CREATE TABLE IF NOT EXISTS secret_versions (
    id UUID PRIMARY KEY,
    secret_id UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    value_sha256 BYTEA NOT NULL,
    key_version TEXT NOT NULL DEFAULT 'v1',
    state TEXT NOT NULL DEFAULT 'active',
    delete_after TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(secret_id, version)
);

CREATE TABLE IF NOT EXISTS leases (
    id UUID PRIMARY KEY,
    namespace TEXT NOT NULL,
    path TEXT NOT NULL,
    secret_id UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    ttl_seconds BIGINT NOT NULL,
    renewable BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    namespace TEXT NOT NULL,
    path_prefix TEXT NOT NULL,
    identity TEXT NOT NULL,
    capabilities TEXT[] NOT NULL,
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    sequence BIGSERIAL UNIQUE,
    event_hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    actor TEXT NOT NULL,
    namespace TEXT NOT NULL,
    path TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pki_cas (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    namespace TEXT NOT NULL,
    ca_type TEXT NOT NULL,
    parent_id UUID REFERENCES pki_cas(id) ON DELETE SET NULL,
    certificate_pem TEXT NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    key_version TEXT NOT NULL DEFAULT 'v1',
    serial_number BIGINT NOT NULL,
    policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY,
    namespace TEXT NOT NULL,
    ca_id UUID REFERENCES pki_cas(id) ON DELETE SET NULL,
    common_name TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    encrypted_private_key BYTEA,
    key_version TEXT DEFAULT 'v1',
    status TEXT NOT NULL DEFAULT 'issued',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(namespace, serial_number)
);

CREATE TABLE IF NOT EXISTS revocations (
    id UUID PRIMARY KEY,
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    serial_number TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_secrets_ns_path ON secrets(namespace, path);
CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id);
CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at);
CREATE INDEX IF NOT EXISTS idx_policies_path ON policies(namespace, path_prefix);
CREATE INDEX IF NOT EXISTS idx_audit_ns_path ON audit_events(namespace, path);
CREATE INDEX IF NOT EXISTS idx_certificates_expiry ON certificates(not_after);
