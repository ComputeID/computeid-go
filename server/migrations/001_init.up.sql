-- ComputeID server initial schema.
-- Schema decisions trace back to:
--   * the Integration Guide PDF (passport_id UUID, RSA-2048/SHA-256 signature,
--     status active|revoked, capabilities list, action audit trail)
--   * the Python SDK (DevicePassport status pending|active|revoked,
--     device_code identifier, admin approval workflow).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The server owns one RSA-2048 key, generated on first boot and persisted so
-- restarts don't break signature verification on previously-issued passports.
CREATE TABLE signing_keys (
    id              SMALLINT PRIMARY KEY DEFAULT 1,
    private_key_pem TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'RSA-SHA256',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT only_one_row CHECK (id = 1)
);

CREATE TABLE agents (
    passport_id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 TEXT         NOT NULL,
    description          TEXT,
    organization         TEXT         NOT NULL,
    capabilities         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    status               TEXT         NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','revoked')),
    public_key_pem       TEXT         NOT NULL,
    signature_b64        TEXT         NOT NULL,
    signature_algorithm  TEXT         NOT NULL DEFAULT 'RSA-SHA256',
    signed_payload       BYTEA        NOT NULL,  -- exact bytes the signature covers; must be byte-for-byte stable for verify
    issued_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at           TIMESTAMPTZ,
    revoke_reason        TEXT,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX agents_status_idx       ON agents (status);
CREATE INDEX agents_organization_idx ON agents (organization);

CREATE TABLE agent_actions (
    action_id    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    passport_id  UUID         NOT NULL REFERENCES agents(passport_id) ON DELETE CASCADE,
    action       TEXT         NOT NULL,
    details      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    outcome      TEXT         NOT NULL DEFAULT 'success'
                 CHECK (outcome IN ('success','blocked','failure')),
    occurred_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX agent_actions_passport_time_idx
    ON agent_actions (passport_id, occurred_at DESC);

-- Device codes are issued as a monotonic per-type sequence (GPU-001, GPU-002...).
CREATE TABLE device_counters (
    device_type TEXT PRIMARY KEY,
    last_n      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE devices (
    device_id    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code  TEXT         UNIQUE NOT NULL,
    name         TEXT         NOT NULL,
    device_type  TEXT         NOT NULL,
    ip_address   TEXT,
    status       TEXT         NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','active','revoked')),
    issued_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    approved_at  TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX devices_status_idx ON devices (status);
