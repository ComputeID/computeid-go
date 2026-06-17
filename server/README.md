# computeid-server

A Postgres-backed implementation of the ComputeID API. Wire-compatible with the production endpoints documented in the [Integration Guide PDF](https://compute-id.com) — the Go SDK and the Python SDK both work against it unchanged.

> This server is suitable for local development, CI, and self-hosted deployments. The production API at `https://api.aicomputeid.com` remains the source of truth for managed deployments.

---

## What it implements

All endpoints from the Integration Guide, plus one dev-only admin path:

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/agents/register` | Issues a passport. Generates an RSA-2048 / SHA-256 signature over canonical JSON of `{passport_id, name, organization, capabilities, issued_at}`. |
| `GET` | `/v1/agents/{id}/verify` | Returns `status` + `signature_valid` (independent — a revoked passport keeps a valid signature). |
| `GET` | `/v1/agents/{id}/capabilities/{name}` | `granted` + `reason`. After revoke, every capability returns `granted=false, reason="passport_revoked"`. |
| `POST` | `/v1/agents/{id}/actions` | Append to the audit trail. |
| `GET` | `/v1/agents/{id}/actions?limit=N` | Read the audit trail (newest first, limit 1-500, default 50). |
| `DELETE` | `/v1/agents/{id}/revoke` | Idempotent revoke; writes a `passport_revoked` action. |
| `GET` | `/v1/agents?status=` | List passports, optional status filter. |
| `POST` | `/api/devices/register` | Issues a device passport (`status=pending`). Device code is allocated monotonically per type: `GPU-001`, `GPU-002`, ... |
| `POST` | `/api/devices/authenticate` | Exchanges `device_code` → HS256 JWT (1h TTL). Requires `status=active`. |
| `GET` | `/api/devices?status=` | List devices. |
| `POST` | `/api/devices/{id}/approve` | **Dev-only.** Moves a device from `pending` to `active`. Not in the production contract. |
| `GET` | `/health`, `GET /v1/status` | Liveness + DB ping. |

---

## Run with the existing leadpilot Postgres

```bash
# 1. Create the database
PGPASSWORD=leadpilot psql -h localhost -p 5439 -U leadpilot -d postgres \
  -c "CREATE DATABASE computeid OWNER leadpilot;"

# 2. Boot the server (migrations apply automatically, RSA key generates on first boot)
export DATABASE_URL=postgres://leadpilot:leadpilot@localhost:5439/computeid?sslmode=disable
export JWT_SECRET=local-dev-secret
go run ./cmd/computeid-server

# 3. Point the SDK at it
export COMPUTEID_API_BASE=http://localhost:8088
go run ./examples/serverbacked
```

## Run with Docker Compose (isolated Postgres on :5440)

```bash
docker compose up --build
# Server on :8088, DB on :5440
export COMPUTEID_API_BASE=http://localhost:8088
go run ./examples/serverbacked
```

---

## Environment

| Var | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | — | Postgres connection string (pgxpool format). |
| `JWT_SECRET` | yes | — | HS256 secret for device JWTs. |
| `PORT` | no | `8088` | HTTP listen port. |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error`. |

---

## Schema

Five tables, single migration:

- `signing_keys` — singleton RSA-2048 keypair persisted on first boot.
- `agents` — passport rows + signed payload bytes (BYTEA so verify is byte-stable).
- `agent_actions` — append-only audit log.
- `devices`, `device_counters` — devices + per-type monotonic code allocator.
- `schema_migrations` — applied versions.

See [`migrations/001_init.up.sql`](migrations/001_init.up.sql) for the canonical definition.

---

## Signing model

- Key: RSA-2048, persisted in `signing_keys` so verification still works after restarts.
- Algorithm: `RSA-SHA256` (matches the production `signature_algorithm` string).
- Payload: stable-order JSON of `{passport_id, name, organization, capabilities, issued_at}`.
- Storage: exact bytes signed are persisted in `agents.signed_payload BYTEA` so the verifier can recompute the SHA-256 hash without re-serializing.

The signature is independent of status. Revoking a passport leaves `signature_valid=true`; the authorization rule is "`status=="active"` AND `signature_valid==true`".

---

## What this server is not (yet)

- The dev `/approve` endpoint is open unless `ADMIN_TOKEN` is set. When set, the endpoint requires a matching `X-Admin-Token` header.
- No rate limiting.
- No post-quantum signing — production roadmap.
- No `X-API-Key` enforcement — keys are accepted and forwarded by the SDK but the server ignores them.

These are appropriate for local development and CI. For anything beyond that, talk to ComputeID.

---

## Testing

```bash
# Fast: SDK unit tests only, no Postgres needed.
make test-unit

# Full: server + SDK↔server E2E tests against real Postgres.
make db-up     # one-time: creates 'computeid' and 'computeid_test' databases
make test      # uses one shared test DB with -p 1 to serialize binaries

# Or run the two packages in parallel against separate DBs (faster).
# Requires: createdb computeid_test_server && createdb computeid_test_e2e
go test -race -count=1 ./...
```

Per-test integration coverage (all hit real Postgres):

| Package | What it tests |
|---|---|
| `server/migrate_test.go` | Idempotent re-runs; all 6 tables created. |
| `server/signer_test.go` | RSA-2048 sign/verify; tampered payload + tampered signature both fail; key persists across reload. |
| `server/integration_test.go` | Every HTTP endpoint end-to-end: register, verify (active+revoked → signature still valid), capabilities (granted/missing/revoked), log+list actions, revoke idempotency, list with status filter, device lifecycle, monotonic GPU code allocation, admin token gate. |
| root `e2e_test.go` | Drives the SDK `*Client` against a live server; verifies the full PDF wire contract. |

To skip integration tests on a machine without Postgres: `COMPUTEID_SKIP_INTEGRATION=1 go test ./...`.
