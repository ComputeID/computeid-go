# Changelog

All notable changes to the ComputeID Go SDK are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-06-17

First release. Go port of the [Python ComputeID SDK](https://github.com/ComputeID/computeid-sdk), wire-compatible with the Integration Guide REST API at `https://api.aicomputeid.com`.

### Added — SDK package (`github.com/ComputeID/computeid-go`)
- `AgentCapabilities` with four presets (`Restricted`, `Standard`, `Elevated`, `Autonomous`) and an `Action` enum for offline capability checks.
- `AgentPassport` — local-model passport with `IssueAgentPassport`, `VerifyAction`, `LogAction`, `Revoke`, `IsTrusted`, `Export`/`LoadAgentPassport`, parent-child trust chain.
- `DevicePassport` + `RegisterDevice` / `AuthenticateDevice` quickstarts.
- `*Client` — full `/v1/agents/*` REST client: `RegisterAgent`, `VerifyAgent`, `CheckCapability`, `LogAgentAction`, `ListAgentActions`, `RevokeAgent`, `ListAgents`.
- `*Client` — full `/api/devices/*` REST client: `RegisterDevice`, `AuthenticateDevice`.
- `PassportOffice` (alias `TrustRegistry`) — org-wide passport registry + audit report.
- `RequirePassport[A,R]` — generic decorator-style helper matching the Python `@requires_passport`.
- Typed errors with `errors.Is`/`errors.As` support: `ErrComputeID`, `ErrAuthentication`, `ErrRegistration`, `ErrRevocation`, `ErrTrust`, `ErrCapability`, `ErrAPI`, `*APIError`.
- Functional options: `WithBaseURL`, `WithAPIKey`, `WithHTTPClient`, `WithUserAgent`.
- `context.Context` on every network call.

### Added — server package + binary
- Pure-Go Postgres-backed implementation of the ComputeID API. Wire-compatible with the production endpoints — the same SDK targets both.
- RSA-2048 / SHA-256 signing. Key is generated on first boot and persisted in `signing_keys` so verification survives restarts.
- Authorization rule from the Integration Guide: `status=="active"` AND `signature_valid==true` (independent fields — revoked passports keep a valid signature).
- After revocation, every capability check returns `granted=false, reason="passport_revoked"`.
- HS256 JWT issuance for device authentication.
- Embedded migrations runner.
- Optional `ADMIN_TOKEN` env to gate the dev-only `POST /api/devices/{id}/approve` endpoint.
- `cmd/computeid-server` binary with env-driven config, slog logging, graceful shutdown.
- `Dockerfile` + `docker-compose.yml` for a self-contained Postgres+server bundle.

### Added — testing
- 17 SDK unit tests with `httptest`-mocked transports. Locks PDF-exact response shapes.
- 22 server integration tests against a real Postgres. Covers every HTTP endpoint, signer round-trip + tamper detection, migration idempotency, admin token gate, monotonic GPU code allocation.
- 4 SDK ↔ server E2E tests. Drives `*Client` against a live server backed by Postgres.
- GitHub Actions CI workflow with a `postgres:16` service container.
- `Makefile` targets: `test-unit`, `test`, `test-integration`, `db-up`, `db-reset`, `run`, `docker-build`, `docker-up`.

### Compatibility
- **Go ≥ 1.22**. SDK package itself has zero third-party dependencies; the server pulls `github.com/jackc/pgx/v5`.

[Unreleased]: https://github.com/ComputeID/computeid-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ComputeID/computeid-go/releases/tag/v0.1.0
