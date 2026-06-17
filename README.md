# ComputeID Go SDK

**Cryptographic identity for AI compute infrastructure and agentic AI systems — for Go.**

> Every GPU needs a passport. Every AI agent needs an identity.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/ComputeID/computeid-go.svg)](https://pkg.go.dev/github.com/ComputeID/computeid-go)

A pure-stdlib Go port of the [Python ComputeID SDK](https://github.com/ComputeID/computeid-sdk), with the server-backed `/v1/agents/*` REST surface wired up from day one.

---

## What ComputeID is

Two things:

1. **DeviceID** — cryptographic passports for GPUs, servers, and compute hardware.
2. **AgentID** — cryptographic passports for AI agents and autonomous systems.

Think of it as a passport system for AI infrastructure: every device and every agent gets a unique cryptographic identity, a certificate of what it is allowed to do, and an immutable audit trail of everything it has done.

---

## Install

```bash
go get github.com/ComputeID/computeid-go
```

Requires Go 1.22+. The SDK package itself has zero third-party dependencies.

> **Not published yet?** See [PUBLISHING.md](PUBLISHING.md) for how to push to the org, stage on a personal account first, or wire up a local-only `go.mod replace` for development.

---

## Run a local API server

The SDK ships with a Postgres-backed implementation of the ComputeID API so you can develop, test, and run examples without hitting `api.aicomputeid.com`. See [`server/README.md`](server/README.md) for details.

```bash
# Option A: against an existing Postgres
createdb computeid
export DATABASE_URL=postgres://localhost/computeid?sslmode=disable
export JWT_SECRET=local-dev-secret
go run ./cmd/computeid-server

# Option B: full bundle (Postgres + server) via Docker
docker compose up --build

# Then point the SDK at it
export COMPUTEID_API_BASE=http://localhost:8088
go run ./examples/serverbacked
```

---

## Quick start

### Agent passport (local model)

```go
import "github.com/ComputeID/computeid-go"

passport, err := computeid.IssueAgentPassportQuick(
    "ResearchAgent", "Acme Corp", "admin@acme.com",
    "claude-sonnet-4-6", computeid.TrustStandard,
)
if err != nil { log.Fatal(err) }

if passport.IsTrusted() {
    runYourAgent(passport)
}

// Gate by capability — denied actions are logged automatically.
if passport.VerifyAction(computeid.ActionBrowseWeb) {
    doWebSearch()
}

passport.LogAction("web_search", map[string]any{"query": "market research"}, computeid.OutcomeSuccess)

passport.Revoke("Unexpected behaviour detected")
```

### Server-backed agent passport (REST)

```go
c := computeid.NewClient(computeid.WithAPIKey(os.Getenv("COMPUTEID_API_KEY")))

sp, err := c.RegisterAgent(ctx, computeid.AgentRegistration{
    Name:         "ResearchAgent",
    Organization: "Acme Corp",
    Capabilities: []string{"read", "web_browse", "api_call"},
})

// Authoritative check: active AND signature_valid.
v, _ := c.VerifyAgent(ctx, sp.PassportID)
if !v.IsTrusted() { return errors.New("not trusted") }

cap, _ := c.CheckCapability(ctx, sp.PassportID, "web_browse")
if cap.Granted {
    doWork()
    c.LogAgentAction(ctx, sp.PassportID, computeid.LogActionRequest{
        Action: "web_search",
        Details: map[string]any{"query": "GPU prices"},
        Outcome: "success",
    })
}

c.RevokeAgent(ctx, sp.PassportID, "Task complete")
```

### Register a GPU

```go
dev, err := computeid.RegisterGPU(ctx, "NVIDIA A100", "192.168.1.10", apiKey)
fmt.Println(dev.DeviceCode) // GPU-001
fmt.Println(dev.IsValid())  // true once admin approves
```

---

## Trust levels

| Level         | Preset                          | Use case                            |
|---------------|---------------------------------|-------------------------------------|
| `restricted`  | `RestrictedCapabilities()`      | Read only, human oversight required |
| `standard`    | `StandardCapabilities()`        | Most production agents              |
| `elevated`    | `ElevatedCapabilities()`        | Code execution, spawn child agents  |
| `autonomous`  | `AutonomousCapabilities()`      | Full autonomy — use with care       |

Or build a custom set:

```go
caps := computeid.AgentCapabilities{
    CanBrowseWeb:      true,
    CanCallAPIs:       true,
    CanExecuteCode:    false,
    TrustLevel:        computeid.TrustStandard,
    HumanInLoop:       true,
    MaxActionsPerHour: 100,
    AllowedDomains:    []string{"example.com"},
}
```

---

## Multi-agent trust chain

```go
orchestrator, _ := computeid.IssueAgentPassport(computeid.IssueOptions{
    AgentName:    "OrchestratorAgent",
    AgentType:    "orchestrator",
    OwnerOrg:     "Acme Corp",
    OwnerEmail:   "admin@acme.com",
    Capabilities: computeid.ElevatedCapabilities(),
    Model:        "claude-opus-4-7",
})

child, err := computeid.IssueAgentPassport(computeid.IssueOptions{
    AgentName:      "SubAgent",
    AgentType:      "worker",
    OwnerOrg:       "Acme Corp",
    OwnerEmail:     "admin@acme.com",
    Capabilities:   computeid.StandardCapabilities(),
    Model:          "claude-sonnet-4-6",
    ParentPassport: orchestrator, // fails unless orchestrator has CanSpawnAgents
})
```

---

## Org-wide registry

```go
office := computeid.NewPassportOffice("Acme Corp", "")
office.RegisterAgent(orchestrator)
office.RegisterAgent(child)
office.RegisterDevice(dev)

if office.IsTrusted(child.AgentID) {
    allowAccess()
}

report := office.AuditReport()
fmt.Println(report.ActiveAgents, "/", report.TotalAgents)
```

`TrustRegistry` is a type alias for `PassportOffice` to match the Python SDK.

---

## Gating functions with a passport

Generic helper that wraps any `func(*AgentPassport, A) (R, error)` with the same checks the Python `@requires_passport` decorator runs:

```go
search := computeid.RequirePassport(computeid.ActionBrowseWeb,
    func(p *computeid.AgentPassport, q string) ([]string, error) {
        return doSearch(q), nil
    })

results, err := search(passport, "GPU rental prices")
```

Returns `ErrAuthentication` if the passport is missing or untrusted, `ErrTrust` if the capability is denied. Match with `errors.Is`.

---

## Errors

All errors wrap typed sentinels you can match with `errors.Is`:

```go
_, err := computeid.IssueAgentPassport(opts)
switch {
case errors.Is(err, computeid.ErrAuthentication):
    // 401/403 from the API
case errors.Is(err, computeid.ErrTrust):
    // capability or trust-chain violation
case errors.Is(err, computeid.ErrRegistration):
    // bad input or server registration failure
case errors.Is(err, computeid.ErrAPI):
    // generic transport / decode failure
    var apiErr *computeid.APIError
    if errors.As(err, &apiErr) {
        log.Println(apiErr.StatusCode, apiErr.Endpoint, apiErr.Message)
    }
}
```

---

## Examples

| Example                                | What it shows                                                 |
|----------------------------------------|---------------------------------------------------------------|
| [`examples/basic`](examples/basic)             | Local-model passport, trust chain, registry, audit log |
| [`examples/serverbacked`](examples/serverbacked) | Live `/v1/agents/*` REST flow against `api.aicomputeid.com` |
| [`examples/devices`](examples/devices)         | Register and authenticate a GPU                         |

Run any example:

```bash
go run ./examples/basic
```

---

## Mapping from the Python SDK

| Python                                  | Go                                                 |
|-----------------------------------------|----------------------------------------------------|
| `AgentCapabilities(...)`                | `AgentCapabilities{...}`                           |
| `AgentCapabilities.standard()`          | `StandardCapabilities()`                           |
| `AgentPassport.issue(...)`              | `IssueAgentPassport(IssueOptions{...})`            |
| `passport.log_action(a, d, o)`          | `passport.LogAction(a, d, o)`                      |
| `passport.verify_action(a)`             | `passport.VerifyAction(ActionBrowseWeb)`           |
| `passport.is_trusted()`                 | `passport.IsTrusted()`                             |
| `passport.revoke(reason)`               | `passport.Revoke(reason)`                          |
| `passport.export()` / `.load(s)`        | `passport.Export()` / `LoadAgentPassport(b)`       |
| `DevicePassport.register(...)`          | `RegisterDevice(ctx, req, apiKey)` or `Client.RegisterDevice` |
| `DevicePassport.authenticate(...)`      | `AuthenticateDevice(ctx, code)`                    |
| `PassportOffice(...)`                   | `NewPassportOffice(name, apiKey)`                  |
| `TrustRegistry`                         | type alias `TrustRegistry = PassportOffice`        |
| `@requires_passport(capability=...)`    | `RequirePassport[A,R](capability, fn)`             |
| `issue_agent_passport(...)`             | `IssueAgentPassportQuick(...)`                     |
| `register_gpu(...)`                     | `RegisterGPU(ctx, name, ip, apiKey)`               |

Additions over the Python SDK (1.1.0):

- **Server-backed `/v1/agents/*` REST client** — `RegisterAgent`, `VerifyAgent`, `CheckCapability`, `LogAgentAction`, `ListAgentActions`, `RevokeAgent`, `ListAgents`. The Python SDK currently runs `AgentPassport` offline; the Go SDK ships both modes.
- `context.Context` on every network call.
- Typed errors (`errors.Is`/`errors.As`) instead of string-keyed exceptions.
- Pluggable `*http.Client`, base URL, and User-Agent via functional options.

---

## License

MIT. Copyright 2026 ComputeID / TrustedAI Compute.
