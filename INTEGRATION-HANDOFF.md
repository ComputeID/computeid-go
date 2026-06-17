# ComputeID Go SDK — Integration Handoff

> **Audience:** an AI agent (or developer) integrating the ComputeID Go SDK into another local project on this machine, while the SDK itself is not yet published to GitHub. Follow this top-to-bottom.

The SDK is local at:
```
/path/to/computeid-go
```
Module path: `github.com/ComputeID/computeid-go`

The local server is at:
```
http://localhost:8088
```

---

## Preflight — confirm the server is running

Before integrating, verify the SDK's local server is up. From any terminal:

```bash
curl -s http://localhost:8088/health
```

Expected output:
```json
{"algorithm":"RSA-SHA256","status":"ok","timestamp":"..."}
```

If the request fails with "Connection refused", the server isn't running. **Ask the user to start it** (you, the integrating agent, should NOT start it yourself — it occupies a terminal). Tell them to run:

```bash
cd /path/to/computeid-go
make db-up      # one-time: creates the Postgres database
make run        # starts the server on :8088
```

Wait for the user to confirm `/health` returns `200 OK` before proceeding.

---

## Step 1 — add the SDK to your project

In your project root:

```bash
# If you don't have a go.mod yet:
go mod init github.com/your-org/your-project

# Add the SDK as a dependency, replaced with the local checkout.
go mod edit -replace github.com/ComputeID/computeid-go=/path/to/computeid-go
go mod edit -require github.com/ComputeID/computeid-go@v0.0.0-00010101000000-000000000000
go mod tidy
```

After `go mod tidy`, your `go.mod` should contain:
```go
require github.com/ComputeID/computeid-go v0.0.0-00010101000000-000000000000

replace github.com/ComputeID/computeid-go => /path/to/computeid-go
```

The SDK package itself has zero third-party deps — your `go.sum` will only grow if you also import `github.com/ComputeID/computeid-go/server` (which you should NOT do; that's the server-side package).

---

## Step 2 — construct the client

The SDK's `*Client` defaults to the production API. Override with `WithBaseURL` to point at the local server. The recommended pattern is env-driven so the same code works locally and in prod:

```go
package myapp

import (
	"os"

	"github.com/ComputeID/computeid-go"
)

func newComputeIDClient() *computeid.Client {
	opts := []computeid.Option{
		computeid.WithAPIKey(os.Getenv("COMPUTEID_API_KEY")), // optional locally
	}
	if base := os.Getenv("COMPUTEID_API_BASE"); base != "" {
		opts = append(opts, computeid.WithBaseURL(base))
	}
	return computeid.NewClient(opts...)
}
```

Then, when running locally:
```bash
export COMPUTEID_API_BASE=http://localhost:8088
go run .
```

---

## Step 3 — the four operations you'll actually use

Per the official Integration Guide, the integration is just four steps. Implement them in this order.

### 3.1 Issue a passport when you create an agent

```go
import (
	"context"
	"fmt"

	"github.com/ComputeID/computeid-go"
)

func issueAgent(ctx context.Context, c *computeid.Client, name, org string) (string, error) {
	sp, err := c.RegisterAgent(ctx, computeid.AgentRegistration{
		Name:         name,
		Organization: org,
		Description:  "what this agent does",
		Capabilities: []string{"read", "web_browse", "api_call"}, // server-side capability strings
	})
	if err != nil {
		return "", fmt.Errorf("register passport: %w", err)
	}
	// Persist sp.PassportID alongside your agent record.
	return sp.PassportID, nil
}
```

Capability strings to use: `read`, `web_browse`, `api_call`, `execute_code`, `access_files`, `spawn_agent`, `access_database`, `send_email`. Use whichever subset fits the agent's role.

### 3.2 Gate the boundary before privileged actions

Before any privileged action (external API call, code execution, spawning child agents), check verify + capability. Cache for **seconds**, not hours — revocation must bite fast.

```go
func agentMay(ctx context.Context, c *computeid.Client, passportID, capability string) (bool, error) {
	v, err := c.VerifyAgent(ctx, passportID)
	if err != nil {
		return false, err
	}
	// PDF authorization rule: status=="active" AND signature_valid==true.
	if !v.IsTrusted() {
		return false, nil
	}
	check, err := c.CheckCapability(ctx, passportID, capability)
	if err != nil {
		return false, err
	}
	return check.Granted, nil
}
```

Wire it at the call site:
```go
if ok, err := agentMay(ctx, c, passportID, "web_browse"); err != nil {
	return err
} else if !ok {
	return errors.New("agent not authorized for web_browse")
}
// ... do the work ...
```

### 3.3 Log meaningful actions

Not every token — every consequential act: external calls, sends, executions.

```go
err := c.LogAgentAction(ctx, passportID, computeid.LogActionRequest{
	Action:  "web_search",
	Details: map[string]any{"query": "GPU prices"},
	Outcome: "success", // or "blocked" / "failure"
})
```

### 3.4 Revoke on offboarding or anomaly

Revocation is immediate and permanent. Verification reflects it on the very next check.

```go
_ = c.RevokeAgent(ctx, passportID, "task complete")
// or
_ = c.RevokeAgent(ctx, passportID, "anomaly: unexpected outbound traffic")
```

---

## Step 4 — verify your integration with a smoke test

After wiring the above, write a one-shot main that exercises the full lifecycle and confirm every step succeeds against the local server. **Run this — don't just compile it.**

```go
// cmd/smoke/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ComputeID/computeid-go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := computeid.NewClient(computeid.WithBaseURL("http://localhost:8088"))

	// 1. Issue
	sp, err := c.RegisterAgent(ctx, computeid.AgentRegistration{
		Name:         "SmokeTestAgent",
		Organization: "Test Co",
		Capabilities: []string{"read", "web_browse"},
	})
	must(err, "register")
	fmt.Println("✓ issued:", sp.PassportID, "algo:", sp.SignatureAlgorithm)

	// 2. Gate (active path)
	v, err := c.VerifyAgent(ctx, sp.PassportID)
	must(err, "verify")
	if !v.IsTrusted() {
		log.Fatalf("✗ not trusted: status=%s sig=%v", v.Status, v.SignatureValid)
	}
	fmt.Println("✓ verified: active + signature_valid")

	check, err := c.CheckCapability(ctx, sp.PassportID, "web_browse")
	must(err, "capability")
	if !check.Granted {
		log.Fatal("✗ web_browse should be granted")
	}
	fmt.Println("✓ capability web_browse: granted")

	// 3. Log
	must(c.LogAgentAction(ctx, sp.PassportID, computeid.LogActionRequest{
		Action: "web_search", Details: map[string]any{"q": "smoke"}, Outcome: "success",
	}), "log")
	fmt.Println("✓ action logged")

	// 4. Revoke + confirm gate flips
	must(c.RevokeAgent(ctx, sp.PassportID, "smoke test done"), "revoke")
	check, _ = c.CheckCapability(ctx, sp.PassportID, "web_browse")
	if check.Granted || check.Reason != "passport_revoked" {
		log.Fatalf("✗ after revoke: granted=%v reason=%s", check.Granted, check.Reason)
	}
	fmt.Println("✓ revoked; capability now denied with reason=passport_revoked")
	fmt.Println("\nALL GREEN — integration is working.")
}

func must(err error, step string) {
	if err != nil {
		log.Fatalf("✗ %s: %v", step, err)
	}
}
```

Run it:
```bash
go run ./cmd/smoke
```

If every line prints `✓` and ends with `ALL GREEN`, the integration is wired correctly. If any line fails, capture the error and stop — don't move on.

---

## Step 5 — error handling reference

All errors from the SDK wrap typed sentinels. Match with `errors.Is`:

```go
import "errors"

_, err := c.RegisterAgent(ctx, reg)
switch {
case errors.Is(err, computeid.ErrAuthentication):
	// 401/403 — bad/missing API key (only matters in production)
case errors.Is(err, computeid.ErrRegistration):
	// 400/422 or server-side registration failure
case errors.Is(err, computeid.ErrAPI):
	// Generic transport / decode / non-2xx. Unwrap *APIError for details.
	var apiErr *computeid.APIError
	if errors.As(err, &apiErr) {
		log.Println(apiErr.StatusCode, apiErr.Endpoint, apiErr.Message)
	}
}
```

---

## Key facts the integrating agent must know

| Fact | Detail |
|---|---|
| Authorization rule | `status=="active"` **AND** `signature_valid==true`. Both fields are independent. A revoked passport keeps a valid signature. |
| After revocation | Every capability check returns `granted=false, reason="passport_revoked"`. |
| Caching verify/cap | Seconds, not hours. Revocation should bite fast. |
| What to log | Consequential acts (external calls, sends, executions), not every token. |
| Capability names | Use the server-side strings: `read`, `web_browse`, `api_call`, `execute_code`, etc. Do **not** confuse with the SDK's local `ActionBrowseWeb` constants — those are for the offline `AgentPassport` model only. |
| Time zones | All timestamps returned by the API are UTC (`Z`-terminated). |
| Local server limits | The dev server's `/api/devices/{id}/approve` is open by default. Set `ADMIN_TOKEN` on the server and `X-Admin-Token` on the request if you're running it on a shared box. |

---

## What NOT to do

- ❌ **Don't import `github.com/ComputeID/computeid-go/server`.** That's the server-side package and pulls in `pgx` + Postgres. Your project only needs the root SDK package.
- ❌ **Don't hard-code `https://api.aicomputeid.com`.** Use `COMPUTEID_API_BASE` so the same binary swings between local and prod.
- ❌ **Don't use the SDK's local `AgentPassport` (the offline model) for production.** That's a prototyping tool. For real agents, always use `Client.RegisterAgent` (server-backed).
- ❌ **Don't start the SDK's server yourself.** If it's not running, ask the user to start it in a separate terminal — don't background it from your tool calls.

---

## When you're done

Report back to the user with:

1. The exact files you added/modified in their project.
2. The output of running the smoke test (Step 4) — paste it verbatim.
3. Any errors you couldn't resolve, with the surrounding code context.

If everything went green, the next step is for the user to push the SDK to the org and tag a release — at which point you'll drop the `replace` directive and pin to `@v0.1.0`.
