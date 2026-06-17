// Server-backed agent passport example — talks to the ComputeID API.
// Mirrors the canonical Integration Guide flow:
//
//  1. POST /v1/agents/register
//  2. GET  /v1/agents/{id}/verify          (status=="active" AND signature_valid)
//  3. GET  /v1/agents/{id}/capabilities/{name}
//  4. POST /v1/agents/{id}/actions
//  5. GET  /v1/agents/{id}/actions?limit=10
//  6. DELETE /v1/agents/{id}/revoke
//
// Endpoint resolution:
//   - COMPUTEID_API_BASE  → if set, used verbatim (e.g. http://localhost:8088 for the
//     local computeid-server). Otherwise defaults to https://api.aicomputeid.com.
//   - COMPUTEID_API_KEY   → optional; required only for live/free tier.
//
//	export COMPUTEID_API_BASE=http://localhost:8088
//	go run .
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ComputeID/computeid-go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := []computeid.Option{computeid.WithAPIKey(os.Getenv("COMPUTEID_API_KEY"))}
	if base := os.Getenv("COMPUTEID_API_BASE"); base != "" {
		opts = append(opts, computeid.WithBaseURL(base))
	}
	c := computeid.NewClient(opts...)

	// 1. Issue a passport when you create an agent.
	sp, err := c.RegisterAgent(ctx, computeid.AgentRegistration{
		Name:         "ResearchAgent",
		Description:  "Summarises market research",
		Organization: "Acme Corp",
		Capabilities: []string{"read", "web_browse", "api_call"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("issued: %s  (algo=%s)\n", sp.PassportID, sp.SignatureAlgorithm)

	// 2. Gate the boundary. Authorisation rule: status == "active" AND
	// signature_valid == true. The two fields are independent by design
	// (per the Integration Guide).
	v, err := c.VerifyAgent(ctx, sp.PassportID)
	if err != nil {
		log.Fatal(err)
	}
	if !v.IsTrusted() {
		log.Fatalf("passport not trusted: status=%s signature_valid=%t", v.Status, v.SignatureValid)
	}

	// 3. Per-capability check before each privileged action.
	check, err := c.CheckCapability(ctx, sp.PassportID, "web_browse")
	if err != nil {
		log.Fatal(err)
	}
	if !check.Granted {
		log.Fatalf("web_browse denied: %s", check.Reason)
	}

	// 4. Log the meaningful action (Integration Guide: not every token, every
	// consequential act).
	if err := c.LogAgentAction(ctx, sp.PassportID, computeid.LogActionRequest{
		Action:  "web_search",
		Details: map[string]any{"query": "GPU prices"},
		Outcome: "success",
	}); err != nil {
		log.Fatal(err)
	}

	// 5. Read it back.
	actions, err := c.ListAgentActions(ctx, sp.PassportID, 10)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("audit trail: %d entries\n", len(actions))
	for _, a := range actions {
		fmt.Printf("  %s | %s | %s\n", a.Timestamp.Format(time.RFC3339), a.Action, a.Outcome)
	}

	// 6. Revoke on offboarding or anomaly. Verification reflects revocation
	// on the next check.
	if err := c.RevokeAgent(ctx, sp.PassportID, "Task complete"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("revoked.")
}
