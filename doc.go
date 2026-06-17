// Package computeid is the Go SDK for ComputeID — cryptographic identity for
// AI compute infrastructure and agentic AI systems.
//
// Every GPU needs a passport. Every AI agent needs an identity.
//
// Three core abstractions:
//
//   - AgentPassport  — local cryptographic passport for an AI agent.
//   - DevicePassport — server-issued passport for a GPU/server.
//   - PassportOffice — organisation-wide registry and audit trail.
//
// Two server-backed REST surfaces, both exposed through *Client:
//
//   - /v1/agents/*    — issue, verify, log, revoke server-side agent passports.
//   - /api/devices/*  — register and authenticate devices.
//
// Quickstart — local agent passport (no network):
//
//	caps := computeid.StandardCapabilities()
//	passport, err := computeid.IssueAgentPassport(computeid.IssueOptions{
//	    AgentName:    "ResearchAgent",
//	    AgentType:    "researcher",
//	    OwnerOrg:     "Acme Corp",
//	    OwnerEmail:   "admin@acme.com",
//	    Capabilities: caps,
//	    Model:        "claude-sonnet-4-6",
//	})
//	if passport.VerifyAction(computeid.ActionBrowseWeb) {
//	    // run the agent
//	}
//
// Quickstart — register a GPU:
//
//	dev, err := computeid.RegisterGPU(ctx, "NVIDIA A100", "192.168.1.10", apiKey)
//
// Quickstart — server-backed agent passport:
//
//	client := computeid.NewClient(computeid.WithAPIKey(apiKey))
//	sp, err := client.RegisterAgent(ctx, computeid.AgentRegistration{
//	    Name:         "ResearchAgent",
//	    Organization: "Acme Corp",
//	    Capabilities: []string{"read", "web_browse", "api_call"},
//	})
//
// Docs:   https://compute-id.com
// GitHub: https://github.com/ComputeID/computeid-sdk
package computeid
