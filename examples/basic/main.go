// Local-only AgentPassport example — mirrors the Python "Full Example" in
// the SDK README. No network calls.
package main

import (
	"fmt"
	"log"

	"github.com/ComputeID/computeid-go"
)

func main() {
	caps := computeid.AgentCapabilities{
		CanBrowseWeb:      true,
		CanCallAPIs:       true,
		CanExecuteCode:    false,
		TrustLevel:        computeid.TrustStandard,
		HumanInLoop:       true,
		MaxActionsPerHour: 100,
	}

	passport, err := computeid.IssueAgentPassport(computeid.IssueOptions{
		AgentName:    "DataAnalysisAgent",
		AgentType:    "analyst",
		OwnerOrg:     "Acme Corp",
		OwnerEmail:   "admin@acme.com",
		Capabilities: caps,
		Model:        "claude-sonnet-4-6",
		Version:      "2.1.0",
	})
	if err != nil {
		log.Fatal(err)
	}

	if passport.VerifyAction(computeid.ActionBrowseWeb) {
		fmt.Println("browse_web allowed — proceeding")
	}
	if !passport.VerifyAction(computeid.ActionExecuteCode) {
		fmt.Println("execute_code denied — logged as blocked")
	}

	// Multi-agent trust chain.
	orchestrator, err := computeid.IssueAgentPassport(computeid.IssueOptions{
		AgentName:    "OrchestratorAgent",
		AgentType:    "orchestrator",
		OwnerOrg:     "Acme Corp",
		OwnerEmail:   "admin@acme.com",
		Capabilities: computeid.ElevatedCapabilities(),
		Model:        "claude-opus-4-7",
	})
	if err != nil {
		log.Fatal(err)
	}
	child, err := computeid.IssueAgentPassport(computeid.IssueOptions{
		AgentName:      "SubAgent-1",
		AgentType:      "worker",
		OwnerOrg:       "Acme Corp",
		OwnerEmail:     "admin@acme.com",
		Capabilities:   computeid.StandardCapabilities(),
		Model:          "claude-sonnet-4-6",
		ParentPassport: orchestrator,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Org-wide registry.
	office := computeid.NewPassportOffice("Acme Corp", "")
	office.RegisterAgent(orchestrator)
	office.RegisterAgent(child)

	report := office.AuditReport()
	fmt.Printf("Total agents:  %d\n", report.TotalAgents)
	fmt.Printf("Active agents: %d\n", report.ActiveAgents)

	// View the audit trail.
	for _, e := range passport.AuditLog() {
		fmt.Printf("%s | %s | %s\n", e.Timestamp.Format("15:04:05"), e.Action, e.Outcome)
	}
}
