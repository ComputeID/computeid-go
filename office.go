package computeid

import (
	"fmt"
	"sync"
	"time"
)

// PassportOffice is an org-wide registry of agent and device passports.
// It is safe for concurrent use.
type PassportOffice struct {
	OrgName   string
	APIKey    string
	CreatedAt time.Time

	mu      sync.RWMutex
	agents  map[string]*AgentPassport
	devices map[string]*DevicePassport
}

// NewPassportOffice constructs an empty office.
func NewPassportOffice(orgName, apiKey string) *PassportOffice {
	return &PassportOffice{
		OrgName:   orgName,
		APIKey:    apiKey,
		CreatedAt: time.Now().UTC(),
		agents:    make(map[string]*AgentPassport),
		devices:   make(map[string]*DevicePassport),
	}
}

// RegisterDevice adds a device passport to the office.
func (o *PassportOffice) RegisterDevice(p *DevicePassport) {
	if p == nil || p.DeviceID == "" {
		return
	}
	o.mu.Lock()
	o.devices[p.DeviceID] = p
	o.mu.Unlock()
}

// RegisterAgent adds an agent passport to the office.
func (o *PassportOffice) RegisterAgent(p *AgentPassport) {
	if p == nil || p.AgentID == "" {
		return
	}
	o.mu.Lock()
	o.agents[p.AgentID] = p
	o.mu.Unlock()
}

// IsTrusted reports whether a registered agent is currently trusted.
func (o *PassportOffice) IsTrusted(agentID string) bool {
	o.mu.RLock()
	p, ok := o.agents[agentID]
	o.mu.RUnlock()
	return ok && p.IsTrusted()
}

// RevokeAgent revokes a registered agent and returns true if found.
func (o *PassportOffice) RevokeAgent(agentID, reason string) bool {
	o.mu.RLock()
	p, ok := o.agents[agentID]
	o.mu.RUnlock()
	if !ok {
		return false
	}
	if reason == "" {
		reason = "Revoked by PassportOffice"
	}
	p.Revoke(reason)
	return true
}

// ActiveAgents returns all currently trusted agents.
func (o *PassportOffice) ActiveAgents() []*AgentPassport {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]*AgentPassport, 0, len(o.agents))
	for _, p := range o.agents {
		if p.IsTrusted() {
			out = append(out, p)
		}
	}
	return out
}

// ActiveDevices returns all currently active devices.
func (o *PassportOffice) ActiveDevices() []*DevicePassport {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]*DevicePassport, 0, len(o.devices))
	for _, p := range o.devices {
		if p.IsValid() {
			out = append(out, p)
		}
	}
	return out
}

// AuditReport summarises everything the office knows.
type AuditReport struct {
	OrgName       string             `json:"org_name"`
	GeneratedAt   time.Time          `json:"generated_at"`
	TotalAgents   int                `json:"total_agents"`
	ActiveAgents  int                `json:"active_agents"`
	TotalDevices  int                `json:"total_devices"`
	ActiveDevices int                `json:"active_devices"`
	Agents        []AgentAuditEntry  `json:"agents"`
}

// AgentAuditEntry is a per-agent record in the audit report.
type AgentAuditEntry struct {
	Summary
	AuditLog []AuditEntry `json:"audit_log"`
}

// AuditReport builds a compliance snapshot across all registered passports.
func (o *PassportOffice) AuditReport() AuditReport {
	o.mu.RLock()
	defer o.mu.RUnlock()
	rep := AuditReport{
		OrgName:      o.OrgName,
		GeneratedAt:  time.Now().UTC(),
		TotalAgents:  len(o.agents),
		TotalDevices: len(o.devices),
		Agents:       make([]AgentAuditEntry, 0, len(o.agents)),
	}
	for _, p := range o.agents {
		if p.IsTrusted() {
			rep.ActiveAgents++
		}
		rep.Agents = append(rep.Agents, AgentAuditEntry{
			Summary:  p.Summary(),
			AuditLog: p.AuditLog(),
		})
	}
	for _, d := range o.devices {
		if d.IsValid() {
			rep.ActiveDevices++
		}
	}
	return rep
}

func (o *PassportOffice) String() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return fmt.Sprintf("<PassportOffice %s | %d agents | %d devices>",
		o.OrgName, len(o.agents), len(o.devices))
}

// TrustRegistry is a backwards-compatible alias matching the Python SDK.
type TrustRegistry = PassportOffice

// NewTrustRegistry mirrors the Python TrustRegistry constructor.
func NewTrustRegistry(orgName, apiKey string) *TrustRegistry {
	return NewPassportOffice(orgName, apiKey)
}
