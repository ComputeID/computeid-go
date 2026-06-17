package computeid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentStatus is the lifecycle state of an AgentPassport.
type AgentStatus string

const (
	StatusActive  AgentStatus = "active"
	StatusRevoked AgentStatus = "revoked"
	StatusExpired AgentStatus = "expired"
)

// ActionOutcome is the result label written into the audit trail.
type ActionOutcome string

const (
	OutcomeSuccess ActionOutcome = "success"
	OutcomeBlocked ActionOutcome = "blocked"
	OutcomeFailure ActionOutcome = "failure"
)

// AuditEntry is one immutable record in an AgentPassport audit log.
type AuditEntry struct {
	LogID     string         `json:"log_id"`
	AgentID   string         `json:"agent_id"`
	Action    string         `json:"action"`
	Details   map[string]any `json:"details,omitempty"`
	Outcome   ActionOutcome  `json:"outcome"`
	Timestamp time.Time      `json:"timestamp"`
}

// AgentPassport is a local cryptographic passport for an AI agent. It carries
// who built it, what it may do, what it has done, and whether it is currently
// trusted. AgentPassports are mutated only through the methods on this type —
// the audit log in particular is append-only.
type AgentPassport struct {
	AgentID        string            `json:"agent_id"`
	AgentName      string            `json:"agent_name"`
	AgentType      string            `json:"agent_type"`
	OwnerOrg       string            `json:"owner_org"`
	OwnerEmail     string            `json:"owner_email"`
	Model          string            `json:"model"`
	Version        string            `json:"version"`
	Status         AgentStatus       `json:"status"`
	TrustLevel     TrustLevel        `json:"trust_level"`
	ParentAgentID  string            `json:"parent_agent_id,omitempty"`
	IssuedAt       time.Time         `json:"issued_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	RevokedAt      *time.Time        `json:"revoked_at,omitempty"`
	RevokeReason   string            `json:"revoke_reason,omitempty"`
	Capabilities   AgentCapabilities `json:"capabilities"`
	Fingerprint    string            `json:"fingerprint"`

	mu       sync.Mutex
	auditLog []AuditEntry
}

// IssueOptions configures IssueAgentPassport. Required fields are AgentName,
// AgentType, OwnerOrg, OwnerEmail, and Capabilities.
type IssueOptions struct {
	AgentName      string
	AgentType      string
	OwnerOrg       string
	OwnerEmail     string
	Capabilities   AgentCapabilities
	Model          string
	Version        string
	ExpiresIn      time.Duration // defaults to 24h
	ParentPassport *AgentPassport
}

// IssueAgentPassport mints a new AgentPassport. When a ParentPassport is
// provided it must be trusted and have CanSpawnAgents=true, mirroring the
// Python SDK's parent-child trust chain.
func IssueAgentPassport(opts IssueOptions) (*AgentPassport, error) {
	if opts.AgentName == "" || opts.OwnerOrg == "" || opts.OwnerEmail == "" {
		return nil, fmt.Errorf("%w: agent_name, owner_org and owner_email are required", ErrRegistration)
	}
	if opts.ParentPassport != nil {
		if !opts.ParentPassport.Capabilities.CanSpawnAgents {
			return nil, fmt.Errorf("%w: parent agent cannot spawn child agents", ErrTrust)
		}
		if !opts.ParentPassport.IsTrusted() {
			return nil, fmt.Errorf("%w: parent agent is not trusted", ErrTrust)
		}
	}
	expires := opts.ExpiresIn
	if expires <= 0 {
		expires = 24 * time.Hour
	}
	if opts.Version == "" {
		opts.Version = "1.0.0"
	}
	if opts.Model == "" {
		opts.Model = "unknown"
	}
	if opts.AgentType == "" {
		opts.AgentType = "general"
	}

	now := time.Now().UTC()
	agentID, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRegistration, err)
	}
	p := &AgentPassport{
		AgentID:      agentID,
		AgentName:    opts.AgentName,
		AgentType:    opts.AgentType,
		OwnerOrg:     opts.OwnerOrg,
		OwnerEmail:   opts.OwnerEmail,
		Model:        opts.Model,
		Version:      opts.Version,
		Status:       StatusActive,
		TrustLevel:   opts.Capabilities.TrustLevel,
		IssuedAt:     now,
		ExpiresAt:    now.Add(expires),
		Capabilities: opts.Capabilities,
	}
	if opts.ParentPassport != nil {
		p.ParentAgentID = opts.ParentPassport.AgentID
	}
	p.Fingerprint = computeFingerprint(p.AgentID, p.AgentName, p.OwnerOrg, p.IssuedAt)
	p.LogAction("passport_issued", map[string]any{"agent_name": opts.AgentName}, OutcomeSuccess)
	return p, nil
}

// LogAction appends an entry to the immutable audit trail. Returns the entry
// written so callers can record its log_id.
func (p *AgentPassport) LogAction(action string, details map[string]any, outcome ActionOutcome) AuditEntry {
	if outcome == "" {
		outcome = OutcomeSuccess
	}
	logID, _ := newUUID()
	entry := AuditEntry{
		LogID:     logID,
		AgentID:   p.AgentID,
		Action:    action,
		Details:   details,
		Outcome:   outcome,
		Timestamp: time.Now().UTC(),
	}
	p.mu.Lock()
	p.auditLog = append(p.auditLog, entry)
	p.mu.Unlock()
	return entry
}

// VerifyAction returns true iff the passport is trusted and the capability
// for the action is granted. A negative result writes a blocked entry to the
// audit log with a reason, matching the Python SDK behaviour.
func (p *AgentPassport) VerifyAction(action Action) bool {
	if !p.IsTrusted() {
		p.LogAction(string(action), map[string]any{"reason": "passport_invalid"}, OutcomeBlocked)
		return false
	}
	if !p.Capabilities.Allows(action) {
		p.LogAction(string(action), map[string]any{"reason": "capability_not_granted"}, OutcomeBlocked)
		return false
	}
	return true
}

// Revoke immediately moves the passport to revoked status. Subsequent
// IsTrusted/VerifyAction calls will fail.
func (p *AgentPassport) Revoke(reason string) {
	if reason == "" {
		reason = "Manual revocation"
	}
	now := time.Now().UTC()
	p.mu.Lock()
	p.Status = StatusRevoked
	p.RevokedAt = &now
	p.RevokeReason = reason
	p.mu.Unlock()
	p.LogAction("passport_revoked", map[string]any{"reason": reason}, OutcomeSuccess)
}

// IsTrusted reports whether the passport is active and not expired. Expiry
// flips the status to expired the first time it is observed.
func (p *AgentPassport) IsTrusted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Status != StatusActive {
		return false
	}
	if !p.ExpiresAt.IsZero() && time.Now().UTC().After(p.ExpiresAt) {
		p.Status = StatusExpired
		return false
	}
	return true
}

// AuditLog returns a defensive copy of the full immutable audit trail.
func (p *AgentPassport) AuditLog() []AuditEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]AuditEntry, len(p.auditLog))
	copy(out, p.auditLog)
	return out
}

// Summary is a compact view suitable for dashboards and JSON exports.
type Summary struct {
	AgentID       string      `json:"agent_id"`
	AgentName     string      `json:"agent_name"`
	OwnerOrg      string      `json:"owner_org"`
	Model         string      `json:"model"`
	Status        AgentStatus `json:"status"`
	TrustLevel    TrustLevel  `json:"trust_level"`
	IssuedAt      time.Time   `json:"issued_at"`
	ExpiresAt     time.Time   `json:"expires_at"`
	ActionsLogged int         `json:"actions_logged"`
	Fingerprint   string      `json:"fingerprint"`
}

// Summary returns a compact snapshot of the passport.
func (p *AgentPassport) Summary() Summary {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Summary{
		AgentID:       p.AgentID,
		AgentName:     p.AgentName,
		OwnerOrg:      p.OwnerOrg,
		Model:         p.Model,
		Status:        p.Status,
		TrustLevel:    p.TrustLevel,
		IssuedAt:      p.IssuedAt,
		ExpiresAt:     p.ExpiresAt,
		ActionsLogged: len(p.auditLog),
		Fingerprint:   p.Fingerprint,
	}
}

type exportedPassport struct {
	Summary
	Capabilities AgentCapabilities `json:"capabilities"`
	AuditLog     []AuditEntry      `json:"audit_log"`
	ParentAgent  string            `json:"parent_agent_id,omitempty"`
	RevokedAt    *time.Time        `json:"revoked_at,omitempty"`
	RevokeReason string            `json:"revoke_reason,omitempty"`
}

// Export serialises the passport to JSON. Round-trips through Load.
func (p *AgentPassport) Export() ([]byte, error) {
	p.mu.Lock()
	logs := make([]AuditEntry, len(p.auditLog))
	copy(logs, p.auditLog)
	p.mu.Unlock()
	return json.MarshalIndent(exportedPassport{
		Summary:      p.Summary(),
		Capabilities: p.Capabilities,
		AuditLog:     logs,
		ParentAgent:  p.ParentAgentID,
		RevokedAt:    p.RevokedAt,
		RevokeReason: p.RevokeReason,
	}, "", "  ")
}

// LoadAgentPassport rebuilds a passport previously serialised by Export.
func LoadAgentPassport(data []byte) (*AgentPassport, error) {
	var x exportedPassport
	if err := json.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRegistration, err)
	}
	p := &AgentPassport{
		AgentID:       x.AgentID,
		AgentName:     x.AgentName,
		AgentType:     "general",
		OwnerOrg:      x.OwnerOrg,
		Model:         x.Model,
		Version:       "1.0.0",
		Status:        x.Status,
		TrustLevel:    x.TrustLevel,
		IssuedAt:      x.IssuedAt,
		ExpiresAt:     x.ExpiresAt,
		Capabilities:  x.Capabilities,
		Fingerprint:   x.Fingerprint,
		ParentAgentID: x.ParentAgent,
		RevokedAt:     x.RevokedAt,
		RevokeReason:  x.RevokeReason,
		auditLog:      x.AuditLog,
	}
	return p, nil
}

// String returns a short debug representation, mirroring Python __repr__.
func (p *AgentPassport) String() string {
	short := p.AgentID
	if len(short) > 8 {
		short = short[:8]
	}
	return fmt.Sprintf("<AgentPassport %s... | %s | %s | %s>",
		short, p.AgentName, p.TrustLevel, p.Status)
}

func computeFingerprint(parts ...any) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprint(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// newUUID returns an RFC-4122 v4 UUID built from crypto/rand. Implemented
// inline so the SDK has no third-party dependencies.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
