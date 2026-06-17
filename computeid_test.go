package computeid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCapabilityPresets(t *testing.T) {
	cases := []struct {
		name  string
		caps  AgentCapabilities
		level TrustLevel
		can   []Action
		cant  []Action
	}{
		{"restricted", RestrictedCapabilities(), TrustRestricted,
			[]Action{ActionCallAPI},
			[]Action{ActionBrowseWeb, ActionExecuteCode, ActionSpawnAgent}},
		{"standard", StandardCapabilities(), TrustStandard,
			[]Action{ActionBrowseWeb, ActionCallAPI, ActionAccessFiles},
			[]Action{ActionExecuteCode, ActionSpawnAgent, ActionSendEmail}},
		{"elevated", ElevatedCapabilities(), TrustElevated,
			[]Action{ActionBrowseWeb, ActionExecuteCode, ActionSpawnAgent},
			[]Action{ActionSendEmail, ActionAccessDatabase}},
		{"autonomous", AutonomousCapabilities(), TrustAutonomous,
			[]Action{ActionExecuteCode, ActionSendEmail, ActionAccessDatabase},
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.caps.TrustLevel != c.level {
				t.Fatalf("trust level: got %s want %s", c.caps.TrustLevel, c.level)
			}
			for _, a := range c.can {
				if !c.caps.Allows(a) {
					t.Errorf("expected %s to allow %s", c.name, a)
				}
			}
			for _, a := range c.cant {
				if c.caps.Allows(a) {
					t.Errorf("expected %s to deny %s", c.name, a)
				}
			}
		})
	}
}

func TestIssueAgentPassportRequiresFields(t *testing.T) {
	_, err := IssueAgentPassport(IssueOptions{Capabilities: StandardCapabilities()})
	if !errors.Is(err, ErrRegistration) {
		t.Fatalf("expected ErrRegistration, got %v", err)
	}
}

func TestAgentPassportLifecycle(t *testing.T) {
	p, err := IssueAgentPassport(IssueOptions{
		AgentName:    "ResearchAgent",
		AgentType:    "researcher",
		OwnerOrg:     "Acme Corp",
		OwnerEmail:   "admin@acme.com",
		Capabilities: StandardCapabilities(),
		Model:        "claude-sonnet-4-6",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !p.IsTrusted() {
		t.Fatal("freshly issued passport should be trusted")
	}
	if !p.VerifyAction(ActionBrowseWeb) {
		t.Fatal("standard caps should allow browse_web")
	}
	if p.VerifyAction(ActionExecuteCode) {
		t.Fatal("standard caps should deny execute_code")
	}
	p.LogAction("web_search", map[string]any{"query": "GPU prices"}, OutcomeSuccess)
	// Successful VerifyAction does not log (Python parity); blocked + issue + manual = 3.
	log := p.AuditLog()
	if len(log) < 3 {
		t.Fatalf("expected >=3 audit entries (issue + blocked-execute + manual), got %d", len(log))
	}
	var sawBlocked bool
	for _, e := range log {
		if e.Outcome == OutcomeBlocked && e.Action == string(ActionExecuteCode) {
			sawBlocked = true
		}
	}
	if !sawBlocked {
		t.Fatal("expected a blocked execute_code audit entry")
	}

	p.Revoke("test")
	if p.IsTrusted() {
		t.Fatal("revoked passport must not be trusted")
	}
	if p.VerifyAction(ActionBrowseWeb) {
		t.Fatal("revoked passport must deny all actions")
	}
}

func TestAgentPassportExpiry(t *testing.T) {
	p, err := IssueAgentPassport(IssueOptions{
		AgentName:    "ShortLived",
		AgentType:    "test",
		OwnerOrg:     "Acme",
		OwnerEmail:   "a@b.com",
		Capabilities: StandardCapabilities(),
		ExpiresIn:    1 * time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if p.IsTrusted() {
		t.Fatal("expired passport should not be trusted")
	}
	if p.Status != StatusExpired {
		t.Fatalf("status should be expired, got %s", p.Status)
	}
}

func TestParentChildTrustChain(t *testing.T) {
	orchestrator, err := IssueAgentPassport(IssueOptions{
		AgentName:    "Orchestrator",
		AgentType:    "orchestrator",
		OwnerOrg:     "Acme",
		OwnerEmail:   "a@b.com",
		Capabilities: ElevatedCapabilities(),
	})
	if err != nil {
		t.Fatalf("orchestrator: %v", err)
	}
	child, err := IssueAgentPassport(IssueOptions{
		AgentName:      "Worker",
		AgentType:      "worker",
		OwnerOrg:       "Acme",
		OwnerEmail:     "a@b.com",
		Capabilities:   StandardCapabilities(),
		ParentPassport: orchestrator,
	})
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	if child.ParentAgentID != orchestrator.AgentID {
		t.Fatal("child should record parent agent id")
	}

	noSpawn, _ := IssueAgentPassport(IssueOptions{
		AgentName:    "Restricted",
		AgentType:    "general",
		OwnerOrg:     "Acme",
		OwnerEmail:   "a@b.com",
		Capabilities: RestrictedCapabilities(),
	})
	_, err = IssueAgentPassport(IssueOptions{
		AgentName:      "ShouldFail",
		AgentType:      "general",
		OwnerOrg:       "Acme",
		OwnerEmail:     "a@b.com",
		Capabilities:   StandardCapabilities(),
		ParentPassport: noSpawn,
	})
	if !errors.Is(err, ErrTrust) {
		t.Fatalf("expected ErrTrust when parent cannot spawn, got %v", err)
	}
}

func TestExportLoad(t *testing.T) {
	p, _ := IssueAgentPassport(IssueOptions{
		AgentName:    "ExportTest",
		AgentType:    "test",
		OwnerOrg:     "Acme",
		OwnerEmail:   "a@b.com",
		Capabilities: ElevatedCapabilities(),
	})
	p.LogAction("test_action", map[string]any{"k": "v"}, OutcomeSuccess)
	data, err := p.Export()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	loaded, err := LoadAgentPassport(data)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.AgentID != p.AgentID || loaded.AgentName != p.AgentName {
		t.Fatal("round-trip identity mismatch")
	}
	if len(loaded.AuditLog()) != len(p.AuditLog()) {
		t.Fatal("round-trip audit log mismatch")
	}
}

func TestPassportOffice(t *testing.T) {
	office := NewPassportOffice("Acme Corp", "")
	a, _ := IssueAgentPassport(IssueOptions{
		AgentName:    "A", AgentType: "t", OwnerOrg: "Acme",
		OwnerEmail: "a@b.com", Capabilities: StandardCapabilities(),
	})
	b, _ := IssueAgentPassport(IssueOptions{
		AgentName:    "B", AgentType: "t", OwnerOrg: "Acme",
		OwnerEmail: "a@b.com", Capabilities: StandardCapabilities(),
	})
	office.RegisterAgent(a)
	office.RegisterAgent(b)
	office.RegisterDevice(&DevicePassport{
		DeviceID:   "dev-1",
		DeviceCode: "GPU-001",
		Name:       "A100",
		Status:     DeviceStatusActive,
	})

	if !office.IsTrusted(a.AgentID) {
		t.Fatal("agent A should be trusted")
	}
	if !office.RevokeAgent(b.AgentID, "test") {
		t.Fatal("revoke should report success")
	}
	if office.IsTrusted(b.AgentID) {
		t.Fatal("revoked agent should not be trusted")
	}

	rep := office.AuditReport()
	if rep.TotalAgents != 2 || rep.ActiveAgents != 1 {
		t.Fatalf("audit counts: total=%d active=%d", rep.TotalAgents, rep.ActiveAgents)
	}
	if rep.TotalDevices != 1 || rep.ActiveDevices != 1 {
		t.Fatalf("device counts: total=%d active=%d", rep.TotalDevices, rep.ActiveDevices)
	}
}

func TestClient_RegisterAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/register" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "test-key" {
			t.Errorf("missing api key, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"passport_id":         "128079cb-9aa2-49ac-94ff-5f7c87f4c5a5",
			"name":                "ResearchAgent",
			"organization":        "Acme Corp",
			"status":              "active",
			"public_key":          "-----BEGIN PUBLIC KEY-----",
			"signature":           "abc",
			"signature_algorithm": "RSA-SHA256",
			"capabilities":        []string{"read", "web_browse"},
			"issued_at":           time.Now().UTC().Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL), WithAPIKey("test-key"))
	got, err := c.RegisterAgent(context.Background(), AgentRegistration{
		Name: "ResearchAgent", Organization: "Acme Corp",
		Capabilities: []string{"read", "web_browse"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got.PassportID == "" || got.Status != "active" {
		t.Fatalf("bad response: %+v", got)
	}
}

func TestClient_VerifyAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/verify") {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"passport_id":     "abc",
			"status":          "active",
			"signature_valid": true,
			"capabilities":    []string{"read"},
		})
	}))
	defer srv.Close()
	c := NewClient(WithBaseURL(srv.URL))
	v, err := c.VerifyAgent(context.Background(), "abc")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.IsTrusted() {
		t.Fatal("verification should report trusted")
	}
}

func TestClient_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad key"})
	}))
	defer srv.Close()
	c := NewClient(WithBaseURL(srv.URL), WithAPIKey("nope"))
	_, err := c.RegisterAgent(context.Background(), AgentRegistration{Name: "x", Organization: "y"})
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
	if !strings.Contains(err.Error(), "bad key") {
		t.Fatalf("expected error to surface server message, got %v", err)
	}
}

func TestClient_LogAndListActions(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			posted = true
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"actions": []map[string]any{
					{"action_id": "1", "action": "web_search", "outcome": "success",
						"timestamp": time.Now().UTC().Format(time.RFC3339)},
				},
			})
		}
	}))
	defer srv.Close()
	c := NewClient(WithBaseURL(srv.URL))
	ctx := context.Background()
	if err := c.LogAgentAction(ctx, "abc", LogActionRequest{Action: "web_search", Outcome: "success"}); err != nil {
		t.Fatalf("log: %v", err)
	}
	if !posted {
		t.Fatal("expected POST")
	}
	logs, err := c.ListAgentActions(ctx, "abc", 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(logs) != 1 || logs[0].Action != "web_search" {
		t.Fatalf("unexpected logs: %+v", logs)
	}
}

func TestClient_RegisterDevice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/devices/register" {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": "d1", "device_code": "GPU-001",
			"name": "A100", "type": "GPU", "status": "pending",
		})
	}))
	defer srv.Close()
	c := NewClient(WithBaseURL(srv.URL))
	dev, err := c.RegisterDevice(context.Background(), RegisterDeviceRequest{
		Name: "A100", DeviceType: "GPU", IPAddress: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !dev.IsPending() || dev.IsValid() {
		t.Fatalf("expected pending, got %+v", dev)
	}
}

// TestClient_PDFExactResponseShapes locks the wire contract to the response
// payloads shown in the official Integration Guide PDF. If the server ever
// reshapes these, this test surfaces it loudly.
func TestClient_PDFExactResponseShapes(t *testing.T) {
	// Verbatim from the PDF page 1, 201 response body.
	registerBody := `{
      "passport_id": "128079cb-9aa2-49ac-94ff-5f7c87f4c5a5",
      "status": "active",
      "signature_algorithm": "RSA-SHA256",
      "signature": "QeTTEA0G401Iyn1wqQ0eN7+...",
      "capabilities": ["read", "web_browse", "api_call"],
      "issued_at": "2026-06-12T08:03:14.973Z"
    }`

	// Verbatim shape from PDF page 2 (Python integration code path).
	verifyBody := `{"status": "active", "signature_valid": true,
                    "capabilities": ["read", "web_browse", "api_call"]}`

	capGrantedBody := `{"granted": true}`
	capRevokedBody := `{"granted": false, "reason": "passport_revoked"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(registerBody))
		case strings.HasSuffix(r.URL.Path, "/verify"):
			_, _ = w.Write([]byte(verifyBody))
		case strings.HasSuffix(r.URL.Path, "/capabilities/web_browse"):
			_, _ = w.Write([]byte(capGrantedBody))
		case strings.HasSuffix(r.URL.Path, "/capabilities/send_email"):
			_, _ = w.Write([]byte(capRevokedBody))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	ctx := context.Background()

	sp, err := c.RegisterAgent(ctx, AgentRegistration{
		Name: "ResearchAgent", Organization: "Acme Corp",
		Capabilities: []string{"read", "web_browse", "api_call"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if sp.PassportID != "128079cb-9aa2-49ac-94ff-5f7c87f4c5a5" {
		t.Errorf("passport_id: %s", sp.PassportID)
	}
	if sp.Status != "active" {
		t.Errorf("status: %s", sp.Status)
	}
	if sp.SignatureAlgorithm != "RSA-SHA256" {
		t.Errorf("signature_algorithm: %s", sp.SignatureAlgorithm)
	}
	if len(sp.Capabilities) != 3 || sp.Capabilities[1] != "web_browse" {
		t.Errorf("capabilities: %v", sp.Capabilities)
	}
	wantIssued, _ := time.Parse(time.RFC3339Nano, "2026-06-12T08:03:14.973Z")
	if !sp.IssuedAt.Equal(wantIssued) {
		t.Errorf("issued_at: got %s want %s", sp.IssuedAt, wantIssued)
	}
	// PDF response omits these fields — they MUST decode as zero values.
	if sp.Name != "" || sp.Organization != "" || sp.PublicKey != "" {
		t.Errorf("optional fields should be zero when absent: %+v", sp)
	}

	v, err := c.VerifyAgent(ctx, sp.PassportID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// PDF authorization rule: status == "active" AND signature_valid == true.
	if !v.IsTrusted() {
		t.Fatal("IsTrusted() must be true when status=active && signature_valid=true")
	}

	grant, err := c.CheckCapability(ctx, sp.PassportID, "web_browse")
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	if !grant.Granted {
		t.Fatal("web_browse should be granted")
	}

	revoked, err := c.CheckCapability(ctx, sp.PassportID, "send_email")
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	// PDF: "After revocation, every capability check returns granted=false
	// with reason 'passport_revoked'."
	if revoked.Granted || revoked.Reason != "passport_revoked" {
		t.Fatalf("revoked check: %+v", revoked)
	}
}

func TestVerificationResult_IsTrustedRules(t *testing.T) {
	cases := []struct {
		v    VerificationResult
		want bool
	}{
		{VerificationResult{Status: "active", SignatureValid: true}, true},
		{VerificationResult{Status: "active", SignatureValid: false}, false}, // independent fields
		{VerificationResult{Status: "revoked", SignatureValid: true}, false}, // revoked retains sig
		{VerificationResult{Status: "revoked", SignatureValid: false}, false},
		{VerificationResult{Status: "expired", SignatureValid: true}, false},
	}
	for _, c := range cases {
		if got := c.v.IsTrusted(); got != c.want {
			t.Errorf("IsTrusted(%+v) = %v want %v", c.v, got, c.want)
		}
	}
}

func TestClient_RevokeURLAndPayload(t *testing.T) {
	var seen struct {
		method string
		path   string
		body   string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.URL.Path
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		seen.body = string(buf[:n])
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewClient(WithBaseURL(srv.URL))
	if err := c.RevokeAgent(context.Background(),
		"128079cb-9aa2-49ac-94ff-5f7c87f4c5a5", "Task complete"); err != nil {
		t.Fatal(err)
	}
	if seen.method != http.MethodDelete {
		t.Errorf("method: %s", seen.method)
	}
	if !strings.HasSuffix(seen.path, "/revoke") {
		t.Errorf("path: %s", seen.path)
	}
	if !strings.Contains(seen.body, `"reason":"Task complete"`) {
		t.Errorf("body: %s", seen.body)
	}
}

func TestClient_ListAgentsStatusFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"agents":[]}`))
	}))
	defer srv.Close()
	c := NewClient(WithBaseURL(srv.URL))
	if _, err := c.ListAgents(context.Background(), "active"); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "status=active" {
		t.Errorf("query: %s", gotQuery)
	}
}

func TestRequirePassportWrapper(t *testing.T) {
	p, _ := IssueAgentPassport(IssueOptions{
		AgentName: "wrap", AgentType: "t", OwnerOrg: "Acme",
		OwnerEmail: "a@b.com", Capabilities: StandardCapabilities(),
	})
	search := RequirePassport(ActionBrowseWeb,
		func(p *AgentPassport, q string) (string, error) {
			return "results for " + q, nil
		})
	out, err := search(p, "GPU prices")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out != "results for GPU prices" {
		t.Fatalf("bad output: %s", out)
	}

	_, err = search(nil, "x")
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}

	denied, _ := IssueAgentPassport(IssueOptions{
		AgentName: "denied", AgentType: "t", OwnerOrg: "Acme",
		OwnerEmail: "a@b.com", Capabilities: RestrictedCapabilities(),
	})
	_, err = search(denied, "x")
	if !errors.Is(err, ErrTrust) {
		t.Fatalf("expected ErrTrust, got %v", err)
	}
}
