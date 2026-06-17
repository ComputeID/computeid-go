package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// httpFixture wires a Server + httptest.Server for HTTP-level integration tests.
type httpFixture struct {
	srv  *Server
	http *httptest.Server
}

func newFixture(t *testing.T) *httpFixture {
	t.Helper()
	srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &httpFixture{srv: srv, http: ts}
}

func (f *httpFixture) do(t *testing.T, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, f.http.URL+path, rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, raw
}

// -------------------- /health --------------------

func TestIntegration_Health(t *testing.T) {
	f := newFixture(t)
	resp, raw := f.do(t, "GET", "/health", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d body=%s", resp.StatusCode, raw)
	}
	var body map[string]any
	mustJSON(t, raw, &body)
	if body["status"] != "ok" {
		t.Errorf("status: %v", body["status"])
	}
	if body["algorithm"] != "RSA-SHA256" {
		t.Errorf("algorithm: %v", body["algorithm"])
	}
}

// -------------------- agent register + verify + capability --------------------

func TestIntegration_AgentRegister_ReturnsPDFWireShape(t *testing.T) {
	f := newFixture(t)

	resp, raw := f.do(t, "POST", "/v1/agents/register", map[string]any{
		"name":         "ResearchAgent",
		"organization": "Acme Corp",
		"description":  "Summarises market research",
		"capabilities": []string{"read", "web_browse", "api_call"},
	})
	if resp.StatusCode != 201 {
		t.Fatalf("status: %d body=%s", resp.StatusCode, raw)
	}
	var out AgentPassportResponse
	mustJSON(t, raw, &out)

	// PDF wire contract (page 1).
	if out.PassportID == "" {
		t.Error("passport_id missing")
	}
	if out.Status != "active" {
		t.Errorf("status: %s", out.Status)
	}
	if out.SignatureAlgorithm != "RSA-SHA256" {
		t.Errorf("signature_algorithm: %s", out.SignatureAlgorithm)
	}
	if _, err := base64.StdEncoding.DecodeString(out.Signature); err != nil {
		t.Errorf("signature is not valid base64: %v", err)
	}
	wantCaps := []string{"read", "web_browse", "api_call"}
	if !sameStrings(out.Capabilities, wantCaps) {
		t.Errorf("capabilities: got %v want %v", out.Capabilities, wantCaps)
	}
	if out.IssuedAt.IsZero() {
		t.Error("issued_at zero")
	}
	if out.IssuedAt.Location() != time.UTC {
		t.Errorf("issued_at not UTC: %s", out.IssuedAt.Location())
	}
	if !strings.HasPrefix(out.PublicKey, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("public_key not PEM: %.40s", out.PublicKey)
	}
}

func TestIntegration_AgentVerify_ActiveSignatureValid(t *testing.T) {
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read", "web_browse"})

	resp, raw := f.do(t, "GET", "/v1/agents/"+pid+"/verify", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("verify status: %d body=%s", resp.StatusCode, raw)
	}
	var v VerifyResponse
	mustJSON(t, raw, &v)
	if v.Status != "active" {
		t.Errorf("status: %s", v.Status)
	}
	if !v.SignatureValid {
		t.Errorf("signature_valid should be true on fresh issue (body=%s)", raw)
	}
}

func TestIntegration_AgentVerify_RevokedKeepsValidSignature(t *testing.T) {
	// PDF rule: "a revoked passport retains a valid signature because it was
	// legitimately issued."
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read"})

	if resp, raw := f.do(t, "DELETE", "/v1/agents/"+pid+"/revoke",
		map[string]string{"reason": "test"}); resp.StatusCode != 200 {
		t.Fatalf("revoke: %d body=%s", resp.StatusCode, raw)
	}

	_, raw := f.do(t, "GET", "/v1/agents/"+pid+"/verify", nil)
	var v VerifyResponse
	mustJSON(t, raw, &v)
	if v.Status != "revoked" {
		t.Errorf("status: %s want revoked", v.Status)
	}
	if !v.SignatureValid {
		t.Errorf("signature_valid should remain true after revoke (body=%s)", raw)
	}
}

func TestIntegration_AgentVerify_NotFound(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.do(t, "GET", "/v1/agents/00000000-0000-0000-0000-000000000000/verify", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("status: %d want 404", resp.StatusCode)
	}
}

func TestIntegration_CapabilityGranted(t *testing.T) {
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read", "web_browse"})

	_, raw := f.do(t, "GET", "/v1/agents/"+pid+"/capabilities/web_browse", nil)
	var c CapabilityResponse
	mustJSON(t, raw, &c)
	if !c.Granted {
		t.Errorf("granted: false body=%s", raw)
	}
	if c.Capability != "web_browse" {
		t.Errorf("capability: %s", c.Capability)
	}
}

func TestIntegration_CapabilityNotFound(t *testing.T) {
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read"})
	_, raw := f.do(t, "GET", "/v1/agents/"+pid+"/capabilities/execute_code", nil)
	var c CapabilityResponse
	mustJSON(t, raw, &c)
	if c.Granted {
		t.Error("expected granted=false")
	}
	if c.Reason != "capability_not_found" {
		t.Errorf("reason: %s", c.Reason)
	}
}

func TestIntegration_CapabilityAfterRevoke(t *testing.T) {
	// PDF rule: "After revocation, every capability check returns
	// granted=false with reason 'passport_revoked'."
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read", "web_browse"})
	f.do(t, "DELETE", "/v1/agents/"+pid+"/revoke", map[string]string{"reason": "test"})

	for _, cap := range []string{"read", "web_browse", "anything_at_all"} {
		_, raw := f.do(t, "GET", "/v1/agents/"+pid+"/capabilities/"+cap, nil)
		var c CapabilityResponse
		mustJSON(t, raw, &c)
		if c.Granted {
			t.Errorf("%s should be denied after revoke", cap)
		}
		if c.Reason != "passport_revoked" {
			t.Errorf("%s reason: %s want passport_revoked", cap, c.Reason)
		}
	}
}

// -------------------- audit trail --------------------

func TestIntegration_LogAndListActions(t *testing.T) {
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read"})

	resp, _ := f.do(t, "POST", "/v1/agents/"+pid+"/actions", map[string]any{
		"action":  "web_search",
		"details": map[string]any{"query": "GPU prices"},
		"outcome": "success",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("log: %d", resp.StatusCode)
	}

	_, raw := f.do(t, "GET", "/v1/agents/"+pid+"/actions?limit=10", nil)
	var list ListActionsResponse
	mustJSON(t, raw, &list)
	// Expect: passport_issued (from register) + web_search.
	if len(list.Actions) != 2 {
		t.Fatalf("audit actions: got %d want 2: %s", len(list.Actions), raw)
	}
	// Newest first.
	if list.Actions[0].Action != "web_search" {
		t.Errorf("newest action should be web_search, got %s", list.Actions[0].Action)
	}
	for _, a := range list.Actions {
		if a.Timestamp.Location() != time.UTC {
			t.Errorf("action timestamp not UTC: %s", a.Timestamp.Location())
		}
	}
}

func TestIntegration_LogAction_BadOutcome(t *testing.T) {
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read"})
	resp, _ := f.do(t, "POST", "/v1/agents/"+pid+"/actions", map[string]any{
		"action":  "x",
		"outcome": "bogus",
	})
	if resp.StatusCode != 400 {
		t.Fatalf("status: %d want 400", resp.StatusCode)
	}
}

func TestIntegration_LogAction_PassportNotFound(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.do(t, "POST",
		"/v1/agents/00000000-0000-0000-0000-000000000000/actions",
		map[string]any{"action": "x"})
	if resp.StatusCode != 404 {
		t.Fatalf("status: %d want 404", resp.StatusCode)
	}
}

// -------------------- revoke + list --------------------

func TestIntegration_RevokeIsIdempotent(t *testing.T) {
	f := newFixture(t)
	pid := registerAgent(t, f, []string{"read"})
	r1, _ := f.do(t, "DELETE", "/v1/agents/"+pid+"/revoke", map[string]string{"reason": "a"})
	r2, _ := f.do(t, "DELETE", "/v1/agents/"+pid+"/revoke", map[string]string{"reason": "b"})
	// Both should succeed (200), second is a no-op (already revoked).
	if r1.StatusCode != 200 || r2.StatusCode != 200 {
		t.Fatalf("status: r1=%d r2=%d", r1.StatusCode, r2.StatusCode)
	}
}

func TestIntegration_ListAgents_StatusFilter(t *testing.T) {
	f := newFixture(t)
	a1 := registerAgent(t, f, []string{"read"})
	registerAgent(t, f, []string{"read"})
	f.do(t, "DELETE", "/v1/agents/"+a1+"/revoke", map[string]string{"reason": "t"})

	_, raw := f.do(t, "GET", "/v1/agents?status=active", nil)
	var got ListAgentsResponse
	mustJSON(t, raw, &got)
	if len(got.Agents) != 1 {
		t.Fatalf("active agents: %d want 1", len(got.Agents))
	}
	if got.Agents[0].Status != "active" {
		t.Errorf("status: %s", got.Agents[0].Status)
	}

	_, raw = f.do(t, "GET", "/v1/agents?status=revoked", nil)
	mustJSON(t, raw, &got)
	if len(got.Agents) != 1 || got.Agents[0].Status != "revoked" {
		t.Fatalf("revoked filter: got %d agents", len(got.Agents))
	}

	_, raw = f.do(t, "GET", "/v1/agents", nil)
	mustJSON(t, raw, &got)
	if len(got.Agents) != 2 {
		t.Fatalf("unfiltered: %d want 2", len(got.Agents))
	}
}

// -------------------- devices --------------------

func TestIntegration_DeviceLifecycle(t *testing.T) {
	f := newFixture(t)

	resp, raw := f.do(t, "POST", "/api/devices/register", map[string]any{
		"name":       "NVIDIA A100",
		"type":       "GPU",
		"ip_address": "10.0.0.1",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register: %d body=%s", resp.StatusCode, raw)
	}
	var dev DeviceResponse
	mustJSON(t, raw, &dev)
	if dev.Status != "pending" {
		t.Errorf("status: %s want pending", dev.Status)
	}
	if dev.DeviceCode != "GPU-001" {
		t.Errorf("device_code: %s want GPU-001", dev.DeviceCode)
	}

	// auth while pending → 403
	r2, _ := f.do(t, "POST", "/api/devices/authenticate",
		map[string]string{"device_code": dev.DeviceCode})
	if r2.StatusCode != 403 {
		t.Fatalf("auth pending: %d want 403", r2.StatusCode)
	}

	// approve
	r3, raw3 := f.do(t, "POST", "/api/devices/"+dev.DeviceID+"/approve", nil)
	if r3.StatusCode != 200 {
		t.Fatalf("approve: %d body=%s", r3.StatusCode, raw3)
	}

	// authenticate → JWT
	r4, raw4 := f.do(t, "POST", "/api/devices/authenticate",
		map[string]string{"device_code": dev.DeviceCode})
	if r4.StatusCode != 200 {
		t.Fatalf("auth active: %d body=%s", r4.StatusCode, raw4)
	}
	var auth DeviceAuthResponse
	mustJSON(t, raw4, &auth)
	if auth.AccessToken == "" {
		t.Error("access_token empty")
	}
	if auth.TokenType != "Bearer" {
		t.Errorf("token_type: %s", auth.TokenType)
	}
	claims, err := verifyJWT("test-jwt-secret", auth.AccessToken)
	if err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
	if claims["sub"] != dev.DeviceID {
		t.Errorf("sub claim: %v want %s", claims["sub"], dev.DeviceID)
	}
}

func TestIntegration_DeviceCode_AllocatesMonotonically(t *testing.T) {
	f := newFixture(t)
	for i, want := range []string{"GPU-001", "GPU-002", "GPU-003"} {
		_, raw := f.do(t, "POST", "/api/devices/register", map[string]any{
			"name": "A100", "type": "GPU", "ip_address": "x",
		})
		var dev DeviceResponse
		mustJSON(t, raw, &dev)
		if dev.DeviceCode != want {
			t.Errorf("iter %d: %s want %s", i, dev.DeviceCode, want)
		}
	}
}

func TestIntegration_DeviceCode_NormalizesType(t *testing.T) {
	// Server should up-case device type for the code (so "gpu" → "GPU-001").
	f := newFixture(t)
	_, raw := f.do(t, "POST", "/api/devices/register", map[string]any{
		"name": "T4", "type": "gpu", "ip_address": "x",
	})
	var dev DeviceResponse
	mustJSON(t, raw, &dev)
	if dev.DeviceCode != "GPU-001" {
		t.Errorf("device_code: %s want GPU-001 (case-folded prefix)", dev.DeviceCode)
	}
}

// -------------------- admin token gate --------------------

func TestIntegration_AdminToken_GatesApprove(t *testing.T) {
	if os.Getenv("COMPUTEID_SKIP_INTEGRATION") == "1" {
		t.Skip("COMPUTEID_SKIP_INTEGRATION=1")
	}
	db := testDB(t)
	srv, err := New(context.Background(), Config{
		DB:         db,
		JWTSecret:  "x",
		AdminToken: "letmein",
		Logger:     discardLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Register a device first.
	regResp, err := http.Post(ts.URL+"/api/devices/register", "application/json",
		strings.NewReader(`{"name":"A","type":"GPU","ip_address":"x"}`))
	if err != nil || regResp.StatusCode != 201 {
		t.Fatalf("register device: %v status=%d", err, regResp.StatusCode)
	}
	defer regResp.Body.Close()
	regRaw, _ := io.ReadAll(regResp.Body)
	var dev DeviceResponse
	mustJSON(t, regRaw, &dev)

	// Approve without token → 401.
	r, _ := http.Post(ts.URL+"/api/devices/"+dev.DeviceID+"/approve",
		"application/json", nil)
	if r.StatusCode != 401 {
		t.Errorf("no token: %d want 401", r.StatusCode)
	}

	// Wrong token → 401.
	req, _ := http.NewRequest("POST",
		ts.URL+"/api/devices/"+dev.DeviceID+"/approve", nil)
	req.Header.Set("X-Admin-Token", "nope")
	r, _ = http.DefaultClient.Do(req)
	if r.StatusCode != 401 {
		t.Errorf("wrong token: %d want 401", r.StatusCode)
	}

	// Correct token → 200.
	req, _ = http.NewRequest("POST",
		ts.URL+"/api/devices/"+dev.DeviceID+"/approve", nil)
	req.Header.Set("X-Admin-Token", "letmein")
	r, _ = http.DefaultClient.Do(req)
	if r.StatusCode != 200 {
		t.Errorf("correct token: %d want 200", r.StatusCode)
	}
}

// -------------------- helpers --------------------

func registerAgent(t *testing.T, f *httpFixture, capabilities []string) string {
	t.Helper()
	_, raw := f.do(t, "POST", "/v1/agents/register", map[string]any{
		"name":         "TestAgent",
		"organization": "Acme",
		"capabilities": capabilities,
	})
	var out AgentPassportResponse
	mustJSON(t, raw, &out)
	if out.PassportID == "" {
		t.Fatalf("register returned no passport_id: %s", raw)
	}
	return out.PassportID
}

func mustJSON(t *testing.T, raw []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode JSON: %v body=%s", err, raw)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
