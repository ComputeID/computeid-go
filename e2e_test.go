package computeid_test

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ComputeID/computeid-go"
	"github.com/ComputeID/computeid-go/server"
)

// E2E: drive the SDK *Client against a real *server backed by real Postgres
// and assert the wire contract holds end-to-end.

// Different DB than the server package's tests so `go test ./...` can run
// both binaries in parallel without colliding on schema resets.
const e2eDefaultDB = "postgres://leadpilot:leadpilot@localhost:5439/computeid_test_e2e?sslmode=disable"

func e2eTestServer(t *testing.T) (*computeid.Client, func()) {
	t.Helper()
	if os.Getenv("COMPUTEID_SKIP_INTEGRATION") == "1" {
		t.Skip("COMPUTEID_SKIP_INTEGRATION=1")
	}
	url := os.Getenv("COMPUTEID_TEST_DATABASE_URL")
	if url == "" {
		url = e2eDefaultDB
	}
	ctx := context.Background()
	db, err := server.ConnectPostgres(ctx, url)
	if err != nil {
		t.Skipf("could not reach test Postgres at %s — skipping. err=%v", url, err)
	}
	if _, err := db.Exec(ctx, `
		DROP TABLE IF EXISTS agent_actions, agents,
		                     devices, device_counters,
		                     signing_keys, schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := server.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	srv, err := server.New(ctx, server.Config{
		DB:        db,
		JWTSecret: "e2e",
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())

	c := computeid.NewClient(computeid.WithBaseURL(ts.URL))
	return c, func() { ts.Close(); db.Close() }
}

func TestE2E_FullLifecycle(t *testing.T) {
	client, cleanup := e2eTestServer(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Issue
	sp, err := client.RegisterAgent(ctx, computeid.AgentRegistration{
		Name:         "ResearchAgent",
		Description:  "Summarises market research",
		Organization: "Acme Corp",
		Capabilities: []string{"read", "web_browse", "api_call"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if sp.PassportID == "" {
		t.Fatal("no passport_id")
	}
	if sp.SignatureAlgorithm != "RSA-SHA256" {
		t.Errorf("signature_algorithm: %s", sp.SignatureAlgorithm)
	}

	// 2. Gate — verify must return active + signature_valid.
	v, err := client.VerifyAgent(ctx, sp.PassportID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.IsTrusted() {
		t.Fatalf("not trusted: status=%s signature_valid=%t", v.Status, v.SignatureValid)
	}

	// 3. Capability check (granted)
	c, err := client.CheckCapability(ctx, sp.PassportID, "web_browse")
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	if !c.Granted {
		t.Errorf("web_browse should be granted")
	}

	// 4. Log an action
	if err := client.LogAgentAction(ctx, sp.PassportID, computeid.LogActionRequest{
		Action:  "web_search",
		Details: map[string]any{"query": "GPU prices"},
		Outcome: "success",
	}); err != nil {
		t.Fatalf("log action: %v", err)
	}

	// 5. Read back
	actions, err := client.ListAgentActions(ctx, sp.PassportID, 10)
	if err != nil {
		t.Fatalf("list actions: %v", err)
	}
	if len(actions) < 2 {
		t.Errorf("audit log: %d entries want >=2", len(actions))
	}

	// 6. List filter
	active, err := client.ListAgents(ctx, "active")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 1 {
		t.Errorf("active agents: %d want 1", len(active))
	}

	// 7. Revoke
	if err := client.RevokeAgent(ctx, sp.PassportID, "Task complete"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// 8. After revoke — signature still valid, status revoked.
	v, _ = client.VerifyAgent(ctx, sp.PassportID)
	if v.Status != "revoked" {
		t.Errorf("status: %s want revoked", v.Status)
	}
	if !v.SignatureValid {
		t.Error("signature_valid should remain true after revoke (PDF rule)")
	}
	if v.IsTrusted() {
		t.Error("IsTrusted() must be false after revoke")
	}

	// 9. Capability after revoke
	c, _ = client.CheckCapability(ctx, sp.PassportID, "web_browse")
	if c.Granted {
		t.Error("capability should be denied after revoke")
	}
	if c.Reason != "passport_revoked" {
		t.Errorf("reason: %s want passport_revoked", c.Reason)
	}
}

func TestE2E_DeviceLifecycle(t *testing.T) {
	client, cleanup := e2eTestServer(t)
	defer cleanup()
	ctx := context.Background()

	dev, err := client.RegisterDevice(ctx, computeid.RegisterDeviceRequest{
		Name: "NVIDIA A100", DeviceType: "GPU", IPAddress: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !dev.IsPending() {
		t.Errorf("status: %s want pending", dev.Status)
	}
	if dev.DeviceCode != "GPU-001" {
		t.Errorf("device_code: %s want GPU-001", dev.DeviceCode)
	}

	// Cannot auth while pending.
	if _, err := client.AuthenticateDevice(ctx, dev.DeviceCode); err == nil {
		t.Error("auth should fail while pending")
	}
}

func TestE2E_APIErrorTyping(t *testing.T) {
	client, cleanup := e2eTestServer(t)
	defer cleanup()
	ctx := context.Background()

	_, err := client.VerifyAgent(ctx, "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error verifying nonexistent passport")
	}
	// The SDK surfaces APIError for non-2xx.
	var apiErr *computeid.APIError
	if !asErr(err, &apiErr) {
		t.Fatalf("expected *computeid.APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 404 {
		t.Errorf("status: %d want 404", apiErr.StatusCode)
	}
}

// asErr is errors.As but inlined to avoid importing errors here.
func asErr[T error](err error, target *T) bool {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if t, ok := err.(T); ok {
			*target = t
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
