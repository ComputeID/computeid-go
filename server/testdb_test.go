package server

import (
	"context"
	"os"
	"testing"
)

// defaultTestDatabaseURL points at the local leadpilot Postgres on port 5439.
// Override with COMPUTEID_TEST_DATABASE_URL to point at any other instance
// (e.g. a CI service container). The "_server" suffix isolates this package
// from the root e2e_test.go (they would otherwise race when `go test ./...`
// runs both binaries in parallel).
const defaultTestDatabaseURL = "postgres://leadpilot:leadpilot@localhost:5439/computeid_test_server?sslmode=disable"

// testDB connects to the integration-test database, wipes it clean, and
// re-runs all migrations. Tests using it should NOT use t.Parallel() — the
// table set is shared.
//
// To opt out (e.g. on a machine without Postgres) set
// COMPUTEID_SKIP_INTEGRATION=1 — tests using testDB will t.Skip.
func testDB(t *testing.T) DB {
	t.Helper()
	if os.Getenv("COMPUTEID_SKIP_INTEGRATION") == "1" {
		t.Skip("COMPUTEID_SKIP_INTEGRATION=1 — skipping real-DB integration test")
	}
	url := os.Getenv("COMPUTEID_TEST_DATABASE_URL")
	if url == "" {
		url = defaultTestDatabaseURL
	}

	ctx := context.Background()
	db, err := ConnectPostgres(ctx, url)
	if err != nil {
		t.Skipf("could not reach test Postgres at %s — skipping. (Set COMPUTEID_TEST_DATABASE_URL or COMPUTEID_SKIP_INTEGRATION=1.) err=%v", url, err)
	}
	t.Cleanup(db.Close)

	// Drop every table the migrations create so the test starts cold.
	_, err = db.Exec(ctx, `
		DROP TABLE IF EXISTS agent_actions, agents,
		                     devices, device_counters,
		                     signing_keys, schema_migrations CASCADE`)
	if err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// newTestServer constructs a *Server backed by testDB. JWT/admin token are
// fixed values so test assertions can use them.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	db := testDB(t)
	srv, err := New(context.Background(), Config{
		DB:        db,
		JWTSecret: "test-jwt-secret",
		Logger:    discardLogger(t),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}
