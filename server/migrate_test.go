package server

import (
	"context"
	"testing"
)

func TestMigrate_Idempotent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	// testDB already ran migrate once. Run it again — should be a no-op.
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	var count int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != 1 {
		t.Fatalf("schema_migrations rows: got %d want 1", count)
	}
}

func TestMigrate_CreatesAllTables(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	want := []string{
		"agent_actions", "agents", "devices", "device_counters",
		"schema_migrations", "signing_keys",
	}
	for _, table := range want {
		var exists bool
		if err := db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables
			               WHERE table_schema='public' AND table_name=$1)`,
			table).Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s should exist after migration", table)
		}
	}
}
