package server

import (
	"context"
	"time"
)

// DB is the minimal driver surface used by the server (pgx-shaped, but
// abstracted so tests can substitute a fake later).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Begin(ctx context.Context) (Tx, error)
	Close()
}

// Tx is a database transaction.
type Tx interface {
	Exec(ctx context.Context, sql string, args ...any) (CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// CommandTag describes the result of an Exec.
type CommandTag interface {
	RowsAffected() int64
}

// Row is a single-row result.
type Row interface {
	Scan(dest ...any) error
}

// Rows is a multi-row iterator.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// isNoRows reports whether the error is the driver's "no rows" sentinel.
// Defined in postgres.go to depend on pgx, kept in this file as a tiny
// indirection point for future fakes.
var isNoRows = func(err error) bool { return false }

// AgentRow is the projected row type the handlers and store agree on.
type AgentRow struct {
	PassportID         string
	Name               string
	Description        string
	Organization       string
	Capabilities       []string
	Status             string
	PublicKeyPEM       string
	SignatureB64       string
	SignatureAlgorithm string
	SignedPayload      []byte
	IssuedAt           time.Time
	RevokedAt          *time.Time
	RevokeReason       string
}

// ActionRow is the projected audit-log row.
type ActionRow struct {
	ActionID   string
	Action     string
	Details    map[string]any
	Outcome    string
	OccurredAt time.Time
}

// DeviceRow is the projected device row.
type DeviceRow struct {
	DeviceID    string
	DeviceCode  string
	Name        string
	DeviceType  string
	IPAddress   string
	Status      string
	IssuedAt    time.Time
	ApprovedAt  *time.Time
}
