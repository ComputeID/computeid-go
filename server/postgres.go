package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectPostgres opens a pooled connection to a Postgres database.
func ConnectPostgres(ctx context.Context, databaseURL string) (DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &pgxDB{pool: pool}, nil
}

func init() {
	isNoRows = func(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
}

type pgxDB struct{ pool *pgxpool.Pool }

func (d *pgxDB) Close() { d.pool.Close() }

func (d *pgxDB) Exec(ctx context.Context, sql string, args ...any) (CommandTag, error) {
	tag, err := d.pool.Exec(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgxTag(tag.RowsAffected()), nil
}

func (d *pgxDB) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := d.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgxRows{rows}, nil
}

func (d *pgxDB) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return pgxRow{d.pool.QueryRow(ctx, sql, args...)}
}

func (d *pgxDB) Begin(ctx context.Context) (Tx, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return pgxTx{tx}, nil
}

type pgxTag int64

func (t pgxTag) RowsAffected() int64 { return int64(t) }

type pgxRow struct{ pgx.Row }

func (r pgxRow) Scan(dest ...any) error { return r.Row.Scan(dest...) }

type pgxRows struct{ pgx.Rows }

func (r pgxRows) Close() { r.Rows.Close() }
func (r pgxRows) Err() error { return r.Rows.Err() }

type pgxTx struct{ pgx.Tx }

func (t pgxTx) Exec(ctx context.Context, sql string, args ...any) (CommandTag, error) {
	tag, err := t.Tx.Exec(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgxTag(tag.RowsAffected()), nil
}
func (t pgxTx) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := t.Tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgxRows{rows}, nil
}
func (t pgxTx) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return pgxRow{t.Tx.QueryRow(ctx, sql, args...)}
}
func (t pgxTx) Commit(ctx context.Context) error   { return t.Tx.Commit(ctx) }
func (t pgxTx) Rollback(ctx context.Context) error { return t.Tx.Rollback(ctx) }
