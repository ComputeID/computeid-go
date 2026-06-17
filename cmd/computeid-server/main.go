// Command computeid-server runs the Postgres-backed ComputeID API.
//
// Required env:
//
//	DATABASE_URL  postgres://user:pass@host:port/dbname?sslmode=disable
//	JWT_SECRET    HS256 secret for device access tokens
//
// Optional env:
//
//	PORT          default 8088
//	LOG_LEVEL     debug|info|warn|error (default info)
//	ADMIN_TOKEN   when set, /api/devices/{id}/approve requires X-Admin-Token header
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ComputeID/computeid-go/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	db, err := server.ConnectPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := server.Migrate(ctx, db); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	logger.Info("migrations applied")

	srv, err := server.New(ctx, server.Config{
		DB:         db,
		JWTSecret:  cfg.JWTSecret,
		AdminToken: cfg.AdminToken,
		Logger:     logger,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return httpServer.Shutdown(shutdownCtx)
}

type config struct {
	DatabaseURL string
	JWTSecret   string
	AdminToken  string
	Port        string
	LogLevel    slog.Level
}

func loadConfig() (config, error) {
	cfg := config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		AdminToken:  os.Getenv("ADMIN_TOKEN"),
		Port:        os.Getenv("PORT"),
		LogLevel:    slog.LevelInfo,
	}
	if cfg.DatabaseURL == "" {
		return cfg, errors.New("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		return cfg, errors.New("JWT_SECRET is required")
	}
	if cfg.Port == "" {
		cfg.Port = "8088"
	}
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "warn":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	}
	return cfg, nil
}
