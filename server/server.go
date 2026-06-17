// Package server is a Postgres-backed ComputeID API implementation. Endpoints
// match the Integration Guide PDF wire contract so the Go SDK and the Python
// SDK both work against it unchanged.
package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Server is the HTTP handler bundle.
type Server struct {
	db         DB
	signer     *Signer
	jwtSecret  string
	adminToken string
	logger     *slog.Logger
}

// Config configures New. AdminToken is optional; when non-empty, the dev-only
// admin endpoints (currently `POST /api/devices/{id}/approve`) require a
// matching `X-Admin-Token` header. When empty, they are open — appropriate
// only for local development.
type Config struct {
	DB         DB
	JWTSecret  string
	AdminToken string
	Logger     *slog.Logger
}

// New constructs a Server. It loads or generates the RSA signing key on
// startup so the first call after a clean install issues a real signature.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.DB == nil {
		return nil, errors.New("server: DB is required")
	}
	if cfg.JWTSecret == "" {
		return nil, errors.New("server: JWTSecret is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	signer, err := LoadOrInitSigner(ctx, cfg.DB)
	if err != nil {
		return nil, fmt.Errorf("init signer: %w", err)
	}
	return &Server{
		db:         cfg.DB,
		signer:     signer,
		jwtSecret:  cfg.JWTSecret,
		adminToken: cfg.AdminToken,
		logger:     cfg.Logger,
	}, nil
}

// Handler returns the HTTP handler with all routes wired up and the request
// logger applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Agents.
	mux.HandleFunc("POST /v1/agents/register", s.handleAgentRegister)
	mux.HandleFunc("GET /v1/agents", s.handleAgentList)
	mux.HandleFunc("/v1/agents/", s.routeAgentSub)

	// Devices.
	mux.HandleFunc("POST /api/devices/register", s.handleDeviceRegister)
	mux.HandleFunc("POST /api/devices/authenticate", s.handleDeviceAuthenticate)
	mux.HandleFunc("GET /api/devices", s.handleDeviceList)
	mux.HandleFunc("/api/devices/", s.routeDeviceSub)

	// Misc.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/status", s.handleHealth)

	return logMiddleware(s.logger, mux)
}

// /v1/agents/{passport_id}/(verify|capabilities/{name}|actions|revoke)
var (
	rxVerify   = regexp.MustCompile(`^/v1/agents/([^/]+)/verify$`)
	rxCapCheck = regexp.MustCompile(`^/v1/agents/([^/]+)/capabilities/([^/]+)$`)
	rxActions  = regexp.MustCompile(`^/v1/agents/([^/]+)/actions$`)
	rxRevoke   = regexp.MustCompile(`^/v1/agents/([^/]+)/revoke$`)
)

func (s *Server) routeAgentSub(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && rxVerify.MatchString(p):
		id := rxVerify.FindStringSubmatch(p)[1]
		s.handleAgentVerify(w, r, id)
	case r.Method == http.MethodGet && rxCapCheck.MatchString(p):
		m := rxCapCheck.FindStringSubmatch(p)
		s.handleAgentCapability(w, r, m[1], m[2])
	case r.Method == http.MethodPost && rxActions.MatchString(p):
		id := rxActions.FindStringSubmatch(p)[1]
		s.handleAgentLogAction(w, r, id)
	case r.Method == http.MethodGet && rxActions.MatchString(p):
		id := rxActions.FindStringSubmatch(p)[1]
		s.handleAgentListActions(w, r, id)
	case r.Method == http.MethodDelete && rxRevoke.MatchString(p):
		id := rxRevoke.FindStringSubmatch(p)[1]
		s.handleAgentRevoke(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "no route for "+r.Method+" "+p)
	}
}

var rxDeviceApprove = regexp.MustCompile(`^/api/devices/([^/]+)/approve$`)

func (s *Server) routeDeviceSub(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && rxDeviceApprove.MatchString(p):
		if !s.checkAdmin(w, r) {
			return
		}
		id := rxDeviceApprove.FindStringSubmatch(p)[1]
		s.handleDeviceApprove(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "no route for "+r.Method+" "+p)
	}
}

// checkAdmin enforces the optional X-Admin-Token header. Returns true when
// the request is allowed to proceed.
func (s *Server) checkAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.adminToken == "" {
		return true // admin endpoints are open in dev mode
	}
	provided := r.Header.Get("X-Admin-Token")
	if provided == "" || !constantTimeEq(provided, s.adminToken) {
		writeError(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.db.QueryRow(r.Context(), `SELECT 1`).Scan(new(int)); err != nil {
		writeError(w, http.StatusServiceUnavailable, "db unreachable: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"timestamp": time.Now().UTC(),
		"algorithm": s.signer.Algorithm(),
	})
}

// -------------------- helpers --------------------

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, dst)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func logMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// newUUID is a small inline RFC4122 v4 generator (we already ship one in the
// SDK package, but the server can't import the SDK to avoid an import cycle
// once the SDK ever depends on this package).
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// (unused-import guard for strings — keeps the file robust if writeError
// later wraps messages.)
var _ = strings.TrimSpace
