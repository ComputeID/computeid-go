package computeid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Default API endpoints. Both can be overridden per-Client via options.
const (
	DefaultAPI = "https://api.aicomputeid.com"
	SDKVersion = "1.0.0"
)

// Client is the HTTP client for the ComputeID REST API. It covers both
// /v1/agents/* (server-backed agent passports) and /api/devices/*
// (device passports). Construct one with NewClient.
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
	userAgent  string
}

// Option customises NewClient.
type Option func(*Client)

// WithBaseURL overrides the API base URL (e.g. for staging or tests).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithAPIKey sets the X-API-Key header sent on every request.
func WithAPIKey(key string) Option { return func(c *Client) { c.apiKey = key } }

// WithHTTPClient injects a custom *http.Client (useful for instrumentation,
// retries, or a shared transport).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.httpClient = h
		}
	}
}

// WithUserAgent sets the User-Agent header sent on every request.
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// NewClient returns a Client wired to the default API. Pass options to
// override the base URL, API key, HTTP client, or User-Agent.
func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL:    DefaultAPI,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "computeid-go/" + SDKVersion,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// -------------------- /v1/agents/* (server-backed) --------------------

// AgentRegistration is the request body for RegisterAgent.
type AgentRegistration struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Organization string   `json:"organization"`
	Capabilities []string `json:"capabilities"`
}

// ServerAgentPassport is the response payload for /v1/agents/register and
// list endpoints. It is distinct from the local-model AgentPassport.
type ServerAgentPassport struct {
	PassportID         string    `json:"passport_id"`
	Name               string    `json:"name"`
	Description        string    `json:"description,omitempty"`
	Organization       string    `json:"organization"`
	Status             string    `json:"status"`
	PublicKey          string    `json:"public_key,omitempty"`
	Signature          string    `json:"signature,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	Capabilities       []string  `json:"capabilities"`
	IssuedAt           time.Time `json:"issued_at"`
}

// VerificationResult is the response from /v1/agents/{id}/verify.
type VerificationResult struct {
	PassportID     string    `json:"passport_id"`
	Status         string    `json:"status"`
	SignatureValid bool      `json:"signature_valid"`
	Capabilities   []string  `json:"capabilities"`
	IssuedAt       time.Time `json:"issued_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

// IsTrusted is the authoritative authorisation check: active and signature
// valid, matching INTEGRATION.md guidance.
func (v VerificationResult) IsTrusted() bool {
	return v.Status == "active" && v.SignatureValid
}

// CapabilityCheck is the response from /v1/agents/{id}/capabilities/{cap}.
type CapabilityCheck struct {
	Granted    bool           `json:"granted"`
	Capability string         `json:"capability,omitempty"`
	Scope      map[string]any `json:"scope,omitempty"`
	BoundAt    *time.Time     `json:"bound_at,omitempty"`
	Reason     string         `json:"reason,omitempty"`
}

// ServerActionLog mirrors a row from /v1/agents/{id}/actions.
type ServerActionLog struct {
	ActionID  string         `json:"action_id"`
	Action    string         `json:"action"`
	Details   map[string]any `json:"details,omitempty"`
	Outcome   string         `json:"outcome"`
	Timestamp time.Time      `json:"timestamp"`
}

// LogActionRequest is the payload for LogAgentAction.
type LogActionRequest struct {
	Action  string         `json:"action"`
	Details map[string]any `json:"details,omitempty"`
	Outcome string         `json:"outcome"`
}

// RegisterAgent issues a server-backed agent passport.
func (c *Client) RegisterAgent(ctx context.Context, reg AgentRegistration) (*ServerAgentPassport, error) {
	var out ServerAgentPassport
	if err := c.do(ctx, http.MethodPost, "/v1/agents/register", reg, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyAgent returns status + signature validity for a passport.
func (c *Client) VerifyAgent(ctx context.Context, passportID string) (*VerificationResult, error) {
	var out VerificationResult
	if err := c.do(ctx, http.MethodGet,
		"/v1/agents/"+url.PathEscape(passportID)+"/verify", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckCapability tests a single capability grant on a passport.
func (c *Client) CheckCapability(ctx context.Context, passportID, capability string) (*CapabilityCheck, error) {
	var out CapabilityCheck
	path := "/v1/agents/" + url.PathEscape(passportID) +
		"/capabilities/" + url.PathEscape(capability)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogAgentAction appends to the server-side audit log.
func (c *Client) LogAgentAction(ctx context.Context, passportID string, req LogActionRequest) error {
	return c.do(ctx, http.MethodPost,
		"/v1/agents/"+url.PathEscape(passportID)+"/actions", req, nil)
}

// ListAgentActions reads the audit trail for a passport. limit <= 0 omits
// the parameter (server default applies).
func (c *Client) ListAgentActions(ctx context.Context, passportID string, limit int) ([]ServerActionLog, error) {
	path := "/v1/agents/" + url.PathEscape(passportID) + "/actions"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out struct {
		Actions []ServerActionLog `json:"actions"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}

// RevokeAgent immediately revokes a server-backed passport.
func (c *Client) RevokeAgent(ctx context.Context, passportID, reason string) error {
	body := map[string]string{"reason": reason}
	return c.do(ctx, http.MethodDelete,
		"/v1/agents/"+url.PathEscape(passportID)+"/revoke", body, nil)
}

// ListAgents enumerates passports. Pass an empty status to list all.
func (c *Client) ListAgents(ctx context.Context, status string) ([]ServerAgentPassport, error) {
	path := "/v1/agents"
	if status != "" {
		path += "?status=" + url.QueryEscape(status)
	}
	var out struct {
		Agents []ServerAgentPassport `json:"agents"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Agents, nil
}

// -------------------- /api/devices/* (server-backed) --------------------

// RegisterDevice registers a new device.
func (c *Client) RegisterDevice(ctx context.Context, req RegisterDeviceRequest) (*DevicePassport, error) {
	var out DevicePassport
	if err := c.do(ctx, http.MethodPost, "/api/devices/register", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuthenticateDevice exchanges a device_code for a JWT access token.
func (c *Client) AuthenticateDevice(ctx context.Context, deviceCode string) (string, error) {
	body := map[string]string{"device_code": deviceCode}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/devices/authenticate", body, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

// -------------------- core transport --------------------

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%w: encode %s: %v", ErrAPI, path, err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("%w: build %s: %v", ErrAPI, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrAPI, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: read %s: %v", ErrAPI, path, err)
	}
	if resp.StatusCode >= 400 {
		return parseAPIError(resp.StatusCode, path, raw)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrAPI, path, err)
	}
	return nil
}

func parseAPIError(status int, path string, raw []byte) error {
	apiErr := &APIError{StatusCode: status, Endpoint: path}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	_ = json.Unmarshal(raw, &body)
	switch {
	case body.Error != "":
		apiErr.Message = body.Error
	case body.Message != "":
		apiErr.Message = body.Message
	case body.Detail != "":
		apiErr.Message = body.Detail
	default:
		apiErr.Message = http.StatusText(status)
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrAuthentication, apiErr.Error())
	case strings.Contains(path, "/revoke"):
		return fmt.Errorf("%w: %s", ErrRevocation, apiErr.Error())
	case strings.Contains(path, "/register"):
		return fmt.Errorf("%w: %s", ErrRegistration, apiErr.Error())
	}
	return apiErr
}
