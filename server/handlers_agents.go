package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AgentRegisterRequest matches POST /v1/agents/register.
type AgentRegisterRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Organization string   `json:"organization"`
	Capabilities []string `json:"capabilities"`
}

// AgentPassportResponse matches the 201 body documented in the Integration
// Guide PDF. Field order and JSON tags are stable.
type AgentPassportResponse struct {
	PassportID         string    `json:"passport_id"`
	Name               string    `json:"name,omitempty"`
	Description        string    `json:"description,omitempty"`
	Organization       string    `json:"organization,omitempty"`
	Status             string    `json:"status"`
	PublicKey          string    `json:"public_key,omitempty"`
	Signature          string    `json:"signature"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	Capabilities       []string  `json:"capabilities"`
	IssuedAt           time.Time `json:"issued_at"`
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req AgentRegisterRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Organization) == "" {
		writeError(w, http.StatusBadRequest, "name and organization are required")
		return
	}
	if req.Capabilities == nil {
		req.Capabilities = []string{}
	}

	passportID := newUUID()
	issuedAt := time.Now().UTC().Truncate(time.Millisecond)

	sigB64, signedJSON, err := s.signer.Sign(CanonicalPayload{
		PassportID:   passportID,
		Name:         req.Name,
		Organization: req.Organization,
		Capabilities: req.Capabilities,
		IssuedAt:     issuedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign passport: "+err.Error())
		return
	}

	capsJSON, _ := json.Marshal(req.Capabilities)
	_, err = s.db.Exec(r.Context(),
		`INSERT INTO agents
		   (passport_id, name, description, organization, capabilities,
		    status, public_key_pem, signature_b64, signature_algorithm,
		    signed_payload, issued_at)
		 VALUES ($1, $2, NULLIF($3,''), $4, $5::jsonb,
		         'active', $6, $7, $8, $9::bytea, $10)`,
		passportID, req.Name, req.Description, req.Organization, string(capsJSON),
		s.signer.PublicKeyPEM(), sigB64, s.signer.Algorithm(), []byte(signedJSON), issuedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store passport: "+err.Error())
		return
	}

	// Lifecycle event in the audit trail.
	_, _ = s.db.Exec(r.Context(),
		`INSERT INTO agent_actions (passport_id, action, details, outcome)
		 VALUES ($1, 'passport_issued', $2::jsonb, 'success')`,
		passportID, fmt.Sprintf(`{"name":%q}`, req.Name))

	writeJSON(w, http.StatusCreated, AgentPassportResponse{
		PassportID:         passportID,
		Name:               req.Name,
		Description:        req.Description,
		Organization:       req.Organization,
		Status:             "active",
		PublicKey:          s.signer.PublicKeyPEM(),
		Signature:          sigB64,
		SignatureAlgorithm: s.signer.Algorithm(),
		Capabilities:       req.Capabilities,
		IssuedAt:           issuedAt,
	})
}

// VerifyResponse matches GET /v1/agents/{id}/verify.
type VerifyResponse struct {
	PassportID     string     `json:"passport_id"`
	Status         string     `json:"status"`
	SignatureValid bool       `json:"signature_valid"`
	Capabilities   []string   `json:"capabilities"`
	IssuedAt       time.Time  `json:"issued_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

func (s *Server) handleAgentVerify(w http.ResponseWriter, r *http.Request, passportID string) {
	row, err := s.loadAgent(r, passportID)
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "passport not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// PDF: revoked passports retain a valid signature. signature_valid is
	// independent of status by design.
	valid := s.signer.Verify(row.SignedPayload, row.SignatureB64)
	writeJSON(w, http.StatusOK, VerifyResponse{
		PassportID:     row.PassportID,
		Status:         row.Status,
		SignatureValid: valid,
		Capabilities:   row.Capabilities,
		IssuedAt:       row.IssuedAt,
		RevokedAt:      row.RevokedAt,
	})
}

// CapabilityResponse matches GET /v1/agents/{id}/capabilities/{name}.
type CapabilityResponse struct {
	Granted    bool           `json:"granted"`
	Capability string         `json:"capability,omitempty"`
	Scope      map[string]any `json:"scope,omitempty"`
	BoundAt    *time.Time     `json:"bound_at,omitempty"`
	Reason     string         `json:"reason,omitempty"`
}

func (s *Server) handleAgentCapability(w http.ResponseWriter, r *http.Request, passportID, cap string) {
	row, err := s.loadAgent(r, passportID)
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "passport not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// PDF rule: after revocation, every capability check returns
	// granted=false with reason "passport_revoked".
	if row.Status == "revoked" {
		writeJSON(w, http.StatusOK, CapabilityResponse{Granted: false, Reason: "passport_revoked"})
		return
	}
	for _, c := range row.Capabilities {
		if c == cap {
			writeJSON(w, http.StatusOK, CapabilityResponse{
				Granted:    true,
				Capability: cap,
				BoundAt:    &row.IssuedAt,
				Scope:      map[string]any{},
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, CapabilityResponse{Granted: false, Reason: "capability_not_found"})
}

// LogActionRequest matches POST /v1/agents/{id}/actions.
type LogActionRequest struct {
	Action  string         `json:"action"`
	Details map[string]any `json:"details"`
	Outcome string         `json:"outcome"`
}

func (s *Server) handleAgentLogAction(w http.ResponseWriter, r *http.Request, passportID string) {
	var req LogActionRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Action) == "" {
		writeError(w, http.StatusBadRequest, "action is required")
		return
	}
	if req.Outcome == "" {
		req.Outcome = "success"
	}
	if !validOutcome(req.Outcome) {
		writeError(w, http.StatusBadRequest, "outcome must be success|blocked|failure")
		return
	}
	if req.Details == nil {
		req.Details = map[string]any{}
	}
	detailsJSON, _ := json.Marshal(req.Details)

	tag, err := s.db.Exec(r.Context(),
		`INSERT INTO agent_actions (passport_id, action, details, outcome)
		 SELECT $1, $2, $3::jsonb, $4
		 WHERE EXISTS (SELECT 1 FROM agents WHERE passport_id = $1)`,
		passportID, req.Action, string(detailsJSON), req.Outcome)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "passport not found")
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged"})
}

// ListActionsResponse matches GET /v1/agents/{id}/actions.
type ListActionsResponse struct {
	Actions []ActionItem `json:"actions"`
}

// ActionItem is a single audit row.
type ActionItem struct {
	ActionID  string         `json:"action_id"`
	Action    string         `json:"action"`
	Details   map[string]any `json:"details,omitempty"`
	Outcome   string         `json:"outcome"`
	Timestamp time.Time      `json:"timestamp"`
}

func (s *Server) handleAgentListActions(w http.ResponseWriter, r *http.Request, passportID string) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	rows, err := s.db.Query(r.Context(),
		`SELECT action_id::text, action, details, outcome, occurred_at
		 FROM agent_actions
		 WHERE passport_id = $1
		 ORDER BY occurred_at DESC
		 LIMIT $2`, passportID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := ListActionsResponse{Actions: []ActionItem{}}
	for rows.Next() {
		var it ActionItem
		var detailsRaw []byte
		if err := rows.Scan(&it.ActionID, &it.Action, &detailsRaw, &it.Outcome, &it.Timestamp); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		it.Timestamp = it.Timestamp.UTC()
		_ = json.Unmarshal(detailsRaw, &it.Details)
		out.Actions = append(out.Actions, it)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// RevokeRequest matches DELETE /v1/agents/{id}/revoke.
type RevokeRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleAgentRevoke(w http.ResponseWriter, r *http.Request, passportID string) {
	var req RevokeRequest
	_ = readJSON(r, &req) // body optional
	if req.Reason == "" {
		req.Reason = "manual revocation"
	}
	tag, err := s.db.Exec(r.Context(),
		`UPDATE agents
		    SET status = 'revoked',
		        revoked_at = now(),
		        revoke_reason = $2,
		        updated_at = now()
		  WHERE passport_id = $1
		    AND status = 'active'`,
		passportID, req.Reason)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		// Could be already revoked or not present — distinguish.
		var exists bool
		_ = s.db.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM agents WHERE passport_id = $1)`, passportID).Scan(&exists)
		if !exists {
			writeError(w, http.StatusNotFound, "passport not found")
			return
		}
	}
	_, _ = s.db.Exec(r.Context(),
		`INSERT INTO agent_actions (passport_id, action, details, outcome)
		 VALUES ($1, 'passport_revoked', $2::jsonb, 'success')`,
		passportID, fmt.Sprintf(`{"reason":%q}`, req.Reason))

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "revoked",
		"reason":  req.Reason,
	})
}

// ListAgentsResponse matches GET /v1/agents.
type ListAgentsResponse struct {
	Agents []AgentPassportResponse `json:"agents"`
}

func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	var (
		rows Rows
		err  error
	)
	const baseSelect = `SELECT passport_id::text, name, COALESCE(description, ''),
	       organization, capabilities, status, public_key_pem,
	       signature_b64, signature_algorithm, issued_at
	  FROM agents`
	if statusFilter == "" {
		rows, err = s.db.Query(r.Context(),
			baseSelect+` ORDER BY issued_at DESC LIMIT 200`)
	} else {
		rows, err = s.db.Query(r.Context(),
			baseSelect+` WHERE status = $1 ORDER BY issued_at DESC LIMIT 200`, statusFilter)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := ListAgentsResponse{Agents: []AgentPassportResponse{}}
	for rows.Next() {
		var (
			row     AgentPassportResponse
			capsRaw []byte
		)
		if err := rows.Scan(
			&row.PassportID, &row.Name, &row.Description, &row.Organization,
			&capsRaw, &row.Status, &row.PublicKey, &row.Signature,
			&row.SignatureAlgorithm, &row.IssuedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		row.IssuedAt = row.IssuedAt.UTC()
		_ = json.Unmarshal(capsRaw, &row.Capabilities)
		out.Agents = append(out.Agents, row)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// loadAgent fetches the full row needed for verify/capability checks.
func (s *Server) loadAgent(r *http.Request, passportID string) (*AgentRow, error) {
	row := &AgentRow{}
	var (
		capsRaw       []byte
		signedPayload []byte
		description   *string
	)
	err := s.db.QueryRow(r.Context(),
		`SELECT passport_id::text, name, description, organization,
		        capabilities, status, public_key_pem, signature_b64,
		        signature_algorithm, signed_payload, issued_at, revoked_at,
		        COALESCE(revoke_reason, '')
		   FROM agents WHERE passport_id = $1`, passportID,
	).Scan(
		&row.PassportID, &row.Name, &description, &row.Organization,
		&capsRaw, &row.Status, &row.PublicKeyPEM, &row.SignatureB64,
		&row.SignatureAlgorithm, &signedPayload, &row.IssuedAt, &row.RevokedAt,
		&row.RevokeReason,
	)
	if isNoRows(err) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if description != nil {
		row.Description = *description
	}
	row.SignedPayload = signedPayload
	row.IssuedAt = row.IssuedAt.UTC()
	if row.RevokedAt != nil {
		t := row.RevokedAt.UTC()
		row.RevokedAt = &t
	}
	_ = json.Unmarshal(capsRaw, &row.Capabilities)
	return row, nil
}

func validOutcome(o string) bool {
	switch o {
	case "success", "blocked", "failure":
		return true
	}
	return false
}

var errNotFound = errors.New("not found")
