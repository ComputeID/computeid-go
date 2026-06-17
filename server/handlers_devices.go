package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DeviceRegisterRequest matches POST /api/devices/register.
type DeviceRegisterRequest struct {
	Name       string `json:"name"`
	DeviceType string `json:"type"`
	IPAddress  string `json:"ip_address"`
}

// DeviceResponse matches the body returned by register / approve / list.
type DeviceResponse struct {
	DeviceID   string    `json:"device_id"`
	DeviceCode string    `json:"device_code"`
	Name       string    `json:"name"`
	DeviceType string    `json:"type"`
	IPAddress  string    `json:"ip_address,omitempty"`
	Status     string    `json:"status"`
	IssuedAt   time.Time `json:"issued_at"`
}

func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	var req DeviceRegisterRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.DeviceType) == "" {
		writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer tx.Rollback(r.Context())

	// Allocate the next monotonic suffix per type (GPU-001, GPU-002, ...).
	var next int
	err = tx.QueryRow(r.Context(),
		`INSERT INTO device_counters (device_type, last_n) VALUES ($1, 1)
		 ON CONFLICT (device_type) DO UPDATE
		   SET last_n = device_counters.last_n + 1
		 RETURNING last_n`, req.DeviceType).Scan(&next)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	deviceID := newUUID()
	code := fmt.Sprintf("%s-%03d", strings.ToUpper(req.DeviceType), next)
	issuedAt := time.Now().UTC().Truncate(time.Millisecond)
	_, err = tx.Exec(r.Context(),
		`INSERT INTO devices
		   (device_id, device_code, name, device_type, ip_address, status, issued_at)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6)`,
		deviceID, code, req.Name, req.DeviceType, req.IPAddress, issuedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, DeviceResponse{
		DeviceID:   deviceID,
		DeviceCode: code,
		Name:       req.Name,
		DeviceType: req.DeviceType,
		IPAddress:  req.IPAddress,
		Status:     "pending",
		IssuedAt:   issuedAt,
	})
}

// DeviceAuthRequest matches POST /api/devices/authenticate.
type DeviceAuthRequest struct {
	DeviceCode string `json:"device_code"`
}

// DeviceAuthResponse mirrors the production JWT exchange.
type DeviceAuthResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *Server) handleDeviceAuthenticate(w http.ResponseWriter, r *http.Request) {
	var req DeviceAuthRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.DeviceCode == "" {
		writeError(w, http.StatusBadRequest, "device_code is required")
		return
	}
	var (
		deviceID string
		status   string
	)
	err := s.db.QueryRow(r.Context(),
		`SELECT device_id::text, status FROM devices WHERE device_code = $1`,
		req.DeviceCode).Scan(&deviceID, &status)
	if isNoRows(err) {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if status != "active" {
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("device status is %s; cannot authenticate", status))
		return
	}
	exp := time.Now().UTC().Add(1 * time.Hour)
	token, err := signJWT(s.jwtSecret, map[string]any{
		"sub":         deviceID,
		"device_code": req.DeviceCode,
		"exp":         exp.Unix(),
		"iss":         "computeid-server",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign token: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, DeviceAuthResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   exp,
	})
}

// handleDeviceApprove is the admin-only equivalent of clicking "approve"
// in the dashboard.
func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request, deviceID string) {
	tag, err := s.db.Exec(r.Context(),
		`UPDATE devices
		    SET status = 'active', approved_at = now()
		  WHERE device_id = $1 AND status = 'pending'`, deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "device not found or not pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
}

func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	var (
		rows Rows
		err  error
	)
	const baseSelect = `SELECT device_id::text, device_code, name, device_type,
	      COALESCE(ip_address, ''), status, issued_at FROM devices`
	if statusFilter == "" {
		rows, err = s.db.Query(r.Context(), baseSelect+` ORDER BY issued_at DESC`)
	} else {
		rows, err = s.db.Query(r.Context(),
			baseSelect+` WHERE status = $1 ORDER BY issued_at DESC`, statusFilter)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := struct {
		Devices []DeviceResponse `json:"devices"`
	}{Devices: []DeviceResponse{}}
	for rows.Next() {
		var d DeviceResponse
		if err := rows.Scan(&d.DeviceID, &d.DeviceCode, &d.Name,
			&d.DeviceType, &d.IPAddress, &d.Status, &d.IssuedAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		d.IssuedAt = d.IssuedAt.UTC()
		out.Devices = append(out.Devices, d)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// -------------------- JWT (HS256, minimal stdlib impl) --------------------

func signJWT(secret string, claims map[string]any) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encH := base64.RawURLEncoding.EncodeToString(hb)
	encC := base64.RawURLEncoding.EncodeToString(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encH + "." + encC))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encH + "." + encC + "." + sig, nil
}

// verifyJWT exists for tests / future middleware; not wired into a route yet.
func verifyJWT(secret, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
