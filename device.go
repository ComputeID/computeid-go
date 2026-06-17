package computeid

import (
	"context"
	"fmt"
	"time"
)

// DeviceStatus is the lifecycle state of a DevicePassport.
type DeviceStatus string

const (
	DeviceStatusPending DeviceStatus = "pending"
	DeviceStatusActive  DeviceStatus = "active"
	DeviceStatusRevoked DeviceStatus = "revoked"
)

// DevicePassport is a cryptographic passport for a GPU, server, or other
// compute device. Unlike AgentPassport it is server-backed: registration and
// authentication round-trip through the ComputeID API.
type DevicePassport struct {
	DeviceID   string       `json:"device_id"`
	DeviceCode string       `json:"device_code"`
	Name       string       `json:"name"`
	DeviceType string       `json:"type"`
	IPAddress  string       `json:"ip_address"`
	Status     DeviceStatus `json:"status"`
	IssuedAt   time.Time    `json:"issued_at"`
}

// IsValid reports whether the passport is active.
func (d *DevicePassport) IsValid() bool { return d.Status == DeviceStatusActive }

// IsPending reports whether the passport is awaiting admin approval.
func (d *DevicePassport) IsPending() bool { return d.Status == DeviceStatusPending }

func (d *DevicePassport) String() string {
	return fmt.Sprintf("<DevicePassport %s | %s | %s>", d.DeviceCode, d.Name, d.Status)
}

// RegisterDeviceRequest is the payload sent to /api/devices/register.
type RegisterDeviceRequest struct {
	Name       string `json:"name"`
	DeviceType string `json:"type"`
	IPAddress  string `json:"ip_address"`
}

// RegisterDevice registers a new device with the default API and returns the
// issued passport. For a customised client use Client.RegisterDevice.
func RegisterDevice(ctx context.Context, req RegisterDeviceRequest, apiKey string) (*DevicePassport, error) {
	c := NewClient(WithAPIKey(apiKey))
	return c.RegisterDevice(ctx, req)
}

// AuthenticateDevice exchanges a device_code for a short-lived access token
// against the default API.
func AuthenticateDevice(ctx context.Context, deviceCode string) (string, error) {
	c := NewClient()
	return c.AuthenticateDevice(ctx, deviceCode)
}
