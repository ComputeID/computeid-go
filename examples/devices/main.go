// Device registration example.
//
// Endpoint resolution:
//   - COMPUTEID_API_BASE  → if set, used verbatim (e.g. http://localhost:8088
//     for the local computeid-server). Otherwise defaults to https://api.aicomputeid.com.
//   - COMPUTEID_API_KEY   → optional; required only for live/free tier.
//   - COMPUTEID_AUTO_APPROVE=1 → call the dev-only /api/devices/{id}/approve
//     endpoint so the example can authenticate without an admin in the loop.
//     The production API does NOT expose this endpoint.
//
//	export COMPUTEID_API_BASE=http://localhost:8088
//	export COMPUTEID_AUTO_APPROVE=1
//	go run .
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ComputeID/computeid-go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := []computeid.Option{computeid.WithAPIKey(os.Getenv("COMPUTEID_API_KEY"))}
	base := os.Getenv("COMPUTEID_API_BASE")
	if base != "" {
		opts = append(opts, computeid.WithBaseURL(base))
	}
	c := computeid.NewClient(opts...)

	dev, err := c.RegisterDevice(ctx, computeid.RegisterDeviceRequest{
		Name:       "NVIDIA A100 #1",
		DeviceType: "GPU",
		IPAddress:  "192.168.1.10",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("registered:", dev.DeviceCode, "status:", dev.Status)

	if dev.IsPending() && os.Getenv("COMPUTEID_AUTO_APPROVE") == "1" {
		if err := autoApproveDev(ctx, base, dev.DeviceID); err != nil {
			log.Fatal("auto-approve: ", err)
		}
		fmt.Println("approved (dev-only path).")
	} else if dev.IsPending() {
		fmt.Println("awaiting admin approval — check the dashboard")
		return
	}

	token, err := c.AuthenticateDevice(ctx, dev.DeviceCode)
	if err != nil {
		log.Fatal(err)
	}
	end := 24
	if len(token) < end {
		end = len(token)
	}
	fmt.Println("access token (truncated):", token[:end], "...")
}

// autoApproveDev is a dev-only helper that pokes the local server's admin
// endpoint. Not in the production API contract — see file header.
func autoApproveDev(ctx context.Context, base, deviceID string) error {
	if base == "" {
		return fmt.Errorf("COMPUTEID_API_BASE must be set for auto-approve")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/devices/"+deviceID+"/approve", nil)
	if err != nil {
		return err
	}
	if tok := os.Getenv("COMPUTEID_ADMIN_TOKEN"); tok != "" {
		req.Header.Set("X-Admin-Token", tok)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("approve returned %d", resp.StatusCode)
	}
	return nil
}
