package server

import (
	"context"
	"testing"
)

func TestSigner_RoundTrip(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	signer, err := LoadOrInitSigner(ctx, db)
	if err != nil {
		t.Fatalf("init signer: %v", err)
	}
	if signer.Algorithm() != "RSA-SHA256" {
		t.Errorf("algorithm: %s want RSA-SHA256", signer.Algorithm())
	}

	payload := CanonicalPayload{
		PassportID:   "11111111-2222-3333-4444-555555555555",
		Name:         "ResearchAgent",
		Organization: "Acme Corp",
		Capabilities: []string{"read", "web_browse", "api_call"},
		IssuedAt:     "2026-06-13T12:00:00.000Z",
	}
	sig, signedJSON, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig == "" || len(signedJSON) == 0 {
		t.Fatal("empty signature output")
	}
	if !signer.Verify(signedJSON, sig) {
		t.Fatal("freshly signed payload should verify")
	}
}

func TestSigner_TamperedPayloadFails(t *testing.T) {
	db := testDB(t)
	signer, err := LoadOrInitSigner(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	_, signedJSON, _ := signer.Sign(CanonicalPayload{
		PassportID: "id", Name: "n", Organization: "o",
		Capabilities: []string{"read"}, IssuedAt: "2026-01-01T00:00:00Z",
	})
	tampered := append([]byte{}, signedJSON...)
	tampered[10] ^= 0xff
	// Need a valid signature on the *original* to test tampering detection.
	sig, _, _ := signer.Sign(CanonicalPayload{
		PassportID: "id", Name: "n", Organization: "o",
		Capabilities: []string{"read"}, IssuedAt: "2026-01-01T00:00:00Z",
	})
	if signer.Verify(tampered, sig) {
		t.Fatal("tampered payload must not verify")
	}
}

func TestSigner_TamperedSignatureFails(t *testing.T) {
	db := testDB(t)
	signer, err := LoadOrInitSigner(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	sig, signedJSON, _ := signer.Sign(CanonicalPayload{
		PassportID: "id", Name: "n", Organization: "o",
		Capabilities: []string{"read"}, IssuedAt: "2026-01-01T00:00:00Z",
	})
	bad := "A" + sig[1:]
	if signer.Verify(signedJSON, bad) {
		t.Fatal("tampered signature must not verify")
	}
	if signer.Verify(signedJSON, "not-base64-!@#") {
		t.Fatal("non-base64 signature must not verify")
	}
}

func TestSigner_PersistsAcrossLoad(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	s1, err := LoadOrInitSigner(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	sig, signedJSON, _ := s1.Sign(CanonicalPayload{
		PassportID: "id", Name: "n", Organization: "o",
		Capabilities: []string{"read"}, IssuedAt: "2026-01-01T00:00:00Z",
	})

	// Simulate a server restart: load signer fresh from DB. The persisted
	// row must round-trip back into a signer that verifies prior signatures.
	s2, err := LoadOrInitSigner(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if s1.PublicKeyPEM() != s2.PublicKeyPEM() {
		t.Fatal("reloaded signer should have the same public key")
	}
	if !s2.Verify(signedJSON, sig) {
		t.Fatal("reloaded signer should verify pre-restart signatures")
	}
}
