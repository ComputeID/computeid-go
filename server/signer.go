package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// Signer issues RSA-2048 / SHA-256 signatures over canonical passport JSON.
// Matches the signature_algorithm == "RSA-SHA256" string returned by the
// production ComputeID API.
type Signer struct {
	priv      *rsa.PrivateKey
	pubPEM    string
	privPEM   string
	algorithm string
}

// LoadOrInitSigner reads the singleton RSA key from the signing_keys table,
// or generates and persists a fresh one if the table is empty.
func LoadOrInitSigner(ctx context.Context, db DB) (*Signer, error) {
	row := db.QueryRow(ctx,
		`SELECT private_key_pem, public_key_pem, algorithm FROM signing_keys WHERE id = 1`)
	var priv, pub, algo string
	switch err := row.Scan(&priv, &pub, &algo); {
	case err == nil:
		return signerFromPEM(priv, pub, algo)
	case isNoRows(err):
		return generateAndPersistSigner(ctx, db)
	default:
		return nil, fmt.Errorf("load signing key: %w", err)
	}
}

func generateAndPersistSigner(ctx context.Context, db DB) (*Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	_, err = db.Exec(ctx,
		`INSERT INTO signing_keys (id, private_key_pem, public_key_pem, algorithm)
		 VALUES (1, $1, $2, 'RSA-SHA256')
		 ON CONFLICT (id) DO NOTHING`,
		privPEM, pubPEM)
	if err != nil {
		return nil, fmt.Errorf("persist signing key: %w", err)
	}
	return &Signer{priv: priv, privPEM: privPEM, pubPEM: pubPEM, algorithm: "RSA-SHA256"}, nil
}

func signerFromPEM(privPEM, pubPEM, algo string) (*Signer, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	if algo == "" {
		algo = "RSA-SHA256"
	}
	return &Signer{priv: priv, privPEM: privPEM, pubPEM: pubPEM, algorithm: algo}, nil
}

// PublicKeyPEM returns the PEM-encoded public key issued passports carry.
func (s *Signer) PublicKeyPEM() string { return s.pubPEM }

// Algorithm returns the signature_algorithm string ("RSA-SHA256").
func (s *Signer) Algorithm() string { return s.algorithm }

// CanonicalPayload is the subset of the passport that is signed at issuance.
// Fixed key order keeps signatures reproducible across runs.
type CanonicalPayload struct {
	PassportID   string   `json:"passport_id"`
	Name         string   `json:"name"`
	Organization string   `json:"organization"`
	Capabilities []string `json:"capabilities"`
	IssuedAt     string   `json:"issued_at"` // RFC3339Nano
}

// Sign returns a base64-encoded RSA-PKCS1v15 signature over a canonical JSON
// of the payload, plus the JSON bytes that were actually signed (stored in
// the agents row so Verify can recompute later).
func (s *Signer) Sign(p CanonicalPayload) (sigB64 string, signedJSON []byte, err error) {
	signedJSON, err = json.Marshal(p)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(signedJSON)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, h[:])
	if err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(sig), signedJSON, nil
}

// Verify returns true iff sigB64 was produced by this signer over signedJSON.
func (s *Signer) Verify(signedJSON []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(signedJSON)
	return rsa.VerifyPKCS1v15(&s.priv.PublicKey, crypto.SHA256, h[:], sig) == nil
}
