// Package sdk provides the consumer-facing API for ironclad secure containers.
//
// This package allows applications to open, validate, and decrypt .tcn
// container files. It does NOT include any packaging, signing, or license
// issuance capabilities — those are in the admin module.
//
// Consumer applications must provide implementations of the
// [verify.SignatureVerifier] and [verify.DEKUnwrapper] interfaces to
// perform cryptographic operations. The admin module's vault.TransitClient
// satisfies both interfaces.
package sdk

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/trendvidia/ironclad/sdk/container"
	tcrypto "github.com/trendvidia/ironclad/sdk/crypto"
	"github.com/trendvidia/ironclad/sdk/license"
	"github.com/trendvidia/ironclad/sdk/verify"
)

// Open parses a container file from disk.
func Open(path string) (*container.Container, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open container: %w", err)
	}
	defer f.Close()
	return container.ReadContainer(f)
}

// ValidationResult wraps the license validation result with
// additional convenience fields.
type ValidationResult struct {
	Status    license.Status
	Terms     *license.EffectiveTerms
	ExpiresAt time.Time
	InGrace   bool
	Valid     bool
}

// Validate checks all signatures and license state of a container.
// The caRoots pool is used to verify the developer certificate chain.
// Pass nil to skip developer signature verification (e.g., for platform-only containers).
func Validate(ctx context.Context, c *container.Container, verifier verify.SignatureVerifier, caRoots *x509.CertPool, signingKey, envelopeKey string) (*ValidationResult, error) {
	v := license.NewValidator(verifier, signingKey, caRoots)
	result, err := v.ValidateContainer(ctx, c, envelopeKey)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	status := license.EvaluateStatus(result.Terms, now)

	return &ValidationResult{
		Status:    status,
		Terms:     result.Terms,
		ExpiresAt: result.Terms.ExpiresAt,
		InGrace:   status == license.StatusInGrace,
		Valid:     status == license.StatusValid || status == license.StatusInGrace,
	}, nil
}

// Decrypt decrypts a container's payload, returning the plaintext.
// It verifies the content hash after decryption to detect tampering.
// The caller is responsible for zeroing the returned plaintext when done.
func Decrypt(ctx context.Context, c *container.Container, unwrapper verify.DEKUnwrapper, dekKeyName string) ([]byte, error) {
	plaintext, dek, err := tcrypto.OpenPayload(
		ctx, unwrapper, dekKeyName,
		c.Envelope.WrappedDEK,
		c.Envelope.Nonce,
		c.Envelope.Payload,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	defer tcrypto.Zero(dek)

	// Verify content hash
	hash := sha256.Sum256(plaintext)
	if hash != c.Envelope.ContentHash {
		tcrypto.Zero(plaintext)
		return nil, fmt.Errorf("content hash mismatch: payload has been tampered with")
	}

	return plaintext, nil
}

// DecryptWithDEK decrypts using a pre-cached DEK (no unwrapper roundtrip).
func DecryptWithDEK(c *container.Container, dek []byte) ([]byte, error) {
	plaintext, err := tcrypto.OpenPayloadWithDEK(dek, c.Envelope.Nonce, c.Envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	// Verify content hash
	hash := sha256.Sum256(plaintext)
	if hash != c.Envelope.ContentHash {
		tcrypto.Zero(plaintext)
		return nil, fmt.Errorf("content hash mismatch: payload has been tampered with")
	}

	return plaintext, nil
}
