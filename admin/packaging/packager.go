// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package packaging

import (
	"context"
	"fmt"
	"io"
	"time"

	admincontainer "github.com/belluikit/ironclad/admin/container"
	sdkcontainer "github.com/belluikit/ironclad/sdk/container"
	sdkcrypto "github.com/belluikit/ironclad/sdk/crypto"
	"github.com/google/uuid"
)

// Encryptor defines the encryption operations needed by the packaging module.
type Encryptor interface {
	Encrypt(ctx context.Context, keyName string, plaintext []byte) (string, error)
}

// Transit combines signing and encryption capabilities.
// Both vault.TransitClient and vault.MockTransit satisfy this interface.
type Transit interface {
	Signer
	Encryptor
}

// SealResult holds the output of the SealPayload operation.
type SealResult struct {
	WrappedDEK []byte
	Ciphertext []byte
	Nonce      []byte
	DEK        []byte
}

// SealPayload encrypts a payload using envelope encryption.
func SealPayload(ctx context.Context, encryptor Encryptor, keyName string, plaintext []byte) (*SealResult, error) {
	dek, err := sdkcrypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	nonce, err := sdkcrypto.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext, err := sdkcrypto.Encrypt(dek, nonce, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}

	wrappedDEK, err := encryptor.Encrypt(ctx, keyName, dek)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK: %w", err)
	}

	return &SealResult{
		WrappedDEK: []byte(wrappedDEK),
		Ciphertext: ciphertext,
		Nonce:      nonce,
		DEK:        dek,
	}, nil
}

// PackConfig holds all parameters for creating a new container.
type PackConfig struct {
	ContentID              uuid.UUID
	ContentType            uint16
	DEKKeyName             string
	SigningKeyName         string
	EnvelopeKeyName        string
	DeveloperCertificate   []byte // DER X.509 cert from developer submission
	DeveloperSignature     []byte // ECDSA signature from developer submission
	DeveloperManifest      []byte // protowire-encoded manifest bytes from developer submission
	DistributorCertificate []byte // DER X.509 cert for the platform
	Subject                string
	ExpiresAt              time.Time
	GracePeriod            time.Duration
	Entitlements           []string
	RenewalEndpoint        string
}

// Packager creates ironclad containers.
type Packager struct {
	transit Transit
}

// NewPackager creates a new Packager.
func NewPackager(transit Transit) *Packager {
	return &Packager{transit: transit}
}

// Pack reads plaintext from the input, encrypts and signs it,
// and writes a complete container to the output.
func (p *Packager) Pack(ctx context.Context, input io.Reader, output io.Writer, cfg PackConfig) (*sdkcontainer.Container, error) {
	plaintext, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	defer sdkcrypto.Zero(plaintext)

	if cfg.ContentID == uuid.Nil {
		cfg.ContentID = uuid.New()
	}

	contentHash := ContentHash(plaintext)

	sealed, err := SealPayload(ctx, p.transit, cfg.DEKKeyName, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal payload: %w", err)
	}
	defer sdkcrypto.Zero(sealed.DEK)

	env := sdkcontainer.ContentEnvelope{
		FormatVersion:          sdkcontainer.FormatVersion,
		ContentID:              cfg.ContentID[:],
		ContentType:            cfg.ContentType,
		HashAlgo:               sdkcontainer.HashAlgoSHA256,
		ContentHash:            contentHash[:],
		WrappedDEK:             sealed.WrappedDEK,
		EncryptAlgo:            sdkcontainer.EncryptionAlgoAES256GCM,
		NonceLen:               uint8(len(sealed.Nonce)),
		Nonce:                  sealed.Nonce,
		DeveloperCertificate:   cfg.DeveloperCertificate,
		DeveloperSignature:     cfg.DeveloperSignature,
		DeveloperManifest:      cfg.DeveloperManifest,
		DistributorCertificate: cfg.DistributorCertificate,
		Payload:                sealed.Ciphertext,
	}

	// Sign the envelope with the distributor (platform) key
	if err := SignDistributorEnvelope(ctx, p.transit, cfg.EnvelopeKeyName, &env); err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	now := time.Now().UTC()
	licID := uuid.New()
	licenseToken := &sdkcontainer.LicenseToken{
		LicenseID:          licID[:],
		ContentID:          cfg.ContentID[:],
		IssuedAtUnix:       now.Unix(),
		ExpiresAtUnix:      cfg.ExpiresAt.Unix(),
		GracePeriodSeconds: int32(cfg.GracePeriod.Seconds()),
		Subject:            cfg.Subject,
		Entitlements:       cfg.Entitlements,
		RenewalEndpoint:    cfg.RenewalEndpoint,
		SigningKeyID:       cfg.SigningKeyName,
	}

	sl, err := sdkcontainer.NewSignedLicense(licenseToken)
	if err != nil {
		return nil, fmt.Errorf("create license: %w", err)
	}

	if err := SignLicense(ctx, p.transit, cfg.SigningKeyName, sl); err != nil {
		return nil, fmt.Errorf("sign license: %w", err)
	}

	c := &sdkcontainer.Container{
		Header:   sdkcontainer.NewFileHeader(2),
		Envelope: env,
		License:  *sl,
	}

	if err := admincontainer.WriteContainer(output, c); err != nil {
		return nil, fmt.Errorf("write container: %w", err)
	}

	return c, nil
}
