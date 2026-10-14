// Package devsdk provides tools for third-party developers to sign artifacts
// and create submission bundles for the ironclad marketplace.
//
// Developers generate an ECDSA P-256 keypair, obtain an X.509 certificate
// from the platform CA, then use this package to sign their artifacts and
// package them into submission bundles (.tcsb files).
//
// This package has minimal dependencies — no Vault, no keyring, no admin tools.
package devsdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/belluikit/ironclad/sdk/submission"
	"github.com/trendvidia/protowire-go/encoding/pb"
)

// GenerateKeyPair generates a new ECDSA P-256 private key.
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}
	return key, nil
}

// GenerateCSR creates a Certificate Signing Request (PEM-encoded) for
// submission to the platform CA. The developer sends this CSR to obtain
// their X.509 certificate.
func GenerateCSR(key *ecdsa.PrivateKey, commonName, organization string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// SignArtifact signs a raw artifact and produces a SignedManifest.
// The developer calls this with their private key, DER-encoded certificate,
// artifact content, and metadata.
func SignArtifact(key *ecdsa.PrivateKey, certDER []byte, content []byte, name, version, contentType, description string) (*submission.SignedManifest, error) {
	// Compute content hash
	hash := sha256.Sum256(content)
	contentHash := "sha256:" + hex.EncodeToString(hash[:])

	// Build manifest
	manifest := &submission.Manifest{
		ContentHash: contentHash,
		ContentType: contentType,
		Name:        name,
		Version:     version,
		Description: description,
	}

	manifestBytes, err := pb.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	// Sign manifest bytes with developer's private key (ECDSA ASN.1 DER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("sign manifest: %w", err)
	}

	return &submission.SignedManifest{
		ManifestBytes:        manifestBytes,
		DeveloperCertificate: certDER,
		DeveloperSignature:   sig,
	}, nil
}

// CreateBundle creates a complete submission bundle from a signed manifest
// and the raw artifact content.
func CreateBundle(signedManifest *submission.SignedManifest, content []byte) *submission.Bundle {
	return &submission.Bundle{
		SignedManifest: *signedManifest,
		Content:        content,
	}
}
