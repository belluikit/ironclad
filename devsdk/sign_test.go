// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package devsdk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/belluikit/ironclad/sdk/submission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfSignedCert creates a self-signed cert for testing (in production,
// the platform CA issues the cert).
func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Developer", Organization: []string{"Test Org"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}

func TestGenerateKeyPair(t *testing.T) {
	key, err := GenerateKeyPair()
	require.NoError(t, err)
	assert.Equal(t, elliptic.P256(), key.Curve)
}

func TestGenerateCSR(t *testing.T) {
	key, err := GenerateKeyPair()
	require.NoError(t, err)

	csrPEM, err := GenerateCSR(key, "Test Dev", "Test Org")
	require.NoError(t, err)
	assert.Contains(t, string(csrPEM), "CERTIFICATE REQUEST")
}

func TestSignArtifactAndVerify(t *testing.T) {
	key, err := GenerateKeyPair()
	require.NoError(t, err)

	certDER := selfSignedCert(t, key)
	content := []byte("this is a test shared library")

	sm, err := SignArtifact(key, certDER, content, "test-plugin", "1.0.0", "shared-library", "A test plugin")
	require.NoError(t, err)

	// Parse manifest
	m, err := sm.Manifest()
	require.NoError(t, err)
	assert.Equal(t, "test-plugin", m.Name)
	assert.Equal(t, "1.0.0", m.Version)
	assert.Equal(t, "shared-library", m.ContentType)
	assert.Contains(t, m.ContentHash, "sha256:")

	// Verify the signature using the certificate
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pubKey := cert.PublicKey.(*ecdsa.PublicKey)
	valid := ecdsa.VerifyASN1(pubKey, sm.ManifestBytes, sm.DeveloperSignature)
	assert.True(t, valid, "developer signature should verify")
}

func TestCreateBundleRoundTrip(t *testing.T) {
	key, _ := GenerateKeyPair()
	certDER := selfSignedCert(t, key)
	content := []byte("shared library bytes")

	sm, err := SignArtifact(key, certDER, content, "my-ext", "2.0.0", "shared-library", "")
	require.NoError(t, err)

	bundle := CreateBundle(sm, content)

	// Write and read back
	var buf bytes.Buffer
	require.NoError(t, submission.WriteBundle(&buf, bundle))

	b2, err := submission.ReadBundle(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	assert.Equal(t, content, b2.Content)
	assert.Equal(t, sm.ManifestBytes, b2.SignedManifest.ManifestBytes)
	assert.Equal(t, sm.DeveloperSignature, b2.SignedManifest.DeveloperSignature)

	// Verify signature from read-back
	cert, _ := x509.ParseCertificate(b2.SignedManifest.DeveloperCertificate)
	pubKey := cert.PublicKey.(*ecdsa.PublicKey)
	assert.True(t, ecdsa.VerifyASN1(pubKey, b2.SignedManifest.ManifestBytes, b2.SignedManifest.DeveloperSignature))
}
