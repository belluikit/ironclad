package sdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trendvidia/ironclad/sdk/container"
	tcrypto "github.com/trendvidia/ironclad/sdk/crypto"
	"github.com/trendvidia/ironclad/sdk/license"
	"github.com/trendvidia/ironclad/sdk/verify"
)

// buildTestContainer creates a fully signed + encrypted container for testing.
func buildTestContainer(t *testing.T, mock *verify.Mock, plaintext []byte, expiresAt time.Time, gracePeriod time.Duration) (*container.Container, []byte) {
	t.Helper()
	ctx := context.Background()

	contentID := uuid.New()
	contentHash := sha256.Sum256(plaintext)

	// Generate DEK and encrypt
	dek, err := tcrypto.GenerateKey()
	require.NoError(t, err)
	nonce, err := tcrypto.GenerateNonce()
	require.NoError(t, err)
	ciphertext, err := tcrypto.Encrypt(dek, nonce, plaintext)
	require.NoError(t, err)

	// Wrap DEK
	wrappedDEK, err := mock.Encrypt(ctx, "ironclad-dek", dek)
	require.NoError(t, err)

	// Generate developer keypair and self-signed cert
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	devCertDER, _ := x509.CreateCertificate(rand.Reader, devCertTemplate, devCertTemplate, &devKey.PublicKey, devKey)

	// Developer manifest bytes (what the developer signs)
	developerManifest := []byte("test-developer-manifest")

	env := container.ContentEnvelope{
		FormatVersion:          container.FormatVersion,
		ContentID:              contentID[:],
		ContentType:            container.ContentTypeAppDefinition,
		HashAlgo:               container.HashAlgoSHA256,
		ContentHash:            contentHash[:],
		WrappedDEK:             []byte(wrappedDEK),
		EncryptAlgo:            container.EncryptionAlgoAES256GCM,
		NonceLen:               uint8(len(nonce)),
		Nonce:                  nonce,
		DeveloperCertificate:   devCertDER,
		DeveloperManifest:      developerManifest,
		DistributorCertificate: []byte("dist-cert"),
		Payload:                ciphertext,
	}

	// Developer sign the manifest
	devSig, err := ecdsa.SignASN1(rand.Reader, devKey, developerManifest)
	require.NoError(t, err)
	env.DeveloperSignature = devSig

	// Distributor sign
	distSig, err := mock.Sign(ctx, "ironclad-sign", env.DistributorSignableBytes())
	require.NoError(t, err)
	env.DistributorSignature = []byte(distSig)

	// License
	licID := uuid.New()
	licenseToken := &container.LicenseToken{
		LicenseID:          licID[:],
		ContentID:          contentID[:],
		IssuedAtUnix:       time.Now().UTC().Unix(),
		ExpiresAtUnix:      expiresAt.Unix(),
		GracePeriodSeconds: int32(gracePeriod.Seconds()),
		Subject:            "test-customer",
		RenewalEndpoint:    "https://example.com/renew",
		SigningKeyID:       "ironclad-sign",
	}
	sl, err := container.NewSignedLicense(licenseToken)
	require.NoError(t, err)
	licSig, err := mock.Sign(ctx, "ironclad-sign", sl.TokenBytes)
	require.NoError(t, err)
	sl.Signature = []byte(licSig)

	c := &container.Container{
		Header:   container.NewFileHeader(2),
		Envelope: env,
		License:  *sl,
	}

	// Build CA root pool from dev cert (self-signed)
	caRoots := x509.NewCertPool()
	devCert, _ := x509.ParseCertificate(devCertDER)
	caRoots.AddCert(devCert)

	return c, dek
}

func writeContainerToFile(t *testing.T, c *container.Container) string {
	t.Helper()
	// Manually serialize (WriteContainer is in admin, we rebuild it here for SDK tests)
	envData, err := c.Envelope.MarshalBinary()
	require.NoError(t, err)
	licData, err := c.License.MarshalBinary()
	require.NoError(t, err)

	header := container.NewFileHeader(2)
	indexSize := 2 * container.SectionIndexEntrySize
	dataStart := container.FileHeaderSize + indexSize

	headerBytes, _ := header.MarshalBinary()
	idx1 := container.SectionIndexEntry{Type: container.SectionEnvelope, Offset: uint64(dataStart), Length: uint64(len(envData))}
	idx2 := container.SectionIndexEntry{Type: container.SectionLicense, Offset: uint64(dataStart + len(envData)), Length: uint64(len(licData))}
	idx1Bytes, _ := idx1.MarshalBinary()
	idx2Bytes, _ := idx2.MarshalBinary()

	var buf bytes.Buffer
	buf.Write(headerBytes)
	buf.Write(idx1Bytes)
	buf.Write(idx2Bytes)
	buf.Write(envData)
	buf.Write(licData)

	f, err := os.CreateTemp("", "ironclad-test-*.tcn")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })
	_, err = f.Write(buf.Bytes())
	require.NoError(t, err)
	f.Close()
	return f.Name()
}

func TestOpenValidateDecrypt(t *testing.T) {
	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	plaintext := []byte("hello, ironclad SDK e2e test!")
	expiresAt := time.Now().UTC().Add(720 * time.Hour)

	c, _ := buildTestContainer(t, mock, plaintext, expiresAt, 72*time.Hour)
	path := writeContainerToFile(t, c)

	// Open
	c2, err := Open(path)
	require.NoError(t, err)
	assert.Equal(t, c.Envelope.ContentID, c2.Envelope.ContentID)

	// Validate (nil caRoots skips developer sig check)
	ctx := context.Background()
	result, err := Validate(ctx, c2, mock, nil, "ironclad-sign", "ironclad-sign")
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, license.StatusValid, result.Status)

	// Decrypt
	decrypted, err := Decrypt(ctx, c2, mock, "ironclad-dek")
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptWithCachedDEK(t *testing.T) {
	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	plaintext := []byte("cached DEK test")

	c, dek := buildTestContainer(t, mock, plaintext, time.Now().Add(720*time.Hour), 72*time.Hour)

	decrypted, err := DecryptWithDEK(c, dek)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptContentHashMismatch(t *testing.T) {
	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	plaintext := []byte("tamper test")

	c, _ := buildTestContainer(t, mock, plaintext, time.Now().Add(720*time.Hour), 72*time.Hour)

	// Tamper with content hash
	c.Envelope.ContentHash[0] ^= 0xFF

	ctx := context.Background()
	_, err := Decrypt(ctx, c, mock, "ironclad-dek")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "content hash mismatch")
}

func TestDecryptWithDEKContentHashMismatch(t *testing.T) {
	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	plaintext := []byte("tamper test dek")

	c, dek := buildTestContainer(t, mock, plaintext, time.Now().Add(720*time.Hour), 72*time.Hour)
	c.Envelope.ContentHash[0] ^= 0xFF

	_, err := DecryptWithDEK(c, dek)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "content hash mismatch")
}

func TestValidateExpired(t *testing.T) {
	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	plaintext := []byte("expired")
	c, _ := buildTestContainer(t, mock, plaintext, time.Now().Add(-48*time.Hour), 24*time.Hour)

	ctx := context.Background()
	result, err := Validate(ctx, c, mock, nil, "ironclad-sign", "ironclad-sign")
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, license.StatusExpired, result.Status)
}

func TestValidateInGrace(t *testing.T) {
	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	plaintext := []byte("grace period")
	c, _ := buildTestContainer(t, mock, plaintext, time.Now().Add(-12*time.Hour), 72*time.Hour)

	ctx := context.Background()
	result, err := Validate(ctx, c, mock, nil, "ironclad-sign", "ironclad-sign")
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.InGrace)
	assert.Equal(t, license.StatusInGrace, result.Status)
}

func TestOpenInvalidPath(t *testing.T) {
	_, err := Open("/nonexistent/file.tcn")
	assert.Error(t, err)
}

func TestDecryptTamperedPayload(t *testing.T) {
	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	plaintext := []byte("tamper payload")

	c, _ := buildTestContainer(t, mock, plaintext, time.Now().Add(720*time.Hour), 72*time.Hour)
	c.Envelope.Payload[0] ^= 0xFF

	ctx := context.Background()
	_, err := Decrypt(ctx, c, mock, "ironclad-dek")
	assert.Error(t, err)
}
