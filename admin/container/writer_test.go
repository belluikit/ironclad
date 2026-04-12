package container

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkcontainer "github.com/trendvidia/ironclad/sdk/container"
)

func testContainer() *sdkcontainer.Container {
	contentID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	licenseID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	licenseToken := &sdkcontainer.LicenseToken{
		LicenseID:          licenseID[:],
		ContentID:          contentID[:],
		IssuedAtUnix:       time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC).Unix(),
		ExpiresAtUnix:      time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC).Unix(),
		GracePeriodSeconds: 259200,
		Subject:            "test",
		RenewalEndpoint:    "https://example.com/renew",
		SigningKeyID:       "ironclad-sign",
	}
	sl, _ := sdkcontainer.NewSignedLicense(licenseToken)
	sl.Signature = []byte("license-sig")

	return &sdkcontainer.Container{
		Header: sdkcontainer.NewFileHeader(2),
		Envelope: sdkcontainer.ContentEnvelope{
			FormatVersion:          sdkcontainer.FormatVersion,
			ContentID:              contentID[:],
			ContentType:            sdkcontainer.ContentTypeDataFile,
			HashAlgo:               sdkcontainer.HashAlgoSHA256,
			ContentHash:            []byte{1, 2, 3},
			WrappedDEK:             []byte("wrapped-dek"),
			EncryptAlgo:            sdkcontainer.EncryptionAlgoAES256GCM,
			NonceLen:               12,
			Nonce:                  make([]byte, 12),
			DeveloperCertificate:   []byte("dev-cert"),
			DeveloperSignature:     []byte("dev-sig"),
			DistributorCertificate: []byte("dist-cert"),
			DistributorSignature:   []byte("dist-sig"),
			Payload:                []byte("encrypted-data"),
		},
		License: *sl,
	}
}

func TestWriteAndReadContainer(t *testing.T) {
	c := testContainer()

	var buf bytes.Buffer
	err := WriteContainer(&buf, c)
	require.NoError(t, err)

	c2, err := sdkcontainer.ReadContainer(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	assert.Equal(t, c.Envelope.ContentID, c2.Envelope.ContentID)
	assert.Equal(t, c.Envelope.DeveloperCertificate, c2.Envelope.DeveloperCertificate)
	assert.Equal(t, c.Envelope.DistributorSignature, c2.Envelope.DistributorSignature)
	assert.Equal(t, c.Envelope.Payload, c2.Envelope.Payload)
	assert.Equal(t, c.License.TokenBytes, c2.License.TokenBytes)
}

func TestWriteContainerWithRenewals(t *testing.T) {
	c := testContainer()

	renewalID := uuid.New()
	parentRef := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	rt := &sdkcontainer.RenewalToken{
		RenewalID:             renewalID[:],
		ParentRef:             parentRef[:],
		ContentID:             c.Envelope.ContentID,
		IssuedAtUnix:          time.Now().UTC().Unix(),
		NewExpiresAtUnix:      time.Now().Add(90 * 24 * time.Hour).UTC().Unix(),
		NewGracePeriodSeconds: 172800,
		SigningKeyID:          "ironclad-sign",
	}
	sr, _ := sdkcontainer.NewSignedRenewal(rt)
	sr.Signature = []byte("renewal-sig")
	c.Renewals = sdkcontainer.RenewalChain{*sr}
	c.Header = sdkcontainer.NewFileHeader(3)

	var buf bytes.Buffer
	require.NoError(t, WriteContainer(&buf, c))

	c2, err := sdkcontainer.ReadContainer(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.Len(t, c2.Renewals, 1)
}

func TestAppendRenewal(t *testing.T) {
	c := testContainer()

	f, err := os.CreateTemp("", "ironclad-writer-test-*.tcn")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	require.NoError(t, WriteContainer(f, c))
	f.Close()

	// Save original envelope for comparison
	origEnvData, _ := c.Envelope.MarshalBinary()

	// Append renewal
	renewalID := uuid.New()
	parentRef := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	rt := &sdkcontainer.RenewalToken{
		RenewalID:        renewalID[:],
		ParentRef:        parentRef[:],
		ContentID:        c.Envelope.ContentID,
		IssuedAtUnix:     time.Now().UTC().Unix(),
		NewExpiresAtUnix: time.Now().Add(90 * 24 * time.Hour).UTC().Unix(),
		SigningKeyID:     "ironclad-sign",
	}
	sr, _ := sdkcontainer.NewSignedRenewal(rt)
	sr.Signature = []byte("renewal-sig")

	require.NoError(t, AppendRenewal(f.Name(), *sr))

	// Read back
	f2, err := os.Open(f.Name())
	require.NoError(t, err)
	defer f2.Close()

	c2, err := sdkcontainer.ReadContainer(f2)
	require.NoError(t, err)

	// Envelope unchanged
	newEnvData, _ := c2.Envelope.MarshalBinary()
	assert.Equal(t, origEnvData, newEnvData)

	// Has renewal
	assert.Len(t, c2.Renewals, 1)
}
