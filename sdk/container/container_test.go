package container

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testEnvelope() ContentEnvelope {
	contentID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	return ContentEnvelope{
		FormatVersion:          FormatVersion,
		ContentID:              contentID[:],
		ContentType:            ContentTypeDataFile,
		HashAlgo:               HashAlgoSHA256,
		ContentHash:            []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		WrappedDEK:             []byte("vault:v1:wrappedkeydata"),
		EncryptAlgo:            EncryptionAlgoAES256GCM,
		NonceLen:               12,
		Nonce:                  make([]byte, 12),
		DeveloperCertificate:   []byte("dev-certificate-der"),
		DeveloperSignature:     []byte("dev-ecdsa-signature"),
		DistributorCertificate: []byte("dist-certificate-der"),
		DistributorSignature:   []byte("dist-vault-signature"),
		Payload:                []byte("encrypted-payload-data"),
	}
}

func testLicenseToken() *LicenseToken {
	licenseID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	contentID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	return &LicenseToken{
		LicenseID:          licenseID[:],
		ContentID:          contentID[:],
		IssuedAtUnix:       time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC).Unix(),
		ExpiresAtUnix:      time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC).Unix(),
		GracePeriodSeconds: 259200,
		Subject:            "test-customer",
		Entitlements:       []string{"pro", "gpu"},
		RenewalEndpoint:    "https://license.example.com/renew",
		SigningKeyID:       "transit/keys/ironclad-sign/v1",
	}
}

func TestFileHeaderRoundTrip(t *testing.T) {
	h := NewFileHeader(3)
	data, err := h.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, FileHeaderSize)

	var h2 FileHeader
	require.NoError(t, h2.UnmarshalBinary(data))
	assert.Equal(t, h.Magic, h2.Magic)
	assert.Equal(t, h.Version, h2.Version)
	assert.Equal(t, h.SectionCount, h2.SectionCount)
}

func TestFileHeaderValidation(t *testing.T) {
	h := NewFileHeader(2)
	assert.NoError(t, h.Validate())

	h.Magic = [4]byte{0, 0, 0, 0}
	assert.ErrorIs(t, h.Validate(), ErrInvalidMagic)

	h.Magic = MagicBytes
	h.Version = 99
	assert.ErrorIs(t, h.Validate(), ErrInvalidVersion)
}

func TestEnvelopeRoundTrip(t *testing.T) {
	env := testEnvelope()
	data, err := env.MarshalBinary()
	require.NoError(t, err)

	var env2 ContentEnvelope
	require.NoError(t, env2.UnmarshalBinary(data))

	assert.Equal(t, env.ContentID, env2.ContentID)
	assert.Equal(t, env.ContentHash, env2.ContentHash)
	assert.Equal(t, env.WrappedDEK, env2.WrappedDEK)
	assert.Equal(t, env.DeveloperCertificate, env2.DeveloperCertificate)
	assert.Equal(t, env.DeveloperSignature, env2.DeveloperSignature)
	assert.Equal(t, env.DistributorCertificate, env2.DistributorCertificate)
	assert.Equal(t, env.DistributorSignature, env2.DistributorSignature)
	assert.Equal(t, env.Payload, env2.Payload)
}

func TestDistributorSignableBytesStability(t *testing.T) {
	env := testEnvelope()
	sig1 := env.DistributorSignableBytes()

	// Changing distributor signature or payload should NOT affect distributor signable bytes
	env.DistributorSignature = []byte("different-dist-sig")
	env.Payload = []byte("different-payload")
	sig2 := env.DistributorSignableBytes()

	assert.Equal(t, sig1, sig2, "distributor signable bytes should exclude distributor sig and payload")

	// But changing developer signature SHOULD affect distributor signable bytes
	env.DeveloperSignature = []byte("different-dev-sig")
	sig3 := env.DistributorSignableBytes()

	assert.NotEqual(t, sig1, sig3, "distributor signable bytes should include developer signature")
}

func TestSignedLicenseRoundTrip(t *testing.T) {
	token := testLicenseToken()
	sl, err := NewSignedLicense(token)
	require.NoError(t, err)
	sl.Signature = []byte("test-sig")

	data, err := sl.MarshalBinary()
	require.NoError(t, err)

	var sl2 SignedLicense
	require.NoError(t, sl2.UnmarshalBinary(data))

	assert.Equal(t, sl.TokenBytes, sl2.TokenBytes)
	assert.Equal(t, sl.Signature, sl2.Signature)
}

func TestRenewalChainRoundTrip(t *testing.T) {
	licenseID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	contentID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	renewalID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	r1 := &RenewalToken{
		RenewalID:             renewalID[:],
		ParentRef:             licenseID[:],
		ContentID:             contentID[:],
		IssuedAtUnix:          time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC).Unix(),
		NewExpiresAtUnix:      time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC).Unix(),
		NewGracePeriodSeconds: 172800,
		SigningKeyID:          "transit/keys/ironclad-sign/v1",
	}
	sr1, err := NewSignedRenewal(r1)
	require.NoError(t, err)
	sr1.Signature = []byte("sig1")

	chain := RenewalChain{*sr1}
	data, err := chain.MarshalBinary()
	require.NoError(t, err)

	var chain2 RenewalChain
	require.NoError(t, chain2.UnmarshalBinary(data))
	assert.Len(t, chain2, 1)
	assert.Equal(t, chain[0].TokenBytes, chain2[0].TokenBytes)
}

func TestContainerMagicBytes(t *testing.T) {
	sl, _ := NewSignedLicense(testLicenseToken())
	sl.Signature = []byte("sig")

	c := &Container{Envelope: testEnvelope(), License: *sl}
	envData, _ := c.Envelope.MarshalBinary()
	licData, _ := c.License.MarshalBinary()

	header := NewFileHeader(2)
	indexSize := 2 * SectionIndexEntrySize
	dataStart := FileHeaderSize + indexSize

	headerBytes, _ := header.MarshalBinary()
	idx1 := SectionIndexEntry{Type: SectionEnvelope, Offset: uint64(dataStart), Length: uint64(len(envData))}
	idx2 := SectionIndexEntry{Type: SectionLicense, Offset: uint64(dataStart + len(envData)), Length: uint64(len(licData))}
	idx1Bytes, _ := idx1.MarshalBinary()
	idx2Bytes, _ := idx2.MarshalBinary()

	var buf bytes.Buffer
	buf.Write(headerBytes)
	buf.Write(idx1Bytes)
	buf.Write(idx2Bytes)
	buf.Write(envData)
	buf.Write(licData)

	data := buf.Bytes()
	assert.Equal(t, byte(0x89), data[0])
	assert.Equal(t, byte('T'), data[1])
	assert.Equal(t, byte('C'), data[2])
	assert.Equal(t, byte('N'), data[3])

	c2, err := ReadContainer(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, c.Envelope.ContentID, c2.Envelope.ContentID)
	assert.Equal(t, c.Envelope.DeveloperCertificate, c2.Envelope.DeveloperCertificate)

	data[0] = 0x00
	_, err = ReadContainer(bytes.NewReader(data))
	assert.ErrorIs(t, err, ErrInvalidMagic)
}

func TestContentTypeSharedLibrary(t *testing.T) {
	assert.Equal(t, "shared-library", ContentTypeName(ContentTypeSharedLibrary))

	ct, err := ParseContentType("shared-library")
	require.NoError(t, err)
	assert.Equal(t, ContentTypeSharedLibrary, ct)
}
