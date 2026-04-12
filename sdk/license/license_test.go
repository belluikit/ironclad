package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trendvidia/ironclad/sdk/container"
	"github.com/trendvidia/ironclad/sdk/verify"
)

var (
	contentID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	licenseID = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	renewalID = uuid.MustParse("33333333-3333-3333-3333-333333333333")
)

func testLicenseToken() *container.LicenseToken {
	return &container.LicenseToken{
		LicenseID:          licenseID,
		ContentID:          contentID,
		IssuedAt:           time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC),
		ExpiresAt:          time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC),
		GracePeriodSeconds: 259200,
		Subject:            "test-customer",
		Entitlements:       []string{"pro"},
		RenewalEndpoint:    "https://license.example.com/renew",
		SigningKeyID:       "ironclad-sign",
	}
}

func signedLicense(t *testing.T, mock *verify.Mock) *container.SignedLicense {
	t.Helper()
	token := testLicenseToken()
	sl, err := container.NewSignedLicense(token)
	require.NoError(t, err)
	sig, err := mock.Sign(context.Background(), "ironclad-sign", sl.TokenBytes)
	require.NoError(t, err)
	sl.Signature = []byte(sig)
	return sl
}

func signedRenewal(t *testing.T, mock *verify.Mock, parentRef uuid.UUID, expiresAt time.Time, grace *int) *container.SignedRenewal {
	t.Helper()
	rt := &container.RenewalToken{
		RenewalID:             renewalID,
		ParentRef:             parentRef,
		ContentID:             contentID,
		IssuedAt:              time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC),
		NewExpiresAt:          expiresAt,
		NewGracePeriodSeconds: grace,
		SigningKeyID:          "ironclad-sign",
	}
	sr, err := container.NewSignedRenewal(rt)
	require.NoError(t, err)
	sig, err := mock.Sign(context.Background(), "ironclad-sign", sr.TokenBytes)
	require.NoError(t, err)
	sr.Signature = []byte(sig)
	return sr
}

func TestEvaluateTermsNoRenewals(t *testing.T) {
	token := testLicenseToken()
	terms, err := EvaluateTerms(token, nil)
	require.NoError(t, err)
	assert.Equal(t, token.ExpiresAt, terms.ExpiresAt)
	assert.Equal(t, token.GracePeriodSeconds, terms.GracePeriodSeconds)
	assert.Equal(t, 0, terms.RenewalCount)
}

func TestEvaluateTermsWithRenewal(t *testing.T) {
	mock := verify.NewMock("ironclad-sign")
	token := testLicenseToken()
	newGrace := 172800
	sr := signedRenewal(t, mock, licenseID, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), &newGrace)

	terms, err := EvaluateTerms(token, container.RenewalChain{*sr})
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), terms.ExpiresAt)
	assert.Equal(t, 172800, terms.GracePeriodSeconds)
	assert.Equal(t, 1, terms.RenewalCount)
}

func TestEvaluateStatusValid(t *testing.T) {
	terms := &EffectiveTerms{ExpiresAt: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC), GracePeriodSeconds: 259200}
	assert.Equal(t, StatusValid, EvaluateStatus(terms, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)))
}

func TestEvaluateStatusInGrace(t *testing.T) {
	terms := &EffectiveTerms{ExpiresAt: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC), GracePeriodSeconds: 259200}
	assert.Equal(t, StatusInGrace, EvaluateStatus(terms, time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)))
}

func TestEvaluateStatusExpired(t *testing.T) {
	terms := &EffectiveTerms{ExpiresAt: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC), GracePeriodSeconds: 259200}
	assert.Equal(t, StatusExpired, EvaluateStatus(terms, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)))
}

func TestValidateContainerSuccess(t *testing.T) {
	ctx := context.Background()
	mock := verify.NewMock("ironclad-sign", "ironclad-envelope")

	env := container.ContentEnvelope{
		FormatVersion:          container.FormatVersion,
		ContentID:              contentID,
		ContentType:            container.ContentTypeDataFile,
		HashAlgo:               container.HashAlgoSHA256,
		WrappedDEK:             []byte("wrapped"),
		EncryptAlgo:            container.EncryptionAlgoAES256GCM,
		NonceLen:               12,
		Nonce:                  make([]byte, 12),
		DeveloperCertificate:   []byte("dev-cert"),
		DeveloperSignature:     []byte("dev-sig"),
		DistributorCertificate: []byte("dist-cert"),
		Payload:                []byte("payload"),
	}

	// Sign with distributor key (developer sig verification skipped when caRoots is nil)
	distSig, err := mock.Sign(ctx, "ironclad-envelope", env.DistributorSignableBytes())
	require.NoError(t, err)
	env.DistributorSignature = []byte(distSig)

	sl := signedLicense(t, mock)
	c := &container.Container{
		Header:   container.NewFileHeader(2),
		Envelope: env,
		License:  *sl,
	}

	v := NewValidator(mock, "ironclad-sign", nil)
	result, err := v.ValidateContainer(ctx, c, "ironclad-envelope")
	require.NoError(t, err)
	assert.True(t, result.EnvelopeValid)
	assert.True(t, result.LicenseValid)
}

func TestValidateRenewalChainBadParentRef(t *testing.T) {
	ctx := context.Background()
	mock := verify.NewMock("ironclad-sign")
	token := testLicenseToken()
	wrongParent := uuid.MustParse("99999999-9999-9999-9999-999999999999")
	sr := signedRenewal(t, mock, wrongParent, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), nil)

	v := NewValidator(mock, "ironclad-sign", nil)
	_, err := v.ValidateRenewalChain(ctx, token, container.RenewalChain{*sr})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parent_ref")
}

func TestStatusString(t *testing.T) {
	assert.Equal(t, "VALID", StatusValid.String())
	assert.Equal(t, "IN_GRACE", StatusInGrace.String())
	assert.Equal(t, "EXPIRED", StatusExpired.String())
	assert.Equal(t, "REVOKED", StatusRevoked.String())
}

func TestValidateEnvelopeDualSignature(t *testing.T) {
	ctx := context.Background()
	mock := verify.NewMock("ironclad-envelope")

	// Generate developer keypair and self-signed cert
	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	devCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Dev", Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	devCertDER, err := x509.CreateCertificate(rand.Reader, devCertTemplate, devCertTemplate, &devKey.PublicKey, devKey)
	require.NoError(t, err)

	env := container.ContentEnvelope{
		FormatVersion:          container.FormatVersion,
		ContentID:              contentID,
		ContentType:            container.ContentTypeSharedLibrary,
		HashAlgo:               container.HashAlgoSHA256,
		ContentHash:            [32]byte{1, 2, 3},
		WrappedDEK:             []byte("wrapped"),
		EncryptAlgo:            container.EncryptionAlgoAES256GCM,
		NonceLen:               12,
		Nonce:                  make([]byte, 12),
		DeveloperCertificate:   devCertDER,
		DistributorCertificate: []byte("dist-cert"),
		Payload:                []byte("payload"),
	}

	// Developer signs
	devSig, err := ecdsa.SignASN1(rand.Reader, devKey, env.DeveloperSignableBytes())
	require.NoError(t, err)
	env.DeveloperSignature = devSig

	// Distributor signs
	distSig, err := mock.Sign(ctx, "ironclad-envelope", env.DistributorSignableBytes())
	require.NoError(t, err)
	env.DistributorSignature = []byte(distSig)

	// Set up CA roots with the self-signed cert
	caRoots := x509.NewCertPool()
	devCert, _ := x509.ParseCertificate(devCertDER)
	caRoots.AddCert(devCert)

	// Validate — should verify both signatures
	v := NewValidator(mock, "ironclad-sign", caRoots)
	err = v.ValidateEnvelope(ctx, &env, "ironclad-envelope")
	require.NoError(t, err)
}

func TestValidateEnvelopeBadDeveloperSig(t *testing.T) {
	ctx := context.Background()
	mock := verify.NewMock("ironclad-envelope")

	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	devCertDER, _ := x509.CreateCertificate(rand.Reader, devCertTemplate, devCertTemplate, &devKey.PublicKey, devKey)

	env := container.ContentEnvelope{
		FormatVersion:          container.FormatVersion,
		ContentID:              contentID,
		ContentType:            container.ContentTypeDataFile,
		HashAlgo:               container.HashAlgoSHA256,
		DeveloperCertificate:   devCertDER,
		DeveloperSignature:     []byte("bad-signature"),
		DistributorCertificate: []byte("dist-cert"),
	}

	caRoots := x509.NewCertPool()
	devCert, _ := x509.ParseCertificate(devCertDER)
	caRoots.AddCert(devCert)

	v := NewValidator(mock, "ironclad-sign", caRoots)
	err := v.ValidateEnvelope(ctx, &env, "ironclad-envelope")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "developer signature invalid")
}

func TestValidateEnvelopeBadDistributorSig(t *testing.T) {
	ctx := context.Background()
	mock := verify.NewMock("ironclad-envelope")

	env := container.ContentEnvelope{
		FormatVersion:          container.FormatVersion,
		ContentID:              contentID,
		DistributorCertificate: []byte("dist-cert"),
		DistributorSignature:   []byte("bad-distributor-sig"),
	}

	// No caRoots — skip developer sig check, test distributor failure
	v := NewValidator(mock, "ironclad-sign", nil)
	err := v.ValidateEnvelope(ctx, &env, "ironclad-envelope")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "distributor")
}
