// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	return caKey, caCert
}

func TestCRLCheckerRevoked(t *testing.T) {
	caKey, caCert := generateTestCA(t)

	// Create a leaf certificate
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	revokedSerial := big.NewInt(42)

	// Create CRL with the leaf's serial revoked
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now()},
		},
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	// Serve CRL via test HTTP server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlBytes)
	}))
	defer srv.Close()

	// Create leaf cert with CRL distribution point
	leafTemplate := &x509.Certificate{
		SerialNumber:          revokedSerial,
		Subject:               pkix.Name{CommonName: "Revoked Dev"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL + "/crl"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	checker := NewCRLChecker()
	revoked, err := checker.IsRevoked(context.Background(), leafCert)
	require.NoError(t, err)
	assert.True(t, revoked, "certificate should be revoked")
}

func TestCRLCheckerNotRevoked(t *testing.T) {
	caKey, caCert := generateTestCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Empty CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlBytes, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlBytes)
	}))
	defer srv.Close()

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Valid Dev"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL + "/crl"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	checker := NewCRLChecker()
	revoked, err := checker.IsRevoked(context.Background(), leafCert)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestCRLCheckerNoCRLPoints(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	checker := NewCRLChecker()
	revoked, err := checker.IsRevoked(context.Background(), cert)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestCompositeRevocationChecker(t *testing.T) {
	// One checker says not revoked, another says revoked → revoked
	notRevoked := &mockRevocationChecker{revoked: false}
	isRevoked := &mockRevocationChecker{revoked: true}

	composite := NewCompositeRevocationChecker(notRevoked, isRevoked)
	revoked, err := composite.IsRevoked(context.Background(), &x509.Certificate{})
	require.NoError(t, err)
	assert.True(t, revoked)
}

type mockRevocationChecker struct {
	revoked bool
	err     error
}

func (m *mockRevocationChecker) IsRevoked(_ context.Context, _ *x509.Certificate) (bool, error) {
	return m.revoked, m.err
}
