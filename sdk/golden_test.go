// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/belluikit/ironclad/sdk/container"
	"github.com/belluikit/ironclad/sdk/license"
	"github.com/belluikit/ironclad/sdk/submission"
	"github.com/belluikit/ironclad/sdk/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The golden files were written by released code: devsdk's
// TestWriteGoldenBundle and admin's TestWriteGoldenContainer, run with
// -update. Every later version must still read them. A failure here after
// a dependency or format change means files already in users' hands would
// stop opening: fix the code, not the golden file, unless the format
// version changed on purpose.

const goldenArtifact = "ironclad golden artifact: if this decrypts, the format still reads.\n"

func goldenBundle(t *testing.T) *submission.Bundle {
	t.Helper()
	f, err := os.Open("testdata/golden/v2.tcsb")
	require.NoError(t, err)
	defer f.Close()
	b, err := submission.ReadBundle(f)
	require.NoError(t, err)
	return b
}

// TestGoldenBundle reads the golden submission bundle: its manifest decodes
// to what the developer wrote, the content hash matches, and the
// developer's signature verifies under the certificate it carries.
func TestGoldenBundle(t *testing.T) {
	b := goldenBundle(t)
	assert.Equal(t, goldenArtifact, string(b.Content))

	m, err := b.SignedManifest.Manifest()
	require.NoError(t, err)
	assert.Equal(t, "golden", m.Name)
	assert.Equal(t, "1.0.0", m.Version)
	assert.Equal(t, "app-definition", m.ContentType)
	sum := sha256.Sum256(b.Content)
	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), m.ContentHash)

	cert, err := x509.ParseCertificate(b.SignedManifest.DeveloperCertificate)
	require.NoError(t, err)
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "developer key is %T, want ECDSA", cert.PublicKey)
	assert.True(t, ecdsa.VerifyASN1(pub, b.SignedManifest.ManifestBytes, b.SignedManifest.DeveloperSignature),
		"developer signature does not verify over the manifest")
}

// TestGoldenContainer opens the golden container the platform packed from
// that bundle: both signatures and the renewal chain verify, the license
// carries its terms with the renewal's later expiry, and the payload
// decrypts to the developer's artifact.
func TestGoldenContainer(t *testing.T) {
	ctx := context.Background()
	b := goldenBundle(t)

	c, err := Open("testdata/golden/v2.tcn")
	require.NoError(t, err)
	assert.Equal(t, container.ContentTypeAppDefinition, c.Envelope.ContentType)
	assert.Equal(t, b.SignedManifest.ManifestBytes, c.Envelope.DeveloperManifest)
	require.Len(t, c.Renewals, 1)

	// The developer's self-signed certificate is its own root.
	devCert, err := x509.ParseCertificate(c.Envelope.DeveloperCertificate)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(devCert)

	mock := verify.NewMock("ironclad-dek", "ironclad-sign")
	result, err := Validate(ctx, c, mock, roots, "ironclad-sign", "ironclad-sign")
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, license.StatusValid, result.Status)
	assert.Equal(t, time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC), result.ExpiresAt.UTC(),
		"the renewal's expiry should replace the license's")

	lic, err := c.License.Token()
	require.NoError(t, err)
	assert.Equal(t, "golden-customer", lic.Subject)
	assert.Equal(t, []string{"pro", "charts-3d"}, lic.Entitlements)
	assert.Equal(t, "https://license.example.com/renew", lic.RenewalEndpoint)

	plain, err := Decrypt(ctx, c, mock, "ironclad-dek")
	require.NoError(t, err)
	assert.Equal(t, goldenArtifact, string(plain))
}
