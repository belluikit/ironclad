// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package packaging

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	admincontainer "github.com/belluikit/ironclad/admin/container"
	"github.com/belluikit/ironclad/admin/vault"
	sdkcontainer "github.com/belluikit/ironclad/sdk/container"
	"github.com/belluikit/ironclad/sdk/submission"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite sdk/testdata/golden/v2.tcn from v2.tcsb")

// goldenDir holds the files sdk's TestGolden* read; see devsdk's
// TestWriteGoldenBundle, which writes the bundle this test packs.
const goldenDir = "../../sdk/testdata/golden"

// TestWriteGoldenContainer writes, with -update, the container the
// platform makes from the golden bundle: its artifact encrypted, its
// developer certificate, manifest and signature carried over, signed and
// licensed with MockTransit's keys (derived from the key names, so sdk's
// verify.Mock checks them), and one renewal appended.
func TestWriteGoldenContainer(t *testing.T) {
	if !*update {
		t.Skip("rewrites a golden file; run devsdk's TestWriteGoldenBundle with -update first, then this")
	}
	ctx := context.Background()
	bf, err := os.Open(filepath.Join(goldenDir, "v2.tcsb"))
	require.NoError(t, err)
	defer bf.Close()
	b, err := submission.ReadBundle(bf)
	require.NoError(t, err)

	mock := vault.NewMockTransit("ironclad-dek", "ironclad-sign")
	var buf bytes.Buffer
	c, err := NewPackager(mock).Pack(ctx, bytes.NewReader(b.Content), &buf, PackConfig{
		ContentID:              uuid.MustParse("6f1c2a5e-0000-4000-8000-00000000c0de"),
		ContentType:            sdkcontainer.ContentTypeAppDefinition,
		DEKKeyName:             "ironclad-dek",
		SigningKeyName:         "ironclad-sign",
		EnvelopeKeyName:        "ironclad-sign",
		DeveloperCertificate:   b.SignedManifest.DeveloperCertificate,
		DeveloperSignature:     b.SignedManifest.DeveloperSignature,
		DeveloperManifest:      b.SignedManifest.ManifestBytes,
		DistributorCertificate: []byte("golden distributor certificate"),
		Subject:                "golden-customer",
		ExpiresAt:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		GracePeriod:            72 * time.Hour,
		Entitlements:           []string{"pro", "charts-3d"},
		RenewalEndpoint:        "https://license.example.com/renew",
	})
	require.NoError(t, err)
	path := filepath.Join(goldenDir, "v2.tcn")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))

	lic, err := c.License.Token()
	require.NoError(t, err)
	renewalID := uuid.MustParse("6f1c2a5e-0000-4000-8000-0000000004e1")
	sr, err := sdkcontainer.NewSignedRenewal(&sdkcontainer.RenewalToken{
		RenewalID:        renewalID[:],
		ParentRef:        lic.LicenseID,
		ContentID:        lic.ContentID,
		IssuedAtUnix:     time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC).Unix(),
		NewExpiresAtUnix: time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		SigningKeyID:     "ironclad-sign",
	})
	require.NoError(t, err)
	sig, err := mock.Sign(ctx, "ironclad-sign", sr.TokenBytes)
	require.NoError(t, err)
	sr.Signature = []byte(sig)
	require.NoError(t, admincontainer.AppendRenewal(path, *sr))
}
