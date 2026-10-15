// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package devsdk

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/belluikit/ironclad/sdk/submission"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite sdk/testdata/golden/v2.tcsb")

// goldenDir holds the files sdk's TestGolden* read: a bundle and a
// container written by released code, which every later version must
// still read. Rewrite them only when the format version changes.
const goldenDir = "../sdk/testdata/golden"

// TestWriteGoldenBundle writes, with -update, the submission bundle a
// developer would send: an artifact signed with a fresh ECDSA P-256 key
// under a self-signed certificate valid until 2126. admin's
// TestWriteGoldenContainer packs it next, as the platform would.
func TestWriteGoldenBundle(t *testing.T) {
	if !*update {
		t.Skip("rewrites a golden file; run with -update")
	}
	key, err := GenerateKeyPair()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ironclad golden developer"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	content := []byte("ironclad golden artifact: if this decrypts, the format still reads.\n")
	sm, err := SignArtifact(key, certDER, content, "golden", "1.0.0", "app-definition", "the golden fixture")
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(goldenDir, 0o755))
	f, err := os.Create(filepath.Join(goldenDir, "v2.tcsb"))
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, submission.WriteBundle(f, CreateBundle(sm, content)))
}
