package submission

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trendvidia/protowire/encoding/pb"
)

func TestBundleRoundTrip(t *testing.T) {
	manifest := &Manifest{
		ContentHash: "sha256:abcdef1234567890",
		ContentType: "shared-library",
		Name:        "my-extension",
		Version:     "1.2.3",
		Description: "A test extension",
	}
	manifestBytes, err := pb.Marshal(manifest)
	require.NoError(t, err)

	b := &Bundle{
		SignedManifest: SignedManifest{
			ManifestBytes:        manifestBytes,
			DeveloperCertificate: []byte("dev-cert-der"),
			DeveloperSignature:   []byte("dev-ecdsa-sig"),
		},
		Content: []byte("raw shared library bytes here"),
	}

	var buf bytes.Buffer
	err = WriteBundle(&buf, b)
	require.NoError(t, err)

	// Verify magic bytes
	data := buf.Bytes()
	assert.Equal(t, byte(0x89), data[0])
	assert.Equal(t, byte('T'), data[1])
	assert.Equal(t, byte('S'), data[2])
	assert.Equal(t, byte('B'), data[3])

	// Read back
	b2, err := ReadBundle(bytes.NewReader(data))
	require.NoError(t, err)

	assert.Equal(t, b.SignedManifest.ManifestBytes, b2.SignedManifest.ManifestBytes)
	assert.Equal(t, b.SignedManifest.DeveloperCertificate, b2.SignedManifest.DeveloperCertificate)
	assert.Equal(t, b.SignedManifest.DeveloperSignature, b2.SignedManifest.DeveloperSignature)
	assert.Equal(t, b.Content, b2.Content)

	// Parse manifest
	m, err := b2.SignedManifest.Manifest()
	require.NoError(t, err)
	assert.Equal(t, "my-extension", m.Name)
	assert.Equal(t, "1.2.3", m.Version)
	assert.Equal(t, "shared-library", m.ContentType)
}

func TestBundleInvalidMagic(t *testing.T) {
	manifestBytes, _ := pb.Marshal(&Manifest{ContentHash: "sha256:abc", ContentType: "data-file", Name: "test", Version: "1.0.0"})

	b := &Bundle{
		SignedManifest: SignedManifest{ManifestBytes: manifestBytes, DeveloperCertificate: []byte("cert"), DeveloperSignature: []byte("sig")},
		Content:        []byte("data"),
	}

	var buf bytes.Buffer
	require.NoError(t, WriteBundle(&buf, b))

	data := buf.Bytes()
	data[0] = 0x00

	_, err := ReadBundle(bytes.NewReader(data))
	assert.ErrorIs(t, err, ErrInvalidMagic)
}

func TestSignedManifestRoundTrip(t *testing.T) {
	sm := SignedManifest{
		ManifestBytes:        []byte(`{"name":"test"}`),
		DeveloperCertificate: []byte("cert-data"),
		DeveloperSignature:   []byte("sig-data"),
	}

	data, err := sm.MarshalBinary()
	require.NoError(t, err)

	var sm2 SignedManifest
	require.NoError(t, sm2.UnmarshalBinary(data))

	assert.Equal(t, sm.ManifestBytes, sm2.ManifestBytes)
	assert.Equal(t, sm.DeveloperCertificate, sm2.DeveloperCertificate)
	assert.Equal(t, sm.DeveloperSignature, sm2.DeveloperSignature)
}
