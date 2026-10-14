// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package loader

import (
	"context"
	"testing"
	"time"

	"github.com/belluikit/ironclad/sdk/container"
	"github.com/belluikit/ironclad/sdk/submission"
	"github.com/belluikit/ironclad/sdk/verify"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trendvidia/protowire-go/encoding/pb"
)

func TestOpenExecutableMissingOptions(t *testing.T) {
	mock := verify.NewMock("key")
	ctx := context.Background()

	_, err := OpenExecutable(ctx, "test.tcn", mock, mock)
	assert.ErrorIs(t, err, ErrMissingOption)

	_, err = OpenExecutable(ctx, "test.tcn", mock, mock,
		WithSigningKey("sign"),
		WithEnvelopeKey("env"),
	)
	assert.ErrorIs(t, err, ErrMissingOption)
}

func TestOpenExecutableInvalidPath(t *testing.T) {
	mock := verify.NewMock("sign", "env", "dek")
	ctx := context.Background()

	_, err := OpenExecutable(ctx, "/nonexistent/path/to/file.tcn", mock, mock,
		WithSigningKey("sign"),
		WithEnvelopeKey("env"),
		WithDEKKeyName("dek"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "open container")
}

func TestSecureExecutableFeatures(t *testing.T) {
	se := &SecureExecutable{
		entitlements: map[string]bool{
			"pro": true,
			"gpu": true,
			// "premium" is NOT licensed
		},
	}

	assert.True(t, se.HasFeature("pro"))
	assert.True(t, se.HasFeature("gpu"))
	assert.False(t, se.HasFeature("premium"))

	features := se.Features()
	assert.Len(t, features, 2)
	assert.Contains(t, features, "pro")
	assert.Contains(t, features, "gpu")
}

func TestSecureExecutableMetadata(t *testing.T) {
	cid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	expires := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)

	se := &SecureExecutable{
		contentID: cid,
		name:      "my-tool",
		version:   "2.1.0",
		subject:   "customer-123",
		expiresAt: expires,
	}

	assert.Equal(t, cid, se.ContentID())
	assert.Equal(t, "my-tool", se.Name())
	assert.Equal(t, "2.1.0", se.Version())
	assert.Equal(t, "customer-123", se.Subject())
	assert.Equal(t, expires, se.ExpiresAt())
}

func TestSecureExecutableCloseIdempotent(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = 0xFF
	}

	se := &SecureExecutable{
		dek: dek,
	}

	// First close should zero the DEK
	se.Close()
	for _, b := range dek {
		assert.Equal(t, byte(0), b)
	}

	// Second close should not panic
	se.Close()
}

func TestSecureExecutableCloseZerosDEK(t *testing.T) {
	dek := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	se := &SecureExecutable{
		dek: dek,
	}

	se.Close()

	// Verify all bytes are zeroed
	for i, b := range dek {
		assert.Equal(t, byte(0), b, "byte %d should be zero", i)
	}
}

func TestBuildFeatureGateForExecutable(t *testing.T) {
	manifest := &submission.Manifest{
		ContentHash: "sha256:abc",
		ContentType: "executable",
		Name:        "my-tool",
		Version:     "1.0.0",
		Features: []submission.Feature{
			{Name: "premium", Symbols: []string{"PremiumFeature"}},
		},
	}
	manifestBytes, err := pb.Marshal(manifest)
	require.NoError(t, err)

	licenseToken := &container.LicenseToken{
		LicenseID:    []byte{1, 2, 3},
		ContentID:    []byte{4, 5, 6},
		Entitlements: []string{"premium", "gpu"},
		SigningKeyID: "key",
	}
	sl, err := container.NewSignedLicense(licenseToken)
	require.NoError(t, err)
	sl.Signature = []byte("sig")

	c := &container.Container{
		Envelope: container.ContentEnvelope{
			ContentType:       container.ContentTypeExecutable,
			DeveloperManifest: manifestBytes,
		},
		License: *sl,
	}

	_, entitlements, err := buildFeatureGate(c)
	require.NoError(t, err)

	assert.True(t, entitlements["premium"])
	assert.True(t, entitlements["gpu"])
	assert.False(t, entitlements["enterprise"])
}
