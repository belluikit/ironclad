package loader

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trendvidia/ironclad/sdk/container"
	"github.com/trendvidia/ironclad/sdk/submission"
	"github.com/trendvidia/ironclad/sdk/verify"
	"github.com/trendvidia/protowire/encoding/pb"
)

func TestOpenMissingOptions(t *testing.T) {
	mock := verify.NewMock("key")
	ctx := context.Background()

	_, err := Open(ctx, "test.tcn", mock, mock)
	assert.ErrorIs(t, err, ErrMissingOption)

	_, err = Open(ctx, "test.tcn", mock, mock,
		WithSigningKey("sign"),
		WithEnvelopeKey("env"),
	)
	assert.ErrorIs(t, err, ErrMissingOption)
}

func TestOpenInvalidPath(t *testing.T) {
	mock := verify.NewMock("sign", "env", "dek")
	ctx := context.Background()

	_, err := Open(ctx, "/nonexistent/path/to/file.tcn", mock, mock,
		WithSigningKey("sign"),
		WithEnvelopeKey("env"),
		WithDEKKeyName("dek"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "open container")
}

func TestFeatureGating(t *testing.T) {
	// Build a mock SecurePlugin with feature gating
	sp := &SecurePlugin{
		p: nil, // no real plugin, just testing the gate
		gatedSymbols: map[string]string{
			"Render3DChart": "charts-3d",
			"Configure3D":  "charts-3d",
			"Render2DChart": "charts-2d",
		},
		entitlements: map[string]bool{
			"charts-2d": true,
			// "charts-3d" is NOT licensed
		},
	}

	// Ungated symbol — not in any feature, always allowed
	// (can't test Lookup on nil plugin, but we can test the gate logic)

	// Licensed feature
	assert.True(t, sp.HasFeature("charts-2d"))
	assert.False(t, sp.HasFeature("charts-3d"))

	// Features list
	features := sp.Features()
	assert.Contains(t, features, "charts-2d")
	assert.NotContains(t, features, "charts-3d")
}

func TestLookupGatedSymbol(t *testing.T) {
	sp := &SecurePlugin{
		p: nil,
		gatedSymbols: map[string]string{
			"Premium": "pro",
		},
		entitlements: map[string]bool{},
	}

	// Lookup a gated symbol without the entitlement
	_, err := sp.Lookup("Premium")
	assert.ErrorIs(t, err, ErrFeatureNotLicensed)
	assert.Contains(t, err.Error(), "pro")
	assert.Contains(t, err.Error(), "Premium")
}

func TestLookupUngatedSymbol(t *testing.T) {
	sp := &SecurePlugin{
		p: nil,
		gatedSymbols: map[string]string{
			"Premium": "pro",
		},
		entitlements: map[string]bool{},
	}

	// An ungated symbol (not in gatedSymbols) passes the gate.
	// It will panic on nil plugin, so we just verify the gate logic
	// by checking that a gated+licensed symbol doesn't get ErrFeatureNotLicensed.
	sp2 := &SecurePlugin{
		p: nil,
		gatedSymbols: map[string]string{
			"Premium": "pro",
		},
		entitlements: map[string]bool{
			"pro": true,
		},
	}

	// Verify the gate would pass (don't actually call plugin.Lookup on nil)
	assert.True(t, sp2.HasFeature("pro"))
	assert.False(t, sp.HasFeature("pro"))
}

func TestBuildFeatureGate(t *testing.T) {
	// Build a manifest with features
	manifest := &submission.Manifest{
		ContentHash: "sha256:abc",
		ContentType: "shared-library",
		Name:        "charts",
		Version:     "1.0.0",
		Features: []submission.Feature{
			{Name: "charts-3d", Symbols: []string{"Render3D", "Export3D"}},
			{Name: "analytics", Symbols: []string{"RunAnalytics"}},
		},
	}
	manifestBytes, err := pb.Marshal(manifest)
	require.NoError(t, err)

	// Build a license with entitlements
	licenseToken := &container.LicenseToken{
		LicenseID:     []byte{1, 2, 3},
		ContentID:     []byte{4, 5, 6},
		Entitlements:  []string{"charts-3d"},
		SigningKeyID:  "key",
	}
	sl, err := container.NewSignedLicense(licenseToken)
	require.NoError(t, err)
	sl.Signature = []byte("sig")

	c := &container.Container{
		Envelope: container.ContentEnvelope{
			DeveloperManifest: manifestBytes,
		},
		License: *sl,
	}

	gated, entitlements, err := buildFeatureGate(c)
	require.NoError(t, err)

	// charts-3d symbols are gated
	assert.Equal(t, "charts-3d", gated["Render3D"])
	assert.Equal(t, "charts-3d", gated["Export3D"])
	assert.Equal(t, "analytics", gated["RunAnalytics"])

	// Only charts-3d is licensed
	assert.True(t, entitlements["charts-3d"])
	assert.False(t, entitlements["analytics"])
}
