// Package loader provides secure loading of Go plugins from encrypted,
// signed ironclad containers (.tcn files).
//
// The loader validates all signatures, checks the license state, decrypts
// the payload in memory, and loads it as a Go plugin using platform-specific
// mechanisms that avoid exposing the decrypted binary on the real filesystem.
//
// Feature gating: if the developer declared feature-to-symbol mappings in
// their manifest, Lookup() will refuse to return symbols gated by features
// not present in the license's Entitlements. Ungated symbols are always
// accessible.
//
// Usage:
//
//	p, err := loader.Open(ctx, "module.tcn", verifier, unwrapper,
//	    loader.WithSigningKey("ironclad-sign"),
//	    loader.WithEnvelopeKey("ironclad-sign"),
//	    loader.WithDEKKeyName("ironclad-dek"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	sym, err := p.Lookup("Render2DChart")  // always available
//	sym, err := p.Lookup("Render3DChart")  // only if "charts-3d" is in entitlements
package loader

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"plugin"

	sdk "github.com/trendvidia/ironclad/sdk"
	"github.com/trendvidia/ironclad/sdk/container"
	tcrypto "github.com/trendvidia/ironclad/sdk/crypto"
	"github.com/trendvidia/ironclad/sdk/submission"
	"github.com/trendvidia/ironclad/sdk/verify"
	"github.com/trendvidia/protowire-go/encoding/pb"
)

var (
	ErrMissingOption = errors.New("loader: required option not set")
	ErrLicenseInvalid = errors.New("loader: license validation failed")
	ErrPlatformLoad  = errors.New("loader: platform load failed")

	// ErrFeatureNotLicensed is returned when Lookup() is called for a
	// symbol that is gated by a feature not present in the license.
	ErrFeatureNotLicensed = errors.New("loader: feature not licensed")
)

// SecurePlugin wraps a loaded Go plugin with entitlement-based access control.
// Symbols gated by features not in the license's Entitlements are blocked.
type SecurePlugin struct {
	p            *plugin.Plugin
	gatedSymbols map[string]string // symbol name → required feature
	entitlements map[string]bool   // licensed features
}

// Lookup searches for a symbol in the plugin.
// Returns ErrFeatureNotLicensed if the symbol is gated by an unlicensed feature.
func (sp *SecurePlugin) Lookup(symName string) (plugin.Symbol, error) {
	if requiredFeature, gated := sp.gatedSymbols[symName]; gated {
		if !sp.entitlements[requiredFeature] {
			return nil, fmt.Errorf("%w: symbol %q requires feature %q", ErrFeatureNotLicensed, symName, requiredFeature)
		}
	}
	return sp.p.Lookup(symName)
}

// HasFeature reports whether the given feature is licensed.
func (sp *SecurePlugin) HasFeature(feature string) bool {
	return sp.entitlements[feature]
}

// Features returns the list of licensed features.
func (sp *SecurePlugin) Features() []string {
	features := make([]string, 0, len(sp.entitlements))
	for f := range sp.entitlements {
		features = append(features, f)
	}
	return features
}

// Option configures the loader.
type Option func(*options)

type options struct {
	signingKey  string
	envelopeKey string
	dekKeyName  string
	caRoots     *x509.CertPool
}

func WithSigningKey(key string) Option {
	return func(o *options) { o.signingKey = key }
}

func WithEnvelopeKey(key string) Option {
	return func(o *options) { o.envelopeKey = key }
}

func WithDEKKeyName(key string) Option {
	return func(o *options) { o.dekKeyName = key }
}

func WithCARoots(roots *x509.CertPool) Option {
	return func(o *options) { o.caRoots = roots }
}

// Open loads a .tcn container as a Go plugin with entitlement-based
// feature gating.
func Open(
	ctx context.Context,
	path string,
	verifier verify.SignatureVerifier,
	unwrapper verify.DEKUnwrapper,
	opts ...Option,
) (*SecurePlugin, error) {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}
	if o.signingKey == "" || o.envelopeKey == "" || o.dekKeyName == "" {
		return nil, fmt.Errorf("%w: signingKey, envelopeKey, and dekKeyName are all required", ErrMissingOption)
	}

	// Parse container
	c, err := sdk.Open(path)
	if err != nil {
		return nil, fmt.Errorf("loader: open container: %w", err)
	}

	// Validate signatures and license
	result, err := sdk.Validate(ctx, c, verifier, o.caRoots, o.signingKey, o.envelopeKey)
	if err != nil {
		return nil, fmt.Errorf("loader: validate: %w", err)
	}
	if !result.Valid {
		return nil, fmt.Errorf("%w: status=%s", ErrLicenseInvalid, result.Status)
	}

	// Build feature gate from developer manifest + license entitlements
	gatedSymbols, entitlements, err := buildFeatureGate(c)
	if err != nil {
		return nil, fmt.Errorf("loader: build feature gate: %w", err)
	}

	// Decrypt payload
	plaintext, err := sdk.Decrypt(ctx, c, unwrapper, o.dekKeyName)
	if err != nil {
		return nil, fmt.Errorf("loader: decrypt: %w", err)
	}
	defer tcrypto.Zero(plaintext)

	// Platform-specific secure loading
	p, err := platformLoad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPlatformLoad, err)
	}

	return &SecurePlugin{
		p:            p,
		gatedSymbols: gatedSymbols,
		entitlements: entitlements,
	}, nil
}

// buildFeatureGate parses the developer manifest for feature-to-symbol
// mappings and the license for entitlements.
func buildFeatureGate(c *container.Container) (gatedSymbols map[string]string, entitlements map[string]bool, err error) {
	gatedSymbols = make(map[string]string)
	entitlements = make(map[string]bool)

	// Parse license entitlements
	licenseToken, err := c.License.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("parse license: %w", err)
	}
	for _, e := range licenseToken.Entitlements {
		entitlements[e] = true
	}

	// Parse developer manifest for feature-gated symbols
	if len(c.Envelope.DeveloperManifest) > 0 {
		var manifest submission.Manifest
		if err := pb.Unmarshal(c.Envelope.DeveloperManifest, &manifest); err != nil {
			return nil, nil, fmt.Errorf("parse developer manifest: %w", err)
		}
		for _, feature := range manifest.Features {
			for _, sym := range feature.Symbols {
				gatedSymbols[sym] = feature.Name
			}
		}
	}

	return gatedSymbols, entitlements, nil
}
