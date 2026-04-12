// Package loader provides secure loading of Go plugins from encrypted,
// signed ironclad containers (.tcn files).
//
// The loader validates all signatures, checks the license state, decrypts
// the payload in memory, and loads it as a Go plugin using platform-specific
// mechanisms that avoid exposing the decrypted binary on the real filesystem.
//
// On Linux, the decrypted binary is loaded entirely from memory via memfd_create.
// On macOS and Windows, a secure temporary file is used with restrictive
// permissions and immediate deletion after loading.
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
//	sym, err := p.Lookup("ProcessData")
//	fn := sym.(func([]byte) []byte)
package loader

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"plugin"

	sdk "github.com/trendvidia/ironclad/sdk"
	tcrypto "github.com/trendvidia/ironclad/sdk/crypto"
	"github.com/trendvidia/ironclad/sdk/verify"
)

var (
	// ErrMissingOption is returned when a required option is not set.
	ErrMissingOption = errors.New("loader: required option not set")

	// ErrLicenseInvalid is returned when the license validation fails
	// (expired, revoked, or invalid signature).
	ErrLicenseInvalid = errors.New("loader: license validation failed")

	// ErrPlatformLoad is returned when the platform-specific loading
	// mechanism fails (memfd, tmpfile, dlopen, etc.).
	ErrPlatformLoad = errors.New("loader: platform load failed")
)

// SecurePlugin wraps a loaded Go plugin with controlled access.
// It mirrors the plugin.Plugin API without exposing the underlying
// plugin pointer.
type SecurePlugin struct {
	p *plugin.Plugin
}

// Lookup searches for a symbol (exported variable or function) in the plugin.
func (sp *SecurePlugin) Lookup(symName string) (plugin.Symbol, error) {
	return sp.p.Lookup(symName)
}

// Option configures the loader.
type Option func(*options)

type options struct {
	signingKey  string
	envelopeKey string
	dekKeyName  string
	caRoots     *x509.CertPool
}

// WithSigningKey sets the Vault Transit key name used for verifying
// license and renewal token signatures.
func WithSigningKey(key string) Option {
	return func(o *options) { o.signingKey = key }
}

// WithEnvelopeKey sets the Vault Transit key name used for verifying
// the content envelope signature.
func WithEnvelopeKey(key string) Option {
	return func(o *options) { o.envelopeKey = key }
}

// WithDEKKeyName sets the Vault Transit key name used for unwrapping
// the Data Encryption Key (DEK).
func WithDEKKeyName(key string) Option {
	return func(o *options) { o.dekKeyName = key }
}

// WithCARoots sets the trusted CA root certificates for verifying
// developer certificate chains. Pass nil to skip developer signature
// verification.
func WithCARoots(roots *x509.CertPool) Option {
	return func(o *options) { o.caRoots = roots }
}

// Open loads a .tcn container as a Go plugin.
//
// It performs the following steps:
//  1. Parses the container file
//  2. Validates all signatures and checks the license state
//  3. Decrypts the payload (shared library) in memory
//  4. Loads the decrypted binary as a Go plugin using a platform-specific
//     mechanism that minimizes disk exposure
//  5. Zeros the decrypted buffer
//
// The verifier and unwrapper are typically backed by Vault Transit
// (via the admin module's vault.TransitClient), but any implementation
// of the interfaces will work.
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

	// Decrypt payload
	plaintext, err := sdk.Decrypt(ctx, c, unwrapper, o.dekKeyName)
	if err != nil {
		return nil, fmt.Errorf("loader: decrypt: %w", err)
	}
	// Zero the decrypted buffer after platformLoad has mapped it
	defer tcrypto.Zero(plaintext)

	// Platform-specific secure loading
	p, err := platformLoad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPlatformLoad, err)
	}

	return &SecurePlugin{p: p}, nil
}
