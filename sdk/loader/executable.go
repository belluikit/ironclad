// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

// Package loader provides secure loading of executables and Go plugins from
// encrypted, signed ironclad containers (.tcn files).
//
// SecureExecutable validates all signatures, checks the license state, and
// uses a decrypt-per-run model: the DEK is cached in memory (32 bytes) but
// the full payload is only decrypted when Run() or Command() is called. The
// decrypted binary is written to a platform-specific secure location (memfd
// on Linux, codesigned temp file on macOS, temp .exe on Windows) and removed
// immediately after the subprocess starts.
//
// Usage:
//
//	exe, err := loader.OpenExecutable(ctx, "tool.tcn", verifier, unwrapper,
//	    loader.WithSigningKey("ironclad-sign"),
//	    loader.WithEnvelopeKey("ironclad-sign"),
//	    loader.WithDEKKeyName("ironclad-dek"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer exe.Close()
//
//	if err := exe.Run(ctx, "--version"); err != nil {
//	    log.Fatal(err)
//	}
package loader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	sdk "github.com/belluikit/ironclad/sdk"
	"github.com/belluikit/ironclad/sdk/container"
	tcrypto "github.com/belluikit/ironclad/sdk/crypto"
	"github.com/belluikit/ironclad/sdk/submission"
	"github.com/belluikit/ironclad/sdk/verify"
	"github.com/google/uuid"
	"github.com/trendvidia/protowire-go/encoding/pb"
)

var (
	// ErrWrongContentType is returned when the container's content type
	// is not ContentTypeExecutable.
	ErrWrongContentType = errors.New("loader: container content type is not executable")
)

// SecureExecutable wraps a validated executable from a .tcn container.
// The executable's DEK is cached in memory; the full payload is decrypted
// only when Run() or Command() is called, minimizing disk exposure.
//
// Close must be called when done to zero the cached DEK.
type SecureExecutable struct {
	container    *container.Container
	dek          []byte // cached 32-byte DEK
	closeOnce    sync.Once
	entitlements map[string]bool

	contentID uuid.UUID
	name      string
	version   string
	subject   string
	expiresAt time.Time
}

// OpenExecutable loads a .tcn container containing an executable,
// validates all signatures and the license, and prepares for execution.
//
// The container's content type must be ContentTypeExecutable.
// The DEK is unwrapped and cached; the full payload is not decrypted
// until Run() or Command() is called.
func OpenExecutable(
	ctx context.Context,
	path string,
	verifier verify.SignatureVerifier,
	unwrapper verify.DEKUnwrapper,
	opts ...Option,
) (*SecureExecutable, error) {
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

	// Enforce content type
	if c.Envelope.ContentType != container.ContentTypeExecutable {
		return nil, fmt.Errorf("%w: got %s", ErrWrongContentType, container.ContentTypeName(c.Envelope.ContentType))
	}

	// Validate signatures and license
	result, err := sdk.Validate(ctx, c, verifier, o.caRoots, o.signingKey, o.envelopeKey)
	if err != nil {
		return nil, fmt.Errorf("loader: validate: %w", err)
	}
	if !result.Valid {
		return nil, fmt.Errorf("%w: status=%s", ErrLicenseInvalid, result.Status)
	}

	// Extract entitlements from license
	_, entitlements, err := buildFeatureGate(c)
	if err != nil {
		return nil, fmt.Errorf("loader: build feature gate: %w", err)
	}

	// Parse manifest for metadata
	var name, version string
	if len(c.Envelope.DeveloperManifest) > 0 {
		var manifest submission.Manifest
		if err := pb.Unmarshal(c.Envelope.DeveloperManifest, &manifest); err == nil {
			name = manifest.Name
			version = manifest.Version
		}
	}

	// Unwrap DEK (cache the 32-byte key, don't decrypt the full payload yet)
	dek, err := unwrapper.Decrypt(ctx, o.dekKeyName, string(c.Envelope.WrappedDEK))
	if err != nil {
		return nil, fmt.Errorf("loader: unwrap DEK: %w", err)
	}

	// Extract license metadata
	licenseToken, err := c.License.Token()
	if err != nil {
		tcrypto.Zero(dek)
		return nil, fmt.Errorf("loader: parse license: %w", err)
	}

	return &SecureExecutable{
		container:    c,
		dek:          dek,
		entitlements: entitlements,
		contentID:    c.Envelope.ContentUUID(),
		name:         name,
		version:      version,
		subject:      licenseToken.Subject,
		expiresAt:    result.Terms.ExpiresAt,
	}, nil
}

// Run decrypts the executable, prepares it for execution on the current
// platform, and runs it as a subprocess with inherited stdin/stdout/stderr.
// The decrypted binary is removed from the filesystem immediately after
// the subprocess starts.
func (se *SecureExecutable) Run(ctx context.Context, args ...string) error {
	cmd, cleanup, err := se.Command(ctx, args...)
	if err != nil {
		return err
	}
	defer cleanup()

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Command decrypts the executable, prepares it for execution, and returns
// an *exec.Cmd ready to be configured and started. The caller has full
// control over stdin/stdout/stderr, environment, and working directory.
//
// The returned cleanup function must be called after the command completes
// (typically deferred after checking the error from Command). On macOS and
// Windows, cleanup removes the temporary executable file. On Linux (memfd),
// cleanup closes the anonymous file descriptor.
func (se *SecureExecutable) Command(ctx context.Context, args ...string) (cmd *exec.Cmd, cleanup func(), err error) {
	// Decrypt payload with cached DEK
	plaintext, err := sdk.DecryptWithDEK(se.container, se.dek)
	if err != nil {
		return nil, nil, fmt.Errorf("loader: decrypt: %w", err)
	}

	// Prepare executable on platform-specific secure location
	execPath, execCleanup, err := platformPrepareExec(plaintext)
	tcrypto.Zero(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPlatformLoad, err)
	}

	cmd = exec.CommandContext(ctx, execPath, args...)
	return cmd, execCleanup, nil
}

// HasFeature reports whether the given feature is licensed.
func (se *SecureExecutable) HasFeature(feature string) bool {
	return se.entitlements[feature]
}

// Features returns the list of licensed features.
func (se *SecureExecutable) Features() []string {
	features := make([]string, 0, len(se.entitlements))
	for f := range se.entitlements {
		features = append(features, f)
	}
	return features
}

// ContentID returns the content UUID from the container envelope.
func (se *SecureExecutable) ContentID() uuid.UUID { return se.contentID }

// Name returns the executable name from the developer manifest.
func (se *SecureExecutable) Name() string { return se.name }

// Version returns the executable version from the developer manifest.
func (se *SecureExecutable) Version() string { return se.version }

// Subject returns the license subject (customer identifier).
func (se *SecureExecutable) Subject() string { return se.subject }

// ExpiresAt returns the effective license expiry time (after renewals).
func (se *SecureExecutable) ExpiresAt() time.Time { return se.expiresAt }

// Close zeros the cached DEK. Safe to call multiple times.
func (se *SecureExecutable) Close() {
	se.closeOnce.Do(func() {
		tcrypto.Zero(se.dek)
	})
}
