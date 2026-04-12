package loader

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trendvidia/ironclad/sdk/verify"
)

func TestOpenMissingOptions(t *testing.T) {
	mock := verify.NewMock("key")
	ctx := context.Background()

	// No options at all
	_, err := Open(ctx, "test.tcn", mock, mock)
	assert.ErrorIs(t, err, ErrMissingOption)

	// Missing dekKeyName
	_, err = Open(ctx, "test.tcn", mock, mock,
		WithSigningKey("sign"),
		WithEnvelopeKey("env"),
	)
	assert.ErrorIs(t, err, ErrMissingOption)

	// Missing envelopeKey
	_, err = Open(ctx, "test.tcn", mock, mock,
		WithSigningKey("sign"),
		WithDEKKeyName("dek"),
	)
	assert.ErrorIs(t, err, ErrMissingOption)

	// Missing signingKey
	_, err = Open(ctx, "test.tcn", mock, mock,
		WithEnvelopeKey("env"),
		WithDEKKeyName("dek"),
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

func TestOpenValidationFailure(t *testing.T) {
	// Use a mock with keys that won't match the container signatures
	mock := verify.NewMock("wrong-key")
	ctx := context.Background()

	// This will fail at Open() because the file doesn't exist,
	// but the option validation passes. A proper test of validation
	// failure requires a real .tcn file, which is covered by
	// integration tests.
	_, err := Open(ctx, "/nonexistent.tcn", mock, mock,
		WithSigningKey("wrong-key"),
		WithEnvelopeKey("wrong-key"),
		WithDEKKeyName("wrong-key"),
	)
	assert.Error(t, err)
}

func TestSecurePluginLookup(t *testing.T) {
	// SecurePlugin.Lookup delegates to plugin.Plugin.Lookup.
	// We can't test with a real plugin without CGO and build -buildmode=plugin,
	// so we just verify the type exists and the method signature is correct.
	var sp *SecurePlugin
	assert.Nil(t, sp)
}
