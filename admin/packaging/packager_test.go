// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package packaging

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/belluikit/ironclad/admin/vault"
	sdk "github.com/belluikit/ironclad/sdk"
	sdkcontainer "github.com/belluikit/ironclad/sdk/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackAndDecrypt(t *testing.T) {
	mock := vault.NewMockTransit("ironclad-dek", "ironclad-sign")
	ctx := context.Background()

	plaintext := []byte("hello, ironclad SDK/admin split!")
	p := NewPackager(mock)

	var buf bytes.Buffer
	c, err := p.Pack(ctx, bytes.NewReader(plaintext), &buf, PackConfig{
		ContentType:            sdkcontainer.ContentTypeAppDefinition,
		DEKKeyName:             "ironclad-dek",
		SigningKeyName:         "ironclad-sign",
		EnvelopeKeyName:        "ironclad-sign",
		DeveloperCertificate:   []byte("test-dev-cert"),
		DeveloperSignature:     []byte("test-dev-sig"),
		DistributorCertificate: []byte("test-dist-cert"),
		Subject:                "test-customer",
		ExpiresAt:              time.Now().UTC().Add(720 * time.Hour),
		GracePeriod:            72 * time.Hour,
		Entitlements:           []string{"pro"},
		RenewalEndpoint:        "https://license.example.com/renew",
	})
	require.NoError(t, err)
	assert.Equal(t, sdkcontainer.ContentTypeAppDefinition, c.Envelope.ContentType)

	// Read back using SDK (proves cross-module compatibility)
	c2, err := sdkcontainer.ReadContainer(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, c.Envelope.ContentID, c2.Envelope.ContentID)

	// Validate using SDK
	result, err := sdk.Validate(ctx, c2, mock, nil, "ironclad-sign", "ironclad-sign")
	require.NoError(t, err)
	assert.True(t, result.Valid)

	// Decrypt using SDK
	decrypted, err := sdk.Decrypt(ctx, c2, mock, "ironclad-dek")
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
