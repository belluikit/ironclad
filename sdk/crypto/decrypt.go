// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package crypto

import (
	"context"
	"fmt"

	"github.com/belluikit/ironclad/sdk/verify"
)

// OpenPayload decrypts a payload using envelope encryption:
// 1. Unwrap the DEK using the provided DEKUnwrapper
// 2. Decrypt the payload with AES-256-GCM using the DEK
// Returns the plaintext and the unwrapped DEK (for optional local caching).
func OpenPayload(ctx context.Context, unwrapper verify.DEKUnwrapper, keyName string, wrappedDEK, nonce, ciphertext []byte) (plaintext, dek []byte, err error) {
	// Unwrap DEK
	dek, err = unwrapper.Decrypt(ctx, keyName, string(wrappedDEK))
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap DEK: %w", err)
	}

	// Decrypt payload with DEK
	plaintext, err = Decrypt(dek, nonce, ciphertext)
	if err != nil {
		Zero(dek)
		return nil, nil, fmt.Errorf("decrypt payload: %w", err)
	}

	return plaintext, dek, nil
}

// OpenPayloadWithDEK decrypts a payload using a pre-cached DEK,
// bypassing the unwrapper. Used when the DEK is available from
// local secure storage.
func OpenPayloadWithDEK(dek, nonce, ciphertext []byte) ([]byte, error) {
	plaintext, err := Decrypt(dek, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}
