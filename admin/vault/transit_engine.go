// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package vault

import "context"

// TransitEngine defines the full set of Transit operations needed by the admin module.
// Both TransitClient and MockTransit implement this interface.
// It is a superset of the SDK's verify.SignatureVerifier and verify.DEKUnwrapper.
type TransitEngine interface {
	Encrypt(ctx context.Context, keyName string, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, keyName string, ciphertext string) ([]byte, error)
	Sign(ctx context.Context, keyName string, data []byte) (string, error)
	Verify(ctx context.Context, keyName string, data []byte, signature string) (bool, error)
}
