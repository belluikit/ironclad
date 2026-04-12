// Package verify defines the interfaces that consumer applications must
// implement to use the ironclad SDK. These interfaces decouple the SDK from
// any specific key management backend (Vault, HSM, local keys, etc.).
package verify

import "context"

// SignatureVerifier verifies digital signatures.
// The admin module's vault.TransitClient implements this interface.
// Consumer apps can also provide their own implementation (e.g., a
// public-key-only verifier that doesn't need Vault access).
type SignatureVerifier interface {
	// Verify checks a signature against the given data using a named key.
	// Returns true if the signature is valid.
	Verify(ctx context.Context, keyName string, data []byte, signature string) (bool, error)
}

// DEKUnwrapper decrypts wrapped Data Encryption Keys.
// The admin module's vault.TransitClient implements this interface.
// Consumer apps can provide their own implementation backed by Vault,
// a local HSM, or a pre-provisioned key.
type DEKUnwrapper interface {
	// Decrypt unwraps a ciphertext string back to the plaintext DEK.
	Decrypt(ctx context.Context, keyName string, ciphertext string) ([]byte, error)
}
