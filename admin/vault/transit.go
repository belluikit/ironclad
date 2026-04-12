package vault

import (
	"context"
	"encoding/base64"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// TransitClient implements cryptographic operations via Vault Transit.
// It satisfies both verify.SignatureVerifier and verify.DEKUnwrapper
// from the SDK package, so it can be passed directly to SDK functions.
type TransitClient struct {
	client *vaultapi.Client
	mount  string
}

// TransitOption configures a TransitClient.
type TransitOption func(*TransitClient)

// WithTransitMount sets a non-default mount path for the Transit engine.
func WithTransitMount(mount string) TransitOption {
	return func(tc *TransitClient) {
		tc.mount = mount
	}
}

// NewTransitClient creates a TransitClient from a Vault API client.
func NewTransitClient(client *vaultapi.Client, opts ...TransitOption) *TransitClient {
	tc := &TransitClient{
		client: client,
		mount:  "transit",
	}
	for _, opt := range opts {
		opt(tc)
	}
	return tc
}

// Encrypt wraps plaintext using a named Transit key.
func (tc *TransitClient) Encrypt(ctx context.Context, keyName string, plaintext []byte) (string, error) {
	path := fmt.Sprintf("%s/encrypt/%s", tc.mount, keyName)
	secret, err := tc.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return "", fmt.Errorf("vault transit encrypt: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault transit encrypt: empty response")
	}
	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("vault transit encrypt: missing ciphertext in response")
	}
	return ciphertext, nil
}

// Decrypt unwraps a Vault Transit ciphertext back to plaintext.
// Implements verify.DEKUnwrapper from the SDK.
func (tc *TransitClient) Decrypt(ctx context.Context, keyName string, ciphertext string) ([]byte, error) {
	path := fmt.Sprintf("%s/decrypt/%s", tc.mount, keyName)
	secret, err := tc.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault transit decrypt: empty response")
	}
	b64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("vault transit decrypt: missing plaintext in response")
	}
	plaintext, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt: decode plaintext: %w", err)
	}
	return plaintext, nil
}

// Sign produces a signature over data using a named Transit key.
func (tc *TransitClient) Sign(ctx context.Context, keyName string, data []byte) (string, error) {
	path := fmt.Sprintf("%s/sign/%s", tc.mount, keyName)
	secret, err := tc.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return "", fmt.Errorf("vault transit sign: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault transit sign: empty response")
	}
	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("vault transit sign: missing signature in response")
	}
	return signature, nil
}

// Verify checks a signature against data.
// Implements verify.SignatureVerifier from the SDK.
func (tc *TransitClient) Verify(ctx context.Context, keyName string, data []byte, signature string) (bool, error) {
	path := fmt.Sprintf("%s/verify/%s", tc.mount, keyName)
	secret, err := tc.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(data),
		"signature": signature,
	})
	if err != nil {
		return false, fmt.Errorf("vault transit verify: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return false, fmt.Errorf("vault transit verify: empty response")
	}
	valid, ok := secret.Data["valid"].(bool)
	if !ok {
		return false, fmt.Errorf("vault transit verify: missing valid field in response")
	}
	return valid, nil
}
