package verify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
)

// Mock implements both SignatureVerifier and DEKUnwrapper for testing.
// It uses HMAC-SHA256 for signing and base64 wrapping for encryption,
// providing the same interface semantics without real cryptographic security.
type Mock struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewMock creates a Mock with the given key names.
func NewMock(keyNames ...string) *Mock {
	m := &Mock{keys: make(map[string][]byte)}
	for _, name := range keyNames {
		h := sha256.Sum256([]byte("mock-key-" + name))
		m.keys[name] = h[:]
	}
	return m
}

func (m *Mock) getKey(name string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, ok := m.keys[name]
	if !ok {
		return nil, fmt.Errorf("mock: unknown key %q", name)
	}
	return key, nil
}

// Sign produces a signature (for test setup — not part of the SDK interfaces).
func (m *Mock) Sign(_ context.Context, keyName string, data []byte) (string, error) {
	key, err := m.getKey(keyName)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("vault:v1:%s", sig), nil
}

func (m *Mock) Verify(_ context.Context, keyName string, data []byte, signature string) (bool, error) {
	expected, err := m.Sign(context.Background(), keyName, data)
	if err != nil {
		return false, err
	}
	return expected == signature, nil
}

func (m *Mock) Encrypt(_ context.Context, keyName string, plaintext []byte) (string, error) {
	if _, err := m.getKey(keyName); err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(plaintext)
	return fmt.Sprintf("vault:v1:%s", encoded), nil
}

func (m *Mock) Decrypt(_ context.Context, keyName string, ciphertext string) ([]byte, error) {
	if _, err := m.getKey(keyName); err != nil {
		return nil, err
	}
	const prefix = "vault:v1:"
	if len(ciphertext) < len(prefix) || ciphertext[:len(prefix)] != prefix {
		return nil, fmt.Errorf("mock: invalid ciphertext format")
	}
	plaintext, err := base64.StdEncoding.DecodeString(ciphertext[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("mock: decode: %w", err)
	}
	return plaintext, nil
}
