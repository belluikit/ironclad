package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize is the AES-256 key size in bytes.
	KeySize = 32
	// NonceSize is the standard GCM nonce size in bytes.
	NonceSize = 12
)

var (
	ErrInvalidKeySize = errors.New("key must be 32 bytes (AES-256)")
	ErrDecryptFailed  = errors.New("decryption failed: ciphertext is not authentic")
)

// GenerateKey generates a cryptographically random 256-bit AES key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}
	return key, nil
}

// GenerateNonce generates a cryptographically random GCM nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns the ciphertext (which includes the GCM authentication tag).
// The nonce must be provided separately and stored alongside the ciphertext.
func Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
// The ciphertext must include the GCM authentication tag (appended by Seal).
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// Zero overwrites a byte slice with zeros.
// Used to wipe sensitive data (keys, decrypted payloads) from memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
