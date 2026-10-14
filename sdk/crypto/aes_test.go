// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	nonce, err := GenerateNonce()
	require.NoError(t, err)

	plaintext := []byte("hello, ironclad secure container!")

	ciphertext, err := Encrypt(key, nonce, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := Decrypt(key, nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	ciphertext, err := Encrypt(key, nonce, []byte{})
	require.NoError(t, err)

	decrypted, err := Decrypt(key, nonce, ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	ciphertext, err := Encrypt(key, nonce, []byte("secret data"))
	require.NoError(t, err)

	// Tamper with the ciphertext
	ciphertext[0] ^= 0xFF

	_, err = Decrypt(key, nonce, ciphertext)
	assert.ErrorIs(t, err, ErrDecryptFailed)
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	ciphertext, err := Encrypt(key1, nonce, []byte("secret data"))
	require.NoError(t, err)

	_, err = Decrypt(key2, nonce, ciphertext)
	assert.ErrorIs(t, err, ErrDecryptFailed)
}

func TestDecryptWrongNonce(t *testing.T) {
	key, _ := GenerateKey()
	nonce1, _ := GenerateNonce()
	nonce2, _ := GenerateNonce()

	ciphertext, err := Encrypt(key, nonce1, []byte("secret data"))
	require.NoError(t, err)

	_, err = Decrypt(key, nonce2, ciphertext)
	assert.ErrorIs(t, err, ErrDecryptFailed)
}

func TestInvalidKeySize(t *testing.T) {
	shortKey := []byte("tooshort")
	nonce, _ := GenerateNonce()

	_, err := Encrypt(shortKey, nonce, []byte("data"))
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	_, err = Decrypt(shortKey, nonce, []byte("data"))
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestGenerateKeyLength(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	assert.Len(t, key, KeySize)
}

func TestGenerateNonceLength(t *testing.T) {
	nonce, err := GenerateNonce()
	require.NoError(t, err)
	assert.Len(t, nonce, NonceSize)
}

func TestGenerateKeyUniqueness(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	assert.NotEqual(t, key1, key2)
}

func TestZero(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	Zero(data)
	for _, b := range data {
		assert.Equal(t, byte(0), b)
	}
}
