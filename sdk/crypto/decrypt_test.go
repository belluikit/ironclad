package crypto

import (
	"context"
	"testing"

	"github.com/belluikit/ironclad/sdk/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenPayloadRoundTrip(t *testing.T) {
	mock := verify.NewMock("test-key")
	ctx := context.Background()

	plaintext := []byte("secret payload data")

	// Encrypt
	key, err := GenerateKey()
	require.NoError(t, err)
	nonce, err := GenerateNonce()
	require.NoError(t, err)
	ciphertext, err := Encrypt(key, nonce, plaintext)
	require.NoError(t, err)

	// Wrap key
	wrappedKey, err := mock.Encrypt(ctx, "test-key", key)
	require.NoError(t, err)

	// Decrypt via OpenPayload
	decrypted, dek, err := OpenPayload(ctx, mock, "test-key", []byte(wrappedKey), nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.Equal(t, key, dek)

	// Zero the dek
	Zero(dek)
}

func TestOpenPayloadBadKey(t *testing.T) {
	mock := verify.NewMock("test-key")
	ctx := context.Background()

	_, _, err := OpenPayload(ctx, mock, "wrong-key", []byte("bad"), []byte("nonce"), []byte("data"))
	assert.Error(t, err)
}

func TestOpenPayloadWithDEKRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()
	plaintext := []byte("payload for cached dek")
	ciphertext, _ := Encrypt(key, nonce, plaintext)

	decrypted, err := OpenPayloadWithDEK(key, nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestOpenPayloadWithDEKTampered(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()
	ciphertext, _ := Encrypt(key, nonce, []byte("data"))
	ciphertext[0] ^= 0xFF

	_, err := OpenPayloadWithDEK(key, nonce, ciphertext)
	assert.Error(t, err)
}
