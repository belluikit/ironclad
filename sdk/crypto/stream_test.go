package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamEncryptDecryptRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()
	plaintext := []byte("hello, streaming encryption in ironclad!")

	var encrypted bytes.Buffer
	encHash, err := StreamEncrypt(key, nonce, bytes.NewReader(plaintext), &encrypted, 16)
	require.NoError(t, err)

	var decrypted bytes.Buffer
	decHash, err := StreamDecrypt(key, nonce, &encrypted, &decrypted)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted.Bytes())
	assert.Equal(t, encHash, decHash)
}

func TestStreamEncryptDecryptLargeData(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	// 256KB of random data
	plaintext := make([]byte, 256*1024)
	_, err := io.ReadFull(rand.Reader, plaintext)
	require.NoError(t, err)

	var encrypted bytes.Buffer
	encHash, err := StreamEncrypt(key, nonce, bytes.NewReader(plaintext), &encrypted, DefaultChunkSize)
	require.NoError(t, err)

	var decrypted bytes.Buffer
	decHash, err := StreamDecrypt(key, nonce, &encrypted, &decrypted)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted.Bytes())
	assert.Equal(t, encHash, decHash)
}

func TestStreamEncryptDecryptEmptyData(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	var encrypted bytes.Buffer
	_, err := StreamEncrypt(key, nonce, bytes.NewReader(nil), &encrypted, 64)
	require.NoError(t, err)

	var decrypted bytes.Buffer
	_, err = StreamDecrypt(key, nonce, &encrypted, &decrypted)
	require.NoError(t, err)
	assert.Empty(t, decrypted.Bytes())
}

func TestStreamDecryptTamperedChunk(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()
	plaintext := []byte("tamper test data for streaming")

	var encrypted bytes.Buffer
	_, err := StreamEncrypt(key, nonce, bytes.NewReader(plaintext), &encrypted, 10)
	require.NoError(t, err)

	// Tamper with a byte in the encrypted data (skip the 4-byte header)
	data := encrypted.Bytes()
	if len(data) > 5 {
		data[5] ^= 0xFF
	}

	var decrypted bytes.Buffer
	_, err = StreamDecrypt(key, nonce, bytes.NewReader(data), &decrypted)
	assert.Error(t, err)
}

func TestStreamDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	var encrypted bytes.Buffer
	_, err := StreamEncrypt(key1, nonce, bytes.NewReader([]byte("secret")), &encrypted, 64)
	require.NoError(t, err)

	var decrypted bytes.Buffer
	_, err = StreamDecrypt(key2, nonce, &encrypted, &decrypted)
	assert.Error(t, err)
}

func TestDeriveChunkNonceUniqueness(t *testing.T) {
	baseNonce, _ := GenerateNonce()
	nonce0 := deriveChunkNonce(baseNonce, 0)
	nonce1 := deriveChunkNonce(baseNonce, 1)
	nonce2 := deriveChunkNonce(baseNonce, 2)

	assert.NotEqual(t, nonce0, nonce1)
	assert.NotEqual(t, nonce1, nonce2)
	assert.NotEqual(t, nonce0, nonce2)
}

func TestStreamEncryptInvalidKeySize(t *testing.T) {
	_, err := StreamEncrypt([]byte("short"), []byte("nonce"), bytes.NewReader(nil), &bytes.Buffer{}, 64)
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	_, err = StreamDecrypt([]byte("short"), []byte("nonce"), bytes.NewReader(nil), &bytes.Buffer{})
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}
