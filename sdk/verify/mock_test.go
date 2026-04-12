package verify

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockSignVerify(t *testing.T) {
	mock := NewMock("key1")
	ctx := context.Background()

	data := []byte("test data")
	sig, err := mock.Sign(ctx, "key1", data)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := mock.Verify(ctx, "key1", data, sig)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestMockVerifyWrongData(t *testing.T) {
	mock := NewMock("key1")
	ctx := context.Background()

	sig, _ := mock.Sign(ctx, "key1", []byte("original"))
	valid, err := mock.Verify(ctx, "key1", []byte("tampered"), sig)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestMockEncryptDecrypt(t *testing.T) {
	mock := NewMock("key1")
	ctx := context.Background()

	plaintext := []byte("secret")
	ciphertext, err := mock.Encrypt(ctx, "key1", plaintext)
	require.NoError(t, err)

	decrypted, err := mock.Decrypt(ctx, "key1", ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestMockUnknownKey(t *testing.T) {
	mock := NewMock("key1")
	ctx := context.Background()

	_, err := mock.Sign(ctx, "unknown", []byte("data"))
	assert.Error(t, err)

	_, err = mock.Verify(ctx, "unknown", []byte("data"), "sig")
	assert.Error(t, err)

	_, err = mock.Encrypt(ctx, "unknown", []byte("data"))
	assert.Error(t, err)

	_, err = mock.Decrypt(ctx, "unknown", "vault:v1:data")
	assert.Error(t, err)
}

func TestMockDecryptInvalidFormat(t *testing.T) {
	mock := NewMock("key1")
	ctx := context.Background()

	_, err := mock.Decrypt(ctx, "key1", "not-vault-format")
	assert.Error(t, err)
}
