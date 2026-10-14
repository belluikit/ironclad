// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
)

const (
	// DefaultChunkSize is the default encryption chunk size (64 KB).
	DefaultChunkSize = 64 * 1024
	chunkHeaderSize  = 4 // uint32 chunk ciphertext length
)

// StreamEncrypt reads plaintext from r in chunks, encrypts each chunk with
// AES-256-GCM using a unique nonce derived from baseNonce + chunk counter,
// and writes the encrypted chunks to w.
//
// Chunk format: [uint32 ciphertext_length][ciphertext with GCM tag]
// Final sentinel: [uint32 0] marks end of stream.
//
// Returns the SHA-256 hash of all plaintext bytes.
func StreamEncrypt(key, baseNonce []byte, r io.Reader, w io.Writer, chunkSize int) ([32]byte, error) {
	if len(key) != KeySize {
		return [32]byte{}, ErrInvalidKeySize
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return [32]byte{}, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return [32]byte{}, fmt.Errorf("create GCM: %w", err)
	}

	hasher := sha256.New()
	buf := make([]byte, chunkSize)
	lenBuf := make([]byte, chunkHeaderSize)
	var chunkCounter uint64

	for {
		n, readErr := readChunk(r, buf)
		if n > 0 {
			hasher.Write(buf[:n])

			chunkNonce := deriveChunkNonce(baseNonce, chunkCounter)
			ciphertext := gcm.Seal(nil, chunkNonce, buf[:n], nil)

			binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
			if _, err := w.Write(lenBuf); err != nil {
				return [32]byte{}, fmt.Errorf("write chunk header: %w", err)
			}
			if _, err := w.Write(ciphertext); err != nil {
				return [32]byte{}, fmt.Errorf("write chunk: %w", err)
			}
			chunkCounter++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return [32]byte{}, fmt.Errorf("read: %w", readErr)
		}
	}

	// Write sentinel (zero-length chunk)
	binary.BigEndian.PutUint32(lenBuf, 0)
	if _, err := w.Write(lenBuf); err != nil {
		return [32]byte{}, fmt.Errorf("write sentinel: %w", err)
	}

	return hashSum(hasher), nil
}

// StreamDecrypt reads encrypted chunks from r, decrypts each one,
// and writes the plaintext to w.
//
// Returns the SHA-256 hash of all decrypted plaintext bytes.
func StreamDecrypt(key, baseNonce []byte, r io.Reader, w io.Writer) ([32]byte, error) {
	if len(key) != KeySize {
		return [32]byte{}, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return [32]byte{}, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return [32]byte{}, fmt.Errorf("create GCM: %w", err)
	}

	hasher := sha256.New()
	lenBuf := make([]byte, chunkHeaderSize)
	var chunkCounter uint64

	for {
		// Read chunk length
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return [32]byte{}, fmt.Errorf("read chunk header: %w", err)
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf)

		// Sentinel — end of stream
		if chunkLen == 0 {
			break
		}

		// Read ciphertext
		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return [32]byte{}, fmt.Errorf("read chunk: %w", err)
		}

		chunkNonce := deriveChunkNonce(baseNonce, chunkCounter)
		plaintext, err := gcm.Open(nil, chunkNonce, ciphertext, nil)
		if err != nil {
			return [32]byte{}, fmt.Errorf("decrypt chunk %d: %w", chunkCounter, ErrDecryptFailed)
		}

		hasher.Write(plaintext)
		if _, err := w.Write(plaintext); err != nil {
			return [32]byte{}, fmt.Errorf("write plaintext: %w", err)
		}
		chunkCounter++
	}

	return hashSum(hasher), nil
}

// deriveChunkNonce derives a per-chunk nonce from a base nonce and counter.
// The last 8 bytes of the base nonce are XORed with the counter.
func deriveChunkNonce(baseNonce []byte, counter uint64) []byte {
	nonce := make([]byte, NonceSize)
	copy(nonce, baseNonce)
	for i := 0; i < 8; i++ {
		nonce[NonceSize-8+i] ^= byte(counter >> (56 - 8*i))
	}
	return nonce
}

// readChunk reads up to len(buf) bytes, handling partial reads.
func readChunk(r io.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func hashSum(h hash.Hash) [32]byte {
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
