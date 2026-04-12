package container

import (
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
)

// ContentEnvelope holds the immutable content section of a container.
// Once created, the envelope is never modified — renewals are appended separately.
//
// The envelope carries two signatures from different parties:
//   - DeveloperSignature: the third-party developer signs the content hash + metadata
//     before encryption, proving they produced the artifact.
//   - DistributorSignature: the platform signs the full envelope (including the
//     developer signature and encrypted payload metadata), proving it was reviewed
//     and approved for distribution.
type ContentEnvelope struct {
	FormatVersion          uint16
	ContentID              uuid.UUID
	ContentType            uint16
	HashAlgo               uint8
	ContentHash            [32]byte // SHA-256 of plaintext
	WrappedDEK             []byte   // Vault Transit ciphertext (opaque)
	EncryptAlgo            uint8
	NonceLen               uint8
	Nonce                  []byte // AES-GCM nonce (typically 12 bytes)
	DeveloperCertificate   []byte // DER-encoded X.509 cert (developer identity, from platform CA)
	DeveloperSignature     []byte // ECDSA signature by developer's private key
	DistributorCertificate []byte // DER-encoded X.509 cert (platform identity)
	DistributorSignature   []byte // Vault Transit signature by platform key
	Payload                []byte // AES-256-GCM encrypted ciphertext
}

// DeveloperSignableBytes returns the bytes the developer signs.
// This covers content identity and integrity fields only:
// FormatVersion + ContentID + ContentType + HashAlgo + ContentHash.
// The developer signs BEFORE encryption — they attest to the plaintext content.
func (e *ContentEnvelope) DeveloperSignableBytes() []byte {
	size := 2 + 16 + 2 + 1 + 32 // FormatVersion + ContentID + ContentType + HashAlgo + ContentHash
	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint16(buf[offset:], e.FormatVersion)
	offset += 2
	copy(buf[offset:], e.ContentID[:])
	offset += 16
	binary.BigEndian.PutUint16(buf[offset:], e.ContentType)
	offset += 2
	buf[offset] = e.HashAlgo
	offset++
	copy(buf[offset:], e.ContentHash[:])

	return buf
}

// DistributorSignableBytes returns the bytes the distributor (platform) signs.
// This covers everything in the envelope EXCEPT the distributor signature itself
// and the payload. It includes the developer certificate and signature, so the
// distributor attests to having verified the developer's identity and signature.
func (e *ContentEnvelope) DistributorSignableBytes() []byte {
	size := 2 + // FormatVersion
		16 + // ContentID
		2 + // ContentType
		1 + // HashAlgo
		32 + // ContentHash
		2 + len(e.WrappedDEK) +
		1 + // EncryptAlgo
		1 + // NonceLen
		len(e.Nonce) +
		2 + len(e.DeveloperCertificate) +
		2 + len(e.DeveloperSignature) +
		2 + len(e.DistributorCertificate)

	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint16(buf[offset:], e.FormatVersion)
	offset += 2
	copy(buf[offset:], e.ContentID[:])
	offset += 16
	binary.BigEndian.PutUint16(buf[offset:], e.ContentType)
	offset += 2
	buf[offset] = e.HashAlgo
	offset++
	copy(buf[offset:], e.ContentHash[:])
	offset += 32

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.WrappedDEK)))
	offset += 2
	copy(buf[offset:], e.WrappedDEK)
	offset += len(e.WrappedDEK)

	buf[offset] = e.EncryptAlgo
	offset++
	buf[offset] = e.NonceLen
	offset++
	copy(buf[offset:], e.Nonce)
	offset += len(e.Nonce)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.DeveloperCertificate)))
	offset += 2
	copy(buf[offset:], e.DeveloperCertificate)
	offset += len(e.DeveloperCertificate)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.DeveloperSignature)))
	offset += 2
	copy(buf[offset:], e.DeveloperSignature)
	offset += len(e.DeveloperSignature)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.DistributorCertificate)))
	offset += 2
	copy(buf[offset:], e.DistributorCertificate)

	return buf
}

// MarshalBinary serializes the full envelope to binary format.
func (e *ContentEnvelope) MarshalBinary() ([]byte, error) {
	distSignable := e.DistributorSignableBytes()

	size := len(distSignable) +
		2 + len(e.DistributorSignature) +
		8 + len(e.Payload)

	buf := make([]byte, size)
	offset := copy(buf, distSignable)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.DistributorSignature)))
	offset += 2
	copy(buf[offset:], e.DistributorSignature)
	offset += len(e.DistributorSignature)

	binary.BigEndian.PutUint64(buf[offset:], uint64(len(e.Payload)))
	offset += 8
	copy(buf[offset:], e.Payload)

	return buf, nil
}

// UnmarshalBinary deserializes an envelope from binary data.
func (e *ContentEnvelope) UnmarshalBinary(data []byte) error {
	if len(data) < 2+16+2+1+32+2+1+1 {
		return fmt.Errorf("%w: envelope too short", ErrTruncated)
	}

	offset := 0

	e.FormatVersion = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	copy(e.ContentID[:], data[offset:offset+16])
	offset += 16
	e.ContentType = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	e.HashAlgo = data[offset]
	offset++
	copy(e.ContentHash[:], data[offset:offset+32])
	offset += 32

	// WrappedDEK
	if offset+2 > len(data) {
		return fmt.Errorf("%w: missing wrapped DEK length", ErrTruncated)
	}
	wrappedDEKLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+wrappedDEKLen > len(data) {
		return fmt.Errorf("%w: wrapped DEK truncated", ErrTruncated)
	}
	e.WrappedDEK = make([]byte, wrappedDEKLen)
	copy(e.WrappedDEK, data[offset:offset+wrappedDEKLen])
	offset += wrappedDEKLen

	// Encryption params
	if offset+2 > len(data) {
		return fmt.Errorf("%w: missing encryption params", ErrTruncated)
	}
	e.EncryptAlgo = data[offset]
	offset++
	e.NonceLen = data[offset]
	offset++

	if offset+int(e.NonceLen) > len(data) {
		return fmt.Errorf("%w: nonce truncated", ErrTruncated)
	}
	e.Nonce = make([]byte, e.NonceLen)
	copy(e.Nonce, data[offset:offset+int(e.NonceLen)])
	offset += int(e.NonceLen)

	// Developer certificate
	if offset+2 > len(data) {
		return fmt.Errorf("%w: missing developer certificate length", ErrTruncated)
	}
	devCertLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+devCertLen > len(data) {
		return fmt.Errorf("%w: developer certificate truncated", ErrTruncated)
	}
	e.DeveloperCertificate = make([]byte, devCertLen)
	copy(e.DeveloperCertificate, data[offset:offset+devCertLen])
	offset += devCertLen

	// Developer signature
	if offset+2 > len(data) {
		return fmt.Errorf("%w: missing developer signature length", ErrTruncated)
	}
	devSigLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+devSigLen > len(data) {
		return fmt.Errorf("%w: developer signature truncated", ErrTruncated)
	}
	e.DeveloperSignature = make([]byte, devSigLen)
	copy(e.DeveloperSignature, data[offset:offset+devSigLen])
	offset += devSigLen

	// Distributor certificate
	if offset+2 > len(data) {
		return fmt.Errorf("%w: missing distributor certificate length", ErrTruncated)
	}
	distCertLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+distCertLen > len(data) {
		return fmt.Errorf("%w: distributor certificate truncated", ErrTruncated)
	}
	e.DistributorCertificate = make([]byte, distCertLen)
	copy(e.DistributorCertificate, data[offset:offset+distCertLen])
	offset += distCertLen

	// Distributor signature
	if offset+2 > len(data) {
		return fmt.Errorf("%w: missing distributor signature length", ErrTruncated)
	}
	distSigLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+distSigLen > len(data) {
		return fmt.Errorf("%w: distributor signature truncated", ErrTruncated)
	}
	e.DistributorSignature = make([]byte, distSigLen)
	copy(e.DistributorSignature, data[offset:offset+distSigLen])
	offset += distSigLen

	// Payload
	if offset+8 > len(data) {
		return fmt.Errorf("%w: missing payload length", ErrTruncated)
	}
	payloadLen := binary.BigEndian.Uint64(data[offset:])
	offset += 8
	if offset+int(payloadLen) > len(data) {
		return fmt.Errorf("%w: payload truncated", ErrTruncated)
	}
	e.Payload = make([]byte, payloadLen)
	copy(e.Payload, data[offset:offset+int(payloadLen)])

	return nil
}
