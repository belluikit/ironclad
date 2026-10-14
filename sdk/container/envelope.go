// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package container

import (
	"encoding/binary"

	"github.com/google/uuid"
	"github.com/trendvidia/protowire-go/encoding/pb"
)

// ContentEnvelope holds the immutable content section of a container.
//
// Two signatures from different parties:
//   - DeveloperSignature: the developer signs their manifest (exact bytes in DeveloperManifest)
//   - DistributorSignature: the platform signs the full envelope after encryption
type ContentEnvelope struct {
	FormatVersion          uint16 `protowire:"1"`
	ContentID              []byte `protowire:"2"`
	ContentType            uint16 `protowire:"3"`
	HashAlgo               uint8  `protowire:"4"`
	ContentHash            []byte `protowire:"5"`
	WrappedDEK             []byte `protowire:"6"`
	EncryptAlgo            uint8  `protowire:"7"`
	NonceLen               uint8  `protowire:"8"`
	Nonce                  []byte `protowire:"9"`
	DeveloperCertificate   []byte `protowire:"10"`
	DeveloperSignature     []byte `protowire:"11"`
	DistributorCertificate []byte `protowire:"12"`
	DistributorSignature   []byte `protowire:"13"`
	Payload                []byte `protowire:"14"`
	DeveloperManifest      []byte `protowire:"15"`
	ChunkedEncryption      bool   `protowire:"16"`
	ChunkSize              uint32 `protowire:"17"`
}

// ContentUUID returns the ContentID as a uuid.UUID.
func (e *ContentEnvelope) ContentUUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], e.ContentID)
	return id
}

// SetContentUUID sets the ContentID from a uuid.UUID.
func (e *ContentEnvelope) SetContentUUID(id uuid.UUID) {
	e.ContentID = id[:]
}

// ContentHashArray returns the ContentHash as a [32]byte.
func (e *ContentEnvelope) ContentHashArray() [32]byte {
	var h [32]byte
	copy(h[:], e.ContentHash)
	return h
}

// DistributorSignableBytes returns the bytes the distributor (platform) signs.
// Covers everything except the distributor signature and payload.
func (e *ContentEnvelope) DistributorSignableBytes() []byte {
	size := 2 + // FormatVersion
		2 + len(e.ContentID) +
		2 + // ContentType
		1 + // HashAlgo
		2 + len(e.ContentHash) +
		2 + len(e.WrappedDEK) +
		1 + // EncryptAlgo
		1 + // NonceLen
		2 + len(e.Nonce) +
		2 + len(e.DeveloperCertificate) +
		2 + len(e.DeveloperSignature) +
		2 + len(e.DeveloperManifest) +
		2 + len(e.DistributorCertificate)

	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint16(buf[offset:], e.FormatVersion)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.ContentID)))
	offset += 2
	copy(buf[offset:], e.ContentID)
	offset += len(e.ContentID)
	binary.BigEndian.PutUint16(buf[offset:], e.ContentType)
	offset += 2
	buf[offset] = e.HashAlgo
	offset++
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.ContentHash)))
	offset += 2
	copy(buf[offset:], e.ContentHash)
	offset += len(e.ContentHash)
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.WrappedDEK)))
	offset += 2
	copy(buf[offset:], e.WrappedDEK)
	offset += len(e.WrappedDEK)
	buf[offset] = e.EncryptAlgo
	offset++
	buf[offset] = e.NonceLen
	offset++
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.Nonce)))
	offset += 2
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
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.DeveloperManifest)))
	offset += 2
	copy(buf[offset:], e.DeveloperManifest)
	offset += len(e.DeveloperManifest)
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.DistributorCertificate)))
	offset += 2
	copy(buf[offset:], e.DistributorCertificate)

	return buf
}

// MarshalBinary serializes the envelope using protowire binary format.
func (e *ContentEnvelope) MarshalBinary() ([]byte, error) {
	return pb.Marshal(e)
}

// UnmarshalBinary deserializes an envelope from protowire binary format.
func (e *ContentEnvelope) UnmarshalBinary(data []byte) error {
	return pb.Unmarshal(data, e)
}
