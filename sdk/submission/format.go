// Package submission defines the submission bundle format (.tcsb) used by
// third-party developers to submit artifacts to the platform.
//
// A submission bundle contains the raw (unencrypted) artifact, a signed
// manifest with content metadata, and the developer's X.509 certificate.
// The platform verifies the developer's identity and signature, runs
// security checks, then encrypts and packages the artifact into a .tcn
// container for distribution.
package submission

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic bytes for submission bundles: 0x89 + "TSB"
var MagicBytes = [4]byte{0x89, 'T', 'S', 'B'}

const (
	FormatVersion         uint16 = 2
	MinSupportedVersion   uint16 = 2
	MaxSupportedVersion   uint16 = 2
	FileHeaderSize               = 32
	SectionIndexEntrySize        = 24
)

// Section types for submission bundles.
const (
	SectionManifest uint16 = 0x10
	SectionContent  uint16 = 0x11
)

var (
	ErrInvalidMagic   = errors.New("invalid submission bundle magic bytes")
	ErrInvalidVersion = errors.New("unsupported submission bundle version")
	ErrTruncated      = errors.New("truncated submission bundle")
)

// FileHeader is the 32-byte fixed header.
type FileHeader struct {
	Magic        [4]byte
	Version      uint16
	Flags        uint16
	SectionCount uint32
	Reserved     [20]byte
}

// SectionIndexEntry describes one section (24 bytes).
type SectionIndexEntry struct {
	Type     uint16
	Flags    uint16
	Reserved uint32
	Offset   uint64
	Length   uint64
}

func (h *FileHeader) Validate() error {
	if h.Magic != MagicBytes {
		return ErrInvalidMagic
	}
	if h.Version < MinSupportedVersion || h.Version > MaxSupportedVersion {
		return fmt.Errorf("%w: got %d, supported [%d, %d]", ErrInvalidVersion, h.Version, MinSupportedVersion, MaxSupportedVersion)
	}
	return nil
}

func (h *FileHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, FileHeaderSize)
	copy(buf[0:4], h.Magic[:])
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	binary.BigEndian.PutUint16(buf[6:8], h.Flags)
	binary.BigEndian.PutUint32(buf[8:12], h.SectionCount)
	return buf, nil
}

func (h *FileHeader) UnmarshalBinary(data []byte) error {
	if len(data) < FileHeaderSize {
		return fmt.Errorf("%w: header too short", ErrTruncated)
	}
	copy(h.Magic[:], data[0:4])
	h.Version = binary.BigEndian.Uint16(data[4:6])
	h.Flags = binary.BigEndian.Uint16(data[6:8])
	h.SectionCount = binary.BigEndian.Uint32(data[8:12])
	copy(h.Reserved[:], data[12:32])
	return nil
}

func (e *SectionIndexEntry) MarshalBinary() ([]byte, error) {
	buf := make([]byte, SectionIndexEntrySize)
	binary.BigEndian.PutUint16(buf[0:2], e.Type)
	binary.BigEndian.PutUint16(buf[2:4], e.Flags)
	binary.BigEndian.PutUint32(buf[4:8], e.Reserved)
	binary.BigEndian.PutUint64(buf[8:16], e.Offset)
	binary.BigEndian.PutUint64(buf[16:24], e.Length)
	return buf, nil
}

func (e *SectionIndexEntry) UnmarshalBinary(data []byte) error {
	if len(data) < SectionIndexEntrySize {
		return fmt.Errorf("%w: section index entry too short", ErrTruncated)
	}
	e.Type = binary.BigEndian.Uint16(data[0:2])
	e.Flags = binary.BigEndian.Uint16(data[2:4])
	e.Reserved = binary.BigEndian.Uint32(data[4:8])
	e.Offset = binary.BigEndian.Uint64(data[8:16])
	e.Length = binary.BigEndian.Uint64(data[16:24])
	return nil
}

func readFileHeader(r io.Reader) (*FileHeader, error) {
	buf := make([]byte, FileHeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTruncated, err)
	}
	h := &FileHeader{}
	if err := h.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return h, h.Validate()
}
