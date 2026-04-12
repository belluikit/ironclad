package container

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic bytes: 0x89 (high bit set for corruption detection) + "TCN"
var MagicBytes = [4]byte{0x89, 'T', 'C', 'N'}

const (
	FormatVersion uint16 = 1

	FileHeaderSize       = 32
	SectionIndexEntrySize = 16
)

// Section types.
const (
	SectionEnvelope uint16 = 0x01
	SectionLicense  uint16 = 0x02
	SectionRenewal  uint16 = 0x03
)

// Content types.
const (
	ContentTypeDataFile      uint16 = 0x01
	ContentTypeAppDefinition uint16 = 0x02
	ContentTypeSharedLibrary uint16 = 0x03
)

// Hash algorithms.
const (
	HashAlgoSHA256 uint8 = 0x01
)

// Encryption algorithms.
const (
	EncryptionAlgoAES256GCM uint8 = 0x01
)

var (
	ErrInvalidMagic   = errors.New("invalid magic bytes")
	ErrInvalidVersion = errors.New("unsupported format version")
	ErrInvalidSection = errors.New("invalid section")
	ErrTruncated      = errors.New("truncated container")
	ErrDuplicateSection = errors.New("duplicate section type")
)

// FileHeader is the 32-byte fixed header at the start of a container file.
type FileHeader struct {
	Magic        [4]byte
	Version      uint16
	Flags        uint16
	SectionCount uint32
	Reserved     [20]byte
}

// SectionIndexEntry describes one section in the container.
type SectionIndexEntry struct {
	Type     uint16
	Pad      uint16
	Offset   uint32
	Length   uint64
}

func (h *FileHeader) Validate() error {
	if h.Magic != MagicBytes {
		return ErrInvalidMagic
	}
	if h.Version != FormatVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrInvalidVersion, h.Version, FormatVersion)
	}
	return nil
}

func (h *FileHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, FileHeaderSize)
	copy(buf[0:4], h.Magic[:])
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	binary.BigEndian.PutUint16(buf[6:8], h.Flags)
	binary.BigEndian.PutUint32(buf[8:12], h.SectionCount)
	// bytes 12..31 are reserved (zero)
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
	binary.BigEndian.PutUint16(buf[2:4], e.Pad)
	binary.BigEndian.PutUint32(buf[4:8], e.Offset)
	binary.BigEndian.PutUint64(buf[8:16], e.Length)
	return buf, nil
}

func (e *SectionIndexEntry) UnmarshalBinary(data []byte) error {
	if len(data) < SectionIndexEntrySize {
		return fmt.Errorf("%w: section index entry too short", ErrTruncated)
	}
	e.Type = binary.BigEndian.Uint16(data[0:2])
	e.Pad = binary.BigEndian.Uint16(data[2:4])
	e.Offset = binary.BigEndian.Uint32(data[4:8])
	e.Length = binary.BigEndian.Uint64(data[8:16])
	return nil
}

func NewFileHeader(sectionCount uint32) FileHeader {
	return FileHeader{
		Magic:        MagicBytes,
		Version:      FormatVersion,
		SectionCount: sectionCount,
	}
}

// ReadFileHeader reads a FileHeader from the given reader.
func ReadFileHeader(r io.Reader) (*FileHeader, error) {
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

// ReadSectionIndex reads sectionCount index entries from the given reader.
func ReadSectionIndex(r io.Reader, count uint32) ([]SectionIndexEntry, error) {
	entries := make([]SectionIndexEntry, count)
	buf := make([]byte, SectionIndexEntrySize)
	for i := uint32(0); i < count; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("%w: section index entry %d: %v", ErrTruncated, i, err)
		}
		if err := entries[i].UnmarshalBinary(buf); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// ContentTypeName returns a human-readable name for a content type.
func ContentTypeName(ct uint16) string {
	switch ct {
	case ContentTypeDataFile:
		return "data-file"
	case ContentTypeAppDefinition:
		return "app-definition"
	case ContentTypeSharedLibrary:
		return "shared-library"
	default:
		return fmt.Sprintf("unknown(0x%04x)", ct)
	}
}

// ParseContentType parses a content type string into its uint16 value.
func ParseContentType(s string) (uint16, error) {
	switch s {
	case "data-file":
		return ContentTypeDataFile, nil
	case "app-definition":
		return ContentTypeAppDefinition, nil
	case "shared-library":
		return ContentTypeSharedLibrary, nil
	default:
		return 0, fmt.Errorf("unknown content type: %q", s)
	}
}
