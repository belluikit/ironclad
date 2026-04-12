package submission

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Manifest holds metadata about the submitted artifact.
// It is serialized as JSON and signed by the developer.
type Manifest struct {
	ContentHash string `json:"content_hash"` // "sha256:<hex>"
	ContentType string `json:"content_type"` // "data-file", "app-definition", "shared-library"
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// SignedManifest pairs the raw JSON manifest bytes with the developer's
// certificate and signature.
type SignedManifest struct {
	ManifestBytes        []byte // raw JSON (signed exactly as-is)
	DeveloperCertificate []byte // DER-encoded X.509 certificate
	DeveloperSignature   []byte // ECDSA signature over ManifestBytes
}

// Manifest parses the JSON manifest bytes.
func (sm *SignedManifest) Manifest() (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(sm.ManifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// MarshalBinary serializes the signed manifest:
//
//	ManifestLen(4) + Manifest + CertLen(2) + Cert + SigLen(2) + Sig
func (sm *SignedManifest) MarshalBinary() ([]byte, error) {
	size := 4 + len(sm.ManifestBytes) + 2 + len(sm.DeveloperCertificate) + 2 + len(sm.DeveloperSignature)
	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(sm.ManifestBytes)))
	offset += 4
	copy(buf[offset:], sm.ManifestBytes)
	offset += len(sm.ManifestBytes)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(sm.DeveloperCertificate)))
	offset += 2
	copy(buf[offset:], sm.DeveloperCertificate)
	offset += len(sm.DeveloperCertificate)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(sm.DeveloperSignature)))
	offset += 2
	copy(buf[offset:], sm.DeveloperSignature)

	return buf, nil
}

// UnmarshalBinary deserializes a signed manifest.
func (sm *SignedManifest) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: manifest section too short", ErrTruncated)
	}
	offset := 0

	manifestLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+manifestLen > len(data) {
		return fmt.Errorf("%w: manifest truncated", ErrTruncated)
	}
	sm.ManifestBytes = make([]byte, manifestLen)
	copy(sm.ManifestBytes, data[offset:offset+manifestLen])
	offset += manifestLen

	if offset+2 > len(data) {
		return fmt.Errorf("%w: certificate length truncated", ErrTruncated)
	}
	certLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+certLen > len(data) {
		return fmt.Errorf("%w: certificate truncated", ErrTruncated)
	}
	sm.DeveloperCertificate = make([]byte, certLen)
	copy(sm.DeveloperCertificate, data[offset:offset+certLen])
	offset += certLen

	if offset+2 > len(data) {
		return fmt.Errorf("%w: signature length truncated", ErrTruncated)
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+sigLen > len(data) {
		return fmt.Errorf("%w: signature truncated", ErrTruncated)
	}
	sm.DeveloperSignature = make([]byte, sigLen)
	copy(sm.DeveloperSignature, data[offset:offset+sigLen])

	return nil
}

// Bundle represents a complete submission bundle (.tcsb file).
type Bundle struct {
	SignedManifest SignedManifest
	Content        []byte // raw artifact bytes (unencrypted)
}

// ReadBundle parses a submission bundle from the given ReadSeeker.
func ReadBundle(r io.ReadSeeker) (*Bundle, error) {
	header, err := readFileHeader(r)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Read section index
	entries := make([]SectionIndexEntry, header.SectionCount)
	buf := make([]byte, SectionIndexEntrySize)
	for i := uint32(0); i < header.SectionCount; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("%w: section index: %v", ErrTruncated, err)
		}
		if err := entries[i].UnmarshalBinary(buf); err != nil {
			return nil, err
		}
	}

	b := &Bundle{}

	for _, entry := range entries {
		if _, err := r.Seek(int64(entry.Offset), io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek to section 0x%04x: %w", entry.Type, err)
		}
		data := make([]byte, entry.Length)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("read section 0x%04x: %w", entry.Type, err)
		}

		switch entry.Type {
		case SectionManifest:
			if err := b.SignedManifest.UnmarshalBinary(data); err != nil {
				return nil, fmt.Errorf("unmarshal manifest: %w", err)
			}
		case SectionContent:
			b.Content = data
		}
	}

	return b, nil
}

// WriteBundle writes a submission bundle to the given writer.
func WriteBundle(w io.Writer, b *Bundle) error {
	manifestData, err := b.SignedManifest.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	sectionCount := uint32(2)
	header := FileHeader{
		Magic:        MagicBytes,
		Version:      FormatVersion,
		SectionCount: sectionCount,
	}

	indexSize := int(sectionCount) * SectionIndexEntrySize
	dataStart := FileHeaderSize + indexSize
	manifestOffset := dataStart
	contentOffset := manifestOffset + len(manifestData)

	entries := []SectionIndexEntry{
		{Type: SectionManifest, Offset: uint32(manifestOffset), Length: uint64(len(manifestData))},
		{Type: SectionContent, Offset: uint32(contentOffset), Length: uint64(len(b.Content))},
	}

	headerBytes, _ := header.MarshalBinary()
	if _, err := w.Write(headerBytes); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	for i, entry := range entries {
		entryBytes, _ := entry.MarshalBinary()
		if _, err := w.Write(entryBytes); err != nil {
			return fmt.Errorf("write section index %d: %w", i, err)
		}
	}

	if _, err := w.Write(manifestData); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if _, err := w.Write(b.Content); err != nil {
		return fmt.Errorf("write content: %w", err)
	}

	return nil
}
