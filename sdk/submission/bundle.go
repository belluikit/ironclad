package submission

import (
	"fmt"
	"io"

	"github.com/trendvidia/protowire/encoding/pb"
)

// Manifest holds metadata about the submitted artifact.
type Manifest struct {
	ContentHash string `protowire:"1"` // "sha256:<hex>"
	ContentType string `protowire:"2"`
	Name        string `protowire:"3"`
	Version     string `protowire:"4"`
	Description string `protowire:"5"`
}

// SignedManifest pairs the protowire-encoded manifest bytes with the
// developer's certificate and signature.
type SignedManifest struct {
	ManifestBytes        []byte `protowire:"1"`
	DeveloperCertificate []byte `protowire:"2"`
	DeveloperSignature   []byte `protowire:"3"`
}

// Manifest parses the manifest bytes.
func (sm *SignedManifest) Manifest() (*Manifest, error) {
	var m Manifest
	if err := pb.Unmarshal(sm.ManifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// MarshalBinary serializes using protowire.
func (sm *SignedManifest) MarshalBinary() ([]byte, error) {
	return pb.Marshal(sm)
}

// UnmarshalBinary deserializes from protowire.
func (sm *SignedManifest) UnmarshalBinary(data []byte) error {
	return pb.Unmarshal(data, sm)
}

// Bundle represents a complete submission bundle (.tcsb file).
type Bundle struct {
	SignedManifest SignedManifest
	Content        []byte
}

// ReadBundle parses a submission bundle from the given ReadSeeker.
func ReadBundle(r io.ReadSeeker) (*Bundle, error) {
	header, err := readFileHeader(r)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

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
		{Type: SectionManifest, Offset: uint64(manifestOffset), Length: uint64(len(manifestData))},
		{Type: SectionContent, Offset: uint64(contentOffset), Length: uint64(len(b.Content))},
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
