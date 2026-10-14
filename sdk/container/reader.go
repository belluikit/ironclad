// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package container

import (
	"fmt"
	"io"
)

// Container holds all three sections of a ironclad container file.
type Container struct {
	Header   FileHeader
	Envelope ContentEnvelope
	License  SignedLicense
	Renewals RenewalChain
}

// ReadContainer parses a full container from the given ReadSeeker.
func ReadContainer(r io.ReadSeeker) (*Container, error) {
	// Read header
	header, err := ReadFileHeader(r)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Read section index
	entries, err := ReadSectionIndex(r, header.SectionCount)
	if err != nil {
		return nil, fmt.Errorf("read section index: %w", err)
	}

	c := &Container{Header: *header}

	// Validate no duplicate section types
	seen := make(map[uint16]bool)
	for _, e := range entries {
		if seen[e.Type] {
			return nil, fmt.Errorf("%w: type 0x%04x", ErrDuplicateSection, e.Type)
		}
		seen[e.Type] = true
	}

	// Read each section
	for _, entry := range entries {
		if _, err := r.Seek(int64(entry.Offset), io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek to section 0x%04x: %w", entry.Type, err)
		}

		data := make([]byte, entry.Length)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("read section 0x%04x: %w", entry.Type, err)
		}

		switch entry.Type {
		case SectionEnvelope:
			if err := c.Envelope.UnmarshalBinary(data); err != nil {
				return nil, fmt.Errorf("unmarshal envelope: %w", err)
			}
		case SectionLicense:
			if err := c.License.UnmarshalBinary(data); err != nil {
				return nil, fmt.Errorf("unmarshal license: %w", err)
			}
		case SectionRenewal:
			if err := c.Renewals.UnmarshalBinary(data); err != nil {
				return nil, fmt.Errorf("unmarshal renewals: %w", err)
			}
		default:
			// Skip unknown section types for forward compatibility
		}
	}

	return c, nil
}
