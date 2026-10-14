// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package container

import (
	"fmt"
	"io"
	"os"

	sdkcontainer "github.com/belluikit/ironclad/sdk/container"
)

// WriteContainer writes a full container to the given writer.
func WriteContainer(w io.Writer, c *sdkcontainer.Container) error {
	// Marshal sections
	envelopeData, err := c.Envelope.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	licenseData, err := c.License.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal license: %w", err)
	}

	sectionCount := uint32(2) // envelope + license
	var renewalData []byte
	if len(c.Renewals) > 0 {
		sectionCount = 3
		renewalData, err = c.Renewals.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal renewals: %w", err)
		}
	}

	// Build header
	header := sdkcontainer.NewFileHeader(sectionCount)

	// Calculate offsets
	indexSize := int(sectionCount) * sdkcontainer.SectionIndexEntrySize
	dataStart := sdkcontainer.FileHeaderSize + indexSize

	envelopeOffset := dataStart
	licenseOffset := envelopeOffset + len(envelopeData)
	renewalOffset := licenseOffset + len(licenseData)

	// Build section index
	entries := []sdkcontainer.SectionIndexEntry{
		{Type: sdkcontainer.SectionEnvelope, Offset: uint64(envelopeOffset), Length: uint64(len(envelopeData))},
		{Type: sdkcontainer.SectionLicense, Offset: uint64(licenseOffset), Length: uint64(len(licenseData))},
	}
	if sectionCount == 3 {
		entries = append(entries, sdkcontainer.SectionIndexEntry{
			Type:   sdkcontainer.SectionRenewal,
			Offset: uint64(renewalOffset),
			Length: uint64(len(renewalData)),
		})
	}

	// Write header
	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal header: %w", err)
	}
	if _, err := w.Write(headerBytes); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write section index
	for i, entry := range entries {
		entryBytes, err := entry.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal section index %d: %w", i, err)
		}
		if _, err := w.Write(entryBytes); err != nil {
			return fmt.Errorf("write section index %d: %w", i, err)
		}
	}

	// Write section data
	if _, err := w.Write(envelopeData); err != nil {
		return fmt.Errorf("write envelope: %w", err)
	}
	if _, err := w.Write(licenseData); err != nil {
		return fmt.Errorf("write license: %w", err)
	}
	if len(renewalData) > 0 {
		if _, err := w.Write(renewalData); err != nil {
			return fmt.Errorf("write renewals: %w", err)
		}
	}

	return nil
}

// AppendRenewal adds a renewal token to an existing container file.
func AppendRenewal(path string, renewal sdkcontainer.SignedRenewal) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open container: %w", err)
	}
	defer f.Close()

	// Read existing container
	c, err := sdkcontainer.ReadContainer(f)
	if err != nil {
		return fmt.Errorf("read container: %w", err)
	}

	// Append renewal to chain
	c.Renewals = append(c.Renewals, renewal)

	// Re-marshal all sections to compute new offsets
	envelopeData, err := c.Envelope.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	licenseData, err := c.License.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal license: %w", err)
	}

	renewalData, err := c.Renewals.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal renewals: %w", err)
	}

	sectionCount := uint32(3)
	header := sdkcontainer.NewFileHeader(sectionCount)

	indexSize := int(sectionCount) * sdkcontainer.SectionIndexEntrySize
	dataStart := sdkcontainer.FileHeaderSize + indexSize

	envelopeOffset := dataStart
	licenseOffset := envelopeOffset + len(envelopeData)
	renewalOffset := licenseOffset + len(licenseData)

	entries := []sdkcontainer.SectionIndexEntry{
		{Type: sdkcontainer.SectionEnvelope, Offset: uint64(envelopeOffset), Length: uint64(len(envelopeData))},
		{Type: sdkcontainer.SectionLicense, Offset: uint64(licenseOffset), Length: uint64(len(licenseData))},
		{Type: sdkcontainer.SectionRenewal, Offset: uint64(renewalOffset), Length: uint64(len(renewalData))},
	}

	// Seek to beginning and rewrite
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek to start: %w", err)
	}

	totalSize := int64(dataStart + len(envelopeData) + len(licenseData) + len(renewalData))
	if err := f.Truncate(totalSize); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal header: %w", err)
	}
	if _, err := f.Write(headerBytes); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	for i, entry := range entries {
		entryBytes, err := entry.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal section index %d: %w", i, err)
		}
		if _, err := f.Write(entryBytes); err != nil {
			return fmt.Errorf("write section index %d: %w", i, err)
		}
	}

	if _, err := f.Write(envelopeData); err != nil {
		return fmt.Errorf("write envelope: %w", err)
	}
	if _, err := f.Write(licenseData); err != nil {
		return fmt.Errorf("write license: %w", err)
	}
	if _, err := f.Write(renewalData); err != nil {
		return fmt.Errorf("write renewals: %w", err)
	}

	return f.Sync()
}
