// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package keystore

import "github.com/google/uuid"

// KeyStore abstracts platform-specific secure storage for cached DEKs.
// Implementations store decryption keys locally so that subsequent
// operations don't require a Vault roundtrip.
type KeyStore interface {
	// Store saves a DEK associated with a content ID.
	Store(contentID uuid.UUID, dek []byte) error

	// Retrieve fetches a previously stored DEK.
	// Returns ErrNotFound if no DEK is cached for the given content ID.
	Retrieve(contentID uuid.UUID) ([]byte, error)

	// Delete removes a cached DEK.
	Delete(contentID uuid.UUID) error
}

// ErrNotFound is returned when a DEK is not found in the keystore.
type ErrNotFound struct {
	ContentID uuid.UUID
}

func (e *ErrNotFound) Error() string {
	return "dek not found for content " + e.ContentID.String()
}
