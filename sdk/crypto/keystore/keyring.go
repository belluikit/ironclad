package keystore

import (
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/zalando/go-keyring"
)

const serviceName = "ironclad"

// KeyringStore implements KeyStore using the platform's native keyring:
// - macOS: Keychain
// - Linux: Secret Service (GNOME Keyring / KDE Wallet)
type KeyringStore struct{}

// NewKeyringStore creates a new platform keyring-backed KeyStore.
func NewKeyringStore() *KeyringStore {
	return &KeyringStore{}
}

func (ks *KeyringStore) Store(contentID uuid.UUID, dek []byte) error {
	encoded := hex.EncodeToString(dek)
	err := keyring.Set(serviceName, contentID.String(), encoded)
	if err != nil {
		return fmt.Errorf("keyring store: %w", err)
	}
	return nil
}

func (ks *KeyringStore) Retrieve(contentID uuid.UUID) ([]byte, error) {
	encoded, err := keyring.Get(serviceName, contentID.String())
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, &ErrNotFound{ContentID: contentID}
		}
		return nil, fmt.Errorf("keyring retrieve: %w", err)
	}
	dek, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("keyring retrieve: decode: %w", err)
	}
	return dek, nil
}

func (ks *KeyringStore) Delete(contentID uuid.UUID) error {
	err := keyring.Delete(serviceName, contentID.String())
	if err != nil {
		if err == keyring.ErrNotFound {
			return &ErrNotFound{ContentID: contentID}
		}
		return fmt.Errorf("keyring delete: %w", err)
	}
	return nil
}
