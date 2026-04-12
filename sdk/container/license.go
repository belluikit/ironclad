package container

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/trendvidia/protowire/encoding/pb"
)

// LicenseToken is the license payload, serialized with protowire.
type LicenseToken struct {
	LicenseID          []byte   `protowire:"1"`
	ContentID          []byte   `protowire:"2"`
	IssuedAtUnix       int64    `protowire:"3"`
	ExpiresAtUnix      int64    `protowire:"4"`
	GracePeriodSeconds int32    `protowire:"5"`
	Subject            string   `protowire:"6"`
	Entitlements       []string `protowire:"7"`
	RenewalEndpoint    string   `protowire:"8"`
	SigningKeyID       string   `protowire:"9"`
}

func (lt *LicenseToken) IssuedAt() time.Time  { return time.Unix(lt.IssuedAtUnix, 0).UTC() }
func (lt *LicenseToken) ExpiresAt() time.Time { return time.Unix(lt.ExpiresAtUnix, 0).UTC() }

func (lt *LicenseToken) LicenseUUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], lt.LicenseID)
	return id
}

func (lt *LicenseToken) ContentUUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], lt.ContentID)
	return id
}

// SignedLicense pairs the protowire-encoded token bytes with their signature.
type SignedLicense struct {
	TokenBytes []byte `protowire:"1"`
	Signature  []byte `protowire:"2"`
}

// Token parses the token bytes into a LicenseToken.
func (sl *SignedLicense) Token() (*LicenseToken, error) {
	var t LicenseToken
	if err := pb.Unmarshal(sl.TokenBytes, &t); err != nil {
		return nil, fmt.Errorf("parse license token: %w", err)
	}
	return &t, nil
}

// NewSignedLicense creates a SignedLicense from a LicenseToken.
func NewSignedLicense(token *LicenseToken) (*SignedLicense, error) {
	data, err := pb.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("marshal license token: %w", err)
	}
	return &SignedLicense{TokenBytes: data}, nil
}

// MarshalBinary serializes using protowire.
func (sl *SignedLicense) MarshalBinary() ([]byte, error) {
	return pb.Marshal(sl)
}

// UnmarshalBinary deserializes from protowire.
func (sl *SignedLicense) UnmarshalBinary(data []byte) error {
	return pb.Unmarshal(data, sl)
}
