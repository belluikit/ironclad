package container

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// LicenseToken is the JSON-serializable license payload.
// It is signed independently of the content envelope so that
// licenses can be verified and renewed without touching the payload.
type LicenseToken struct {
	LicenseID          uuid.UUID `json:"license_id"`
	ContentID          uuid.UUID `json:"content_id"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	GracePeriodSeconds int       `json:"grace_period_seconds"`
	Subject            string    `json:"subject"`
	Entitlements       []string  `json:"entitlements,omitempty"`
	RenewalEndpoint    string    `json:"renewal_endpoint"`
	SigningKeyID       string    `json:"signing_key_id"`
}

// SignedLicense pairs the raw JSON token bytes with their signature.
// We store the raw bytes rather than re-serializing to ensure the
// signature always matches exactly what was signed.
type SignedLicense struct {
	TokenBytes []byte
	Signature  []byte
}

// Token parses the JSON token bytes into a LicenseToken.
func (sl *SignedLicense) Token() (*LicenseToken, error) {
	var t LicenseToken
	if err := json.Unmarshal(sl.TokenBytes, &t); err != nil {
		return nil, fmt.Errorf("parse license token: %w", err)
	}
	return &t, nil
}

// NewSignedLicense creates a SignedLicense from a LicenseToken.
// The signature field must be filled in separately after signing.
func NewSignedLicense(token *LicenseToken) (*SignedLicense, error) {
	data, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("marshal license token: %w", err)
	}
	return &SignedLicense{TokenBytes: data}, nil
}

// MarshalBinary serializes a SignedLicense to the container section format:
//
//	TokenLen(4) + Token + SignatureLen(2) + Signature
func (sl *SignedLicense) MarshalBinary() ([]byte, error) {
	size := 4 + len(sl.TokenBytes) + 2 + len(sl.Signature)
	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(sl.TokenBytes)))
	offset += 4

	copy(buf[offset:], sl.TokenBytes)
	offset += len(sl.TokenBytes)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(sl.Signature)))
	offset += 2

	copy(buf[offset:], sl.Signature)
	return buf, nil
}

// UnmarshalBinary deserializes a SignedLicense from binary data.
func (sl *SignedLicense) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("%w: license section too short", ErrTruncated)
	}
	offset := 0

	tokenLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	if offset+tokenLen > len(data) {
		return fmt.Errorf("%w: license token truncated", ErrTruncated)
	}
	sl.TokenBytes = make([]byte, tokenLen)
	copy(sl.TokenBytes, data[offset:offset+tokenLen])
	offset += tokenLen

	if offset+2 > len(data) {
		return fmt.Errorf("%w: license signature length truncated", ErrTruncated)
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if offset+sigLen > len(data) {
		return fmt.Errorf("%w: license signature truncated", ErrTruncated)
	}
	sl.Signature = make([]byte, sigLen)
	copy(sl.Signature, data[offset:offset+sigLen])
	return nil
}
