package container

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// RenewalToken is the JSON-serializable renewal payload.
// Each renewal extends the license expiration without modifying
// the content envelope or re-encrypting the payload.
type RenewalToken struct {
	RenewalID             uuid.UUID `json:"renewal_id"`
	ParentRef             uuid.UUID `json:"parent_ref"`                         // license_id or previous renewal_id
	ContentID             uuid.UUID `json:"content_id"`                         // must match envelope
	IssuedAt              time.Time `json:"issued_at"`
	NewExpiresAt          time.Time `json:"new_expires_at"`
	NewGracePeriodSeconds *int      `json:"new_grace_period_seconds,omitempty"` // nil = inherit from parent
	SigningKeyID          string    `json:"signing_key_id"`
}

// SignedRenewal pairs the raw JSON token bytes with their signature.
type SignedRenewal struct {
	TokenBytes []byte
	Signature  []byte
}

// Token parses the JSON token bytes into a RenewalToken.
func (sr *SignedRenewal) Token() (*RenewalToken, error) {
	var t RenewalToken
	if err := json.Unmarshal(sr.TokenBytes, &t); err != nil {
		return nil, fmt.Errorf("parse renewal token: %w", err)
	}
	return &t, nil
}

// NewSignedRenewal creates a SignedRenewal from a RenewalToken.
// The signature field must be filled in separately after signing.
func NewSignedRenewal(token *RenewalToken) (*SignedRenewal, error) {
	data, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("marshal renewal token: %w", err)
	}
	return &SignedRenewal{TokenBytes: data}, nil
}

// MarshalBinary serializes a SignedRenewal to binary:
//
//	TokenLen(4) + Token + SignatureLen(2) + Signature
func (sr *SignedRenewal) MarshalBinary() ([]byte, error) {
	size := 4 + len(sr.TokenBytes) + 2 + len(sr.Signature)
	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(sr.TokenBytes)))
	offset += 4

	copy(buf[offset:], sr.TokenBytes)
	offset += len(sr.TokenBytes)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(sr.Signature)))
	offset += 2

	copy(buf[offset:], sr.Signature)
	return buf, nil
}

// UnmarshalBinary deserializes a SignedRenewal from binary data.
func (sr *SignedRenewal) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("%w: renewal token too short", ErrTruncated)
	}
	offset := 0

	tokenLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	if offset+tokenLen > len(data) {
		return fmt.Errorf("%w: renewal token truncated", ErrTruncated)
	}
	sr.TokenBytes = make([]byte, tokenLen)
	copy(sr.TokenBytes, data[offset:offset+tokenLen])
	offset += tokenLen

	if offset+2 > len(data) {
		return fmt.Errorf("%w: renewal signature length truncated", ErrTruncated)
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if offset+sigLen > len(data) {
		return fmt.Errorf("%w: renewal signature truncated", ErrTruncated)
	}
	sr.Signature = make([]byte, sigLen)
	copy(sr.Signature, data[offset:offset+sigLen])
	return nil
}

// RenewalChain is an ordered list of signed renewal tokens.
type RenewalChain []SignedRenewal

// MarshalBinary serializes the renewal chain:
//
//	Count(4) + [TokenLen(4) + Token + SignatureLen(2) + Signature]...
func (rc RenewalChain) MarshalBinary() ([]byte, error) {
	// Calculate total size
	size := 4 // count
	for i := range rc {
		tokenData, err := rc[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal renewal %d: %w", i, err)
		}
		size += len(tokenData)
		// We'll re-marshal below; just sizing here
		_ = tokenData
	}

	buf := make([]byte, 0, size)
	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, uint32(len(rc)))
	buf = append(buf, countBuf...)

	for i := range rc {
		tokenData, err := rc[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal renewal %d: %w", i, err)
		}
		buf = append(buf, tokenData...)
	}

	return buf, nil
}

// UnmarshalBinary deserializes a renewal chain from binary data.
func (rc *RenewalChain) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("%w: renewal chain too short", ErrTruncated)
	}

	count := binary.BigEndian.Uint32(data[0:4])
	offset := 4

	*rc = make(RenewalChain, count)
	for i := uint32(0); i < count; i++ {
		if offset >= len(data) {
			return fmt.Errorf("%w: renewal chain truncated at token %d", ErrTruncated, i)
		}

		// Parse token length first to know how much to read
		if offset+4 > len(data) {
			return fmt.Errorf("%w: renewal token %d length truncated", ErrTruncated, i)
		}
		tokenLen := int(binary.BigEndian.Uint32(data[offset:]))

		// We need: tokenLen(4) + token + sigLen(2) + sig
		// First figure out the sig length
		sigLenOffset := offset + 4 + tokenLen
		if sigLenOffset+2 > len(data) {
			return fmt.Errorf("%w: renewal token %d signature length truncated", ErrTruncated, i)
		}
		sigLen := int(binary.BigEndian.Uint16(data[sigLenOffset:]))

		totalTokenSize := 4 + tokenLen + 2 + sigLen
		if offset+totalTokenSize > len(data) {
			return fmt.Errorf("%w: renewal token %d truncated", ErrTruncated, i)
		}

		if err := (*rc)[i].UnmarshalBinary(data[offset : offset+totalTokenSize]); err != nil {
			return fmt.Errorf("unmarshal renewal token %d: %w", i, err)
		}
		offset += totalTokenSize
	}

	return nil
}
