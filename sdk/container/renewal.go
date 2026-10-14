package container

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/trendvidia/protowire-go/encoding/pb"
)

// RenewalToken extends a license expiration without modifying the envelope.
type RenewalToken struct {
	RenewalID             []byte `protowire:"1"`
	ParentRef             []byte `protowire:"2"`
	ContentID             []byte `protowire:"3"`
	IssuedAtUnix          int64  `protowire:"4"`
	NewExpiresAtUnix      int64  `protowire:"5"`
	NewGracePeriodSeconds int32  `protowire:"6"` // 0 = inherit from parent
	SigningKeyID          string `protowire:"7"`
}

func (rt *RenewalToken) IssuedAt() time.Time     { return time.Unix(rt.IssuedAtUnix, 0).UTC() }
func (rt *RenewalToken) NewExpiresAt() time.Time { return time.Unix(rt.NewExpiresAtUnix, 0).UTC() }

func (rt *RenewalToken) RenewalUUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], rt.RenewalID)
	return id
}

func (rt *RenewalToken) ParentRefUUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], rt.ParentRef)
	return id
}

func (rt *RenewalToken) ContentUUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], rt.ContentID)
	return id
}

// SignedRenewal pairs the protowire-encoded token bytes with their signature.
type SignedRenewal struct {
	TokenBytes []byte `protowire:"1"`
	Signature  []byte `protowire:"2"`
}

// Token parses the token bytes into a RenewalToken.
func (sr *SignedRenewal) Token() (*RenewalToken, error) {
	var t RenewalToken
	if err := pb.Unmarshal(sr.TokenBytes, &t); err != nil {
		return nil, fmt.Errorf("parse renewal token: %w", err)
	}
	return &t, nil
}

// NewSignedRenewal creates a SignedRenewal from a RenewalToken.
func NewSignedRenewal(token *RenewalToken) (*SignedRenewal, error) {
	data, err := pb.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("marshal renewal token: %w", err)
	}
	return &SignedRenewal{TokenBytes: data}, nil
}

// MarshalBinary serializes using protowire.
func (sr *SignedRenewal) MarshalBinary() ([]byte, error) {
	return pb.Marshal(sr)
}

// UnmarshalBinary deserializes from protowire.
func (sr *SignedRenewal) UnmarshalBinary(data []byte) error {
	return pb.Unmarshal(data, sr)
}

// RenewalChain is an ordered list of signed renewal tokens.
type RenewalChain []SignedRenewal

type renewalChainWrapper struct {
	Items []SignedRenewal `protowire:"1"`
}

// MarshalBinary serializes the renewal chain using protowire.
func (rc RenewalChain) MarshalBinary() ([]byte, error) {
	w := renewalChainWrapper{Items: []SignedRenewal(rc)}
	return pb.Marshal(&w)
}

// UnmarshalBinary deserializes a renewal chain from protowire.
func (rc *RenewalChain) UnmarshalBinary(data []byte) error {
	var w renewalChainWrapper
	if err := pb.Unmarshal(data, &w); err != nil {
		return err
	}
	*rc = RenewalChain(w.Items)
	return nil
}
