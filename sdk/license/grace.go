package license

import (
	"time"

	"github.com/trendvidia/ironclad/sdk/container"
)

// Status represents the current state of a license.
type Status int

const (
	StatusValid   Status = iota // before expires_at
	StatusInGrace               // after expires_at, within grace period
	StatusExpired               // beyond grace period
	StatusRevoked               // explicitly revoked
)

func (s Status) String() string {
	switch s {
	case StatusValid:
		return "VALID"
	case StatusInGrace:
		return "IN_GRACE"
	case StatusExpired:
		return "EXPIRED"
	case StatusRevoked:
		return "REVOKED"
	default:
		return "UNKNOWN"
	}
}

// EffectiveTerms holds the computed expiry and grace period
// after walking the renewal chain.
type EffectiveTerms struct {
	ExpiresAt          time.Time
	GracePeriodSeconds int
	RenewalCount       int
}

// GraceDeadline returns the absolute deadline after which
// the license is fully expired (expiry + grace period).
func (et *EffectiveTerms) GraceDeadline() time.Time {
	return et.ExpiresAt.Add(time.Duration(et.GracePeriodSeconds) * time.Second)
}

// EvaluateTerms walks the license and renewal chain to determine
// the effective expiration and grace period.
func EvaluateTerms(license *container.LicenseToken, renewals container.RenewalChain) (*EffectiveTerms, error) {
	terms := &EffectiveTerms{
		ExpiresAt:          license.ExpiresAt(),
		GracePeriodSeconds: int(license.GracePeriodSeconds),
	}

	for _, sr := range renewals {
		rt, err := sr.Token()
		if err != nil {
			return nil, err
		}

		terms.ExpiresAt = rt.NewExpiresAt()
		if rt.NewGracePeriodSeconds != 0 {
			terms.GracePeriodSeconds = int(rt.NewGracePeriodSeconds)
		}
		terms.RenewalCount++
	}

	return terms, nil
}

// EvaluateStatus determines the license status at the given time.
func EvaluateStatus(terms *EffectiveTerms, now time.Time) Status {
	if now.Before(terms.ExpiresAt) {
		return StatusValid
	}
	if now.Before(terms.GraceDeadline()) {
		return StatusInGrace
	}
	return StatusExpired
}
