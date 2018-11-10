package jwt

import (
	"errors"

	"github.com/nats-io/nkeys"
)

// Activation defines the custom parts of an activation claim
type Activation struct {
	Exports Exports `json:"exports,omitempty"`
	Limits
}

// Validate checks the exports and limits in an activation JWT
func (a *Activation) Validate(vr *ValidationResults) {
	a.Exports.Validate(vr)
	a.Limits.Validate(vr)
}

// ActivationClaims holds the data specific to an activation JWT
type ActivationClaims struct {
	ClaimsData
	Activation `json:"nats,omitempty"`
}

// NewActivationClaims creates a new activation claim with the provided subject
func NewActivationClaims(subject string) *ActivationClaims {
	if subject == "" {
		return nil
	}
	ac := &ActivationClaims{}
	ac.Subject = subject
	return ac
}

// Encode turns an activation claim into a JWT strimg
func (a *ActivationClaims) Encode(pair nkeys.KeyPair) (string, error) {
	if a.Subject != "public" && !nkeys.IsValidPublicAccountKey(([]byte(a.Subject))) {
		return "", errors.New("expected subject 'public' or an account")
	}
	a.ClaimsData.Type = ActivationClaim
	return a.ClaimsData.encode(pair, a)
}

// DecodeActivationClaims tries to create an activation claim from a JWT string
func DecodeActivationClaims(token string) (*ActivationClaims, error) {
	v := ActivationClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Payload returns the activation specific part of the JWT
func (a *ActivationClaims) Payload() interface{} {
	return a.Activation
}

// Validate checks the claims
func (a *ActivationClaims) Validate(vr *ValidationResults) {
	a.ClaimsData.Validate(vr)
	a.Activation.Validate(vr)
}

// ExpectedPrefixes defines the types that can sign an activation jwt, account and oeprator
func (a *ActivationClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount, nkeys.PrefixByteOperator}
}

// Claims returns the generic part of the JWT
func (a *ActivationClaims) Claims() *ClaimsData {
	return &a.ClaimsData
}

func (a *ActivationClaims) String() string {
	return a.ClaimsData.String(a)
}
