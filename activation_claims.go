package jwt

import (
	"errors"
	"github.com/nats-io/nkeys"
)

type ActivationClaims struct {
	ClaimsData
	Activation `json:"nats,omitempty"`
}

func NewActivationClaims(subject string) *ActivationClaims {
	if subject == "" {
		return nil
	}
	ac := &ActivationClaims{}
	ac.Subject = subject
	return ac
}

func (a *ActivationClaims) Encode(pair nkeys.KeyPair) (string, error) {
	if a.Subject != "public" && !nkeys.IsValidPublicAccountKey(a.Subject) {
		return "", errors.New("expected subject 'public' or an account")
	}
	a.ClaimsData.Type = ActivationClaim
	return a.ClaimsData.encode(pair, a)
}

func DecodeActivationClaims(token string) (*ActivationClaims, error) {
	v := ActivationClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (a *ActivationClaims) Payload() interface{} {
	return a.Activation
}

func (a *ActivationClaims) Valid() error {
	if err := a.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := a.Activation.Valid(); err != nil {
		return err
	}

	if !nkeys.IsValidPublicOperatorKey(a.Issuer) && !a.IsSelfSigned() {
		if a.OperatorLimits.Conn > 0 || a.OperatorLimits.Maps > 0 || a.OperatorLimits.Subs > 0 {
			return errors.New("operator limits can only be set by operators or self-signed")
		}
	}

	return nil
}

func (a *ActivationClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount, nkeys.PrefixByteOperator}
}

func (a *ActivationClaims) Claims() *ClaimsData {
	return &a.ClaimsData
}

func (a *ActivationClaims) String() string {
	return a.ClaimsData.String(a)
}
