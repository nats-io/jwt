package jwt

import "github.com/nats-io/nkeys"

type ActivationClaims struct {
	ClaimsData
	Activation `json:"nats,omitempty"`
}

func NewActivationClaims(subject string) *ActivationClaims {
	ac := &ActivationClaims{}
	ac.Subject = subject
	return ac
}

func (a *ActivationClaims) Encode(pair nkeys.KeyPair) (string, error) {
	return a.ClaimsData.encode(pair, &a)
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
