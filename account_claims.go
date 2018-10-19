package jwt

import (
	"github.com/nats-io/nkeys"
	"github.com/pkg/errors"
)

type AccountClaims struct {
	ClaimsData
	Account `json:"nats,omitempty"`
}

func NewAccountClaims(subject string) *AccountClaims {
	if subject == "" {
		return nil
	}
	c := &AccountClaims{}
	c.Subject = subject
	return c
}

func (a *AccountClaims) Encode(pair nkeys.KeyPair) (string, error) {
	if !nkeys.IsValidPublicAccountKey(a.Subject) {
		return "", errors.New("expected subject to be account public key")
	}
	a.ClaimsData.Type = AccountClaim
	return a.ClaimsData.encode(pair, a)
}

func DecodeAccountClaims(token string) (*AccountClaims, error) {
	v := AccountClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (a *AccountClaims) String() string {
	return a.ClaimsData.String(a)
}

func (a *AccountClaims) Payload() interface{} {
	return &a.Account
}

func (a *AccountClaims) Valid() error {
	var err error
	if err = a.ClaimsData.Valid(); err != nil {
		return err
	}
	if err = a.Account.Valid(); err != nil {
		return err
	}
	return nil
}

func (a *AccountClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount}
}

func (a *AccountClaims) Claims() *ClaimsData {
	return &a.ClaimsData
}
