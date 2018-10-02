package jwt

import (
	"github.com/nats-io/nkeys"
)

type AccountClaims struct {
	ClaimsData
	Account `json:"nats,omitempty"`
}

func NewAccountClaims() *AccountClaims {
	return &AccountClaims{}
}

func (a *AccountClaims) Encode(pair nkeys.KeyPair) (string, error) {
	return a.ClaimsData.encode(pair, &a)
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
	if err := a.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := a.Account.Valid(); err != nil {
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
