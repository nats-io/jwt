package jwt

import (
	"github.com/nats-io/nkeys"
)

type UserClaim struct {
	ClaimsData
	User `json:"nats,omitempty"`
}

func NewUserClaim(subject string) *UserClaim {
	ac := &UserClaim{}
	ac.Subject = subject
	return ac
}

func (a *UserClaim) Encode(pair nkeys.KeyPair) (string, error) {
	return a.ClaimsData.encode(pair, &a)
}

func DecodeUserClaims(token string) (*UserClaim, error) {
	v := UserClaim{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (a *UserClaim) Valid() error {
	if err := a.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := a.User.Valid(); err != nil {
		return err
	}
	return nil
}

func (a *UserClaim) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount}
}

func (a *UserClaim) Claims() *ClaimsData {
	return &a.ClaimsData
}

func (a *UserClaim) Payload() interface{} {
	return &a.User
}

func (a *UserClaim) String() string {
	return a.ClaimsData.String(a)
}
