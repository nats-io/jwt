package jwt

import (
	"errors"
	"github.com/nats-io/nkeys"
)

type UserClaims struct {
	ClaimsData
	User `json:"nats,omitempty"`
}

func NewUserClaim(subject string) *UserClaims {
	if subject == "" {
		return nil
	}
	c := &UserClaims{}
	c.Subject = subject
	return c
}

func (u *UserClaims) Encode(pair nkeys.KeyPair) (string, error) {
	if !nkeys.IsValidPublicUserKey(u.Subject) {
		return "", errors.New("expected subject to be user public key")
	}
	u.ClaimsData.Type = UserClaim
	return u.ClaimsData.encode(pair, u)
}

func DecodeUserClaims(token string) (*UserClaims, error) {
	v := UserClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (u *UserClaims) Valid() error {
	if err := u.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := u.User.Valid(); err != nil {
		return err
	}
	return nil
}

func (u *UserClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount}
}

func (u *UserClaims) Claims() *ClaimsData {
	return &u.ClaimsData
}

func (u *UserClaims) Payload() interface{} {
	return &u.User
}

func (u *UserClaims) String() string {
	return u.ClaimsData.String(u)
}
