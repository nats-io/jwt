package jwt

import (
	"github.com/nats-io/nkeys"
)

type User struct {
	Pub []string `json:"pub,omitempty"`
	Sub []string `json:"sub,omitempty"`
	Limits
}

func (u *User) AddPub(p string) {
	if u.canAdd(&u.Pub, p) {
		u.Pub = append(u.Pub, p)
	}
}

func (u *User) RemovePub(p string) {
	for i, t := range u.Pub {
		if t == p {
			u.Pub = append(u.Pub[:i], u.Pub[i+1:]...)
			break
		}
	}
}

func (u *User) RemoveSub(p string) {
	for i, t := range u.Sub {
		if t == p {
			u.Sub = append(u.Pub[:i], u.Pub[i+1:]...)
			break
		}
	}
}

func (u *User) AddSub(p string) {
	if u.canAdd(&u.Sub, p) {
		u.Sub = append(u.Sub, p)
	}
}

func (u *User) contains(a *[]string, p string) bool {
	for _, t := range *a {
		if t == p {
			return true
		}
	}
	return false
}

func (u *User) canAdd(a *[]string, s string) bool {
	return !u.contains(a, s)
}

func (u *User) Valid() error {
	return nil
}

type UserClaim struct {
	ClaimsData
	User `json:"natsuser,omitempty"`
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

func (a *UserClaim) Payload() interface{} {
	return a.User
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

func (a *UserClaim) String() string {
	return a.ClaimsData.String(a)
}
