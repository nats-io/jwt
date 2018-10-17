package jwt

import (
	"fmt"

	"github.com/nats-io/nkeys"
)

type RevocationClaims struct {
	ClaimsData
	Revocation `json:"nats,omitempty"`
}

func NewRevocationClaims(subject string) *RevocationClaims {
	if subject == "" {
		return nil
	}
	c := &RevocationClaims{}
	c.Subject = subject
	return c
}

func (s *RevocationClaims) Encode(pair nkeys.KeyPair) (string, error) {
	s.ClaimsData.Type = RevocationClaim
	return s.ClaimsData.encode(pair, s)
}

func DecodeRevocationClaims(token string) (*RevocationClaims, error) {
	v := RevocationClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *RevocationClaims) String() string {
	return s.ClaimsData.String(s)
}

func (s *RevocationClaims) Payload() interface{} {
	return &s.Revocation
}

func (s *RevocationClaims) Valid() error {
	if err := s.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := s.Revocation.Valid(); err != nil {
		return err
	}

	theJWT, err := DecodeGeneric(s.Revocation.JWT)
	if err != nil {
		return err
	}

	if theJWT.Issuer != s.Issuer {
		return fmt.Errorf("Revocation issuer doesn't match JWT to revoke")
	}

	return nil
}

func (s *RevocationClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteOperator, nkeys.PrefixByteAccount}
}

func (s *RevocationClaims) Claims() *ClaimsData {
	return &s.ClaimsData
}
