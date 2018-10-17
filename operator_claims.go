package jwt

import (
	"errors"

	"github.com/nats-io/nkeys"
)

type OperatorClaims struct {
	ClaimsData
	Operator `json:"nats,omitempty"`
}

func NewOperatorClaims(subject string) *OperatorClaims {
	if subject == "" {
		return nil
	}
	c := &OperatorClaims{}
	c.Subject = subject
	return c
}

func (s *OperatorClaims) Encode(pair nkeys.KeyPair) (string, error) {
	if !nkeys.IsValidPublicOperatorKey(s.Subject) {
		return "", errors.New("expected subject to be an operator public key")
	}
	s.ClaimsData.Type = OperatorClaim
	return s.ClaimsData.encode(pair, s)
}

func DecodeOperatorClaims(token string) (*OperatorClaims, error) {
	v := OperatorClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *OperatorClaims) String() string {
	return s.ClaimsData.String(s)
}

func (s *OperatorClaims) Payload() interface{} {
	return &s.Operator
}

func (s *OperatorClaims) Valid() error {
	if err := s.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := s.Operator.Valid(); err != nil {
		return err
	}
	return nil
}

func (s *OperatorClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteOperator}
}

func (s *OperatorClaims) Claims() *ClaimsData {
	return &s.ClaimsData
}
