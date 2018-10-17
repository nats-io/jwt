package jwt

import (
	"errors"

	"github.com/nats-io/nkeys"
)

type ServerClaims struct {
	ClaimsData
	Server `json:"nats,omitempty"`
}

func NewServerClaims(subject string) *ServerClaims {
	if subject == "" {
		return nil
	}
	c := &ServerClaims{}
	c.Subject = subject
	return c
}

func (s *ServerClaims) Encode(pair nkeys.KeyPair) (string, error) {
	if !nkeys.IsValidPublicServerKey(s.Subject) {
		return "", errors.New("expected subject to be a server public key")
	}
	s.ClaimsData.Type = ServerClaim
	return s.ClaimsData.encode(pair, s)
}

func DecodeServerClaims(token string) (*ServerClaims, error) {
	v := ServerClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *ServerClaims) String() string {
	return s.ClaimsData.String(s)
}

func (s *ServerClaims) Payload() interface{} {
	return &s.Server
}

func (s *ServerClaims) Valid() error {
	if err := s.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := s.Server.Valid(); err != nil {
		return err
	}
	return nil
}

func (s *ServerClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteCluster}
}

func (s *ServerClaims) Claims() *ClaimsData {
	return &s.ClaimsData
}
