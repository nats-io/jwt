package jwt

import (
	"encoding/base64"
	"fmt"
	"encoding/json"
	"strings"
	"errors"

	"github.com/nats-io/nkeys"
)

type Claims struct {
	Issuer    string            `json:"iss,omitempty"`
	Subject   string            `json:"nbf,omitempty"`
	Audience  string            `json:"aud,omitempty"`
	Expires   int64             `json:"exp,omitempty"`
	NotBefore int64             `json:"nbf,omitempty"`
	ID        string            `json:"jti,omitempty"`
	IssuedAt  int64             `json:"iat,omitempty"`
	Nats      map[string]string `json:"nats,omitempty"`
}

func encode(v interface{}) (string, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(j), nil
}

func (c *Claims) Encode(kp nkeys.KeyPair) (string, error) {
	header, err := encode(Header{"jwt", "nkey"})
	if err != nil {
		return "", err
	}

	c.Issuer, err = kp.PublicKey()
	if err != nil {
		return "", err
	}
	payload, err := encode(c)
	if err != nil {
		return "", err
	}

	sig, err := kp.Sign([]byte(payload))
	esig := base64.RawStdEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", header, payload, esig), nil
}

func (c *Claims) String() string {
	j, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(j)
}

func ParseClaims(s string) (*Claims, error) {
	h, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	claims := Claims{}
	if err := json.Unmarshal(h, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func (c *Claims) KnownIssuer(keys []string) bool {
	for _, k := range keys {
		if k == c.Issuer {
			return true
		}
	}
	return false
}

func (c *Claims) Valid(payload string, sig []byte) (bool) {
	// decode the public key
	kp, err := nkeys.FromPublicKey(c.Issuer)
	if err != nil {
		return false
	}
	if err := kp.Verify([]byte(payload), sig); err != nil {
		return false
	}
	return true
}

func Decode(keys []string, token string) (*Claims, error) {
	chunks := strings.Split(token, ".")
	if len(chunks) != 3 {
		return nil, errors.New("expected 3 chunks")
	}

	header, err := ParseHeader(chunks[0])
	if err != nil {
		return nil, err
	}
	if !header.Valid() {
		return nil, errors.New("unable to validate the JWT header")
	}

	claims, err := ParseClaims(chunks[1])
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawStdEncoding.DecodeString(chunks[2])
	if err != nil {
		return nil, err
	}

	if !claims.KnownIssuer(keys) {
		return nil, errors.New("claim issuer is unknown")
	}

	if !claims.Valid(chunks[1], sig) {
		return nil, errors.New("claim was not valid")
	}

	return claims, nil
}
