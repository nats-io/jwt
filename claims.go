package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

// Claims is a JWT claims
type Claims struct {
	Issuer    string                 `json:"iss,omitempty"`
	Subject   string                 `json:"sub,omitempty"`
	Audience  string                 `json:"aud,omitempty"`
	Expires   int64                  `json:"exp,omitempty"`
	NotBefore int64                  `json:"nbf,omitempty"`
	ID        string                 `json:"jti,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"`
	Nats      map[string]interface{} `json:"nats,omitempty"`
}

// NewClaims creates a Claims
func NewClaims() *Claims {
	c := Claims{}
	c.Nats = make(map[string]interface{})
	return &c
}

func encode(v interface{}) (string, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(j), nil
}

func (c *Claims) doEncode(header *Header, kp nkeys.KeyPair) (string, error) {
	h, err := encode(header)
	if err != nil {
		return "", err
	}

	c.Issuer, err = kp.PublicKey()
	if err != nil {
		return "", err
	}

	c.IssuedAt = time.Now().UTC().Unix()

	payload, err := encode(c)
	if err != nil {
		return "", err
	}

	sig, err := kp.Sign([]byte(payload))
	if err != nil {
		return "", err
	}
	eSig := base64.RawStdEncoding.EncodeToString(sig)
	return fmt.Sprintf("%s.%s.%s", h, payload, eSig), nil
}

// Encode encodes a claim into a JWT token. The claim is signed with the
// provided nkey's private key
func (c *Claims) Encode(kp nkeys.KeyPair) (string, error) {
	return c.doEncode(&Header{TokenTypeJwt, AlgorithmNkey}, kp)
}

// Returns a JSON representation of the claim
func (c *Claims) String() string {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return ""
	}
	return string(j)
}

func parseClaims(s string) (*Claims, error) {
	h, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	claims := Claims{}
	if err := json.Unmarshal(h, &claims); err != nil {
		return nil, err
	}
	if err := claims.Valid(); err != nil {
		return nil, err
	}
	return &claims, nil
}

// Verify verifies that the encoded payload was signed by the
// provided public key. Verify is called automatically with
// the claims portion of the token and the public key in the claim.
// Client code need to insure that the public key in the
// claim is trusted.
func (c *Claims) Verify(payload string, sig []byte) bool {
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

// Valid validates a claim to make sure it is valid. Validity checks
// include expiration and use before constraints.
func (c *Claims) Valid() error {
	now := time.Now().UTC().Unix()
	if c.NotBefore > 0 && c.NotBefore > now {
		return errors.New("claim is not yet valid")
	}
	if c.Expires > 0 && now > c.Expires {
		return errors.New("claim is expired")
	}

	return nil
}

// Decode takes a JWT string decodes it and validates it
// and return the embedded Claims. If the token header
// doesn't match the expected algorithm, or the claim is
// not valid or verification fails an error is returned
func Decode(token string) (*Claims, error) {
	// must have 3 chunks
	chunks := strings.Split(token, ".")
	if len(chunks) != 3 {
		return nil, errors.New("expected 3 chunks")
	}

	_, err := parseHeaders(chunks[0])
	if err != nil {
		return nil, err
	}

	claims, err := parseClaims(chunks[1])
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawStdEncoding.DecodeString(chunks[2])
	if err != nil {
		return nil, err
	}

	if !claims.Verify(chunks[1], sig) {
		return nil, errors.New("claim failed signature verification")
	}

	return claims, nil
}
