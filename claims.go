package jwt

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

type ClaimType string

const (
	AccountClaim    = "account"
	ActivationClaim = "activation"
	UserClaim       = "user"
	ServerClaim     = "server"
	ClusterClaim    = "cluster"
	OperatorClaim   = "operator"
	RevocationClaim = "revocation"
)

// Claims is a JWT claims
type Claims interface {
	Claims() *ClaimsData
	Encode(kp nkeys.KeyPair) (string, error)
	ExpectedPrefixes() []nkeys.PrefixByte
	Payload() interface{}
	String() string
	Valid() error
	Verify(payload string, sig []byte) bool
}

// ClaimsData is the base struct for all claims
type ClaimsData struct {
	Audience  string    `json:"aud,omitempty"`
	Expires   int64     `json:"exp,omitempty"`
	ID        string    `json:"jti,omitempty"`
	IssuedAt  int64     `json:"iat,omitempty"`
	Issuer    string    `json:"iss,omitempty"`
	Name      string    `json:"name,omitempty"`
	NotBefore int64     `json:"nbf,omitempty"`
	Subject   string    `json:"sub,omitempty"`
	Type      ClaimType `json:"type,omitempty"`
}

type Prefix struct {
	nkeys.PrefixByte
}

func serialize(v interface{}) (string, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(j), nil
}

func (c *ClaimsData) doEncode(header *Header, kp nkeys.KeyPair, claim Claims) (string, error) {
	if header == nil {
		return "", errors.New("header is required")
	}

	if kp == nil {
		return "", errors.New("keypair is required")
	}

	if c.Subject == "" {
		return "", errors.New("subject is not set")
	}

	h, err := serialize(header)
	if err != nil {
		return "", err
	}

	issuerBytes, err := kp.PublicKey()
	if err != nil {
		return "", err
	}
	c.Issuer = string(issuerBytes)

	c.IssuedAt = time.Now().UTC().Unix()

	c.ID, err = c.hash()
	if err != nil {
		return "", err
	}

	if err := claim.Valid(); err != nil {
		return "", err
	}

	payload, err := serialize(claim)
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

func (c *ClaimsData) hash() (string, error) {
	j, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha512.New512_256()
	h.Write(j)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil)), nil
}

// encode encodes a claim into a JWT token. The claim is signed with the
// provided nkey's private key
func (c *ClaimsData) encode(kp nkeys.KeyPair, payload Claims) (string, error) {
	return c.doEncode(&Header{TokenTypeJwt, AlgorithmNkey}, kp, payload)
}

// Returns a JSON representation of the claim
func (c *ClaimsData) String(claim interface{}) string {
	j, err := json.MarshalIndent(claim, "", "  ")
	if err != nil {
		return ""
	}
	return string(j)
}

func parseClaims(s string, target Claims) error {
	h, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(h, &target); err != nil {
		return err
	}
	if err := target.Valid(); err != nil {
		return err
	}

	// validity on decoding enforces NotBefore - this cannot be tested
	// on Valid() as that is used on generation.
	now := time.Now().UTC().Unix()
	if target.Claims().NotBefore > 0 && target.Claims().NotBefore > now {
		return errors.New("claim is not yet valid")
	}

	return nil
}

// Verify verifies that the encoded payload was signed by the
// provided public key. Verify is called automatically with
// the claims portion of the token and the public key in the claim.
// Client code need to insure that the public key in the
// claim is trusted.
func (c *ClaimsData) Verify(payload string, sig []byte) bool {
	// decode the public key
	kp, err := nkeys.FromPublicKey([]byte(c.Issuer))
	if err != nil {
		return false
	}
	if err := kp.Verify([]byte(payload), sig); err != nil {
		return false
	}
	return true
}

// Valid validates a claim to make sure it is valid. Validity checks
// include expiration constraints.
func (c *ClaimsData) Valid() error {
	now := time.Now().UTC().Unix()
	if c.Expires > 0 && now > c.Expires {
		return errors.New("claim is expired")
	}

	return nil
}

func (c *ClaimsData) IsSelfSigned() bool {
	return c.Issuer == c.Subject
}

// Decode takes a JWT string decodes it and validates it
// and return the embedded Claims. If the token header
// doesn't match the expected algorithm, or the claim is
// not valid or verification fails an error is returned
func Decode(token string, target Claims) error {
	// must have 3 chunks
	chunks := strings.Split(token, ".")
	if len(chunks) != 3 {
		return errors.New("expected 3 chunks")
	}

	_, err := parseHeaders(chunks[0])
	if err != nil {
		return err
	}

	if err := parseClaims(chunks[1], target); err != nil {
		return err
	}

	sig, err := base64.RawStdEncoding.DecodeString(chunks[2])
	if err != nil {
		return err
	}

	if !target.Verify(chunks[1], sig) {
		return errors.New("claim failed signature verification")
	}

	prefixes := target.ExpectedPrefixes()
	if prefixes != nil {
		ok := false
		issuer := []byte(target.Claims().Issuer)
		for _, p := range prefixes {
			switch p {
			case nkeys.PrefixByteAccount:
				if nkeys.IsValidPublicAccountKey(issuer) {
					ok = true
					break
				}
			case nkeys.PrefixByteOperator:
				if nkeys.IsValidPublicOperatorKey(issuer) {
					ok = true
					break
				}
			case nkeys.PrefixByteServer:
				if nkeys.IsValidPublicServerKey(issuer) {
					ok = true
					break
				}
			case nkeys.PrefixByteCluster:
				if nkeys.IsValidPublicClusterKey(issuer) {
					ok = true
					break
				}
			case nkeys.PrefixByteUser:
				if nkeys.IsValidPublicUserKey(issuer) {
					ok = true
					break
				}
			}
		}
		if !ok {
			return fmt.Errorf("unable to validate expected prefixes - %v", prefixes)
		}
	}

	return nil
}
