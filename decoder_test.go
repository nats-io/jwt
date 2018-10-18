package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewToken(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	claims := NewGenericClaims(publicKey(createUserNKey(t), t))
	claims.Data["foo"] = "bar"

	token, err := claims.Encode(kp)
	if err != nil {
		t.Fatal("error encoding token", err)
	}

	c, err := DecodeGeneric(token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.NotBefore != c.NotBefore {
		t.Fatal("notbefore don't match")
	}

	if claims.Issuer != c.Issuer {
		t.Fatal("notbefore don't match")
	}

	if !reflect.DeepEqual(claims.Data, c.Data) {
		t.Fatal("data sections don't match")
	}
}

func TestBadType(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{"JWS", AlgorithmNkey}
	c := NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, c)
	if err != nil {
		t.Fatal(err)
	}

	claim, err := DecodeGeneric(token)
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != fmt.Sprintf("not supported type %q", "JWS") {
		t.Fatal("expected not supported type error")
	}
}

func TestBadAlgo(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{TokenTypeJwt, "foobar"}
	c := NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, c)
	if err != nil {
		t.Fatal(err)
	}

	claim, err := DecodeGeneric(token)
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != fmt.Sprintf("unexpected %q algorithm", "foobar") {
		t.Fatal("expected unexpected algorithm")
	}
}

func TestBadJWT(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{"JWS", AlgorithmNkey}
	c := NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, c)
	if err != nil {
		t.Fatal(err)
	}

	chunks := strings.Split(token, ".")
	badToken := fmt.Sprintf("%s.%s", chunks[0], chunks[1])

	claim, err := DecodeGeneric(badToken)
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != "expected 3 chunks" {
		t.Fatalf("unexpeced error: %q", err.Error())
	}
}

func TestBadSignature(t *testing.T) {
	kp := createAccountNKey(t)

	h := Header{TokenTypeJwt, AlgorithmNkey}
	c := NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, c)
	if err != nil {
		t.Fatal(err)
	}

	token = token + "A"

	claim, err := DecodeGeneric(token)
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != "claim failed signature verification" {
		m := fmt.Sprintf("expected failed signature: %q", err.Error())
		t.Fatal(m)
	}
}

func TestDifferentPayload(t *testing.T) {
	akp1 := createAccountNKey(t)

	c1 := NewGenericClaims(publicKey(createUserNKey(t), t))
	c1.Data["foo"] = "barz"
	jwt1 := encode(c1, akp1, t)
	c1t := strings.Split(jwt1, ".")
	c1.Data["foo"] = "bar"

	kp2 := createAccountNKey(t)
	token2 := encode(c1, kp2, t)
	c2t := strings.Split(token2, ".")

	c1t[1] = c2t[1]

	claim, err := DecodeGeneric(fmt.Sprintf("%s.%s.%s", c1t[0], c1t[1], c1t[2]))
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != "claim failed signature verification" {
		m := fmt.Sprintf("expected failed signature: %q", err.Error())
		t.Fatal(m)
	}
}

func TestExpiredToken(t *testing.T) {
	akp := createAccountNKey(t)
	c := NewGenericClaims(publicKey(akp, t))
	c.Expires = time.Now().UTC().Unix() - 100
	c.Data["foo"] = "barz"

	_, err := c.Encode(akp)
	if err == nil {
		t.Fatal("shouldn't be able to encode an expired claim")
	}
}

func TestNotYetValid(t *testing.T) {
	akp1, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}
	c := NewGenericClaims(publicKey(akp1, t))
	now := time.Now().UTC().Unix()
	c.NotBefore = now + 100
	c.Data["foo"] = "barz"

	token := encode(c, akp1, t)

	claim, err := DecodeGeneric(token)
	if claim != nil {
		t.Fatalf("non nil claim on bad token: %q", claim.String())
	}

	if err == nil {
		t.Fatalf("nil error on bad token")
	}

	if err.Error() != "claim is not yet valid" {
		t.Fatalf("expected not yet valid claim: %q", err.Error())
	}
}

func TestIssuedAtIsSet(t *testing.T) {
	akp := createAccountNKey(t)
	c := NewGenericClaims(publicKey(akp, t))
	c.Data["foo"] = "barz"

	token, err := c.Encode(akp)
	if err != nil {
		t.Fatal(err)
	}

	claim, err := DecodeGeneric(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claim.IssuedAt == 0 {
		t.Fatalf("issued at is not set")
	}
}

func TestSample(t *testing.T) {
	// Need a private key to sign the claim
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	// add a bunch of claims
	claims.Data["foo"] = "bar"

	// serialize the claim to a JWT token
	token, err := claims.Encode(akp)
	if err != nil {
		t.Fatal("error encoding token", err)
	}

	// on the receiving side, decode the token
	c, err := DecodeGeneric(token)
	if err != nil {
		t.Fatal(err)
	}

	// if the token was decoded, it means that it
	// validated and it wasn't tampered. the remaining and
	// required test is to insure the issuer is trusted
	pk, err := akp.PublicKey()
	if err != nil {
		t.Fatalf("unable to read public key: %v", err)
	}

	if c.Issuer != pk {
		t.Fatalf("the public key is not trusted")
	}
}

func TestBadHeaderEncoding(t *testing.T) {
	// the '=' will be illegal
	_, err := parseHeaders("=hello=")
	if err == nil {
		t.Fatal("should have failed it is not encoded")
	}
}

func TestBadClaimsEncoding(t *testing.T) {
	// the '=' will be illegal
	c := GenericClaims{}
	err := parseClaims("=hello=", &c)
	if err == nil {
		t.Fatal("should have failed it is not encoded")
	}
}

func TestBadHeaderJSON(t *testing.T) {
	payload := base64.RawStdEncoding.EncodeToString([]byte("{foo: bar}"))
	_, err := parseHeaders(payload)
	if err == nil {
		t.Fatal("should have failed bad json")
	}
}

func TestBadClaimsJSON(t *testing.T) {
	payload := base64.RawStdEncoding.EncodeToString([]byte("{foo: bar}"))
	c := GenericClaims{}
	err := parseClaims(payload, &c)
	if err == nil {
		t.Fatal("should have failed bad json")
	}
}

func TestBadPublicKeyDecodeGeneric(t *testing.T) {
	c := &GenericClaims{}
	c.Issuer = "foo"
	if ok := c.Verify("foo", []byte("bar")); ok {
		t.Fatal("Should have failed to verify")
	}
}

func TestBadSig(t *testing.T) {
	opk := createOperatorNKey(t)
	kp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(kp, t))
	claims.Data["foo"] = "bar"

	// serialize the claim to a JWT token
	token := encode(claims, opk, t)

	tokens := strings.Split(token, ".")
	badToken := fmt.Sprintf("%s.%s.=hello=", tokens[0], tokens[1])
	_, err := DecodeGeneric(badToken)
	if err == nil {
		t.Fatal("should have failed to base64  decode signature")
	}
}

func TestClaimsStringIsJSON(t *testing.T) {
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	// add a bunch of claims
	claims.Data["foo"] = "bar"

	claims2 := NewGenericClaims(publicKey(akp, t))
	json.Unmarshal([]byte(claims.String()), claims2)
	if claims2.Data["foo"] != "bar" {
		t.Fatalf("Failed to decode expected claim from String representation: %q", claims.String())
	}
}

func TestDoEncodeNilHeader(t *testing.T) {
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	_, err := claims.doEncode(nil, nil, claims)
	if err == nil {
		t.Fatal("should have failed to encode")
	}
	if err.Error() != "header is required" {
		t.Fatalf("unexpected error on encode: %v", err)
	}
}

func TestDoEncodeNilKeyPair(t *testing.T) {
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	_, err := claims.doEncode(&Header{}, nil, claims)
	if err == nil {
		t.Fatal("should have failed to encode")
	}
	if err.Error() != "keypair is required" {
		t.Fatalf("unexpected error on encode: %v", err)
	}
}
