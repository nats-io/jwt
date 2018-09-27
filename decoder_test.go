package jwt

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"encoding/base64"
	"encoding/json"
	"github.com/nats-io/nkeys"
)

func TestNewToken(t *testing.T) {
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	claims := NewGenericClaims()
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
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{"JWS", AlgorithmNkey}
	c := NewGenericClaims()
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, &c)
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
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{TokenTypeJwt, "foobar"}
	c := NewGenericClaims()
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, &c)
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
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{"JWS", AlgorithmNkey}
	c := NewGenericClaims()
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, &c)
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
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{TokenTypeJwt, AlgorithmNkey}
	c := NewGenericClaims()
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, &c)
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
	kp1, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	c1 := NewGenericClaims()
	c1.Data["foo"] = "barz"

	token1, err := c1.Encode(kp1)
	if err != nil {
		t.Fatal(err)
	}
	c1t := strings.Split(token1, ".")

	c1.Data["foo"] = "bar"

	kp2, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	token2, err := c1.Encode(kp2)
	if err != nil {
		t.Fatal(err)
	}
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
	kp1, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}
	c := NewGenericClaims()
	c.Expires = time.Now().UTC().Unix() - 100
	c.Data["foo"] = "barz"

	token, err := c.Encode(kp1)
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

	if err.Error() != "claim is expired" {
		m := fmt.Sprintf("expected expired claim: %q", err.Error())
		t.Fatal(m)
	}
}

func TestNotYetValid(t *testing.T) {
	kp1, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}
	c := NewGenericClaims()
	now := time.Now().UTC().Unix()
	c.NotBefore = now + 100
	c.Data["foo"] = "barz"

	token, err := c.Encode(kp1)
	if err != nil {
		t.Fatal(err)
	}

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
	kp1, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}
	c := NewGenericClaims()
	c.Data["foo"] = "barz"

	token, err := c.Encode(kp1)
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
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	claims := NewGenericClaims()
	// add a bunch of claims
	claims.Data["foo"] = "bar"

	// serialize the claim to a JWT token
	token, err := claims.Encode(kp)
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
	pk, err := kp.PublicKey()
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

	// Need a private key to sign the claim
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	claims := NewGenericClaims()
	// add a bunch of claims
	claims.Data["foo"] = "bar"

	// serialize the claim to a JWT token
	token, err := claims.Encode(kp)
	if err != nil {
		t.Fatal("error encoding token", err)
	}

	tokens := strings.Split(token, ".")
	badToken := fmt.Sprintf("%s.%s.=hello=", tokens[0], tokens[1])
	_, err = DecodeGeneric(badToken)
	if err == nil {
		t.Fatal("should have failed to base64  decode signature")
	}
}

func TestClaimsStringIsJSON(t *testing.T) {
	claims := NewGenericClaims()
	// add a bunch of claims
	claims.Data["foo"] = "bar"

	claims2 := NewGenericClaims()
	json.Unmarshal([]byte(claims.String()), claims2)
	if claims2.Data["foo"] != "bar" {
		t.Fatalf("Failed to decode expected claim from String representation: %q", claims.String())
	}
}

func TestDoEncodeNilHeader(t *testing.T) {
	claims := NewGenericClaims()
	_, err := claims.doEncode(nil, nil, &claims)
	if err == nil {
		t.Fatal("should have failed to encode")
	}
	if err.Error() != "header is required" {
		t.Fatalf("unexpected error on encode: %v", err)
	}
}

func TestDoEncodeNilKeyPair(t *testing.T) {
	claims := NewGenericClaims()
	_, err := claims.doEncode(&Header{}, nil, &claims)
	if err == nil {
		t.Fatal("should have failed to encode")
	}
	if err.Error() != "keypair is required" {
		t.Fatalf("unexpected error on encode: %v", err)
	}
}
