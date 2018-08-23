package jwt

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewToken(t *testing.T) {
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}

	claims := NewClaims()
	claims.Nats["foo"] = "bar"

	token, err := claims.Encode(kp)
	if err != nil {
		t.Error("error encoding token", err)
	}

	c, err := Decode(token)
	if err != nil {
		t.Error(err)
	}

	if claims.NotBefore != c.NotBefore {
		t.Error("notbefore don't match")
	}

	if claims.Issuer != c.Issuer {
		t.Error("notbefore don't match")
	}

	if !reflect.DeepEqual(claims.Nats, c.Nats) {
		t.Error("nats sections don't match")
	}
}

func TestBadType(t *testing.T) {
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}

	h := Header{"JWS", AlgorithmNkey}
	c := NewClaims()
	c.Nats["foo"] = "bar"

	token, err := c.doEncode(&h, kp)
	if err != nil {
		t.Error(err)
	}

	claim, err := Decode(token)
	if claim != nil {
		t.Error("non nil claim on bad token")
	}

	if err == nil {
		t.Error("nil error on bad token")
	}

	if err.Error() != fmt.Sprintf("not supported type %q", "JWS") {
		t.Error("expected not supported type error")
	}
}

func TestBadAlgo(t *testing.T) {
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}

	h := Header{TokenTypeJwt, "foobar"}
	c := NewClaims()
	c.Nats["foo"] = "bar"

	token, err := c.doEncode(&h, kp)
	if err != nil {
		t.Error(err)
	}

	claim, err := Decode(token)
	if claim != nil {
		t.Error("non nil claim on bad token")
	}

	if err == nil {
		t.Error("nil error on bad token")
	}

	if err.Error() != fmt.Sprintf("unexpected %q algorithm", "foobar") {
		t.Error("expected unexpected algorithm")
	}
}

func TestBadSignature(t *testing.T) {
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}

	h := Header{TokenTypeJwt, AlgorithmNkey}
	c := NewClaims()
	c.Nats["foo"] = "bar"

	token, err := c.doEncode(&h, kp)
	if err != nil {
		t.Error(err)
	}

	token = token + "A"

	claim, err := Decode(token)
	if claim != nil {
		t.Error("non nil claim on bad token")
	}

	if err == nil {
		t.Error("nil error on bad token")
	}

	if err.Error() != "claim failed signature verification" {
		m := fmt.Sprintf("expected failed signature: %q", err.Error())
		t.Error(m)
	}
}

func TestDifferentPayload(t *testing.T) {
	kp1, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}

	c1 := NewClaims()
	c1.Nats["foo"] = "barz"

	token1, err := c1.Encode(kp1)
	if err != nil {
		t.Error(err)
	}
	c1t := strings.Split(token1, ".")

	c1.Nats["foo"] = "bar"

	kp2, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}

	token2, err := c1.Encode(kp2)
	if err != nil {
		t.Error(err)
	}
	c2t := strings.Split(token2, ".")

	c1t[1] = c2t[1]

	claim, err := Decode(fmt.Sprintf("%s.%s.%s", c1t[0], c1t[1], c1t[2]))
	if claim != nil {
		t.Error("non nil claim on bad token")
	}

	if err == nil {
		t.Error("nil error on bad token")
	}

	if err.Error() != "claim failed signature verification" {
		m := fmt.Sprintf("expected failed signature: %q", err.Error())
		t.Error(m)
	}
}

func TestExpiredToken(t *testing.T) {
	kp1, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}
	c := NewClaims()
	c.Expires = time.Now().UTC().Unix() - 100
	c.Nats["foo"] = "barz"

	token, err := c.Encode(kp1)
	if err != nil {
		t.Error(err)
	}

	claim, err := Decode(token)
	if claim != nil {
		t.Error("non nil claim on bad token")
	}

	if err == nil {
		t.Error("nil error on bad token")
	}

	if err.Error() != "claim is expired" {
		m := fmt.Sprintf("expected expired claim: %q", err.Error())
		t.Error(m)
	}
}

func TestNotYetValid(t *testing.T) {
	kp1, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}
	c := NewClaims()
	now := time.Now().UTC().Unix()
	c.NotBefore = now + 100
	c.Nats["foo"] = "barz"

	token, err := c.Encode(kp1)
	if err != nil {
		t.Error(err)
	}

	claim, err := Decode(token)
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
		t.Error("unable to create account key", err)
	}
	c := NewClaims()
	c.Nats["foo"] = "barz"

	token, err := c.Encode(kp1)
	if err != nil {
		t.Error(err)
	}

	claim, err := Decode(token)
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

	claims := NewClaims()
	// add a bunch of claims
	claims.Nats["foo"] = "bar"

	// serialize the claim to a JWT token
	token, err := claims.Encode(kp)
	if err != nil {
		t.Fatal("error encoding token", err)
	}

	// on the receiving side, decode the token
	c, err := Decode(token)
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