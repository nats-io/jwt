package jwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewAccountClaims(t *testing.T) {
	akp := createAccountNKey(t)
	akp2 := createAccountNKey(t)
	apk := publicKey(akp, t)
	apk2 := publicKey(akp2, t)

	activation := NewActivationClaims(apk)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.Exports = Exports{}
	activation.Exports.Add(
		&Export{
			NamedSubject: NamedSubject{
				Subject: "test",
			},
			Type: StreamType,
		})
	actJWT := encode(activation, akp2, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).UTC().Unix()
	account.Imports = Imports{}
	account.Imports.Add(
		&Import{
			NamedSubject: NamedSubject{
				Subject: "test",
				Name:    "test import",
			},
			Account: apk2,
			Token:   actJWT,
			To:      "my",
			Type:    StreamType,
		})

	actJwt := encode(account, akp, t)

	account2, err := DecodeAccountClaims(actJwt)
	if err != nil {
		t.Fatal("error decoding account jwt", err)
	}

	AssertEquals(account.String(), account2.String(), t)
}

func TestAccountCantSignOperatorLimits(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.OperatorLimits.Conn = 1

	_, err := account.Encode(akp)
	if err == nil {
		t.Fatal("account should not be able to encode operator limits", err)
	}
}

func TestAccountCantSignIdentities(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.Identities = []Identity{
		{
			ID:    "stephen",
			Proof: "yougotit",
		},
	}

	_, err := account.Encode(akp)
	if err == nil {
		t.Fatal("account should not be able to encode identities", err)
	}
}

func TestOperatorCanSignClaims(t *testing.T) {
	akp := createAccountNKey(t)
	okp := createOperatorNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.OperatorLimits.Conn = 1
	account.Identities = []Identity{
		{
			ID:    "stephen",
			Proof: "yougotit",
		},
	}

	actJwt := encode(account, okp, t)

	account2, err := DecodeAccountClaims(actJwt)
	if err != nil {
		t.Fatal("error decoding account jwt", err)
	}

	AssertEquals(account.String(), account2.String(), t)
}

func TestInvalidAccountClaimIssuer(t *testing.T) {
	akp := createAccountNKey(t)
	ac := NewAccountClaims(publicKey(akp, t))
	ac.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	aJwt := encode(ac, akp, t)

	temp, err := DecodeGeneric(aJwt)
	if err != nil {
		t.Fatal("failed to decode", err)
	}

	type kpInputs struct {
		name string
		kp   nkeys.KeyPair
		ok   bool
	}

	inputs := []kpInputs{
		{"account", createAccountNKey(t), true},
		{"user", createUserNKey(t), false},
		{"operator", createOperatorNKey(t), true},
		{"server", createServerNKey(t), false},
		{"cluster", createClusterNKey(t), false},
	}

	for _, i := range inputs {
		bad := encode(temp, i.kp, t)
		_, err = DecodeAccountClaims(bad)
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to decode account signed by %q", i.name)
			t.Fail()
		}
	}
}

func TestInvalidAccountSubjects(t *testing.T) {
	type kpInputs struct {
		name string
		kp   nkeys.KeyPair
		ok   bool
	}

	inputs := []kpInputs{
		{"account", createAccountNKey(t), true},
		{"user", createUserNKey(t), false},
		{"operator", createOperatorNKey(t), false},
		{"server", createServerNKey(t), false},
		{"cluster", createClusterNKey(t), false},
	}

	for _, i := range inputs {
		pk := publicKey(i.kp, t)
		var err error

		c := NewAccountClaims(pk)
		if i.ok && err != nil {
			t.Fatalf("error encoding activation: %v", err)
		}
		_, err = c.Encode(i.kp)
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to encode account with with %q subject", i.name)
			t.Fail()
		}
	}
}

func TestAccountImports(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()

	actJwt := encode(account, akp, t)

	account2, err := DecodeAccountClaims(actJwt)
	if err != nil {
		t.Fatal("error decoding account jwt", err)
	}

	AssertEquals(account.String(), account2.String(), t)
}

func TestNewNilAccountClaim(t *testing.T) {
	v := NewAccountClaims("")
	if v != nil {
		t.Fatal(fmt.Sprintf("expected nil account claim"))
	}
}
