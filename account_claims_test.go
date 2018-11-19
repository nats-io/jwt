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
	activation.Exports.Add(&Export{Subject: "test", Type: Stream})
	actJWT := encode(activation, akp2, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).UTC().Unix()
	account.Imports = Imports{}
	account.Imports.Add(&Import{Subject: "test", Name: "test import", Account: apk2, Token: actJWT, To: "my", Type: Stream})

	vr := CreateValidationResults()
	account.Validate(vr)

	if !vr.IsEmpty() {
		t.Fatal("Valid account will have no validation results")
	}

	actJwt := encode(account, akp, t)

	account2, err := DecodeAccountClaims(actJwt)
	if err != nil {
		t.Fatal("error decoding account jwt", err)
	}

	AssertEquals(account.String(), account2.String(), t)
	AssertEquals(account2.IsSelfSigned(), true, t)

	AssertEquals(account2.Claims() != nil, true, t)
	AssertEquals(account2.Payload() != nil, true, t)
}

func TestAccountCantSignOperatorLimits(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.Limits.Conn = 1

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
	account.Limits.Conn = 1
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
	AssertEquals(account2.IsSelfSigned(), false, t)
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

func TestLimitValidationInAccount(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.Limits.Conn = 10
	account.Limits.Imports = 10
	account.Limits.Exports = 10
	account.Limits.Data = 1024
	account.Limits.Payload = 1024
	account.Limits.Subs = 10
	account.Identities = []Identity{
		{
			ID:    "stephen",
			Proof: "yougotit",
		},
	}

	vr := CreateValidationResults()
	account.Validate(vr)

	if len(vr.Issues) != 0 {
		t.Fatal("valid account should have no validation issues")
	}

	account.Limits.Conn = -1
	account.Limits.Imports = -1
	account.Limits.Exports = -1
	account.Limits.Subs = -1
	account.Limits.Data = -1
	account.Limits.Payload = -1
	vr = CreateValidationResults()
	account.Validate(vr)

	if len(vr.Issues) != 0 {
		t.Fatal("valid account should have no validation issues")
	}

	op := createOperatorNKey(t)
	opk := publicKey(op, t)
	account.Issuer = opk

	vr = CreateValidationResults()
	account.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Fatal("operator can encode limits and identity")
	}

	account.Identities = nil
	account.Issuer = apk
	vr = CreateValidationResults()
	account.Validate(vr)

	if len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Fatal("bad issuer should be blocking")
	}

	account.Identities = []Identity{
		{
			ID:    "stephen",
			Proof: "yougotit",
		},
	}
	account.Limits = OperatorLimits{}
	account.Issuer = apk
	vr = CreateValidationResults()
	account.Validate(vr)

	if len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Fatal("bad issuer should be blocking")
	}

	account.Identities = nil
	account.Issuer = apk
	vr = CreateValidationResults()
	account.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Fatal("account can encode without limits and identity")
	}
}
