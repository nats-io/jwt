package jwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewOperatorClaims(t *testing.T) {
	ckp := createOperatorNKey(t)

	uc := NewOperatorClaims(publicKey(ckp, t))
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	uJwt := encode(uc, ckp, t)

	uc2, err := DecodeOperatorClaims(uJwt)
	if err != nil {
		t.Fatal("failed to decode", err)
	}

	AssertEquals(uc.String(), uc2.String(), t)

	AssertEquals(uc.Claims() != nil, true, t)
	AssertEquals(uc.Payload() != nil, true, t)
}

func TestOperatorSubjects(t *testing.T) {
	type kpInputs struct {
		name string
		kp   nkeys.KeyPair
		ok   bool
	}

	inputs := []kpInputs{
		{"account", createAccountNKey(t), false},
		{"cluster", createClusterNKey(t), false},
		{"operator", createOperatorNKey(t), true},
		{"server", createServerNKey(t), false},
		{"user", createUserNKey(t), false},
	}

	for _, i := range inputs {
		c := NewOperatorClaims(publicKey(i.kp, t))
		_, err := c.Encode(createOperatorNKey(t))
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to encode server with with %q subject", i.name)
			t.Fail()
		}
	}
}

func TestInvalidOperatorClaimIssuer(t *testing.T) {
	akp := createOperatorNKey(t)
	ac := NewOperatorClaims(publicKey(akp, t))
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
		{"account", createAccountNKey(t), false},
		{"user", createUserNKey(t), false},
		{"operator", createOperatorNKey(t), true},
		{"server", createServerNKey(t), false},
		{"cluster", createClusterNKey(t), false},
	}

	for _, i := range inputs {
		bad := encode(temp, i.kp, t)
		_, err = DecodeOperatorClaims(bad)
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to decode account signed by %q", i.name)
			t.Fail()
		}
	}
}

func TestNewNilOperatorClaims(t *testing.T) {
	v := NewOperatorClaims("")
	if v != nil {
		t.Fatal(fmt.Sprintf("expected nil user claim"))
	}
}

func TestOperatorType(t *testing.T) {
	c := NewOperatorClaims(publicKey(createOperatorNKey(t), t))
	s := encode(c, createOperatorNKey(t), t)
	u, err := DecodeOperatorClaims(s)
	if err != nil {
		t.Fatalf("failed to decode operator claim: %v", err)
	}

	if OperatorClaim != u.Type {
		t.Fatalf("type is unexpected %q (wanted operator)", u.Type)
	}

}

func TestSigningKeyValidation(t *testing.T) {
	ckp := createOperatorNKey(t)
	ckp2 := createOperatorNKey(t)

	uc := NewOperatorClaims(publicKey(ckp, t))
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	uc.AddSigningKey(publicKey(ckp2, t))
	uJwt := encode(uc, ckp, t)

	uc2, err := DecodeOperatorClaims(uJwt)
	if err != nil {
		t.Fatal("failed to decode", err)
	}

	AssertEquals(len(uc2.SigningKeys), 1, t)
	AssertEquals(uc2.SigningKeys[0] == publicKey(ckp2, t), true, t)

	vr := &ValidationResults{}
	uc.Validate(vr)

	if len(vr.Issues) != 0 {
		t.Fatal("valid operator key should have no validation issues")
	}

	uc.AddSigningKey("") // add an invalid one

	vr = &ValidationResults{}
	uc.Validate(vr)
	if len(vr.Issues) == 0 {
		t.Fatal("bad signing key should be invalid")
	}
}
