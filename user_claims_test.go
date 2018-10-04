package jwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewUserClaims(t *testing.T) {
	akp := createAccountNKey(t)
	ukp := createUserNKey(t)

	uc := NewUserClaims(publicKey(ukp, t))
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	uJwt := encode(uc, akp, t)

	uc2, err := DecodeUserClaims(uJwt)
	if err != nil {
		t.Fatal("failed to decode activation", err)
	}

	AssertEquals(uc.String(), uc2.String(), t)
}

func TestUserClaimIssuer(t *testing.T) {
	akp := createAccountNKey(t)
	ukp := createUserNKey(t)

	uc := NewUserClaims(publicKey(ukp, t))
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	uJwt := encode(uc, akp, t)

	temp, err := DecodeGeneric(uJwt)
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
		{"operator", createOperatorNKey(t), false},
		{"server", createServerNKey(t), false},
		{"cluster", createClusterNKey(t), false},
	}

	for _, i := range inputs {
		bad := encode(temp, i.kp, t)
		_, err = DecodeUserClaims(bad)
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to decode user signed by %q", i.name)
			t.Fail()
		}
	}
}

func TestUserSubjects(t *testing.T) {
	type kpInputs struct {
		name string
		kp   nkeys.KeyPair
		ok   bool
	}

	inputs := []kpInputs{
		{"account", createAccountNKey(t), false},
		{"cluster", createClusterNKey(t), false},
		{"operator", createOperatorNKey(t), false},
		{"server", createServerNKey(t), false},
		{"user", createUserNKey(t), true},
	}

	for _, i := range inputs {
		c := NewUserClaims(publicKey(i.kp, t))
		_, err := c.Encode(createOperatorNKey(t))
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to encode user with with %q subject", i.name)
			t.Fail()
		}
	}
}

func TestNewNilUserClaim(t *testing.T) {
	v := NewUserClaims("")
	if v != nil {
		t.Fatal(fmt.Sprintf("expected nil user claim"))
	}
}

func TestUserType(t *testing.T) {
	c := NewUserClaims(publicKey(createUserNKey(t), t))
	s := encode(c, createAccountNKey(t), t)
	u, err := DecodeUserClaims(s)
	if err != nil {
		t.Fatalf("failed to decode user claim: %v", err)
	}

	if UserClaim != u.Type {
		t.Fatalf("user type is unexpected %q", u.Type)
	}

}
