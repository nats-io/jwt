package jwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewClusterClaims(t *testing.T) {
	ckp := createClusterNKey(t)
	skp := createClusterNKey(t)

	uc := NewClusterClaims(publicKey(skp, t))
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	uJwt := encode(uc, ckp, t)

	uc2, err := DecodeClusterClaims(uJwt)
	if err != nil {
		t.Fatal("failed to decode", err)
	}

	AssertEquals(uc.String(), uc2.String(), t)

	AssertEquals(uc.Claims() != nil, true, t)
	AssertEquals(uc.Payload() != nil, true, t)
}

func TestClusterClaimsIssuer(t *testing.T) {
	ckp := createClusterNKey(t)
	skp := createClusterNKey(t)

	uc := NewClusterClaims(publicKey(skp, t))
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	uJwt := encode(uc, ckp, t)

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
		{"account", createAccountNKey(t), false},
		{"user", createUserNKey(t), false},
		{"operator", createOperatorNKey(t), true},
		{"server", createServerNKey(t), false},
		{"cluster", createClusterNKey(t), true},
	}

	for _, i := range inputs {
		bad := encode(temp, i.kp, t)
		_, err = DecodeClusterClaims(bad)
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to decode cluster signed by %q", i.name)
			t.Fail()
		}
	}
}

func TestClusterSubjects(t *testing.T) {
	type kpInputs struct {
		name string
		kp   nkeys.KeyPair
		ok   bool
	}

	inputs := []kpInputs{
		{"account", createAccountNKey(t), false},
		{"server", createServerNKey(t), false},
		{"operator", createOperatorNKey(t), false},
		{"cluster", createClusterNKey(t), true},
		{"user", createUserNKey(t), false},
	}

	for _, i := range inputs {
		c := NewClusterClaims(publicKey(i.kp, t))
		_, err := c.Encode(createOperatorNKey(t))
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to encode cluster with with %q subject", i.name)
			t.Fail()
		}
	}
}

func TestNewNilClusterClaims(t *testing.T) {
	v := NewClusterClaims("")
	if v != nil {
		t.Fatal(fmt.Sprintf("expected nil user claim"))
	}
}

func TestClusterType(t *testing.T) {
	c := NewClusterClaims(publicKey(createClusterNKey(t), t))
	s := encode(c, createClusterNKey(t), t)
	u, err := DecodeClusterClaims(s)
	if err != nil {
		t.Fatalf("failed to decode cluster claim: %v", err)
	}

	if ClusterClaim != u.Type {
		t.Fatalf("type is unexpected %q (wanted cluster)", u.Type)
	}

}
