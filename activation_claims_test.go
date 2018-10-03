package jwt

import (
	"fmt"
	"github.com/nats-io/nkeys"
	"testing"
	"time"
)

func TestNewActivationClaims(t *testing.T) {
	okp := createOperatorNKey(t)
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	activation := NewActivationClaims(apk)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()

	actJwt := encode(activation, okp, t)

	activation2, err := DecodeActivationClaims(actJwt)
	if err != nil {
		t.Fatal("failed to decode activation", err)
	}

	AssertEquals(activation.String(), activation2.String(), t)
}

func TestInvalidActivationSubjects(t *testing.T) {
	type kpInputs struct {
		name string
		kp   nkeys.KeyPair
		ok   bool
	}

	inputs := []kpInputs{
		{"account", createAccountNKey(t), true},
		{"cluster", createClusterNKey(t), false},
		{"operator", createOperatorNKey(t), false},
		{"server", createServerNKey(t), false},
		{"user", createUserNKey(t), false},
	}

	for _, i := range inputs {
		c := NewActivationClaims(publicKey(i.kp, t))
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

func TestPublicIsValidSubject(t *testing.T) {
	c := NewActivationClaims("public")
	_, err := c.Encode(createOperatorNKey(t))
	if err != nil {
		t.Fatal("should have encoded public activation")
	}
}

func TestNilActivationClaim(t *testing.T) {
	v := NewActivationClaims("")
	if v != nil {
		t.Fatal(fmt.Sprintf("expected nil user claim"))
	}
}
