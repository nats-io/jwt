package jwt

import (
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewActivationClaims(t *testing.T) {
	okp := createOperatorNKey(t)
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	activation := NewActivationClaims(apk)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	activation.Limits.Max = 10
	activation.Limits.Payload = 10
	activation.Limits.Src = "255.255.255.0"

	vr := CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Error("valid activation should pass validation")
	}

	actJwt := encode(activation, okp, t)

	activation2, err := DecodeActivationClaims(actJwt)
	if err != nil {
		t.Fatal("failed to decode activation", err)
	}

	AssertEquals(activation.String(), activation2.String(), t)

	AssertEquals(activation.Claims() != nil, true, t)
	AssertEquals(activation.Payload() != nil, true, t)
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

func TestInvalidActivationClaimIssuer(t *testing.T) {
	akp := createAccountNKey(t)
	ac := NewActivationClaims(publicKey(akp, t))
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

func TestActivationValidation(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	activation := NewActivationClaims(apk)
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	activation.Limits.Max = 10
	activation.Limits.Payload = 10
	activation.Limits.Src = "1.1.1.1"
	activation.Limits.Times = []TimeRange{
		{
			Start: "01:15:00",
			End:   "03:15:00",
		},
		{
			Start: "06:15:00",
			End:   "09:15:00",
		},
	}

	vr := CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Error("valid activation should pass validation")
	}

	activation.Limits.Max = -1
	vr = CreateValidationResults()
	activation.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad limit should be invalid")
	}

	activation.Limits.Max = 10
	activation.Limits.Payload = -1
	vr = CreateValidationResults()
	activation.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad limit should be invalid")
	}

	activation.Limits.Payload = 10
	activation.Limits.Src = "hello world"
	vr = CreateValidationResults()
	activation.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad limit should be invalid")
	}

	activation.Limits.Payload = 10
	activation.Limits.Src = "hello world"
	vr = CreateValidationResults()
	activation.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad limit should be invalid")
	}

	tr := TimeRange{
		Start: "hello",
		End:   "03:15:00",
	}
	activation.Limits.Src = "1.1.1.1"
	activation.Limits.Times = append(activation.Limits.Times, tr)
	vr = CreateValidationResults()
	activation.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad limit should be invalid")
	}
}

func TestCleanSubject(t *testing.T) {
	input := [][]string{
		{"foo", "foo"},
		{"*", "_"},
		{">", "_"},
		{"foo.*", "foo"},
		{"foo.bar.>", "foo.bar"},
		{"foo.*.bar", "foo"},
		{"bam.boom.blat.*", "bam.boom.blat"},
		{"*.blam", "_"},
	}

	for _, pair := range input {
		clean := cleanSubject(pair[0])
		if pair[1] != clean {
			t.Errorf("Expected %s but got %s", pair[1], clean)
		}
	}
}
