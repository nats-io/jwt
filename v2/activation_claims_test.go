/*
 * Copyright 2018-2020 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
	activation.Expires = time.Now().Add(time.Hour).Unix()

	activation.ImportSubject = "foo"
	activation.Name = "Foo"
	activation.ImportType = Stream

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

func TestInvalidActivationTargets(t *testing.T) {
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
	ac.Expires = time.Now().Add(time.Hour).Unix()
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
		_, err = DecodeActivationClaims(bad)
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to decode account signed by %q", i.name)
			t.Fail()
		}
	}
}

func TestPublicIsNotValid(t *testing.T) {
	c := NewActivationClaims("public")
	_, err := c.Encode(createOperatorNKey(t))
	if err == nil {
		t.Fatal("should not have encoded public activation anymore")
	}
}

func TestNilActivationClaim(t *testing.T) {
	v := NewActivationClaims("")
	if v != nil {
		t.Fatal("expected nil user claim")
	}
}

func TestActivationImportSubjectValidation(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	akp2 := createAccountNKey(t)
	apk2 := publicKey(akp2, t)

	activation := NewActivationClaims(apk)
	activation.Issuer = apk
	activation.Subject = apk2

	activation.ImportSubject = "foo"
	activation.Name = "Foo"
	activation.ImportType = Stream

	vr := CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Error("valid activation should pass validation")
	}

	activation.ImportType = Service

	vr = CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Error("valid activation should pass validation")
	}

	activation.ImportSubject = "foo.*" // wildcards are ok

	vr = CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() {
		t.Error("wildcard service activation should pass validation")
	}

	activation.ImportSubject = ">" // wildcards are ok

	vr = CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() {
		t.Error("wildcard service activation should pass validation")
	}

	activation.ImportType = Stream // Stream is ok with wildcards
	vr = CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Error("valid activation should pass validation")
	}

	activation.ImportSubject = "" // empty strings are bad

	vr = CreateValidationResults()
	activation.Validate(vr)

	if vr.IsEmpty() || !vr.IsBlocking(true) {
		t.Error("empty activation should not pass validation")
	}

	activation.ImportSubject = "foo bar" // spaces are bad

	vr = CreateValidationResults()
	activation.Validate(vr)

	if vr.IsEmpty() || !vr.IsBlocking(true) {
		t.Error("spaces in activation should not pass validation")
	}
}

func TestActivationValidation(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	akp2 := createAccountNKey(t)
	apk2 := publicKey(akp2, t)

	activation := NewActivationClaims(apk)
	activation.Issuer = apk
	activation.Subject = apk2
	activation.Expires = time.Now().Add(time.Hour).Unix()

	activation.ImportSubject = "foo"
	activation.Name = "Foo"
	activation.ImportType = Stream

	vr := CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Error("valid activation should pass validation")
	}

	activation.ImportSubject = "times.*"
	activation.ImportType = Stream
	activation.Name = "times"

	vr = CreateValidationResults()
	activation.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Error("valid activation should pass validation")
	}
}

func TestActivationHashIDLimits(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	akp2 := createAccountNKey(t)
	apk2 := publicKey(akp2, t)

	activation := NewActivationClaims(apk)
	activation.Issuer = apk
	activation.Subject = apk2

	_, err := activation.HashID()
	if err == nil {
		t.Fatal("activation without subject should fail to hash")
	}

	activation.ImportSubject = "times.*"
	activation.ImportType = Stream
	activation.Name = "times"

	hash, err := activation.HashID()
	if err != nil {
		t.Fatalf("activation with subject should hash %v", err)
	}

	activation2 := NewActivationClaims(apk)
	activation2.Issuer = apk
	activation2.Subject = apk2
	activation2.ImportSubject = "times.*.bar"
	activation2.ImportType = Stream
	activation2.Name = "times"

	hash2, err := activation2.HashID()
	if err != nil {
		t.Fatalf("activation with subject should hash %v", err)
	}

	if hash != hash2 {
		t.Fatal("subjects should be stripped to create hash")
	}
}

func TestActivationClaimAccountIDValidation(t *testing.T) {
	issuerAccountKP := createAccountNKey(t)
	issuerAccountPK := publicKey(issuerAccountKP, t)

	issuerKP := createAccountNKey(t)
	issuerPK := publicKey(issuerKP, t)

	account := NewAccountClaims(issuerAccountPK)
	account.SigningKeys.Add(issuerPK)
	token, err := account.Encode(issuerAccountKP)
	if err != nil {
		t.Fatal(err)
	}
	account, err = DecodeAccountClaims(token)
	if err != nil {
		t.Fatal(err)
	}

	importerKP := createAccountNKey(t)
	importerPK := publicKey(importerKP, t)

	ac := NewActivationClaims(importerPK)
	ac.IssuerAccount = issuerAccountPK
	ac.Name = "foo.bar"
	ac.Activation.ImportSubject = "foo.bar"
	ac.Activation.ImportType = Stream

	var vr ValidationResults
	ac.Validate(&vr)
	if len(vr.Issues) != 0 {
		t.Fatalf("expected no validation errors: %v", vr.Issues[0].Error())
	}
	token, err = ac.Encode(issuerKP)
	if err != nil {
		t.Fatal(err)
	}
	ac, err = DecodeActivationClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if ac.Issuer != issuerPK {
		t.Fatal("expected activation subject to be different")
	}
	if ac.IssuerAccount != issuerAccountPK {
		t.Fatal("expected activation account id to be different")
	}

	ac.IssuerAccount = publicKey(createUserNKey(t), t)
	ac.Validate(&vr)
	if len(vr.Issues) != 1 {
		t.Fatal("expected validation error")
	}

	if !account.DidSign(ac) {
		t.Fatal("expected account to have signed activation")
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

func TestActivationClaimRevocation(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	account := NewAccountClaims(apk)
	e := &Export{Subject: "q.>", Type: Service, TokenReq: true}
	account.Exports.Add(e)

	a := publicKey(createAccountNKey(t), t)
	aminAgo := time.Now().Add(-time.Minute)

	if account.Exports[0].Revocations.IsRevoked(a, aminAgo) {
		t.Fatal("should not be revoked")
	}
	e.RevokeAt(a, aminAgo)
	if !account.Exports[0].Revocations.IsRevoked(a, aminAgo) {
		t.Fatal("should be revoked")
	}

	a2 := publicKey(createAccountNKey(t), t)
	if account.Exports[0].Revocations.IsRevoked(a2, aminAgo) {
		t.Fatal("should not be revoked")
	}
	e.RevokeAt("*", aminAgo)
	if !account.Exports[0].Revocations.IsRevoked(a2, time.Now().Add(-time.Hour)) {
		t.Fatal("should be revoked")
	}

	vr := ValidationResults{}
	account.Validate(&vr)
	if !vr.IsEmpty() {
		t.Fatal("account validation shouldn't have failed")
	}
}
