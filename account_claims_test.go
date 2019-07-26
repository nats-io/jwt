/*
 * Copyright 2018 The NATS Authors
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

func TestNewAccountClaims(t *testing.T) {
	akp := createAccountNKey(t)
	akp2 := createAccountNKey(t)
	apk := publicKey(akp, t)
	apk2 := publicKey(akp2, t)

	activation := NewActivationClaims(apk)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.ImportSubject = "test"
	activation.ImportType = Stream
	actJWT := encode(activation, akp2, t)

	account := NewAccountClaims(apk)
	if !account.Limits.IsUnlimited() {
		t.Fatalf("Expected unlimited operator limits")
	}

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

func TestAccountCanSignOperatorLimits(t *testing.T) { // don't block encoding!!!
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.Limits.Conn = 10
	account.Limits.LeafNodeConn = 2

	_, err := account.Encode(akp)
	if err != nil {
		t.Fatal("account should not be able to encode operator limits", err)
	}
}

func TestAccountCanSignIdentities(t *testing.T) { // don't block encoding!!!
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
	if err != nil {
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
	account.Limits.LeafNodeConn = 4

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

	if account2.Limits.Conn != 1 {
		t.Fatalf("Expected Limits.Conn == 1, got %d", account2.Limits.Conn)
	}
	if account2.Limits.LeafNodeConn != 4 {
		t.Fatalf("Expected Limits.Conn == 4, got %d", account2.Limits.LeafNodeConn)
	}
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
	account.Limits.WildcardExports = true
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

	if vr.IsEmpty() || vr.IsBlocking(true) {
		t.Fatal("bad issuer for limits should have non-blocking validation results")
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

	if vr.IsEmpty() || vr.IsBlocking(true) {
		t.Fatal("bad issuer for identities should have non-blocking validation results")
	}

	account.Identities = nil
	account.Issuer = apk
	vr = CreateValidationResults()
	account.Validate(vr)

	if !vr.IsEmpty() || vr.IsBlocking(true) {
		t.Fatal("account can encode without limits and identity")
	}
}

func TestWildcardExportLimit(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.Limits.Conn = 10
	account.Limits.Imports = 10
	account.Limits.Exports = 10
	account.Limits.WildcardExports = true
	account.Exports = Exports{
		&Export{Subject: "foo", Type: Stream},
		&Export{Subject: "bar.*", Type: Stream},
	}

	vr := CreateValidationResults()
	account.Validate(vr)

	if !vr.IsEmpty() {
		t.Fatal("valid account should have no validation issues")
	}

	account.Limits.WildcardExports = false
	vr = CreateValidationResults()
	account.Validate(vr)

	if vr.IsEmpty() || !vr.IsBlocking(true) {
		t.Fatal("invalid account should have validation issues")
	}

	account.Limits.WildcardExports = true
	account.Limits.Exports = 1
	vr = CreateValidationResults()
	account.Validate(vr)

	if vr.IsEmpty() || !vr.IsBlocking(true) {
		t.Fatal("invalid account should have validation issues")
	}
}

func TestAccountSigningKeyValidation(t *testing.T) {
	okp := createOperatorNKey(t)

	akp1 := createAccountNKey(t)
	apk1 := publicKey(akp1, t)
	akp2 := createAccountNKey(t)
	apk2 := publicKey(akp2, t)

	ac := NewAccountClaims(apk1)
	ac.SigningKeys.Add(apk2)

	var vr ValidationResults
	ac.Validate(&vr)
	if len(vr.Issues) != 0 {
		t.Fatal("expected no validation issues")
	}

	// try encoding/decoding
	token, err := ac.Encode(okp)
	if err != nil {
		t.Fatal(err)
	}
	ac2, err := DecodeAccountClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(ac2.SigningKeys) != 1 {
		t.Fatal("expected claim to have a signing key")
	}
	if ac.SigningKeys[0] != apk2 {
		t.Fatalf("expected signing key to be %s - got %s", apk2, ac.SigningKeys[0])
	}

	bkp := createUserNKey(t)
	ac.SigningKeys.Add(publicKey(bkp, t))
	ac.Validate(&vr)
	if len(vr.Issues) != 1 {
		t.Fatal("expected 1 validation issue")
	}
}

func TestAccountSignedBy(t *testing.T) {
	okp := createOperatorNKey(t)

	akp1 := createAccountNKey(t)
	apk1 := publicKey(akp1, t)
	akp2 := createAccountNKey(t)
	apk2 := publicKey(akp2, t)

	ac := NewAccountClaims(apk1)
	ac.SigningKeys.Add(apk2)

	token, err := ac.Encode(okp)
	if err != nil {
		t.Fatal(err)
	}
	ac2, err := DecodeAccountClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(ac2.SigningKeys) != 1 {
		t.Fatal("expected claim to have a signing key")
	}
	if ac.SigningKeys[0] != apk2 {
		t.Fatalf("expected signing key to be %s - got %s", apk2, ac.SigningKeys[0])
	}

	ukp := createUserNKey(t)
	upk := publicKey(ukp, t)

	// claim signed by alternate key
	uc := NewUserClaims(upk)
	utoken, err := uc.Encode(akp2)
	if err != nil {
		t.Fatal(err)
	}

	uc2, err := DecodeUserClaims(utoken)
	if err != nil {
		t.Fatal(err)
	}
	if !ac2.DidSign(uc2) {
		t.Fatal("failed to verify user claim")
	}

	// claim signed by the account pk
	uc3 := NewUserClaims(upk)
	utoken2, err := uc3.Encode(akp1)
	if err != nil {
		t.Fatal(err)
	}
	uc4, err := DecodeUserClaims(utoken2)
	if err != nil {
		t.Fatal(err)
	}
	if !ac2.DidSign(uc4) {
		t.Fatal("failed to verify user claim")
	}
}

func TestAddRemoveSigningKey(t *testing.T) {
	akp1 := createAccountNKey(t)
	apk1 := publicKey(akp1, t)
	akp2 := createAccountNKey(t)
	apk2 := publicKey(akp2, t)
	akp3 := createAccountNKey(t)
	apk3 := publicKey(akp3, t)

	ac := NewAccountClaims(apk1)
	ac.SigningKeys.Add(apk2, apk3)

	if len(ac.SigningKeys) != 2 {
		t.Fatal("expected 2 signing keys")
	}

	ac.SigningKeys.Remove(publicKey(createAccountNKey(t), t))
	if len(ac.SigningKeys) != 2 {
		t.Fatal("expected 2 signing keys")
	}

	ac.SigningKeys.Remove(apk2)
	if len(ac.SigningKeys) != 1 {
		t.Fatal("expected single signing keys")
	}
}

func TestUserRevocation(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	account := NewAccountClaims(apk)

	pubKey := "bar"
	now := time.Now()

	// test that clear is safe before we add any
	account.ClearRevocation(pubKey)

	if account.IsRevokedAt(pubKey, now) {
		t.Errorf("no revocation was added so is revoked should be false")
	}

	account.RevokeAt(pubKey, now.Add(time.Second*100))

	if !account.IsRevokedAt(pubKey, now) {
		t.Errorf("revocation should hold when timestamp is in the future")
	}

	if account.IsRevokedAt(pubKey, now.Add(time.Second*150)) {
		t.Errorf("revocation should time out")
	}

	account.RevokeAt(pubKey, now.Add(time.Second*50)) // shouldn't change the revocation, you can't move it in

	if !account.IsRevokedAt(pubKey, now.Add(time.Second*60)) {
		t.Errorf("revocation should hold, 100 > 50")
	}

	encoded, _ := account.Encode(akp)
	decoded, _ := DecodeAccountClaims(encoded)

	if !decoded.IsRevokedAt(pubKey, now.Add(time.Second*60)) {
		t.Errorf("revocation should last across encoding")
	}

	account.ClearRevocation(pubKey)

	if account.IsRevokedAt(pubKey, now) {
		t.Errorf("revocations should be cleared")
	}

	account.RevokeAt(pubKey, now.Add(time.Second*1000))

	if !account.IsRevoked(pubKey) {
		t.Errorf("revocation be true we revoked in the future")
	}
}
