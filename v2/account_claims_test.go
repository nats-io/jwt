/*
 * Copyright 2018-2024 The NATS Authors
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
	"strings"
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
	activation.Expires = time.Now().Add(time.Hour).UTC().Unix()
	activation.ImportSubject = "test"
	activation.ImportType = Stream
	actJWT := encode(activation, akp2, t)

	account := NewAccountClaims(apk)
	if !account.Limits.NatsLimits.IsUnlimited() {
		t.Fatalf("Expected unlimited nats operator limits")
	}
	if !account.Limits.AccountLimits.IsUnlimited() {
		t.Fatalf("Expected unlimited account operator limits")
	}
	if account.Limits.JetStreamLimits.DiskStorage != 0 ||
		account.Limits.JetStreamLimits.MemoryStorage != 0 ||
		account.Limits.JetStreamLimits.Consumer != 0 ||
		account.Limits.JetStreamLimits.Streams != 0 {
		t.Fatalf("Expected unlimited operator limits")
	}

	account.Expires = time.Now().Add(time.Hour * 24 * 365).UTC().Unix()

	account.InfoURL = "http://localhost/my-account/doc"
	account.Description = "my account"
	account.Imports = Imports{}
	account.Imports.Add(&Import{Subject: "test", Name: "test import", Account: apk2, Token: actJWT, LocalSubject: "my", Type: Stream})

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
	AssertEquals(account.InfoURL, account2.InfoURL, t)
	AssertEquals(account.Description, account2.Description, t)
}

func TestAccountCanSignOperatorLimits(t *testing.T) { // don't block encoding!!!
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Hour * 24 * 365).Unix()
	account.Limits.Conn = 10
	account.Limits.LeafNodeConn = 2

	_, err := account.Encode(akp)
	if err != nil {
		t.Fatal("account should not be able to encode operator limits", err)
	}
}

func TestOperatorCanSignClaims(t *testing.T) {
	akp := createAccountNKey(t)
	okp := createOperatorNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Hour * 24 * 365).Unix()
	account.Limits.Conn = 1
	account.Limits.LeafNodeConn = 4

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
		_, err = DecodeAccountClaims(bad)
		if i.ok && err != nil {
			t.Fatalf("unexpected error for %q: %v", i.name, err)
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
		_, err = c.Encode(i.kp)
		if i.ok && err != nil {
			t.Fatalf("unexpected error for %q: %v", i.name, err)
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
	account.Expires = time.Now().Add(time.Hour * 24 * 365).Unix()

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
		t.Fatal("expected nil account claim")
	}
}

func TestLimitValidationInAccount(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Hour * 24 * 365).Unix()
	account.Limits.Conn = 10
	account.Limits.Imports = 10
	account.Limits.Exports = 10
	account.Limits.Data = 1024
	account.Limits.Payload = 1024
	account.Limits.Subs = 10
	account.Limits.WildcardExports = true

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

	account.Issuer = apk
	vr = CreateValidationResults()
	account.Validate(vr)

	if vr.IsEmpty() || vr.IsBlocking(true) {
		t.Fatal("bad issuer for limits should have non-blocking validation results")
	}
}

func TestWildcardExportLimit(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Expires = time.Now().Add(time.Hour * 24 * 365).Unix()
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

func TestJetstreamLimits(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	acc1 := NewAccountClaims(apk)
	if acc1.Limits.JetStreamLimits.DiskStorage != 0 ||
		acc1.Limits.JetStreamLimits.MemoryStorage != 0 ||
		acc1.Limits.JetStreamLimits.Consumer != 0 ||
		acc1.Limits.JetStreamLimits.Streams != 0 ||
		acc1.Limits.JetStreamLimits.MaxBytesRequired != false ||
		acc1.Limits.JetStreamLimits.MemoryMaxStreamBytes != 0 ||
		acc1.Limits.JetStreamLimits.DiskMaxStreamBytes != 0 ||
		acc1.Limits.JetStreamLimits.MaxAckPending != 0 {
		t.Fatalf("Expected unlimited operator limits")
	}
	acc1.Limits.Consumer = 1
	acc1.Limits.Streams = 2
	acc1.Limits.MemoryStorage = 3
	acc1.Limits.DiskStorage = 4
	acc1.Limits.MemoryMaxStreamBytes = 1000
	acc1.Limits.DiskMaxStreamBytes = 1000
	acc1.Limits.MaxBytesRequired = true
	acc1.Limits.MaxAckPending = 200
	vr := CreateValidationResults()
	acc1.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("valid account should have no validation issues")
	}
	if token, err := acc1.Encode(akp); err != nil {
		t.Fatal("valid account should have no validation issues")
	} else if acc2, err := DecodeAccountClaims(token); err != nil {
		t.Fatal("valid account should have no validation issues")
	} else if acc1.Limits.JetStreamLimits != acc2.Limits.JetStreamLimits {
		t.Fatal("account should have same properties")
	}
}

func TestTieredLimits(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	acc1 := NewAccountClaims(apk)
	l := JetStreamLimits{
		MemoryStorage:    1024,
		DiskStorage:      1024,
		Streams:          1,
		Consumer:         1,
		MaxBytesRequired: true,
	}
	acc1.Limits.JetStreamTieredLimits["R1"] = l
	l.Streams = 2 // minor change so both tiers differ
	acc1.Limits.JetStreamTieredLimits["R3"] = l

	vr := CreateValidationResults()
	acc1.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("valid account should have validation issues")
	}

	if token, err := acc1.Encode(akp); err != nil {
		t.Fatal("valid account should have no validation issues")
	} else if acc2, err := DecodeAccountClaims(token); err != nil {
		t.Fatal("valid account should have no validation issues")
	} else if acc1.Limits.JetStreamTieredLimits["R1"] != acc2.Limits.JetStreamTieredLimits["R1"] {
		t.Fatal("tier R1 should have same limits")
	} else if acc1.Limits.JetStreamTieredLimits["R3"] != acc2.Limits.JetStreamTieredLimits["R3"] {
		t.Fatal("tier R2 should have same limits")
	}
	// test tiers and js limits being mutual exclusive
	acc1.Limits.JetStreamLimits = l
	acc1.Validate(vr)
	if vr.IsEmpty() {
		t.Fatal("valid account should have validation issues")
	}
}

func TestJetstreamLimitsDeEnCode(t *testing.T) {
	// token (generated without this change) with js disabled
	c1, err := DecodeAccountClaims(`eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI3V0NYQkZKS0lIN1Y0SkdPR0FVTEtTS05aQUxVTUZMVExZWVgyNTdDSzZORk5OWTdGRVdBIiwiaWF0IjoxNjQ0Mjc5NDY3LCJpc3MiOiJPQk5UUVJFSEVJUFJFVE1BVlBWUVVDSUdFUktHWkIzRVJBVjVTNUdNM0lPRVFOSFJFQkpPVUFSRiIsIm5hbWUiOiJ0ZXN0Iiwic3ViIjoiQUM2SFFJMlVBTVVQREVQN1dTWVFZV1JDTEVZQkxZVlNQTDZBSExDVVBKVEdVMzJUNEtRQktZU0ciLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsIndpbGRjYXJkcyI6dHJ1ZSwiY29ubiI6LTEsImxlYWYiOi0xfSwiZGVmYXVsdF9wZXJtaXNzaW9ucyI6eyJwdWIiOnt9LCJzdWIiOnt9fSwidHlwZSI6ImFjY291bnQiLCJ2ZXJzaW9uIjoyfX0.73vDu9osNeLKwQ-g1Uu1fAtszMNz_QRZXRJLp0kzZh-0eMBmt0nb2mMwBwg-fufJs1FqYe9WbWKeXAYStnVnBg`)
	if err != nil {
		t.Fatal(err)
	} else if c1.Limits.IsJSEnabled() {
		t.Fatal("JetStream expected to be disabled")
	}
	// token (generated without this change) with js enabled
	c2, err := DecodeAccountClaims(`eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJPVFFXVEQyVkFMWkRQQTZYU1hLS09GRVFZR1VaVFBDNEtKV1BYMlAyWU1XMjVTMzRTVjNRIiwiaWF0IjoxNjQ0Mjc5MzM0LCJpc3MiOiJPQk5UUVJFSEVJUFJFVE1BVlBWUVVDSUdFUktHWkIzRVJBVjVTNUdNM0lPRVFOSFJFQkpPVUFSRiIsIm5hbWUiOiJ0ZXN0Iiwic3ViIjoiQUM2SFFJMlVBTVVQREVQN1dTWVFZV1JDTEVZQkxZVlNQTDZBSExDVVBKVEdVMzJUNEtRQktZU0ciLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsIndpbGRjYXJkcyI6dHJ1ZSwiY29ubiI6LTEsImxlYWYiOi0xLCJkaXNrX3N0b3JhZ2UiOjEwMDAwMDB9LCJkZWZhdWx0X3Blcm1pc3Npb25zIjp7InB1YiI6e30sInN1YiI6e319LCJ0eXBlIjoiYWNjb3VudCIsInZlcnNpb24iOjJ9fQ.Xt5azhxOkC7nywz9Q8xVtzX8lZIqdOhpfGyQI30aNdd-nbVGX2O13OOfouIaTLyajZiS4bcJFXa29q6QCFRUDA`)
	if err != nil {
		t.Fatal(err)
	} else if !c2.Limits.IsJSEnabled() {
		t.Fatal("JetStream expected to be enabled")
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
	if !ac.SigningKeys.Contains(apk2) {
		t.Fatalf("expected signing key %s", apk2)
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
	if !ac.SigningKeys.Contains(apk2) {
		t.Fatalf("expected signing key %s", apk2)
	}

	ukp := createUserNKey(t)
	upk := publicKey(ukp, t)

	// claim signed by alternate key
	uc := NewUserClaims(upk)
	uc.IssuerAccount = apk1
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

	ukp := createUserNKey(t)
	pubKey := publicKey(ukp, t)
	uc := NewUserClaims(pubKey)
	uJwt, _ := uc.Encode(akp)
	uc, err := DecodeUserClaims(uJwt)
	if err != nil {
		t.Errorf("Failed to decode user claim: %v", err)
	}
	now := time.Now()

	// test that clear is safe before we add any
	account.ClearRevocation(pubKey)

	if account.isRevoked(pubKey, now) {
		t.Errorf("no revocation was added so is revoked should be false")
	}

	account.RevokeAt(pubKey, now.Add(time.Second*100))

	if !account.isRevoked(pubKey, now) {
		t.Errorf("revocation should hold when timestamp is in the future")
	}

	if account.isRevoked(pubKey, now.Add(time.Second*150)) {
		t.Errorf("revocation should time out")
	}

	account.RevokeAt(pubKey, now.Add(time.Second*50)) // shouldn't change the revocation, you can't move it in

	if !account.isRevoked(pubKey, now.Add(time.Second*60)) {
		t.Errorf("revocation should hold, 100 > 50")
	}

	encoded, _ := account.Encode(akp)
	decoded, _ := DecodeAccountClaims(encoded)

	if !decoded.isRevoked(pubKey, now.Add(time.Second*60)) {
		t.Errorf("revocation should last across encoding")
	}

	account.ClearRevocation(pubKey)

	if account.IsClaimRevoked(uc) {
		t.Errorf("revocations should be cleared")
	}

	account.RevokeAt(pubKey, now.Add(time.Second*1000))

	if !account.IsClaimRevoked(uc) {
		t.Errorf("revocation be true we revoked in the future")
	}
}

func TestAccountDefaultPermissions(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.DefaultPermissions.Sub = Permission{
		Allow: []string{"foo.1", "bar.*"},
		Deny:  []string{"foo.2", "baz.>"},
	}
	account.DefaultPermissions.Pub = Permission{
		Allow: []string{"foo.4", "bar.>"},
		Deny:  []string{"foo.4", "baz.*"},
	}
	account.DefaultPermissions.Resp = &ResponsePermission{
		5,
		5 * time.Second}

	actJwt := encode(account, akp, t)

	account2, err := DecodeAccountClaims(actJwt)
	if err != nil {
		t.Fatal("error decoding account jwt", err)
	}

	AssertEquals(account.String(), account2.String(), t)
}

func TestUserRevocationAll(t *testing.T) {
	akp := createAccountNKey(t)
	ukp := createUserNKey(t)
	upk := publicKey(ukp, t)
	user := NewUserClaims(upk)
	token, err := user.Encode(akp)
	if err != nil {
		t.Fatal(err)
	}

	ud, err := DecodeUserClaims(token)
	if err != nil {
		t.Fatal(err)
	}

	apk := publicKey(akp, t)
	account := NewAccountClaims(apk)
	account.RevokeAt(All, time.Now().Add(time.Second))
	if !account.IsClaimRevoked(ud) {
		t.Fatal("user should have been revoked")
	}

	account.RevokeAt(All, time.Now().Add(time.Second*-10))
	if !account.IsClaimRevoked(ud) {
		t.Fatal("user should have not been revoked")
	}
}

func TestInvalidAccountInfo(t *testing.T) {
	a := NewAccountClaims(publicKey(createAccountNKey(t), t))
	a.InfoURL = "/bad"
	vr := CreateValidationResults()
	a.Validate(vr)
	if vr.IsEmpty() {
		t.Errorf("export info should not validate cleanly")
	}
	if !vr.IsBlocking(true) {
		t.Errorf("invalid info needs to be blocking")
	}
}

func TestAccountMapping(t *testing.T) { // don't block encoding!!!
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	vr := &ValidationResults{}

	account.AddMapping("foo1", WeightedMapping{Subject: "to"})
	account.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Expected no errors")
	}
	account.AddMapping("foo2",
		WeightedMapping{Subject: "to1", Weight: 50},
		WeightedMapping{Subject: "to2", Weight: 50})
	account.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Expected no errors")
	}
	account.AddMapping("foo3",
		WeightedMapping{Subject: "to1", Weight: 50},
		WeightedMapping{Subject: "to2", Weight: 51})
	account.Validate(vr)
	if !vr.IsBlocking(false) {
		t.Fatal("Expected blocking error as sum of weights is > 100")
	}

	vr = &ValidationResults{}
	account.Mappings = Mapping{}
	account.AddMapping("foo4",
		WeightedMapping{Subject: "to1"}, // no weight means 100
		WeightedMapping{Subject: "to2", Weight: 1})
	account.Validate(vr)
	if !vr.IsBlocking(false) {
		t.Fatal("Expected blocking error as sum of weights is > 100")
	}

	vr = &ValidationResults{}
	account.Mappings = Mapping{}
	account.AddMapping("foo5.>", WeightedMapping{Subject: "to.*.>"})
	account.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Expected no errors")
	}

	vr = &ValidationResults{}
	account.Mappings = Mapping{}
	account.AddMapping("foo6.>", WeightedMapping{Subject: "to.boo.>"})
	account.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Expected no errors")
	}
}

func TestAccountClusterMany100MappingOK(t *testing.T) { // don't block encoding!!!
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	vr := &ValidationResults{}

	account.AddMapping("q",
		WeightedMapping{Subject: "qq", Weight: 100, Cluster: "A"},
		WeightedMapping{Subject: "qq", Weight: 100, Cluster: "B"},
		WeightedMapping{Subject: "bb", Weight: 100, Cluster: "C"},
		WeightedMapping{Subject: "qq", Weight: 100})
	account.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Expected no errors")
	}
}

func TestAccountClusterNoOver100Mapping(t *testing.T) { // don't block encoding!!!
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	vr := &ValidationResults{}

	account.AddMapping("q",
		WeightedMapping{Subject: "qq", Weight: 100, Cluster: "A"},
		WeightedMapping{Subject: "qq", Weight: 5, Cluster: "A"})
	account.Validate(vr)
	if !vr.IsBlocking(false) {
		t.Fatal("Expected blocking error as sum of weights is > 100")
	}
}

func TestAccountExternalAuthorization(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	vr := &ValidationResults{}

	ukp := createUserNKey(t)
	account.EnableExternalAuthorization(publicKey(ukp, t))
	account.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Expected no errors")
	}

	akp2 := createAccountNKey(t)
	account.Authorization.AllowedAccounts.Add(publicKey(akp2, t))
	account.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Expected no errors")
	}

	if !account.HasExternalAuthorization() {
		t.Fatalf("Expected to have authorization enabled")
	}

	vr = &ValidationResults{}
	account.Authorization = ExternalAuthorization{}

	account.Authorization.AuthUsers.Add("Z")
	account.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatalf("Expected blocking error on bad auth user")
	}

	vr = &ValidationResults{}
	account.Authorization = ExternalAuthorization{}
	account.Authorization.AllowedAccounts.Add("Z")
	account.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatalf("Expected blocking error on bad allowed account")
	}

	account.Authorization = ExternalAuthorization{}
	if account.Authorization.IsEnabled() {
		t.Fatalf("Expected not to have authorization enabled")
	}
}

func TestAccountExternalAuthorizationRequiresOneUser(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	account.Authorization.AllowedAccounts.Add(publicKey(createAccountNKey(t), t))

	vr := &ValidationResults{}
	account.Validate(vr)

	AssertEquals(len(vr.Errors()), 1, t)
	AssertEquals("External authorization cannot have accounts without users specified",
		vr.Errors()[0].Error(),
		t)
}

func TestAccountExternalAuthorizationAnyAccount(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	ukp := createUserNKey(t)
	upk := publicKey(ukp, t)

	account := NewAccountClaims(apk)
	account.Authorization.AllowedAccounts.Add("*")
	account.Authorization.AuthUsers.Add(upk)

	vr := &ValidationResults{}
	account.Validate(vr)
	AssertEquals(len(vr.Errors()), 0, t)
}

func TestAccountExternalAuthorizationAnyAccountAndSpecificFails(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	ukp := createUserNKey(t)
	upk := publicKey(ukp, t)

	account := NewAccountClaims(apk)
	account.Authorization.AllowedAccounts.Add("*", apk)
	account.Authorization.AuthUsers.Add(upk)

	vr := &ValidationResults{}
	account.Validate(vr)
	AssertEquals(len(vr.Errors()), 1, t)
	AssertEquals(vr.Errors()[0].Error(), fmt.Sprintf("AllowedAccounts can only be a list of accounts or %q", AnyAccount), t)
}

func TestAccountClaims_DidSign(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	skp := createAccountNKey(t)
	spk := publicKey(skp, t)

	ac := NewAccountClaims(apk)
	ac.SigningKeys.Add(spk)

	upk := publicKey(createUserNKey(t), t)
	uc := NewUserClaims(upk)
	tok, err := uc.Encode(akp)
	if err != nil {
		t.Fatal("error encoding")
	}
	uc, err = DecodeUserClaims(tok)
	if err != nil {
		t.Fatal("error decoding")
	}
	if !ac.DidSign(uc) {
		t.Fatal("expected account to have been issued")
	}
	uc = NewUserClaims(upk)
	uc.IssuerAccount = publicKey(createAccountNKey(t), t)
	tok, err = uc.Encode(skp)
	if err != nil {
		t.Fatalf("encode failed %v", err)
	}
	uc, err = DecodeUserClaims(tok)
	if err != nil {
		t.Fatalf("decode failed %v", err)
	}
	if ac.DidSign(uc) {
		t.Fatal("this is not issued by account A")
	}
}

func TestAccountClaims_GetTags(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	ac := NewAccountClaims(apk)
	ac.Account.Tags.Add("foo", "bar")
	tags := ac.GetTags()
	if len(tags) != 2 {
		t.Fatal("expected 2 tags")
	}
	if tags[0] != "foo" {
		t.Fatal("expected tag foo")
	}
	if tags[1] != "bar" {
		t.Fatal("expected tag bar")
	}

	token, err := ac.Encode(akp)
	if err != nil {
		t.Fatal("error encoding")
	}
	ac, err = DecodeAccountClaims(token)
	if err != nil {
		t.Fatal("error decoding")
	}
	tags = ac.GetTags()
	if len(tags) != 2 {
		t.Fatal("expected 2 tags")
	}
	if tags[0] != "foo" {
		t.Fatal("expected tag foo")
	}
	if tags[1] != "bar" {
		t.Fatal("expected tag bar")
	}
}

func TestAccountClaimsTraceDest(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	for i, test := range []struct {
		name        string
		invalidSubj Subject
		expectErr   bool
	}{
		{"trace not specified", "", false},
		{"trace created but with empty destination", "", true},
		{"trace dest has spaces", "invalid dest", true},
		{"trace dest start with a dot", ".invalid.dest", true},
		{"trace dest ends with a dot", "invalid.dest.", true},
		{"trace dest has consecutive dots", "invalid..dest", true},
		{"trace dest invalid publish dest", "invalid.publish.*.dest", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if i > 0 {
				account.Trace = &MsgTrace{Destination: test.invalidSubj}
			}
			vr := CreateValidationResults()
			account.Validate(vr)

			if test.expectErr && vr.IsEmpty() {
				t.Fatal("account validation should have failed")
			} else if !test.expectErr && !vr.IsEmpty() {
				t.Fatalf("account validation should not have failed, got %+v", vr.Issues)
			}
		})
	}
}

func TestAccountClaimsTraceDestSampling(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	account := NewAccountClaims(apk)
	for _, test := range []struct {
		name      string
		dest      string
		sampling  int
		expectErr string
	}{
		{"sampling without destination", "", 10, "subject cannot be empty"},
		{"sampling negative", "dest", -1, "should be in the range [1..100]"},
		{"sampling above 100", "dest", 101, "should be in the range [1..100]"},
		{"sampling at 50", "dest", 50, ""},
		{"sampling at zero sets to 100", "dest", 0, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			account.Trace = &MsgTrace{Destination: Subject(test.dest), Sampling: test.sampling}
			vr := CreateValidationResults()
			account.Validate(vr)

			if test.expectErr == "" {
				if !vr.IsEmpty() {
					t.Fatalf("account validation should not have failed, got %+v", vr.Issues)
				}
				if test.sampling == 0 {
					if account.Trace.Sampling != 100 {
						t.Fatalf("account sampling should have been set to 100 got %d", account.Trace.Sampling)
					}
				} else if test.sampling != account.Trace.Sampling {
					t.Fatalf("account sampling should be %d, got %d", test.sampling, account.Trace.Sampling)
				}
			} else {
				if vr.IsEmpty() {
					t.Fatal("account validation should have failed")
				}
				if !strings.Contains(vr.Issues[0].Description, test.expectErr) {
					t.Fatalf("account validation should have failed with error %q, got %q", test.expectErr, vr.Issues[0].Description)
				}
			}
		})
	}
}

func TestClusterTraffic_Valid(t *testing.T) {
	type clustertest struct {
		input string
		ok    bool
	}

	tests := []clustertest{
		{input: "", ok: true},
		{input: "system", ok: true},
		{input: "SYSTEM", ok: false},
		{input: "owner", ok: true},
		{input: "OWNER", ok: false},
		{input: "unknown", ok: false},
		{input: "account", ok: false},
	}

	for _, test := range tests {
		ct := ClusterTraffic(test.input)
		err := ct.Valid()
		if test.ok && err != nil {
			t.Fatalf("unexpected err for input %q: %v", test.input, err)
		}
		if !test.ok && err == nil {
			t.Fatalf("expected to fail input %q", test.input)
		}
	}
}

func TestSignFn(t *testing.T) {
	okp := createOperatorNKey(t)
	opub := publicKey(okp, t)
	opk, err := nkeys.FromPublicKey(opub)
	if err != nil {
		t.Fatal(err)
	}

	akp := createAccountNKey(t)
	pub := publicKey(akp, t)

	var ok bool
	ac := NewAccountClaims(pub)
	ac.Name = "A"
	s, err := ac.EncodeWithSigner(opk, func(pub string, data []byte) ([]byte, error) {
		if pub != opub {
			t.Fatal("expected pub key in callback to match")
		}
		ok = true
		return okp.Sign(data)
	})

	if err != nil {
		t.Fatal("error encoding")
	}
	if !ok {
		t.Fatal("expected ok to be true")
	}

	ac, err = DecodeAccountClaims(s)
	if err != nil {
		t.Fatal("error decoding encoded jwt")
	}
	vr := CreateValidationResults()
	ac.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatalf("claims validation should not have failed, got %+v", vr.Issues)
	}
}
