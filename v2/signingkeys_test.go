/*
 * Copyright 2020 The NATS Authors
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
	"encoding/json"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func makeRole(t *testing.T, role string, pub []string, sub []string, bearer bool) (*UserScope, nkeys.KeyPair) {
	akp := createAccountNKey(t)
	pk := publicKey(akp, t)
	r := NewUserScope()
	r.Key = pk
	r.Template.BearerToken = bearer
	r.Template.Sub.Allow.Add(sub...)
	r.Template.Pub.Allow.Add(pub...)
	r.Template.BearerToken = bearer
	r.Role = role
	return r, akp
}

func makeUser(t *testing.T, ac *AccountClaims, signer nkeys.KeyPair, pub []string, sub []string) *UserClaims {
	ukp := createUserNKey(t)
	uc := NewUserClaims(publicKey(ukp, t))
	if pub == nil && sub == nil {
		uc.UserPermissionLimits = UserPermissionLimits{}
	}
	spk := publicKey(signer, t)
	if ac.Subject != spk {
		uc.IssuerAccount = ac.Subject
	}

	uc.Pub.Allow.Add(pub...)
	uc.Sub.Allow.Add(sub...)
	ut, err := uc.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	uc, err = DecodeUserClaims(ut)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pub {
		if !uc.Pub.Allow.Contains(p) {
			t.Fatalf("expected user to have pub %q", p)
		}
	}
	for _, p := range pub {
		if !uc.Pub.Allow.Contains(p) {
			t.Fatalf("expected user to have pub %q", p)
		}
	}
	for _, s := range sub {
		if !uc.Sub.Allow.Contains(s) {
			t.Fatalf("expected user to have sub %q", s)
		}
	}
	return uc
}

func makeAccount(t *testing.T, sks []string, roles []Scope) (*AccountClaims, nkeys.KeyPair) {
	akp := createAccountNKey(t)
	pk := publicKey(akp, t)

	ac := NewAccountClaims(pk)
	ac.SigningKeys.Add(sks...)
	for _, r := range roles {
		ac.SigningKeys.AddScopedSigner(r)
	}

	token, err := ac.Encode(createOperatorNKey(t))
	if err != nil {
		t.Fatal(err)
	}

	ac, err = DecodeAccountClaims(token)
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range sks {
		if !ac.SigningKeys.Contains(k) {
			t.Fatalf("expected to find signer: %s", k)
		}
	}
	for _, r := range roles {
		rr, _ := ac.SigningKeys.GetScope(r.SigningKey())
		if rr == nil {
			t.Fatalf("expected scope for signer %s", r.SigningKey())
		}
	}
	return ac, akp
}

func TestScopesAreAccounts(t *testing.T) {
	// make a bad role that has user sk
	bad, _ := makeRole(t, "bad", []string{">"}, nil, false)
	bad.Key = publicKey(createUserNKey(t), t)

	ac, _ := makeAccount(t, nil, []Scope{bad})
	var vr ValidationResults
	ac.Validate(&vr)
	if vr.IsEmpty() {
		t.Fatal("should have had validation errors")
	}
	if len(vr.Errors()) != 1 {
		t.Fatal("expected one error")
	}
	if !strings.Contains(vr.Errors()[0].Error(), bad.Key) {
		t.Fatal("expected error to be about the user key")
	}
}

func TestScopesCheckIssuer(t *testing.T) {
	// make a bad role that has user sk
	r, _ := makeRole(t, "bad", []string{">"}, nil, false)
	ac, akp := makeAccount(t, nil, []Scope{r})
	uc := makeUser(t, ac, akp, nil, nil)
	err := r.ValidateScopedSigner(uc)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "issuer not the scoped signer") {
		t.Fatalf("expected scoped signer error - but got: %v", err)
	}
}

func TestScopesCheckClaimType(t *testing.T) {
	// make a bad role that has user sk
	r, _ := makeRole(t, "bad", []string{">"}, nil, false)
	ac, _ := makeAccount(t, nil, []Scope{r})
	err := r.ValidateScopedSigner(ac)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not an user claim") {
		t.Fatalf("expected claim type error - but got: %v", err)
	}
}

func TestScopedSigningKeysBasics(t *testing.T) {
	adm, _ := makeRole(t, "admin", []string{">"}, []string{">"}, false)
	dash, dashKP := makeRole(t, "dashboard", []string{"dashboard.>"}, []string{"dashboard.>"}, true)
	signer := createAccountNKey(t)
	signerPK := publicKey(signer, t)

	ac, apk := makeAccount(t, []string{signerPK}, []Scope{adm, dash})

	// test a user issued by the account
	uc := makeUser(t, ac, apk, nil, nil)
	if !ac.DidSign(uc) {
		t.Fatalf("should have been a valid user")
	}
	_, ok := ac.SigningKeys.GetScope(uc.Issuer)
	if ok {
		t.Fatal("this was issued by the account")
	}

	// test a user issued by a the signer
	uc = makeUser(t, ac, signer, nil, nil)
	if !ac.DidSign(uc) {
		t.Fatalf("should have been a valid user")
	}
	scope, ok := ac.SigningKeys.GetScope(uc.Issuer)
	if !ok {
		t.Fatal("signer should have been found")
	}
	if scope != nil {
		t.Fatal("unexpected scope")
	}

	// test a user with a scope
	uc = makeUser(t, ac, dashKP, nil, nil)
	if !ac.DidSign(uc) {
		t.Fatalf("should have been a valid user")
	}
	scope, ok = ac.SigningKeys.GetScope(uc.Issuer)
	if !ok {
		t.Fatal("signer should have been found")
	}
	if scope == nil {
		t.Fatal("expected scope")
	}
	if scope.SigningKey() != publicKey(dashKP, t) {
		t.Fatal("expected scope to be dashboard key")
	}
	if err := scope.ValidateScopedSigner(uc); err != nil {
		t.Fatalf("expected scope to be correct: %v", err)
	}

	// test user with a scope that has wrong permissions
	uc = makeUser(t, ac, dashKP, []string{">"}, nil)
	if !ac.DidSign(uc) {
		t.Fatalf("should have been a valid user")
	}
	scope, ok = ac.SigningKeys.GetScope(uc.Issuer)
	if !ok {
		t.Fatal("signer should have been found")
	}
	if scope == nil {
		t.Fatal("expected scope")
	}
	if scope.SigningKey() != publicKey(dashKP, t) {
		t.Fatal("expected scope to be dashboard key")
	}
	if err := scope.ValidateScopedSigner(uc); err == nil {
		t.Fatalf("expected scope to reject user")
	}
}

func TestGetKeys(t *testing.T) {

	ac, apk := makeAccount(t, nil, nil)
	ac.SigningKeys.Add(publicKey(createAccountNKey(t), t))
	ac.SigningKeys.Add(publicKey(createAccountNKey(t), t))
	ac.SigningKeys.Add(publicKey(createAccountNKey(t), t))

	token, err := ac.Encode(apk)
	if err != nil {
		t.Fatal(err)
	}
	aac, err := DecodeAccountClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	keys := aac.SigningKeys.Keys()
	if len(keys) != 3 {
		t.Fatal("expected 3 signing keys")
	}
	for _, k := range keys {
		if !ac.SigningKeys.Contains(k) {
			t.Fatal("expected to find key")
		}
	}
}

func TestJson(t *testing.T) {
	ac, apk := makeAccount(t, nil, nil)
	ac.SigningKeys.Add(publicKey(createAccountNKey(t), t))
	ac.SigningKeys.Add(publicKey(createAccountNKey(t), t))
	ac.SigningKeys.Add(publicKey(createAccountNKey(t), t))

	token, err := ac.Encode(apk)
	if err != nil {
		t.Fatal(err)
	}
	aac, err := DecodeAccountClaims(token)
	if err != nil {
		t.Fatal(err)
	}

	j, err := json.Marshal(aac)
	if err != nil {
		t.Fatal(err)
	}
	var myAcc AccountClaims
	err = json.Unmarshal(j, &myAcc)
	if err != nil {
		t.Fatal(err)
	}
	if len(myAcc.SigningKeys) != 3 {
		t.Fatalf("Expected 3 signing keys got: %d",len(myAcc.SigningKeys))
	}

}
