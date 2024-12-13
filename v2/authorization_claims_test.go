/*
 * Copyright 2022-2024 The NATS Authors
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
	"testing"

	"github.com/nats-io/nkeys"
)

func TestNewAuthorizationRequestClaims(t *testing.T) {
	skp, _ := nkeys.CreateServer()

	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("Error creating user: %v", err)
	}
	pub, _ := kp.PublicKey()

	// the subject of the claim is the user we are generating an authorization response
	ac := NewAuthorizationRequestClaims(pub)
	ac.Server.Name = "NATS-1"

	vr := CreateValidationResults()

	// Make sure that user nkey is required.
	ac.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatalf("Expected blocking error on an nkey user not being specified")
	}

	// Make sure it is required to be valid public user nkey.
	ac.UserNkey = "derek"
	vr = CreateValidationResults()
	ac.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatalf("Expected blocking error on invalid user nkey")
	}

	ac.UserNkey = pub
	vr = CreateValidationResults()
	ac.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatal("Valid authorization request will have no validation results")
	}

	acJWT := encode(ac, skp, t)

	ac2, err := DecodeAuthorizationRequestClaims(acJWT)
	if err != nil {
		t.Fatal("error decoding authorization request jwt", err)
	}

	AssertEquals(ac.String(), ac2.String(), t)
	AssertEquals(ac.Server.Name, ac2.Server.Name, t)
}

func TestAuthorizationResponse_EmptyShouldFail(t *testing.T) {
	rc := NewAuthorizationResponseClaims("$G")
	vr := CreateValidationResults()
	rc.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatal("Expected blocking errors")
	}
	errs := vr.Errors()
	AssertEquals(3, len(errs), t)
	AssertEquals("Subject must be a user public key", errs[0].Error(), t)
	AssertEquals("Audience must be a server public key", errs[1].Error(), t)
	AssertEquals("Error or Jwt is required", errs[2].Error(), t)
}

func TestAuthorizationResponse_SubjMustBeServer(t *testing.T) {
	rc := NewAuthorizationResponseClaims(publicKey(createUserNKey(t), t))
	rc.Error = "bad"
	vr := CreateValidationResults()
	rc.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatal("Expected blocking errors")
	}
	errs := vr.Errors()
	AssertEquals(1, len(errs), t)
	AssertEquals("Audience must be a server public key", errs[0].Error(), t)

	rc = NewAuthorizationResponseClaims(publicKey(createUserNKey(t), t))
	rc.Audience = publicKey(createServerNKey(t), t)
	rc.Error = "bad"
	vr = CreateValidationResults()
	rc.Validate(vr)
	AssertEquals(true, vr.IsEmpty(), t)
}

func TestAuthorizationResponse_OneOfErrOrJwt(t *testing.T) {
	rc := NewAuthorizationResponseClaims(publicKey(createUserNKey(t), t))
	rc.Audience = publicKey(createServerNKey(t), t)
	rc.Error = "bad"
	rc.Jwt = "jwt"
	vr := CreateValidationResults()
	rc.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatal("Expected blocking errors")
	}
	errs := vr.Errors()
	AssertEquals(1, len(errs), t)
	AssertEquals("Only Error or Jwt can be set", errs[0].Error(), t)
}

func TestAuthorizationResponse_IssuerAccount(t *testing.T) {
	rc := NewAuthorizationResponseClaims(publicKey(createUserNKey(t), t))
	rc.Audience = publicKey(createServerNKey(t), t)
	rc.Jwt = "jwt"
	rc.IssuerAccount = rc.Subject
	vr := CreateValidationResults()
	rc.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(false) {
		t.Fatal("Expected blocking errors")
	}
	errs := vr.Errors()
	AssertEquals(1, len(errs), t)
	AssertEquals("issuer_account is not an account public key", errs[0].Error(), t)

	akp := createAccountNKey(t)
	rc.IssuerAccount = publicKey(akp, t)
	vr = CreateValidationResults()
	rc.Validate(vr)
	AssertEquals(true, vr.IsEmpty(), t)
}

func TestAuthorizationResponse_Decode(t *testing.T) {
	rc := NewAuthorizationResponseClaims(publicKey(createUserNKey(t), t))
	rc.Audience = publicKey(createServerNKey(t), t)
	rc.Jwt = "jwt"
	akp := createAccountNKey(t)
	tok, err := rc.Encode(akp)
	AssertNoError(err, t)

	r, err := DecodeAuthorizationResponseClaims(tok)
	AssertNoError(err, t)
	vr := CreateValidationResults()
	r.Validate(vr)
	AssertEquals(true, vr.IsEmpty(), t)
	AssertEquals("jwt", r.Jwt, t)
	AssertTrue(nkeys.IsValidPublicUserKey(r.Subject), t)
	AssertTrue(nkeys.IsValidPublicServerKey(r.Audience), t)
}

func TestNewAuthorizationRequestSignerFn(t *testing.T) {
	skp, _ := nkeys.CreateServer()

	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("Error creating user: %v", err)
	}

	// the subject of the claim is the user we are generating an authorization response
	ac := NewAuthorizationRequestClaims(publicKey(kp, t))
	ac.Server.Name = "NATS-1"
	ac.UserNkey = publicKey(kp, t)

	ok := false
	ar, err := ac.EncodeWithSigner(skp, func(pub string, data []byte) ([]byte, error) {
		ok = true
		return skp.Sign(data)
	})
	if err != nil {
		t.Fatal("error signing request")
	}
	if !ok {
		t.Fatal("not signed by signer function")
	}

	ac2, err := DecodeAuthorizationRequestClaims(ar)
	if err != nil {
		t.Fatal("error decoding authorization request jwt", err)
	}

	vr := CreateValidationResults()
	ac2.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatalf("claims validation should not have failed, got %+v", vr.Issues)
	}
}
