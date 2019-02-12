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
)

func TestNewRevocationClaims(t *testing.T) {
	okp := createOperatorNKey(t)
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	activation := NewActivationClaims(apk)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()

	actJwt := encode(activation, okp, t)

	revocation := NewRevocationClaims(apk)
	revocation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	revocation.JWT = actJwt
	revocation.Reason = "Closing account"

	revJWT := encode(revocation, okp, t)

	revocation2, err := DecodeRevocationClaims(revJWT)
	if err != nil {
		t.Fatal("failed to decode activation", err)
	}

	AssertEquals(revocation.String(), revocation2.String(), t)

	AssertEquals(revocation.Claims() != nil, true, t)
	AssertEquals(revocation.Payload() != nil, true, t)
}

func TestIssuerMustMatch(t *testing.T) {
	okp := createOperatorNKey(t)
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	activation := NewActivationClaims(apk)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()

	actJwt := encode(activation, okp, t)

	revocation := NewRevocationClaims(apk)
	revocation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	revocation.JWT = actJwt
	revocation.Reason = "Closing account"

	vr := CreateValidationResults()
	revocation.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(true) {
		t.Fatal("validation should fail with a different issuer")
	}
}

func TestBadJWTInRevocation(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	revocation := NewRevocationClaims(apk)
	revocation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	revocation.JWT = "invalidjwt"
	revocation.Reason = "Closing account"

	vr := CreateValidationResults()
	revocation.Validate(vr)
	if vr.IsEmpty() || !vr.IsBlocking(true) {
		t.Fatal("validation should fail with bad JWT string in revocation")
	}
}

func TestNilRevocationClaim(t *testing.T) {
	v := NewRevocationClaims("")
	if v != nil {
		t.Fatal(fmt.Sprintf("expected nil revocation claim"))
	}
}
