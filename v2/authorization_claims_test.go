/*
 * Copyright 2022 The NATS Authors
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

func TestNewAuthorizationClaims(t *testing.T) {
	skp, _ := nkeys.CreateServer()
	ac := NewAuthorizationRequestClaims("TEST")
	ac.Server.Name = "NATS-1"

	vr := CreateValidationResults()
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
