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

func TestNewServerClaims(t *testing.T) {
	ckp := createClusterNKey(t)
	skp := createServerNKey(t)

	uc := NewServerClaims(publicKey(skp, t))
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()
	uJwt := encode(uc, ckp, t)

	uc2, err := DecodeServerClaims(uJwt)
	if err != nil {
		t.Fatal("failed to decode", err)
	}

	AssertEquals(uc.String(), uc2.String(), t)

	AssertEquals(uc.Claims() != nil, true, t)
	AssertEquals(uc.Payload() != nil, true, t)
}

func TestServerClaimsIssuer(t *testing.T) {
	ckp := createClusterNKey(t)
	skp := createServerNKey(t)

	uc := NewServerClaims(publicKey(skp, t))
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
		_, err = DecodeServerClaims(bad)
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to decode server signed by %q", i.name)
			t.Fail()
		}
	}
}

func TestServerSubjects(t *testing.T) {
	type kpInputs struct {
		name string
		kp   nkeys.KeyPair
		ok   bool
	}

	inputs := []kpInputs{
		{"account", createAccountNKey(t), false},
		{"cluster", createClusterNKey(t), false},
		{"operator", createOperatorNKey(t), false},
		{"server", createServerNKey(t), true},
		{"user", createUserNKey(t), false},
	}

	for _, i := range inputs {
		c := NewServerClaims(publicKey(i.kp, t))
		_, err := c.Encode(createOperatorNKey(t))
		if i.ok && err != nil {
			t.Fatal(fmt.Sprintf("unexpected error for %q: %v", i.name, err))
		}
		if !i.ok && err == nil {
			t.Logf("should have failed to encode server with with %q subject", i.name)
			t.Fail()
		}
	}
}

func TestNewNilServerClaims(t *testing.T) {
	v := NewServerClaims("")
	if v != nil {
		t.Fatal(fmt.Sprintf("expected nil user claim"))
	}
}

func TestServerType(t *testing.T) {
	c := NewServerClaims(publicKey(createServerNKey(t), t))
	s := encode(c, createClusterNKey(t), t)
	u, err := DecodeServerClaims(s)
	if err != nil {
		t.Fatalf("failed to decode server claim: %v", err)
	}

	if ServerClaim != u.Type {
		t.Fatalf("type is unexpected %q (wanted server)", u.Type)
	}

}
