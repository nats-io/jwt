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
	"testing"
	"time"
)

func TestNewGenericClaims(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	gc := NewGenericClaims(apk)
	gc.Expires = time.Now().Add(time.Hour).UTC().Unix()
	gc.Name = "alberto"
	gc.Audience = "everyone"
	gc.NotBefore = time.Now().UTC().Unix()
	gc.Data["test"] = true

	gcJwt := encode(gc, akp, t)

	uc2, err := DecodeGeneric(gcJwt)
	if err != nil {
		t.Fatal("failed to decode", err)
	}

	AssertEquals(gc.String(), uc2.String(), t)
	AssertEquals(gc.Name, uc2.Name, t)
	AssertEquals(gc.Audience, uc2.Audience, t)
	AssertEquals(gc.Expires, uc2.Expires, t)
	AssertEquals(gc.NotBefore, uc2.NotBefore, t)
	AssertEquals(gc.Subject, uc2.Subject, t)

	AssertEquals(gc.Data["test"], true, t)
	AssertEquals(gc.Claims() != nil, true, t)
	AssertEquals(gc.Payload() != nil, true, t)
}
