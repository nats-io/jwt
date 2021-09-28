/*
 * Copyright 2018-2021 The NATS Authors
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
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	. "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func Trace(message string) string {
	lines := make([]string, 0, 32)
	err := errors.New(message)
	msg := err.Error()
	lines = append(lines, msg)

	for i := 2; true; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		msg := fmt.Sprintf("%s:%d", file, line)
		lines = append(lines, msg)
	}
	return strings.Join(lines, "\n")
}

func AssertEquals(expected, v interface{}, t *testing.T) {
	if expected != v {
		t.Fatalf("%v", Trace(fmt.Sprintf("The expected value %v != %v", expected, v)))
	}
}

func AssertNil(v interface{}, t *testing.T) {
	if v != nil {
		t.FailNow()
	}
}

func AssertNoError(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}

func AssertTrue(condition bool, t *testing.T) {
	if !condition {
		t.FailNow()
	}
}

func AssertFalse(condition bool, t *testing.T) {
	if condition {
		t.FailNow()
	}
}

func createAccountNKey(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("error creating account kp", err)
	}
	return kp
}

func createOperatorNKey(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal("error creating operator kp", err)
	}
	return kp
}

func publicKey(kp nkeys.KeyPair, t *testing.T) string {
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatal("error reading public key", err)
	}
	return pk
}

func encode(c Claims, kp nkeys.KeyPair, t *testing.T) string {
	s, err := c.Encode(kp)
	if err != nil {
		t.Fatal("error encoding claim", err)
	}
	return s
}
