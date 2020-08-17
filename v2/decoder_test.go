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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestNewToken(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	claims := NewGenericClaims(publicKey(createUserNKey(t), t))
	claims.Data["foo"] = "bar"

	token, err := claims.Encode(kp)
	if err != nil {
		t.Fatal("error encoding token", err)
	}

	c, err := DecodeGeneric(token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.NotBefore != c.NotBefore {
		t.Fatal("notbefore don't match")
	}

	if claims.Issuer != c.Issuer {
		t.Fatal("notbefore don't match")
	}

	if !reflect.DeepEqual(claims.Data, c.Data) {
		t.Fatal("data sections don't match")
	}
}

func TestBadType(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{"JWS", AlgorithmNkey}
	c := NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, c)
	if err != nil {
		t.Fatal(err)
	}

	claim, err := DecodeGeneric(token)
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != fmt.Sprintf("not supported type %q", "JWS") {
		t.Fatal("expected not supported type error")
	}
}

func TestBadAlgo(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{TokenTypeJwt, "foobar"}
	c := NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	if _, err := c.doEncode(&h, kp, c); err == nil {
		t.Fatal("expected an error due to bad algorithm")
	}

	h = Header{TokenTypeJwt, AlgorithmNkeyOld}
	c = NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	if _, err := c.doEncode(&h, kp, c); err == nil {
		t.Fatal("expected an error due to bad algorithm")
	}
}

func TestBadJWT(t *testing.T) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}

	h := Header{"JWS", AlgorithmNkey}
	c := NewGenericClaims(publicKey(createUserNKey(t), t))
	c.Data["foo"] = "bar"

	token, err := c.doEncode(&h, kp, c)
	if err != nil {
		t.Fatal(err)
	}

	chunks := strings.Split(token, ".")
	badToken := fmt.Sprintf("%s.%s", chunks[0], chunks[1])

	claim, err := DecodeGeneric(badToken)
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != "expected 3 chunks" {
		t.Fatalf("unexpeced error: %q", err.Error())
	}
}

func TestBadSignature(t *testing.T) {
	kp := createAccountNKey(t)
	for algo, error := range map[string]string{
		AlgorithmNkey: "claim failed V2 signature verification",
	} {
		h := Header{TokenTypeJwt, algo}
		c := NewGenericClaims(publicKey(createUserNKey(t), t))
		c.Data["foo"] = "bar"

		token, err := c.doEncode(&h, kp, c)
		if err != nil {
			t.Fatal(err)
		}

		token = token + "A"

		claim, err := DecodeGeneric(token)
		if claim != nil {
			t.Fatal("non nil claim on bad token")
		}

		if err == nil {
			t.Fatal("nil error on bad token")
		}

		if err.Error() != error {
			m := fmt.Sprintf("expected failed signature: %q", err.Error())
			t.Fatal(m)
		}
	}
}

func TestDifferentPayload(t *testing.T) {
	akp1 := createAccountNKey(t)

	c1 := NewGenericClaims(publicKey(createUserNKey(t), t))
	c1.Data["foo"] = "barz"
	jwt1 := encode(c1, akp1, t)
	c1t := strings.Split(jwt1, ".")
	c1.Data["foo"] = "bar"

	kp2 := createAccountNKey(t)
	token2 := encode(c1, kp2, t)
	c2t := strings.Split(token2, ".")

	c1t[1] = c2t[1]

	claim, err := DecodeGeneric(fmt.Sprintf("%s.%s.%s", c1t[0], c1t[1], c1t[2]))
	if claim != nil {
		t.Fatal("non nil claim on bad token")
	}

	if err == nil {
		t.Fatal("nil error on bad token")
	}

	if err.Error() != "claim failed V2 signature verification" {
		m := fmt.Sprintf("expected failed signature: %q", err.Error())
		t.Fatal(m)
	}
}

func TestExpiredToken(t *testing.T) {
	akp := createAccountNKey(t)
	c := NewGenericClaims(publicKey(akp, t))
	c.Expires = time.Now().UTC().Unix() - 100
	c.Data["foo"] = "barz"

	vr := CreateValidationResults()
	c.Validate(vr)
	if !vr.IsBlocking(true) {
		t.Fatalf("expired tokens should be blocking when time is included")
	}

	if vr.IsBlocking(false) {
		t.Fatalf("expired tokens should not be blocking when time is not included")
	}
}

func TestNotYetValid(t *testing.T) {
	akp1, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("unable to create account key", err)
	}
	c := NewGenericClaims(publicKey(akp1, t))
	c.NotBefore = time.Now().Add(time.Duration(1) * time.Hour).UTC().Unix()

	vr := CreateValidationResults()
	c.Validate(vr)
	if !vr.IsBlocking(true) {
		t.Fatalf("not yet valid tokens should be blocking when time is included")
	}

	if vr.IsBlocking(false) {
		t.Fatalf("not yet valid tokens should not be blocking when time is not included")
	}
}

func TestIssuedAtIsSet(t *testing.T) {
	akp := createAccountNKey(t)
	c := NewGenericClaims(publicKey(akp, t))
	c.Data["foo"] = "barz"

	token, err := c.Encode(akp)
	if err != nil {
		t.Fatal(err)
	}

	claim, err := DecodeGeneric(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claim.IssuedAt == 0 {
		t.Fatalf("issued at is not set")
	}
}

func TestSample(t *testing.T) {
	// Need a private key to sign the claim
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	// add a bunch of claims
	claims.Data["foo"] = "bar"

	// serialize the claim to a JWT token
	token, err := claims.Encode(akp)
	if err != nil {
		t.Fatal("error encoding token", err)
	}

	// on the receiving side, decode the token
	c, err := DecodeGeneric(token)
	if err != nil {
		t.Fatal(err)
	}

	// if the token was decoded, it means that it
	// validated and it wasn't tampered. the remaining and
	// required test is to insure the issuer is trusted
	pk, err := akp.PublicKey()
	if err != nil {
		t.Fatalf("unable to read public key: %v", err)
	}

	if c.Issuer != pk {
		t.Fatalf("the public key is not trusted")
	}
}

func TestBadHeaderEncoding(t *testing.T) {
	// the '=' will be illegal
	_, err := parseHeaders("=hello=")
	if err == nil {
		t.Fatal("should have failed it is not encoded")
	}
}

func TestBadClaimsEncoding(t *testing.T) {
	// the '=' will be illegal
	c := GenericClaims{}
	err := parseClaims("=hello=", &c)
	if err == nil {
		t.Fatal("should have failed it is not encoded")
	}
}

func TestBadHeaderJSON(t *testing.T) {
	payload := encodeToString([]byte("{foo: bar}"))
	_, err := parseHeaders(payload)
	if err == nil {
		t.Fatal("should have failed bad json")
	}
}

func TestBadClaimsJSON(t *testing.T) {
	payload := encodeToString([]byte("{foo: bar}"))
	c := GenericClaims{}
	err := parseClaims(payload, &c)
	if err == nil {
		t.Fatal("should have failed bad json")
	}
}

func TestBadPublicKeyDecodeGeneric(t *testing.T) {
	c := &GenericClaims{}
	c.Issuer = "foo"
	if ok := c.verify("foo", []byte("bar")); ok {
		t.Fatal("Should have failed to verify")
	}
}

func TestBadSig(t *testing.T) {
	opk := createOperatorNKey(t)
	kp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(kp, t))
	claims.Data["foo"] = "bar"

	// serialize the claim to a JWT token
	token := encode(claims, opk, t)

	tokens := strings.Split(token, ".")
	badToken := fmt.Sprintf("%s.%s.=hello=", tokens[0], tokens[1])
	_, err := DecodeGeneric(badToken)
	if err == nil {
		t.Fatal("should have failed to base64  decode signature")
	}
}

func TestClaimsStringIsJSON(t *testing.T) {
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	// add a bunch of claims
	claims.Data["foo"] = "bar"

	claims2 := NewGenericClaims(publicKey(akp, t))
	json.Unmarshal([]byte(claims.String()), claims2)
	if claims2.Data["foo"] != "bar" {
		t.Fatalf("Failed to decode expected claim from String representation: %q", claims.String())
	}
}

func TestDoEncodeNilHeader(t *testing.T) {
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	_, err := claims.doEncode(nil, nil, claims)
	if err == nil {
		t.Fatal("should have failed to encode")
	}
	if err.Error() != "header is required" {
		t.Fatalf("unexpected error on encode: %v", err)
	}
}

func TestDoEncodeNilKeyPair(t *testing.T) {
	akp := createAccountNKey(t)
	claims := NewGenericClaims(publicKey(akp, t))
	_, err := claims.doEncode(&Header{}, nil, claims)
	if err == nil {
		t.Fatal("should have failed to encode")
	}
	if err.Error() != "keypair is required" {
		t.Fatalf("unexpected error on encode: %v", err)
	}
}

// if this fails, the URL decoder was changed and JWTs will flap
func TestUsingURLDecoder(t *testing.T) {
	token := "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJGQ1lZRjJLR0EzQTZHTlZQR0pIVjNUSExYR1VZWkFUREZLV1JTT1czUUo1T0k3QlJST0ZRIiwiaWF0IjoxNTQzOTQzNjc1LCJpc3MiOiJBQ1NKWkhOWlI0QUFUVE1KNzdUV1JONUJHVUZFWFhUS0gzWEtGTldDRkFCVzJRWldOUTRDQkhRRSIsInN1YiI6IkFEVEFHWVZYRkpPRENRM0g0VUZQQU43R1dXWk1BVU9FTTJMMkRWQkFWVFdLM01TU0xUS1JUTzVGIiwidHlwZSI6ImFjdGl2YXRpb24iLCJuYXRzIjp7InN1YmplY3QiOiJmb28iLCJ0eXBlIjoic2VydmljZSJ9fQ.HCZTCF-7wolS3Wjx3swQWMkoDhoo_4gp9EsuM5diJfZrH8s6NTpO0iT7_fKZm7dNDeEoqjwU--3ebp8j-Mm_Aw"
	ac, err := DecodeActivationClaims(token)
	if err != nil {
		t.Fatal("shouldn't have failed to decode", err)
	}
	if ac == nil {
		t.Fatal("should have returned activation")
	}
}
