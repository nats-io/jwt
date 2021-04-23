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
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func makeJWT(t *testing.T) (string, nkeys.KeyPair) {
	akp := createAccountNKey(t)
	kp := createUserNKey(t)
	pk := publicKey(kp, t)
	oc := NewUserClaims(pk)
	token, err := oc.Encode(akp)
	if err != nil {
		t.Fatal(err)
	}
	return token, kp
}

func Test_DecorateJwt(t *testing.T) {
	token, _ := makeJWT(t)
	d, err := DecorateJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	s := string(d)
	if !strings.Contains(s, "-BEGIN NATS USER JWT-") {
		t.Fatal("doesn't contain expected header")
	}
	if !strings.Contains(s, "eyJ0") {
		t.Fatal("doesn't contain public key")
	}
	if !strings.Contains(s, "-END NATS USER JWT------\n\n") {
		t.Fatal("doesn't contain expected footer")
	}
}

func Test_FormatUserConfig(t *testing.T) {
	token, kp := makeJWT(t)
	d, err := FormatUserConfig(token, seedKey(kp, t))
	if err != nil {
		t.Fatal(err)
	}
	s := string(d)
	if !strings.Contains(s, "-BEGIN NATS USER JWT-") {
		t.Fatal("doesn't contain expected header")
	}
	if !strings.Contains(s, "eyJ0") {
		t.Fatal("doesn't contain public key")
	}
	if !strings.Contains(s, "-END NATS USER JWT-") {
		t.Fatal("doesn't contain expected footer")
	}

	validateSeed(t, d, kp)
}

func validateSeed(t *testing.T, decorated []byte, nk nkeys.KeyPair) {
	kind := ""
	seed := seedKey(nk, t)
	switch string(seed[0:2]) {
	case "SO":
		kind = "operator"
	case "SA":
		kind = "account"
	case "SU":
		kind = "user"
	default:
		kind = "not supported"
	}
	kind = strings.ToUpper(kind)

	s := string(decorated)
	if !strings.Contains(s, fmt.Sprintf("\n\n-----BEGIN %s NKEY SEED-", kind)) {
		t.Fatal("doesn't contain expected seed header")
	}
	if !strings.Contains(s, string(seed)) {
		t.Fatal("doesn't contain the seed")
	}
	if !strings.Contains(s, fmt.Sprintf("-END %s NKEY SEED------\n\n", kind)) {
		t.Fatal("doesn't contain expected seed footer")
	}
}

func Test_ParseDecoratedJWT(t *testing.T) {
	token, _ := makeJWT(t)

	t2, err := ParseDecoratedJWT([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	if token != t2 {
		t.Fatal("jwt didn't match expected")
	}

	decorated, err := DecorateJWT(token)
	if err != nil {
		t.Fatal(err)
	}

	t3, err := ParseDecoratedJWT(decorated)
	if err != nil {
		t.Fatal(err)
	}
	if token != t3 {
		t.Fatal("parse decorated jwt didn't match expected")
	}
}

func Test_ParseDecoratedJWTBad(t *testing.T) {
	v, err := ParseDecoratedJWT([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if v != "foo" {
		t.Fatal("unexpected input was not returned")
	}
}

func Test_ParseDecoratedOPJWT(t *testing.T) {
	content := []string{
`-----BEGIN TEST OPERATOR JWT-----
eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJhdWQiOiJURVNUUyIsImV4cCI6MTg1OTEyMTI3NSwianRpIjoiWE5MWjZYWVBIVE1ESlFSTlFPSFVPSlFHV0NVN01JNVc1SlhDWk5YQllVS0VRVzY3STI1USIsImlhdCI6MTU0Mzc2MTI3NSwiaXNzIjoiT0NBVDMzTVRWVTJWVU9JTUdOR1VOWEo2NkFIMlJMU0RBRjNNVUJDWUFZNVFNSUw2NU5RTTZYUUciLCJuYW1lIjoiU3luYWRpYSBDb21tdW5pY2F0aW9ucyBJbmMuIiwibmJmIjoxNTQzNzYxMjc1LCJzdWIiOiJPQ0FUMzNNVFZVMlZVT0lNR05HVU5YSjY2QUgyUkxTREFGM01VQkNZQVk1UU1JTDY1TlFNNlhRRyIsInR5cGUiOiJvcGVyYXRvciIsIm5hdHMiOnsic2lnbmluZ19rZXlzIjpbIk9EU0tSN01ZRlFaNU1NQUo2RlBNRUVUQ1RFM1JJSE9GTFRZUEpSTUFWVk40T0xWMllZQU1IQ0FDIiwiT0RTS0FDU1JCV1A1MzdEWkRSVko2NTdKT0lHT1BPUTZLRzdUNEhONk9LNEY2SUVDR1hEQUhOUDIiLCJPRFNLSTM2TFpCNDRPWTVJVkNSNlA1MkZaSlpZTVlXWlZXTlVEVExFWjVUSzJQTjNPRU1SVEFCUiJdfX0.hyfz6E39BMUh0GLzovFfk3wT4OfualftjdJ_eYkLfPvu5tZubYQ_Pn9oFYGCV_6yKy3KMGhWGUCyCdHaPhalBw
------END TEST OPERATOR JWT------`,
`-----BEGIN TEST OPERATOR JWT-----
eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJKV01TUzNRUFpDS0lHSE1BWko3RUpQSlVHN01DTFNQUkJaTEpSUUlRQkRVTkFaUE5MQVVBIiwiaWF0IjoxNTY1ODg5NzEyLCJpc3MiOiJPQU01VlNINDJXRlZWTkpXNFNMRTZRVkpCREpVRTJGUVNYWkxRTk1SRDdBMlBaTTIzTDIyWFlVWSIsIm5hbWUiOiJzeW5hZGlhIiwic3ViIjoiT0FNNVZTSDQyV0ZWVk5KVzRTTEU2UVZKQkRKVUUyRlFTWFpMUU5NUkQ3QTJQWk0yM0wyMlhZVVkiLCJ0eXBlIjoib3BlcmF0b3IiLCJuYXRzIjp7ImFjY291bnRfc2VydmVyX3VybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjA2MC9qd3QvdjEiLCJvcGVyYXRvcl9zZXJ2aWNlX3VybHMiOlsibmF0czovL2xvY2FsaG9zdDo0MTQxIl19fQ.XPvAezQj3AxwEvYLVBq-EIssP4OhjoMGLbIaripzBKv1oCtHdPNKz96YwB2vUoY-4OrN9ZOPo9TKR3jVxq0uBQ
------END TEST OPERATOR JWT------`}
	test := func(content string) {
		t.Helper()
		v, err := ParseDecoratedJWT([]byte(content))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(v, "eyJ") {
			t.Fatal("unexpected input was not returned")
		}
	}
	for i, cont := range content {
		t.Run( fmt.Sprintf("%d", i), func(t *testing.T) {
			test(cont)
		})
		t.Run( fmt.Sprintf("%d-win", i), func(t *testing.T) {
			test(strings.ReplaceAll(cont, "\n", "\r\n"))
		})
		cont = cont + "\n"
		t.Run( fmt.Sprintf("%d-trail-nl", i), func(t *testing.T) {
			test(cont)
		})
		t.Run( fmt.Sprintf("%d-trail-nl-win", i), func(t *testing.T) {
			test(strings.ReplaceAll(cont, "\n", "\r\n"))
		})
	}
}


func Test_ParseDecoratedSeed(t *testing.T) {
	token, ukp := makeJWT(t)
	us := seedKey(ukp, t)
	decorated, err := FormatUserConfig(token, us)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := ParseDecoratedUserNKey(decorated)
	if err != nil {
		t.Fatal(err)
	}
	pu := seedKey(kp, t)
	if !bytes.Equal(us, pu) {
		t.Fatal("seeds don't match")
	}
}

func Test_ParseDecoratedBadKey(t *testing.T) {
	token, ukp := makeJWT(t)
	us, err := ukp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	akp := createAccountNKey(t)
	as := seedKey(akp, t)

	_, err = FormatUserConfig(token, as)
	if err == nil {
		t.Fatal("should have failed to encode with bad seed")
	}

	sc, err := FormatUserConfig(token, us)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(sc), string(us), string(as), -1)
	_, err = ParseDecoratedUserNKey([]byte(bad))
	if err == nil {
		t.Fatal("parse should have failed for non user nkey")
	}
}

func Test_FailsOnNonUserJWT(t *testing.T) {
	akp := createAccountNKey(t)
	pk := publicKey(akp, t)

	ac := NewAccountClaims(pk)
	token, err := ac.Encode(akp)
	if err != nil {
		t.Fatal(err)
	}
	ukp := createUserNKey(t)
	us := seedKey(ukp, t)
	_, err = FormatUserConfig(token, us)
	if err == nil {
		t.Fatal("should have failed with account claims")
	}
}

func Test_DecorateNKeys(t *testing.T) {
	var kps []nkeys.KeyPair
	kps = append(kps, createOperatorNKey(t))
	kps = append(kps, createAccountNKey(t))
	kps = append(kps, createUserNKey(t))

	for _, kp := range kps {
		seed := seedKey(kp, t)
		d, err := DecorateSeed(seed)
		if err != nil {
			t.Fatal(err, string(seed))
		}
		validateSeed(t, d, kp)

		kp2, err := ParseDecoratedNKey(d)
		if err != nil {
			t.Fatal(string(seed), err)
		}
		seed2 := seedKey(kp2, t)
		if !bytes.Equal(seed, seed2) {
			t.Fatalf("seeds dont match %q != %q", string(seed), string(seed2))
		}
	}

	_, err := ParseDecoratedNKey([]byte("bad"))
	if err == nil {
		t.Fatal("required error parsing bad nkey")
	}
}

func Test_ParseCreds(t *testing.T) {
	token, kp := makeJWT(t)
	d, err := FormatUserConfig(token, seedKey(kp, t))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	token2, err := ParseDecoratedJWT(d)
	if err != nil {
		t.Fatal(err)
	}
	if token != token2 {
		t.Fatal("expected jwts to match")
	}
	kp2, err := ParseDecoratedUserNKey(d)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := kp2.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if pk != pk2 {
		t.Fatal("expected keys to match")
	}
}

func Test_ParseCredsWithCrLfs(t *testing.T) {
	token, kp := makeJWT(t)
	d, err := FormatUserConfig(token, seedKey(kp, t))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	d = bytes.ReplaceAll(d, []byte{'\n'}, []byte{'\r', '\n'})

	token2, err := ParseDecoratedJWT(d)
	if err != nil {
		t.Fatal(err)
	}
	if token != token2 {
		t.Fatal("expected jwts to match")
	}
	kp2, err := ParseDecoratedUserNKey(d)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := kp2.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if pk != pk2 {
		t.Fatal("expected keys to match")
	}
}
