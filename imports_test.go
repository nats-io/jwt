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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestImportValidation(t *testing.T) {
	ak := createAccountNKey(t)
	ak2 := createAccountNKey(t)
	akp := publicKey(ak, t)
	akp2 := publicKey(ak2, t)
	i := &Import{RemoteSubject: "test", Account: akp2, LocalSubject: "bar", Type: Stream}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	i.Type = Service
	vr = CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()

	activation.ImportSubject = "test"
	activation.ImportType = Stream
	actJWT := encode(activation, ak2, t)

	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with token should be valid")
	}
}

func TestInvalidImportType(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{RemoteSubject: "foo", Account: akp, LocalSubject: "bar", Type: Unknown}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if !vr.IsBlocking(true) {
		t.Errorf("invalid type is blocking")
	}
}

func TestInvalidImportToken(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{RemoteSubject: "foo", Account: akp, Token: "bad token", LocalSubject: "bar", Type: Stream}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports with a bad token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("invalid type shouldnt be blocking")
	}
}

func TestInvalidImportURL(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{RemoteSubject: "foo", Account: akp, Token: "foo://bad token url", LocalSubject: "bar", Type: Stream}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports with a bad token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("invalid type shouldnt be blocking")
	}
}

func TestInvalidImportTokenValuesValidation(t *testing.T) {
	ak := createAccountNKey(t)
	ak2 := createAccountNKey(t)
	akp := publicKey(ak, t)
	akp2 := publicKey(ak2, t)
	i := &Import{RemoteSubject: "test", Account: akp2, LocalSubject: "bar", Type: Stream}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	i.Type = Service
	vr = CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()

	activation.ImportSubject = "test"
	activation.ImportType = Stream
	actJWT := encode(activation, ak2, t)

	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with token should be valid")
	}

	actJWT = encode(activation, ak, t) // wrong issuer
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with wrong issuer")
	}

	activation.Subject = akp2           // wrong subject
	actJWT = encode(activation, ak2, t) // right issuer
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with wrong issuer")
	}
}
func TestMissingAccountInImport(t *testing.T) {
	i := &Import{RemoteSubject: "foo", LocalSubject: "bar", Type: Stream}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if len(vr.Issues) != 2 {
		t.Errorf("imports without token or url should warn the caller, as should missing account")
	}

	if vr.IsBlocking(true) {
		t.Errorf("Missing Account is not blocking, must import failures are warnings")
	}
}

func TestServiceImportWithWildcard(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{RemoteSubject: "foo.*", Account: akp, LocalSubject: "bar", Type: Service}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if len(vr.Issues) != 1 {
		t.Errorf("imports without token should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}
}

func TestImportsValidation(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{RemoteSubject: "foo", Account: akp, LocalSubject: "bar", Type: Stream}
	i2 := &Import{RemoteSubject: "foo.*", Account: akp, LocalSubject: "bar", Type: Service}

	imports := &Imports{}
	imports.Add(i, i2)

	vr := CreateValidationResults()
	imports.Validate("", vr)

	if len(vr.Issues) != 2 {
		t.Errorf("imports without token or url should warn the caller x2")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}
}

func TestTokenURLImportValidation(t *testing.T) {
	ak := createAccountNKey(t)
	ak2 := createAccountNKey(t)
	akp := publicKey(ak, t)
	akp2 := publicKey(ak2, t)
	i := &Import{RemoteSubject: "test", Account: akp2, LocalSubject: "bar", Type: Stream}

	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.ImportSubject = "test"
	activation.ImportType = Stream

	actJWT := encode(activation, ak2, t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(actJWT))
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()

	i.Token = ts.URL
	vr := CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		fmt.Printf("vr is %+v\n", vr)
		t.Errorf("imports with token url should be valid")
	}

	i.Token = "http://Bad URL"
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with bad token url should be valid")
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("bad jwt"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()

	i.Token = ts.URL
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with token url pointing to bad JWT")
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	i.Token = ts.URL
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with token url pointing to bad url")
	}
}

func TestImportSubjectValidation(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.ImportSubject = "one.*"
	activation.ImportType = Stream

	ak2 := createAccountNKey(t)
	akp2 := publicKey(ak2, t)
	i := &Import{RemoteSubject: "one.two", Account: akp2, LocalSubject: "bar", Type: Stream}

	actJWT := encode(activation, ak2, t)
	i.Token = actJWT
	vr := CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Log(vr.Issues[0].Description)
		t.Errorf("imports with valid contains subject should be valid")
	}

	activation.ImportSubject = "two"
	activation.ImportType = Stream
	actJWT = encode(activation, ak2, t)
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with non-contains subject should be not valid")
	}

	activation.ImportSubject = ">"
	activation.ImportType = Stream
	actJWT = encode(activation, ak2, t)
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with valid contains subject should be valid")
	}
}

func TestImport_Migration(t *testing.T) {
	ak := createAccountNKey(t)
	apk := publicKey(ak, t)
	ac := NewAccountClaims(apk)

	a2k := createAccountNKey(t)
	a2pk := publicKey(a2k, t)
	// Do not update Subject or To
	i := &Import{Subject: "foo", Account: a2pk, To: "bar", Type: Service}
	ac.Imports.Add(i)
	// Do not update Subject or To
	i2 := &Import{Subject: "x", Account: a2pk, To: "y", Type: Stream}
	ac.Imports.Add(i2)

	token, err := ac.Encode(ak)
	if err != nil {
		t.Fatal(err)
	}

	ac2, err := DecodeAccountClaims(token)
	if err != nil {
		t.Fatal(err)
	}

	if ac2.Migrated() == false {
		t.Fatal("account claim should have migrated")
	}

	for _, i := range ac2.Imports {
		if i.RemoteSubject == "" {
			t.Fatal("import 'remote_subject' should be set when old token was loaded")
		}
		if i.Subject != "" {
			t.Fatalf("import 'subject' shouldn't be set when old token was loaded: %s", i.Subject)
		}
		if i.LocalSubject == "" {
			t.Fatal("import 'local_subject' should be set when old token was loaded")
		}
		if i.To != "" {
			t.Fatalf("import 'to' shouldn't be set when old token was loaded: %s", i.To)
		}
	}

	if ac2.Imports[0].RemoteSubject != "foo" && ac2.Imports[0].LocalSubject != "bar" {
		t.Fatal("import remapped subjects don't match expected")
	}
	if ac2.Imports[1].RemoteSubject != "x" && ac2.Imports[1].LocalSubject != "y" {
		t.Fatal("import remapped subjects don't match expected")
	}
}

func TestImport_Mix(t *testing.T) {
	ak := createAccountNKey(t)
	apk := publicKey(ak, t)
	ac := NewAccountClaims(apk)

	a2k := createAccountNKey(t)
	a2pk := publicKey(a2k, t)
	// Do not update Subject or To
	i := &Import{Subject: "foo", Account: a2pk, To: "bar", RemoteSubject: "foo", LocalSubject: "bar", Type: Service}
	ac.Imports.Add(i)

	token, err := ac.Encode(ak)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecodeAccountClaims(token)
	if err == nil {
		t.Fatal("should have failed decoding")
	}
}
