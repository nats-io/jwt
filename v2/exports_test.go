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
	"sort"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func TestSimpleExportValidation(t *testing.T) {
	e := &Export{Subject: "foo", Type: Stream, Info: Info{InfoURL: "http://localhost/foo/bar", Description: "description"}}

	vr := CreateValidationResults()
	e.Validate(vr)

	if !vr.IsEmpty() {
		t.Errorf("simple export should validate cleanly")
	}

	e.Type = Service
	vr = CreateValidationResults()
	e.Validate(vr)

	if !vr.IsEmpty() {
		t.Errorf("simple export should validate cleanly")
	}
}

func TestResponseTypeValidation(t *testing.T) {
	e := &Export{Subject: "foo", Type: Stream, ResponseType: ResponseTypeSingleton}

	vr := CreateValidationResults()
	e.Validate(vr)

	if vr.IsEmpty() {
		t.Errorf("response type on stream should have an validation issue")
	}
	if e.IsSingleResponse() {
		t.Errorf("response type should always fail for stream")
	}

	e.Type = Service
	vr = CreateValidationResults()
	e.Validate(vr)
	if !vr.IsEmpty() {
		t.Errorf("response type on service should validate cleanly")
	}
	if !e.IsSingleResponse() || e.IsChunkedResponse() || e.IsStreamResponse() {
		t.Errorf("response type should be single")
	}

	e.ResponseType = ResponseTypeChunked
	vr = CreateValidationResults()
	e.Validate(vr)
	if !vr.IsEmpty() {
		t.Errorf("response type on service should validate cleanly")
	}
	if e.IsSingleResponse() || !e.IsChunkedResponse() || e.IsStreamResponse() {
		t.Errorf("response type should be chunk")
	}

	e.ResponseType = ResponseTypeStream
	vr = CreateValidationResults()
	e.Validate(vr)
	if !vr.IsEmpty() {
		t.Errorf("response type on service should validate cleanly")
	}
	if e.IsSingleResponse() || e.IsChunkedResponse() || !e.IsStreamResponse() {
		t.Errorf("response type should be stream")
	}

	e.ResponseType = ""
	vr = CreateValidationResults()
	e.Validate(vr)
	if !vr.IsEmpty() {
		t.Errorf("response type on service should validate cleanly")
	}
	if !e.IsSingleResponse() || e.IsChunkedResponse() || e.IsStreamResponse() {
		t.Errorf("response type should be single")
	}

	e.ResponseType = "bad"
	vr = CreateValidationResults()
	e.Validate(vr)
	if vr.IsEmpty() {
		t.Errorf("response type should match available options")
	}
	if e.IsSingleResponse() || e.IsChunkedResponse() || e.IsStreamResponse() {
		t.Errorf("response type should be bad")
	}
}

func TestInvalidExportType(t *testing.T) {
	i := &Export{Subject: "foo", Type: Unknown}

	vr := CreateValidationResults()
	i.Validate(vr)

	if vr.IsEmpty() {
		t.Errorf("export with bad type should not validate cleanly")
	}

	if !vr.IsBlocking(true) {
		t.Errorf("invalid type is blocking")
	}
}

func TestInvalidExportInfo(t *testing.T) {
	e := &Export{Subject: "foo", Type: Stream, Info: Info{InfoURL: "/bad"}}
	vr := CreateValidationResults()
	e.Validate(vr)
	if vr.IsEmpty() {
		t.Errorf("export info should not validate cleanly")
	}
	if !vr.IsBlocking(true) {
		t.Errorf("invalid info needs to be blocking")
	}
}

func TestOverlappingExports(t *testing.T) {
	i := &Export{Subject: "bar.foo", Type: Stream}
	i2 := &Export{Subject: "bar.*", Type: Stream}

	exports := &Exports{}
	exports.Add(i, i2)

	vr := CreateValidationResults()
	exports.Validate(vr)

	if len(vr.Issues) != 1 {
		t.Errorf("export has overlapping subjects")
	}
}

func TestDifferentExportTypes_OverlapOK(t *testing.T) {
	i := &Export{Subject: "bar.foo", Type: Service}
	i2 := &Export{Subject: "bar.*", Type: Stream}

	exports := &Exports{}
	exports.Add(i, i2)

	vr := CreateValidationResults()
	exports.Validate(vr)

	if len(vr.Issues) != 0 {
		t.Errorf("should allow overlaps on different export kind")
	}
}

func TestDifferentExportTypes_SameSubjectOK(t *testing.T) {
	i := &Export{Subject: "bar", Type: Service}
	i2 := &Export{Subject: "bar", Type: Stream}

	exports := &Exports{}
	exports.Add(i, i2)

	vr := CreateValidationResults()
	exports.Validate(vr)

	if len(vr.Issues) != 0 {
		t.Errorf("should allow overlaps on different export kind")
	}
}

func TestSameExportType_SameSubject(t *testing.T) {
	i := &Export{Subject: "bar", Type: Service}
	i2 := &Export{Subject: "bar", Type: Service}

	exports := &Exports{}
	exports.Add(i, i2)

	vr := CreateValidationResults()
	exports.Validate(vr)

	if len(vr.Issues) != 1 {
		t.Errorf("should not allow same subject on same export kind")
	}
}

func TestExportRevocation(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	account := NewAccountClaims(apk)
	e := &Export{Subject: "foo", Type: Stream}

	account.Exports.Add(e)

	ikp := createAccountNKey(t)
	pubKey := publicKey(ikp, t)

	ac := NewActivationClaims(pubKey)
	ac.IssuerAccount = apk
	ac.Name = "foo"
	ac.Activation.ImportSubject = "foo"
	ac.Activation.ImportType = Stream
	aJwt, _ := ac.Encode(akp)
	ac, err := DecodeActivationClaims(aJwt)
	if err != nil {
		t.Errorf("Failed to decode activation claim: %v", err)
	}

	now := time.Now()

	// test that clear is safe before we add any
	e.ClearRevocation(pubKey)

	if e.isRevoked(pubKey, now) {
		t.Errorf("no revocation was added so is revoked should be false")
	}

	e.RevokeAt(pubKey, now.Add(time.Second*100))

	if !e.isRevoked(pubKey, now) {
		t.Errorf("revocation should hold when timestamp is in the future")
	}

	if e.isRevoked(pubKey, now.Add(time.Second*150)) {
		t.Errorf("revocation should time out")
	}

	e.RevokeAt(pubKey, now.Add(time.Second*50)) // shouldn't change the revocation, you can't move it in

	if !e.isRevoked(pubKey, now.Add(time.Second*60)) {
		t.Errorf("revocation should hold, 100 > 50")
	}

	encoded, _ := account.Encode(akp)
	decoded, _ := DecodeAccountClaims(encoded)

	if !decoded.Exports[0].isRevoked(pubKey, now.Add(time.Second*60)) {
		t.Errorf("revocation should last across encoding")
	}

	e.ClearRevocation(pubKey)

	if e.IsClaimRevoked(ac) {
		t.Errorf("revocations should be cleared")
	}

	e.RevokeAt(pubKey, now)

	if !e.IsClaimRevoked(ac) {
		t.Errorf("revocation be true we revoked in the future")
	}
}

func TestExportTrackLatency(t *testing.T) {
	e := &Export{Subject: "foo", Type: Service}
	e.Latency = &ServiceLatency{Sampling: 100, Results: "results"}
	vr := CreateValidationResults()
	e.Validate(vr)
	if !vr.IsEmpty() {
		t.Errorf("Expected to validate with simple tracking")
	}

	e = &Export{Subject: "foo", Type: Service}
	e.Latency = &ServiceLatency{Sampling: Headers, Results: "results"}
	vr = CreateValidationResults()
	e.Validate(vr)
	if !vr.IsEmpty() {
		t.Errorf("Headers must not need to ")
	}

	e = &Export{Subject: "foo", Type: Stream}
	e.Latency = &ServiceLatency{Sampling: 100, Results: "results"}
	vr = CreateValidationResults()
	e.Validate(vr)
	if vr.IsEmpty() {
		t.Errorf("adding latency tracking to a stream should have an validation issue")
	}

	e = &Export{Subject: "foo", Type: Service}
	e.Latency = &ServiceLatency{Sampling: -1, Results: "results"}
	vr = CreateValidationResults()
	e.Validate(vr)
	if vr.IsEmpty() {
		t.Errorf("Sampling <1 should have a validation issue")
	}

	e = &Export{Subject: "foo", Type: Service}
	e.Latency = &ServiceLatency{Sampling: 122, Results: "results"}
	vr = CreateValidationResults()
	e.Validate(vr)
	if vr.IsEmpty() {
		t.Errorf("Sampling >100 should have a validation issue")
	}

	e = &Export{Subject: "foo", Type: Service}
	e.Latency = &ServiceLatency{Sampling: 22, Results: "results.*"}
	vr = CreateValidationResults()
	e.Validate(vr)
	if vr.IsEmpty() {
		t.Errorf("Results subject needs to be valid publish subject")
	}
}

func TestExportTrackHeader(t *testing.T) {
	akp, err := nkeys.CreateAccount()
	AssertNoError(err, t)
	apk, err := akp.PublicKey()
	AssertNoError(err, t)
	ac := NewAccountClaims(apk)
	e := &Export{Subject: "foo", Type: Service}
	e.Latency = &ServiceLatency{Sampling: Headers, Results: "results"}
	ac.Exports.Add(e)
	theJWT, err := ac.Encode(akp)
	AssertNoError(err, t)
	ac2, err := DecodeAccountClaims(theJWT)
	AssertNoError(err, t)
	if *(ac2.Exports[0].Latency) != *e.Latency {
		t.Errorf("Headers need to de serialize as headers")
	}
}

func TestExport_Sorting(t *testing.T) {
	var exports Exports
	exports.Add(&Export{Subject: "x", Type: Service})
	exports.Add(&Export{Subject: "z", Type: Service})
	exports.Add(&Export{Subject: "y", Type: Service})

	if exports[0] == nil || exports[0].Subject != "x" {
		t.Fatal("added export not in expected order")
	}
	sort.Sort(exports)
	if exports[0].Subject != "x" && exports[1].Subject != "y" && exports[2].Subject != "z" {
		t.Fatal("exports not sorted")
	}
}

func TestExportAccountTokenPos(t *testing.T) {
	okp := createOperatorNKey(t)
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	tbl := map[Subject]uint{
		"*":           1,
		"foo.*":       2,
		"foo.*.bar.*": 2,
		"foo.*.bar.>": 2,
		"*.*.*.>":     2,
		"*.*.>":       1,
	}
	for k, v := range tbl {
		t.Run(string(k), func(t *testing.T) {
			account := NewAccountClaims(apk)
			//account.Limits = OperatorLimits{}
			account.Exports = append(account.Exports,
				&Export{Type: Stream, Subject: k, AccountTokenPosition: v})
			actJwt := encode(account, okp, t)
			account2, err := DecodeAccountClaims(actJwt)
			if err != nil {
				t.Fatal("error decoding account jwt", err)
			}
			AssertEquals(account.String(), account2.String(), t)
			vr := &ValidationResults{}
			account2.Validate(vr)
			if len(vr.Issues) != 0 {
				t.Fatal("validation issues", *vr)
			}
		})
	}
}

func TestExportAccountTokenPosFail(t *testing.T) {
	okp := createOperatorNKey(t)
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)
	tbl := map[Subject]uint{
		">":          5,
		"foo.>":      2,
		"bar.>":      1,
		"*":          5,
		"*.*":        5,
		"bar":        1,
		"foo.bar":    2,
		"foo.*.bar":  3,
		"*.>":        3,
		"*.*.>":      3,
		"foo.*x.bar": 2,
		"foo.x*.bar": 2,
	}
	for k, v := range tbl {
		t.Run(string(k), func(t *testing.T) {
			account := NewAccountClaims(apk)
			//account.Limits = OperatorLimits{}
			account.Exports = append(account.Exports,
				&Export{Type: Stream, Subject: k, AccountTokenPosition: v})
			actJwt := encode(account, okp, t)
			account2, err := DecodeAccountClaims(actJwt)
			if err != nil {
				t.Fatal("error decoding account jwt", err)
			}
			AssertEquals(account.String(), account2.String(), t)
			vr := &ValidationResults{}
			account2.Validate(vr)
			if len(vr.Issues) != 1 {
				t.Fatal("validation issue expected", *vr)
			}
		})
	}
}

func TestExport_ResponseThreshold(t *testing.T) {
	var exports Exports
	exports.Add(&Export{Subject: "x", Type: Service, ResponseThreshold: time.Second})
	vr := ValidationResults{}
	exports.Validate(&vr)
	if !vr.IsEmpty() {
		t.Fatal("expected this to pass")
	}

	exports = Exports{}
	exports.Add(&Export{Subject: "x", Type: Stream, ResponseThreshold: time.Second})
	vr = ValidationResults{}
	exports.Validate(&vr)
	if vr.IsEmpty() {
		t.Fatal("expected this to fail due to type")
	}

	exports = Exports{}
	exports.Add(&Export{Subject: "x", Type: Service, ResponseThreshold: -1 * time.Second})
	vr = ValidationResults{}
	exports.Validate(&vr)
	if vr.IsEmpty() {
		t.Fatal("expected this to fail due to negative duration")
	}
}
