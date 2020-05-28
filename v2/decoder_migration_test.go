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
	"strings"
	"testing"
	"time"

	v1jwt "github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

func createExport(sub string) *v1jwt.Export {
	var e v1jwt.Export
	e.Type = v1jwt.Service
	e.Subject = v1jwt.Subject(sub)
	e.Name = "foo"
	e.TokenReq = true
	e.ResponseType = v1jwt.ResponseTypeSingleton
	return &e
}

func createImport(t *testing.T, e *v1jwt.Export, target string, signer nkeys.KeyPair) *v1jwt.Import {
	var i v1jwt.Import
	i.Account = target
	i.Subject = e.Subject
	i.Type = e.Type
	i.Name = e.Name
	if e.TokenReq {
		i.Token = createActivation(t, e, target, signer)
		i.To = v1jwt.Subject(e.Name)
	}
	return &i
}

func createActivation(t *testing.T, e *v1jwt.Export, target string, signer nkeys.KeyPair) string {
	ac := v1jwt.NewActivationClaims(target)
	ac.Name = e.Name
	ac.ImportType = e.Type
	s := strings.Replace(string(e.Subject), "*", target, -1)
	ac.ImportSubject = v1jwt.Subject(s)
	tok, err := ac.Encode(signer)
	AssertNoError(err, t)
	return tok
}

func TestMigrateOperator(t *testing.T) {
	okp, err := nkeys.CreateOperator()
	AssertNoError(err, t)

	opk, err := okp.PublicKey()
	AssertNoError(err, t)

	sapk, err := okp.PublicKey()
	AssertNoError(err, t)

	oc := v1jwt.NewOperatorClaims(opk)
	oc.Name = "O"
	oc.Audience = "Audience"

	now := time.Now()
	oc.NotBefore = now.Unix()
	e := now.Add(time.Hour)
	oc.ClaimsData.Expires = e.Unix()

	oc.Tags.Add("a")

	oc.OperatorServiceURLs.Add("nats://localhost:4222")
	oc.AccountServerURL = "http://localhost:9090/jwt/v1"
	oc.SystemAccount = sapk

	sk, err := nkeys.CreateOperator()
	AssertNoError(err, t)
	psk, err := sk.PublicKey()
	AssertNoError(err, t)
	oc.Operator.SigningKeys.Add(psk)

	oc.Identities = append(oc.Identities, v1jwt.Identity{
		ID:    "O",
		Proof: "http://www.o.com/o",
	})

	token, err := oc.Encode(okp)
	AssertNoError(err, t)

	c, err := Decode(token)
	AssertNoError(err, t)
	oc2, ok := c.(*OperatorClaims)
	AssertTrue(ok, t)

	equalOperators(t, oc, oc2)
}

func TestMigrateAccount(t *testing.T) {
	okp, err := nkeys.CreateOperator()
	AssertNoError(err, t)

	akp, err := nkeys.CreateAccount()
	AssertNoError(err, t)
	apk, err := akp.PublicKey()
	AssertNoError(err, t)

	ac := v1jwt.NewAccountClaims(apk)
	ac.Name = "A"
	ac.Audience = "Audience"

	now := time.Now()
	ac.NotBefore = now.Unix()
	e := now.Add(time.Hour)
	ac.ClaimsData.Expires = e.Unix()
	ac.Tags.Add("a")

	// create an import
	ea, err := nkeys.CreateAccount()
	AssertNoError(err, t)
	hex := createExport("help")
	ac.Imports.Add(createImport(t, hex, apk, ea))

	// add an export
	ac.Exports = append(ac.Exports, createExport("q"))

	// add an identity
	ac.Identities = append(ac.Identities, v1jwt.Identity{
		ID:    "A",
		Proof: "http://www.a.com/a",
	})

	// set the limits
	ac.Limits.Subs = 1
	ac.Limits.Conn = 2
	ac.Limits.LeafNodeConn = 4
	ac.Limits.Imports = 8
	ac.Limits.Exports = 16
	ac.Limits.Data = 32
	ac.Limits.Payload = 64
	ac.Limits.WildcardExports = true

	// add a signing key
	sk, err := nkeys.CreateAccount()
	AssertNoError(err, t)
	psk, err := sk.PublicKey()
	AssertNoError(err, t)
	ac.Account.SigningKeys.Add(psk)

	// add a revocation
	ukp, err := nkeys.CreateUser()
	AssertNoError(err, t)
	upk, err := ukp.PublicKey()
	AssertNoError(err, t)
	ac.Revocations = make(map[string]int64)
	ac.Revocations.Revoke(upk, time.Now())

	token, err := ac.Encode(okp)
	AssertNoError(err, t)

	c, err := Decode(token)
	AssertNoError(err, t)
	ac2, ok := c.(*AccountClaims)
	AssertTrue(ok, t)
	equalAccounts(t, ac, ac2)
}

func TestMigrateUser(t *testing.T) {

	ukp, err := nkeys.CreateUser()
	AssertNoError(err, t)
	upk, err := ukp.PublicKey()
	AssertNoError(err, t)

	uc := v1jwt.NewUserClaims(upk)
	uc.Name = "U"
	uc.Audience = "Audience"

	now := time.Now()
	uc.NotBefore = now.Unix()
	e := now.Add(time.Hour)
	uc.ClaimsData.Expires = e.Unix()
	uc.Tags.Add("a")

	uc.Permissions.Sub.Allow.Add("q")
	uc.Permissions.Sub.Deny.Add("d")

	uc.Permissions.Pub.Allow.Add("help")
	uc.Permissions.Pub.Deny.Add("pleh")

	uc.Permissions.Resp = &v1jwt.ResponsePermission{}
	uc.Permissions.Resp.MaxMsgs = 100
	uc.Permissions.Resp.Expires = time.Second

	uc.BearerToken = true

	akp, err := nkeys.CreateAccount()
	AssertNoError(err, t)
	tok, err := uc.Encode(akp)
	AssertNoError(err, t)

	c, err := Decode(tok)
	AssertNoError(err, t)
	uc2, ok := c.(*UserClaims)
	AssertTrue(ok, t)

	equalUsers(t, uc, uc2)
}

func equalClaims(t *testing.T, o *v1jwt.ClaimsData, n *ClaimsData, gf *GenericFields) {
	AssertEquals(o.Subject, n.Subject, t)
	AssertEquals(o.Issuer, n.Issuer, t)
	AssertEquals(o.Name, n.Name, t)
	AssertEquals(o.Audience, n.Audience, t)
	AssertEquals(o.NotBefore, n.NotBefore, t)
	AssertEquals(o.Expires, n.Expires, t)
	AssertEquals(string(o.Type), string(gf.Type), t)
	AssertTrue(len(o.Tags) == len(gf.Tags), t)
	for _, v := range gf.Tags {
		AssertTrue(o.Tags.Contains(v), t)
	}
}

func equalOperators(t *testing.T, o *v1jwt.OperatorClaims, n *OperatorClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.GenericFields)
	for _, v := range o.OperatorServiceURLs {
		AssertTrue(n.OperatorServiceURLs.Contains(v), t)
	}
	for _, v := range o.SigningKeys {
		AssertTrue(n.Operator.SigningKeys.Contains(v), t)
	}

	AssertEquals(o.Identities[0].ID, n.Operator.Identities[0].ID, t)
	AssertEquals(o.Identities[0].Proof, n.Operator.Identities[0].Proof, t)
	AssertEquals(o.SystemAccount, o.Operator.SystemAccount, t)
}

func equalAccounts(t *testing.T, o *v1jwt.AccountClaims, n *AccountClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.GenericFields)
	equalImports(t, o.Imports[0], n.Imports[0])
	equalExports(t, o.Exports[0], n.Exports[0])
	AssertEquals(o.Identities[0].ID, n.Account.Identities[0].ID, t)
	AssertEquals(o.Identities[0].Proof, n.Account.Identities[0].Proof, t)
	equalLimits(t, &o.Account.Limits, &n.Account.Limits)
	for _, v := range o.SigningKeys {
		AssertTrue(n.Account.SigningKeys.Contains(v), t)
	}
}

func equalUsers(t *testing.T, o *v1jwt.UserClaims, n *UserClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.GenericFields)
	for _, v := range o.Sub.Allow {
		AssertTrue(n.Sub.Allow.Contains(v), t)
	}
	for _, v := range o.Pub.Allow {
		AssertTrue(n.Pub.Allow.Contains(v), t)
	}
	for _, v := range o.Sub.Deny {
		AssertTrue(n.Sub.Deny.Contains(v), t)
	}
	for _, v := range o.Pub.Deny {
		AssertTrue(n.Pub.Deny.Contains(v), t)
	}
	if o.User.Resp == nil {
		AssertNil(n.User.Resp, t)
	} else {
		AssertEquals(o.User.Resp.Expires, n.User.Resp.Expires, t)
		AssertEquals(o.User.Resp.MaxMsgs, n.User.Resp.MaxMsgs, t)
	}
	if o.IssuerAccount != "" {
		AssertEquals(o.IssuerAccount, n.User.IssuerAccount, t)
	}
	AssertEquals(o.User.BearerToken, n.User.BearerToken, t)
}

func equalExports(t *testing.T, o *v1jwt.Export, n *Export) {
	AssertEquals(o.Name, n.Name, t)
	AssertEquals(string(o.Subject), string(n.Subject), t)
	AssertEquals(int(o.Type), int(n.Type), t)
	AssertEquals(o.TokenReq, n.TokenReq, t)
	AssertEquals(string(o.ResponseType), string(n.ResponseType), t)
}

func equalImports(t *testing.T, o *v1jwt.Import, n *Import) {
	AssertEquals(o.Name, n.Name, t)
	AssertEquals(string(o.Subject), string(n.Subject), t)
	AssertEquals(string(o.To), string(n.To), t)
	AssertEquals(int(o.Type), int(n.Type), t)

	if o.Token != "" {
		ot, err := v1jwt.DecodeActivationClaims(o.Token)
		AssertNoError(err, t)
		nt, err := DecodeActivationClaims(n.Token)
		AssertNoError(err, t)
		equalActivation(t, ot, nt)
	}
}

func equalActivation(t *testing.T, o *v1jwt.ActivationClaims, n *ActivationClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.Activation.GenericFields)
	AssertEquals(string(o.ImportSubject), string(n.ImportSubject), t)
	AssertEquals(int(o.ImportType), int(n.ImportType), t)
}

func equalLimits(t *testing.T, o *v1jwt.OperatorLimits, n *OperatorLimits) {
	AssertEquals(o.Subs, n.Subs, t)
	AssertEquals(o.Conn, n.Conn, t)
	AssertEquals(o.LeafNodeConn, n.LeafNodeConn, t)
	AssertEquals(o.Imports, n.Imports, t)
	AssertEquals(o.Exports, n.Exports, t)
	AssertEquals(o.Data, n.Data, t)
	AssertEquals(o.Payload, n.Payload, t)
	AssertEquals(o.WildcardExports, n.WildcardExports, t)
}
