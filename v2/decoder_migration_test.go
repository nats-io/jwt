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
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	return tok
}

func TestMigrateOperator(t *testing.T) {
	okp, err := nkeys.CreateOperator()
	require.NoError(t, err)

	opk, err := okp.PublicKey()
	require.NoError(t, err)

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

	sk, err := nkeys.CreateOperator()
	require.NoError(t, err)
	psk, err := sk.PublicKey()
	require.NoError(t, err)
	oc.Operator.SigningKeys.Add(psk)

	oc.Identities = append(oc.Identities, v1jwt.Identity{
		ID:    "O",
		Proof: "http://www.o.com/o",
	})

	token, err := oc.Encode(okp)
	require.NoError(t, err)

	c, err := Decode(token)
	require.NoError(t, err)
	oc2, ok := c.(*OperatorClaims)
	require.True(t, ok)

	equalOperators(t, oc, oc2)
}

func TestMigrateAccount(t *testing.T) {
	okp, err := nkeys.CreateOperator()
	require.NoError(t, err)

	akp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	apk, err := akp.PublicKey()
	require.NoError(t, err)

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
	require.NoError(t, err)
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
	require.NoError(t, err)
	psk, err := sk.PublicKey()
	require.NoError(t, err)
	ac.Account.SigningKeys.Add(psk)

	// add a revocation
	ukp, err := nkeys.CreateUser()
	require.NoError(t, err)
	upk, err := ukp.PublicKey()
	require.NoError(t, err)
	ac.Revocations = make(map[string]int64)
	ac.Revocations.Revoke(upk, time.Now())

	token, err := ac.Encode(okp)
	require.NoError(t, err)

	c, err := Decode(token)
	require.NoError(t, err)
	ac2, ok := c.(*AccountClaims)
	require.True(t, ok)
	equalAccounts(t, ac, ac2)
}

func TestMigrateUser(t *testing.T) {

	ukp, err := nkeys.CreateUser()
	require.NoError(t, err)
	upk, err := ukp.PublicKey()
	require.NoError(t, err)

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
	require.NoError(t, err)
	tok, err := uc.Encode(akp)
	require.NoError(t, err)

	c, err := Decode(tok)
	require.NoError(t, err)
	uc2, ok := c.(*UserClaims)
	require.True(t, ok)

	equalUsers(t, uc, uc2)
}

func equalClaims(t *testing.T, o *v1jwt.ClaimsData, n *ClaimsData, gf *GenericFields) {
	require.Equal(t, o.Subject, n.Subject)
	require.Equal(t, o.Issuer, n.Issuer)
	require.Equal(t, o.Name, n.Name)
	require.Equal(t, o.Audience, n.Audience)
	require.Equal(t, o.NotBefore, n.NotBefore)
	require.Equal(t, o.Expires, n.Expires)
	require.Equal(t, string(o.Type), string(gf.Type))
	require.EqualValues(t, o.Tags, gf.Tags)
}

func equalOperators(t *testing.T, o *v1jwt.OperatorClaims, n *OperatorClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.GenericFields)
	for _, v := range o.OperatorServiceURLs {
		require.Contains(t, n.Operator.OperatorServiceURLs, v)
	}
	for _, v := range o.SigningKeys {
		require.Contains(t, n.Operator.SigningKeys, v)
	}

	require.Equal(t, o.Identities[0].ID, n.Operator.Identities[0].ID)
	require.Equal(t, o.Identities[0].Proof, n.Operator.Identities[0].Proof)
}

func equalAccounts(t *testing.T, o *v1jwt.AccountClaims, n *AccountClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.GenericFields)
	equalImports(t, o.Imports[0], n.Imports[0])
	equalExports(t, o.Exports[0], n.Exports[0])
	require.Equal(t, o.Identities[0].ID, n.Account.Identities[0].ID)
	require.Equal(t, o.Identities[0].Proof, n.Account.Identities[0].Proof)
	equalLimits(t, &o.Account.Limits, &n.Account.Limits)
	for _, v := range o.SigningKeys {
		require.Contains(t, n.Account.SigningKeys, v)
	}
}

func equalUsers(t *testing.T, o *v1jwt.UserClaims, n *UserClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.GenericFields)
	for _, v := range o.Sub.Allow {
		require.True(t, n.Sub.Allow.Contains(v))
	}
	for _, v := range o.Pub.Allow {
		require.True(t, n.Pub.Allow.Contains(v))
	}
	for _, v := range o.Sub.Deny {
		require.True(t, n.Sub.Deny.Contains(v))
	}
	for _, v := range o.Pub.Deny {
		require.True(t, n.Pub.Deny.Contains(v))
	}
	if o.User.Resp == nil {
		require.Nil(t, n.User.Resp)
	} else {
		require.Equal(t, o.User.Resp.Expires, n.User.Resp.Expires)
		require.Equal(t, o.User.Resp.MaxMsgs, n.User.Resp.MaxMsgs)
	}
	if o.IssuerAccount != "" {
		require.Equal(t, o.IssuerAccount, n.User.IssuerAccount)
	}
	require.Equal(t, o.User.BearerToken, n.User.BearerToken)
}

func equalExports(t *testing.T, o *v1jwt.Export, n *Export) {
	require.Equal(t, o.Name, n.Name)
	require.Equal(t, string(o.Subject), string(n.Subject))
	require.EqualValues(t, o.Type, n.Type)
	require.Equal(t, o.TokenReq, n.TokenReq)
	require.EqualValues(t, o.ResponseType, n.ResponseType)
}

func equalImports(t *testing.T, o *v1jwt.Import, n *Import) {
	require.Equal(t, o.Name, n.Name)
	require.Equal(t, string(o.Subject), string(n.Subject))
	require.Equal(t, string(o.To), string(n.To))
	require.EqualValues(t, o.Type, n.Type)

	if o.Token != "" {
		ot, err := v1jwt.DecodeActivationClaims(o.Token)
		require.NoError(t, err)
		nt, err := DecodeActivationClaims(n.Token)
		require.NoError(t, err)
		equalActivation(t, ot, nt)
	}
}

func equalActivation(t *testing.T, o *v1jwt.ActivationClaims, n *ActivationClaims) {
	equalClaims(t, &o.ClaimsData, &n.ClaimsData, &n.Activation.GenericFields)
	require.Equal(t, string(o.ImportSubject), string(n.ImportSubject))
	require.EqualValues(t, o.ImportType, n.ImportType)
}

func equalLimits(t *testing.T, o *v1jwt.OperatorLimits, n *OperatorLimits) {
	require.Equal(t, o.Subs, n.Subs)
	require.Equal(t, o.Conn, n.Conn)
	require.Equal(t, o.LeafNodeConn, n.LeafNodeConn)
	require.Equal(t, o.Imports, n.Imports)
	require.Equal(t, o.Exports, n.Exports)
	require.Equal(t, o.Data, n.Data)
	require.Equal(t, o.Payload, n.Payload)
	require.Equal(t, o.WildcardExports, n.WildcardExports)
}
