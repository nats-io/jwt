# JWT
A [JWT](https://jwt.io/) implementation that uses [nkeys](https://github.com/nats-io/nkeys) to digitally sign JWT tokens.
Nkeys use [Ed25519](https://ed25519.cr.yp.to/) to provide authentication of JWT claims.


[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![ReportCard](https://goreportcard.com/badge/github.com/nats-io/jwt)](https://goreportcard.com/report/nats-io/jwt)
[![Build Status](https://travis-ci.com/nats-io/jwt.svg?branch=master)](https://travis-ci.com/github/nats-io/jwt)
[![GoDoc](https://godoc.org/github.com/nats-io/jwt?status.png)](https://godoc.org/github.com/nats-io/jwt/v2)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/jwt/badge.svg?branch=main)](https://coveralls.io/github/nats-io/jwt?branch=main)
```go
// create an operator key pair (private key)
okp, err := nkeys.CreateOperator()
if err != nil {
  t.Fatal(err)
}
// extract the public key
opk, err := okp.PublicKey()
if err != nil {
  t.Fatal(err)
}

// create an operator claim using the public key for the identifier
oc := jwt.NewOperatorClaims(opk)
oc.Name = "O"
// add an operator signing key to sign accounts
oskp, err := nkeys.CreateOperator()
if err != nil {
  t.Fatal(err)
}
// get the public key for the signing key
ospk, err := oskp.PublicKey()
if err != nil {
  t.Fatal(err)
}
// add the signing key to the operator - this makes any account
// issued by the signing key to be valid for the operator
oc.SigningKeys.Add(ospk)

// self-sign the operator JWT - the operator trusts itself
operatorJWT, err := oc.Encode(okp)
if err != nil {
  t.Fatal(err)
}

// create an account keypair
akp, err := nkeys.CreateAccount()
if err != nil {
  t.Fatal(err)
}
// extract the public key for the account
apk, err := akp.PublicKey()
if err != nil {
  t.Fatal(err)
}
// create the claim for the account using the public key of the account
ac := jwt.NewAccountClaims(apk)
ac.Name = "A"
// create a signing key that we can use for issuing users
askp, err := nkeys.CreateAccount()
if err != nil {
  t.Fatal(err)
}
// extract the public key
aspk, err := askp.PublicKey()
if err != nil {
  t.Fatal(err)
}
// add the signing key (public) to the account
ac.SigningKeys.Add(aspk)

// now we could encode an issue the account using the operator
// key that we generated above, but this will illustrate that
// the account could be self-signed, and given to the operator
// who can then re-sign it
accountJWT, err := ac.Encode(akp)
if err != nil {
  t.Fatal(err)
}

// the operator would decode the provided token, if the token
// is not self-signed or signed by an operator or tampered with
// the decoding would fail
ac, err = jwt.DecodeAccountClaims(accountJWT)
if err != nil {
  t.Fatal(err)
}
// here the operator is going to use its private signing key to
// re-issue the account
accountJWT, err = ac.Encode(oskp)
if err != nil {
  t.Fatal(err)
}

// now back to the account, the account can issue users
// need not be known to the operator - the users are trusted
// because they will be signed by the account. The server will
// look up the account get a list of keys the account has and
// verify that the user was issued by one of those keys
ukp, err := nkeys.CreateUser()
if err != nil {
  t.Fatal(err)
}
upk, err := ukp.PublicKey()
if err != nil {
  t.Fatal(err)
}
uc := jwt.NewUserClaims(upk)
// since the jwt will be issued by a signing key, the issuer account
// must be set to the public ID of the account
uc.IssuerAccount = apk
userJwt, err := uc.Encode(askp)
if err != nil {
  t.Fatal(err)
}
// the seed is a version of the keypair that is stored as text
useed, err := ukp.Seed()
if err != nil {
  t.Fatal(err)
}
// generate a creds formatted file that can be used by a NATS client
creds, err := jwt.FormatUserConfig(userJwt, useed)
if err != nil {
  t.Fatal(err)
}

// now we are going to put it together into something that can be run
// we create a directory to store the server configuration, the creds
// file and a small go program that uses the creds file
dir, err := os.MkdirTemp(os.TempDir(), "jwt_example")
if err != nil {
  t.Fatal(err)
}
// print where we generated the file
t.Logf("generated example %s", dir)
t.Log("to run this example:")
t.Logf("> cd %s", dir)
t.Log("> go mod init example")
t.Log("> go mod tidy")
t.Logf("> nats-server -c %s/resolver.conf &", dir)
t.Log("> go run main.go")

// we are generating a memory resolver server configuration
// it lists the operator and all account jwts the server should
// know about
resolver := fmt.Sprintf(`operator: %s

resolver: MEMORY
resolver_preload: {
	%s: %s
}
`, operatorJWT, apk, accountJWT)
if err := os.WriteFile(path.Join(dir, "resolver.conf"),
  []byte(resolver), 0644); err != nil {
    t.Fatal(err)
}

// store the creds
credsPath := path.Join(dir, "u.creds")
if err := os.WriteFile(credsPath, creds, 0644); err != nil {
  t.Fatal(err)
}

// here we generate as small go program that connects using the creds file
// subscribes, and publishes a message
connect := fmt.Sprintf(`
package main

import (
  "fmt"
  "sync"

  "github.com/nats-io/nats.go"
)

func main() {
  var wg sync.WaitGroup
  wg.Add(1)
  nc, err := nats.Connect(nats.DefaultURL, nats.UserCredentials(%q))
  if err != nil {
	panic(err)
  }
  nc.Subscribe("hello.world", func(m *nats.Msg) {
    fmt.Println(m.Subject)
	wg.Done()
  })
  nc.Publish("hello.world", []byte("hello"))
  nc.Flush()
  wg.Wait()
  nc.Close()
}

`, credsPath)
if err := os.WriteFile(path.Join(dir, "main.go"), []byte(connect), 0644); err != nil {
  t.Fatal(err)
}
```