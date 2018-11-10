package jwt

import (
	"testing"
	"time"
)

func TestNewGenericClaims(t *testing.T) {
	akp := createAccountNKey(t)
	apk := publicKey(akp, t)

	uc := NewGenericClaims(apk)
	uc.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	uc.Name = "alberto"
	uc.Audience = "everyone"
	uc.NotBefore = time.Now().UTC().Unix()
	uc.Tags.Add("one")
	uc.Tags.Add("one")
	uc.Tags.Add("one")
	uc.Tags.Add("TWO") // should become lower case
	uc.Tags.Add("three")

	uJwt := encode(uc, akp, t)

	uc2, err := DecodeGeneric(uJwt)
	if err != nil {
		t.Fatal("failed to decode", err)
	}

	AssertEquals(uc.String(), uc2.String(), t)
	AssertEquals(uc.Name, uc2.Name, t)
	AssertEquals(uc.Audience, uc2.Audience, t)
	AssertEquals(uc.Expires, uc2.Expires, t)
	AssertEquals(uc.NotBefore, uc2.NotBefore, t)
	AssertEquals(uc.Subject, uc2.Subject, t)

	AssertEquals(3, len(uc2.Tags), t)
	AssertEquals(true, uc2.Tags.Contains("two"), t)
	AssertEquals("one", uc2.Tags[0], t)
	AssertEquals("two", uc2.Tags[1], t)
	AssertEquals("three", uc2.Tags[2], t)

	AssertEquals(uc.Claims() != nil, true, t)
	AssertEquals(uc.Payload() != nil, true, t)
}
