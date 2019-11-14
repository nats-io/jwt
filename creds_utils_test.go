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
