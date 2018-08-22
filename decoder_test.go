package jwt

import (
	"testing"
	"time"
	"reflect"
	"fmt"

	"github.com/nats-io/nkeys"
)

func TestNewToken(t *testing.T) {
	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Error("unable to create account key", err)
	}

	claims := &Claims{}
	claims.NotBefore = time.Now().UTC().Unix()
	claims.Nats = make(map[string]string)
	claims.Nats["foo"] = "bar"

	token, err := claims.Encode(kp)
	if err != nil {
		t.Error("error encoding token", err)
	}

	fmt.Println(token)

	pk, err := kp.PublicKey()
	if err != nil {
		t.Error(err)
	}

	c, err := Decode([]string{pk}, token)
	if err != nil {
		t.Error(err)
	}

	if claims.NotBefore != c.NotBefore {
		t.Error("notbefore don't match")
	}

	if claims.Issuer != c.Issuer {
		t.Error("notbefore don't match")
	}

	if !reflect.DeepEqual(claims.Nats, c.Nats) {
		t.Error("nats sections don't match")
	}
}
