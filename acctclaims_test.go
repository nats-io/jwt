package jwt

import (
	"fmt"
	"github.com/nats-io/nkeys"
	"testing"
	"time"
)

func TestNewAccountClaims(t *testing.T) {
	okp, err := nkeys.CreateOperator(nil)
	if err != nil {
		t.Fatal("error creating operator kp", err)
	}

	activation := NewActivationClaims()
	activation.Mps = 100
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()

	actJwt, err := activation.Encode(okp)
	if err != nil {
		t.Fatal("error encoding activation jwt", err)
	}

	kp, err := nkeys.CreateAccount(nil)
	if err != nil {
		t.Fatal("error creating account kp", err)
	}

	account := NewAccountClaims()
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.AppendActivation(actJwt)

	accJwt, err := account.Encode(kp)
	if err != nil {
		t.Fatal("error generating account jwt", err)
	}

	fmt.Println(accJwt)

}
