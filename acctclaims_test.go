package jwt

import (
	"fmt"
	"github.com/nats-io/nkeys"
	"testing"
	"time"
)

func TestNewAccountClaims(t *testing.T) {
	okp, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal("error creating operator kp", err)
	}

	akp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("error creating account kp", err)
	}

	pk, err := akp.PublicKey()
	if err != nil {
		t.Fatal("error getting public key from account", err)
	}


	activation := NewActivationClaims(pk)
	activation.Mps = 100
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()

	actJwt, err := activation.Encode(okp)
	if err != nil {
		t.Fatal("error encoding activation jwt", err)
	}


	account := NewAccountClaims()
	account.Expires = time.Now().Add(time.Duration(time.Hour * 24 * 365)).Unix()
	account.AppendActivation(actJwt)

	accJwt, err := account.Encode(akp)
	if err != nil {
		t.Fatal("error generating account jwt", err)
	}

	fmt.Println(accJwt)

}
