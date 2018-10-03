package jwt

import (
	"errors"
	"fmt"
	"github.com/nats-io/nkeys"
	"runtime"
	"strings"
	"testing"
)

func Trace(message string) string {
	lines := make([]string, 0, 32)
	err := errors.New(message)
	msg := fmt.Sprintf("%s", err.Error())
	lines = append(lines, msg)

	for i := 2; true; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		msg := fmt.Sprintf("%s:%d", file, line)
		lines = append(lines, msg)
	}
	return strings.Join(lines, "\n")
}

func AssertEquals(expected, v interface{}, t *testing.T) {
	if expected != v {
		t.Fatalf("%v", Trace(fmt.Sprintf("The expected value %v != %v", expected, v)))
	}
}

func createAccountNKey(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("error creating account kp", err)
	}
	return kp
}

func createUserNKey(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("error creating account kp", err)
	}
	return kp
}

func createOperatorNKey(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal("error creating operator kp", err)
	}
	return kp
}

func createServerNKey(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateServer()
	if err != nil {
		t.Fatal("error creating server kp", err)
	}
	return kp
}

func createClusterNKey(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateCluster()
	if err != nil {
		t.Fatal("error creating cluster kp", err)
	}
	return kp
}

func publicKey(kp nkeys.KeyPair, t *testing.T) string {
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatal("error reading public key", err)
	}
	return pk
}

func encode(c Claims, kp nkeys.KeyPair, t *testing.T) string {
	s, err := c.Encode(kp)
	if err != nil {
		t.Fatal("error encoding claim", err)
	}
	return s
}
