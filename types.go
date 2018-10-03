package jwt

import (
	"errors"
	"fmt"
	"github.com/nats-io/nkeys"
)

type ImportExportType string

const ImportExportTypeStream = "stream"
const ImportExportTypeService = "service"

type Import struct {
	Type    ImportExportType `json:"type,omitempty"`
	Account string           `json:"account,omitempty"`
	Subject string           `json:"subject,omitempty"`
	To      string           `json:"to,omitempty"`
	Prefix  string           `json:"prefix,omitempty"`
}

func (a *Import) Valid() error {
	if a.Type != ImportExportTypeService && a.Type != ImportExportTypeStream {
		return fmt.Errorf("import type %q is invalid", a.Type)
	}
	return nil
}

type Account struct {
	Imports []Import `json:"imports,omitempty"`
	Act     []string `json:"act,omitempty"`
}

func (a *Account) AppendActivation(act string) {
	a.Act = append(a.Act, act)
}

func (a *Account) Activations() ([]*ActivationClaims, error) {
	var buf []*ActivationClaims
	for i, s := range a.Act {
		ac, err := DecodeActivationClaims(s)
		if err != nil {
			return nil, fmt.Errorf("error decoding activation [%d]: %v", i, err)
		}
		buf = append(buf, ac)
	}
	return buf, nil
}

func (a *Account) Valid() error {
	activations, err := a.Activations()
	if err != nil {
		return err
	}

	tokenMap := make(map[string]bool)
	for _, t := range activations {
		tokenMap[t.Activation.Name] = true
	}

	for _, t := range a.Imports {
		if !nkeys.IsValidPublicAccountKey(t.Account) && !tokenMap[t.Account] {
			return fmt.Errorf("import references account %q - but it is not an account pk nor an activation token name", t.Account)
		}
	}

	return nil
}

type Limits struct {
	Max     int64   `json:"max,omitempty"`
	Pyaload int64   `json:"payload,omitempty"`
	Src     string  `json:"src,omitempty"`
	Times   []int64 `json:"times,omitempty"`
}

type OperatorLimits struct {
	Subs int64 `json:"subs,omitempty"`
	Conn int64 `json:"con,omitempty"`
	Maps int64 `json:"maps,omitempty"`
}

type Permissions struct {
	Pub     Subjects `json:"pub,omitempty"`
	Sub     Subjects `json:"sub,omitempty"`
	Cluster string   `json:"cluster,omitempty"`
}

type Subjects []string

func (u *Subjects) contains(p string) bool {
	for _, t := range *u {
		if t == p {
			return true
		}
	}
	return false
}


func (u *Permissions) AddPub(p string) {
	if !u.Pub.contains(p) {
		u.Pub = append(u.Pub, p)
	}
}

func (u *Permissions) AddSub(p string) {
	if !u.Sub.contains(p) {
		u.Sub = append(u.Sub, p)
	}
}

func (u *Permissions) RemovePub(p string) {
	for i, t := range u.Pub {
		if t == p {
			u.Pub = append(u.Pub[:i], u.Pub[i+1:]...)
			break
		}
	}
}

func (u *Permissions) RemoveSub(p string) {
	for i, t := range u.Sub {
		if t == p {
			u.Sub = append(u.Pub[:i], u.Pub[i+1:]...)
			break
		}
	}
}

func (u *Permissions) Valid() error {
	return nil
}

type Export struct {
	Type    ImportExportType `json:"type,omitempty"`
	Subject string           `json:"subject,omitempty"`
}

func (e *Export) Valid() error {
	if e.Type != ImportExportTypeService && e.Type != ImportExportTypeStream {
		return fmt.Errorf("export type %q is invalid", e.Type)
	}
	if e.Subject == "" {
		return errors.New("export subject is empty")
	}

	return nil
}

type Activation struct {
	Name    string   `json:"name,omitempty"`
	Exports []Export `json:"exports,omitempty"`
	Limits
	OperatorLimits
}

func (a *Activation) Valid() error {
	for i, t := range a.Exports {
		if err := t.Valid(); err != nil {
			return fmt.Errorf("error validating activation %q (index %d):%v", a.Name, i, err)
		}
	}
	return nil
}

type Identity struct {
	ID    string `json:"id,omitempty"`
	Proof string `json:"id,omitempty"`
}

type Operator struct {
	Identities []Identity `json:"identity,omitempty"`
}

type Cluster struct {
	Trust []string `json:"identity,omitempty"`
	Accounts []string `json:"accts,omitempty"`
	AccountURL string `json:"accturl,omitempty"`
	OperatorURL string `json:"opurl,omitempty"`
}


type Server struct {
	Permissions
}
