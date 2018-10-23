package jwt

import (
	"fmt"
)

type Account struct {
	Imports Imports `json:"imports,omitempty"`
	Exports Exports `json:"exports,omitempty"`
	Access  string  `json:"access,omitempty"`
}

func (a *Account) Valid() error {
	if err := a.Imports.Valid(); err != nil {
		return err
	}

	return nil
}

type Limits struct {
	Max     int64   `json:"max,omitempty"`
	Payload int64   `json:"payload,omitempty"`
	Src     string  `json:"src,omitempty"`
	Times   []int64 `json:"times,omitempty"`
}

type OperatorLimits struct {
	Subs int64 `json:"subs,omitempty"`
	Conn int64 `json:"con,omitempty"`
	Maps int64 `json:"maps,omitempty"`
}

type Permission struct {
	Allow StringList `json:"allow,omitempty"`
	Deny  StringList `json:"deny,omitempty"`
}

type Permissions struct {
	Pub Permission `json:"pub,omitempty"`
	Sub Permission `json:"sub,omitempty"`
}

type StringList []string

func (u *StringList) contains(p string) bool {
	for _, t := range *u {
		if t == p {
			return true
		}
	}
	return false
}

func (u *StringList) Add(p ...string) {
	for _, v := range p {
		if !u.contains(v) && v != "" {
			*u = append(*u, v)
		}
	}
}

func (u *StringList) Remove(p ...string) {
	for _, v := range p {
		for i, t := range *u {
			if t == v {
				a := *u
				*u = append(a[:i], a[i+1:]...)
				break
			}
		}
	}
}

func (u *Permissions) Valid() error {
	return nil
}

type Activation struct {
	Exports Exports `json:"exports,omitempty"`
	Limits
	OperatorLimits
}

func (a *Activation) Valid() error {
	return a.Exports.Valid()
}

type Identity struct {
	ID    string `json:"id,omitempty"`
	Proof string `json:"proof,omitempty"`
}

type Operator struct {
	Identities []Identity `json:"identity,omitempty"`
}

func (u *Operator) Valid() error {
	return nil
}

type Cluster struct {
	Trust       []string `json:"identity,omitempty"`
	Accounts    []string `json:"accts,omitempty"`
	AccountURL  string   `json:"accturl,omitempty"`
	OperatorURL string   `json:"opurl,omitempty"`
}

type Server struct {
	Permissions
	Cluster string `json:"cluster,omitempty"`
}

type User struct {
	Permissions
	Limits
}

type Revocation struct {
	JWT    string `json:"jwt,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (u *Revocation) Valid() error {
	if u.JWT == "" {
		return fmt.Errorf("error validating revocation token, no JWT to revoke")
	}

	_, err := DecodeGeneric(u.JWT)

	if err != nil {
		return err
	}

	return nil
}
