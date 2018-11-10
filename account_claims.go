package jwt

import (
	"github.com/nats-io/nkeys"
	"github.com/pkg/errors"
)

// OperatorLimits are used to limit access by an account
type OperatorLimits struct {
	Subs int64 `json:"subs,omitempty"`
	Conn int64 `json:"con,omitempty"`
	Maps int64 `json:"maps,omitempty"`
}

// IsEmpty returns true if all of the limits are 0
func (o *OperatorLimits) IsEmpty() bool {
	return (o.Subs == 0 && o.Conn == 0 && o.Maps == 0)
}

// Validate checks that the operator limits contain valid values
func (o *OperatorLimits) Validate(vr *ValidationResults) {
	if o.Subs < 0 {
		vr.AddError("the operator limit on subscriptions can't be less than 0, %d", o.Subs)
	}
	if o.Conn < 0 {
		vr.AddError("the operator limit on connections can't be less than 0, %d", o.Conn)
	}
	if o.Maps < 0 {
		vr.AddError("the operator limit on maps can't be less than 0, %d", o.Maps)
	}
}

// Account holds account specific claims data
type Account struct {
	Imports    Imports    `json:"imports,omitempty"`
	Exports    Exports    `json:"exports,omitempty"`
	Identities []Identity `json:"identity,omitempty"`
	OperatorLimits
}

// Validate checks if the account is valid, based on the wrapper
func (a *Account) Validate(acct *AccountClaims, vr *ValidationResults) {
	a.Imports.Validate(acct, vr)
	a.Exports.Validate(vr)
	a.OperatorLimits.Validate(vr)

	for _, i := range a.Identities {
		i.Validate(vr)
	}
}

// AccountClaims defines the body of an account JWT
type AccountClaims struct {
	ClaimsData
	Account `json:"nats,omitempty"`
}

// NewAccountClaims creates a new account JWT
func NewAccountClaims(subject string) *AccountClaims {
	if subject == "" {
		return nil
	}
	c := &AccountClaims{}
	c.Subject = subject
	return c
}

// Encode converts account claims into a JWT string
func (a *AccountClaims) Encode(pair nkeys.KeyPair) (string, error) {
	if !nkeys.IsValidPublicAccountKey([]byte(a.Subject)) {
		return "", errors.New("expected subject to be account public key")
	}

	pubKey, err := pair.PublicKey()
	if err != nil {
		return "", err
	}

	if nkeys.IsValidPublicAccountKey(pubKey) {
		if len(a.Identities) > 0 {
			return "", errors.New("self-signed account JWTs can't contain identity proofs")
		}
		if !a.OperatorLimits.IsEmpty() {
			return "", errors.New("self-signed account JWTs can't contain operator limits")
		}
	}

	a.ClaimsData.Type = AccountClaim
	return a.ClaimsData.encode(pair, a)
}

// DecodeAccountClaims decodes account claims from a JWT string
func DecodeAccountClaims(token string) (*AccountClaims, error) {
	v := AccountClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (a *AccountClaims) String() string {
	return a.ClaimsData.String(a)
}

// Payload pulls the accounts specific payload out of the claims
func (a *AccountClaims) Payload() interface{} {
	return &a.Account
}

// Validate checks the accounts contents
func (a *AccountClaims) Validate(vr *ValidationResults) {
	a.ClaimsData.Validate(vr)
	a.Account.Validate(a, vr)

	if nkeys.IsValidPublicAccountKey([]byte(a.ClaimsData.Issuer)) {
		if len(a.Identities) > 0 {
			vr.AddError("self-signed account JWTs can't contain identity proofs")
		}
		if !a.OperatorLimits.IsEmpty() {
			vr.AddError("self-signed account JWTs can't contain operator limits")
		}
	}
}

// ExpectedPrefixes defines the types that can encode an account jwt, account and operator
func (a *AccountClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount, nkeys.PrefixByteOperator}
}

// Claims returns the accounts claims data
func (a *AccountClaims) Claims() *ClaimsData {
	return &a.ClaimsData
}
