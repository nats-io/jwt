package jwt

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/pkg/errors"
)

// OperatorLimits are used to limit access by an account
type OperatorLimits struct {
	Subs    int64  `json:"subs,omitempty"`
	Conn    int64  `json:"conn,omitempty"`
	Imports int64  `json:"imports,omitempty"`
	Exports int64  `json:"exports,omitempty"`
	Data    string `json:"data,omitempty"`
	Payload string `json:"payload,omitempty"`
}

// IsEmpty returns true if all of the limits are 0
func (o *OperatorLimits) IsEmpty() bool {
	return (o.Subs == 0 && o.Conn == 0 && o.Imports == 0 && o.Exports == 0 && o.Data == "" && o.Payload == "")
}

// Validate checks that the operator limits contain valid values
func (o *OperatorLimits) Validate(vr *ValidationResults) {
	if o.Subs < 0 {
		vr.AddError("the operator limit on subscriptions can't be less than 0, %d", o.Subs)
	}
	if o.Conn < 0 {
		vr.AddError("the operator limit on connections can't be less than 0, %d", o.Conn)
	}
	if o.Imports < 0 {
		vr.AddError("the operator limit o imports can't be less than 0, %d", o.Imports)
	}
	if o.Exports < 0 {
		vr.AddError("the operator limit on exports can't be less than 0, %d", o.Exports)
	}

	if o.Data != "" {
		size, err := ParseDataSize(o.Data)

		if err != nil || size < 0 {
			vr.AddError("the operator limit on data must be a valid size, %q", o.Data)
		}
	}

	if o.Payload != "" {
		size, err := ParseDataSize(o.Payload)

		if err != nil || size < 0 {
			vr.AddError("the operator limit on payload must be a valid size, %q", o.Payload)
		}
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
	a.Imports.Validate(acct.Subject, vr)
	a.Exports.Validate(vr)
	a.OperatorLimits.Validate(vr)

	for _, i := range a.Identities {
		i.Validate(vr)
	}

	if !a.OperatorLimits.IsEmpty() && a.OperatorLimits.Imports >= 0 && int64(len(a.Imports)) > a.OperatorLimits.Imports {
		vr.AddError("the account contains more imports than allowed by the operator limits")
	}

	if !a.OperatorLimits.IsEmpty() && a.OperatorLimits.Exports >= 0 && int64(len(a.Exports)) > a.OperatorLimits.Exports {
		vr.AddError("the account contains more exports than allowed by the operator limits")
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

// ParseDataSize takes a string size and returns an int64 number of bytes
func ParseDataSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.ToUpper(s)
	re := regexp.MustCompile(`(^\d+$)`)
	m := re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[0], 10, 64)
		if err != nil {
			return 0, err
		}
		return v, nil
	}
	re = regexp.MustCompile(`(^\d+)([B|K|M|G])`)
	m = re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, err
		}
		if m[2] == "B" {
			return v, nil
		}
		if m[2] == "K" {
			return v * 1000, nil
		}
		if m[2] == "M" {
			return v * 1000 * 1000, nil
		}
		if m[2] == "G" {
			return v * 1000 * 1000 * 1000, nil
		}
	}
	return 0, fmt.Errorf("couldn't parse data size: %v", s)
}
