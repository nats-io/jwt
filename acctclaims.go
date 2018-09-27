package jwt

import (
	"fmt"
	"github.com/nats-io/nkeys"
)

// TargetSubject represents a target for a subject mapping
type TargetSubject struct {
	Acct    string `json:"acct,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// SubjectMap is an actual mapping. Only one of Frm or To should be set
type SubjectMap struct {
	Name string         `json:"name,omitempty"`
	Frm  *TargetSubject `json:"frm,omitempty"`
	To   *TargetSubject `json:"to,omitempty"`
}

// Valid validates that a SubjectMap sets only one of Frm or To.
func (t *SubjectMap) Valid() error {
	if t.To == nil && t.Frm == nil {
		return fmt.Errorf("%q needs to set a target subject", t.Name)
	}
	if t.To != nil && t.Frm != nil {
		return fmt.Errorf("%q should set either to or frm, not both", t.Name)
	}
	return nil
}

// SubjectMapList is a list of subject mappings
type SubjectMapList []SubjectMap

// Valid validates the SubjectMapList by calling SubjectMap#Valid()
// on all. It returns the first error found
func (tl *SubjectMapList) Valid() error {
	for _, e := range *tl {
		if err := e.Valid(); err != nil {
			return err
		}
	}
	return nil
}

type Account struct {
	Streams  SubjectMapList `json:"streams,omitempty"`
	Services SubjectMapList `json:"services,omitempty"`
	Act      []string       `json:"act,omitempty"`
}

func (a *Account) AppendStream(sm SubjectMap) {
	a.Streams = append(a.Streams, sm)
}

func (a *Account) AppendService(sm SubjectMap) {
	a.Services = append(a.Services, sm)
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
	if err := a.Streams.Valid(); err != nil {
		return fmt.Errorf("streams - %s", err.Error())
	}
	if err := a.Services.Valid(); err != nil {
		return fmt.Errorf("services - %s", err.Error())
	}
	return nil
}

type AccountClaims struct {
	ClaimsData
	Account `json:"natsacct,omitempty"`
}

func NewAccountClaims() *AccountClaims {
	return &AccountClaims{}
}

func (a *AccountClaims) Encode(pair nkeys.KeyPair) (string, error) {
	return a.ClaimsData.encode(pair, &a)
}

func DecodeAccountClaims(token string) (*AccountClaims, error) {
	v := AccountClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (a *AccountClaims) Payload() interface{} {
	return a.Account
}

func (a *AccountClaims) String() string {
	return a.ClaimsData.String(a)
}

func (a *AccountClaims) Valid() error {
	if err := a.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := a.Account.Valid(); err != nil {
		return err
	}
	return nil
}

func (a *AccountClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount}
}

func (a *AccountClaims) Claims() *ClaimsData {
	return &a.ClaimsData
}
