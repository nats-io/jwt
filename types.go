package jwt

import "fmt"

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



type Limits struct {
	Mps   int64   `json:"mps,omitempty"`
	Bps   int64   `json:"bps,omitempty"`
	Max   int64   `json:"max,omitempty"`
	Src   string  `json:"src,omitempty"`
	Times []int64 `json:"times,omitempty"`
}

type Activation struct {
	Lnk      string         `json:"lnk,omitempty"`
	Streams  SubjectMapList `json:"streams,omitempty"`
	Services SubjectMapList `json:"services,omitempty"`
	Subs     int64          `json:"subs,omitempty"`
	Conn     int64          `json:"conn,omitempty"`
	Maps     int64          `json:"maps,omitempty"`
	Limits
}

func (a *Activation) Valid() error {
	return nil
}


type User struct {
	Pub []string `json:"pub,omitempty"`
	Sub []string `json:"sub,omitempty"`
	Limits
}

func (u *User) AddPub(p string) {
	if u.canAdd(&u.Pub, p) {
		u.Pub = append(u.Pub, p)
	}
}

func (u *User) RemovePub(p string) {
	for i, t := range u.Pub {
		if t == p {
			u.Pub = append(u.Pub[:i], u.Pub[i+1:]...)
			break
		}
	}
}

func (u *User) RemoveSub(p string) {
	for i, t := range u.Sub {
		if t == p {
			u.Sub = append(u.Pub[:i], u.Pub[i+1:]...)
			break
		}
	}
}

func (u *User) AddSub(p string) {
	if u.canAdd(&u.Sub, p) {
		u.Sub = append(u.Sub, p)
	}
}

func (u *User) contains(a *[]string, p string) bool {
	for _, t := range *a {
		if t == p {
			return true
		}
	}
	return false
}

func (u *User) canAdd(a *[]string, s string) bool {
	return !u.contains(a, s)
}

func (u *User) Valid() error {
	return nil
}