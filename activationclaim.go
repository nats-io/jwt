package jwt

import "github.com/nats-io/nkeys"

type Limits struct {
	Mps      int64          `json:"mps,omitempty"`
	Bps      int64          `json:"bps,omitempty"`
	Max      int64          `json:"max,omitempty"`
	Src      string         `json:"src,omitempty"`
	Times    []int64        `json:"times,omitempty"`
}

type Avt struct {
	Lnk      string         `json:"lnk,omitempty"`
	Streams  SubjectMapList `json:"streams,omitempty"`
	Services SubjectMapList `json:"services,omitempty"`
	Subs     int64          `json:"subs,omitempty"`
	Conn     int64          `json:"conn,omitempty"`
	Maps     int64          `json:"maps,omitempty"`
	Limits
}

func (a *Avt) Valid() error {
	return nil
}

type ActivationClaims struct {
	ClaimsData
	Avt `json:"natsact,omitempty"`
}

func NewActivationClaims(subject string) *ActivationClaims {
	ac := &ActivationClaims{}
	ac.Subject = subject
	return ac
}

func (a *ActivationClaims) Encode(pair nkeys.KeyPair) (string, error) {
	return a.ClaimsData.encode(pair, &a)
}

func DecodeActivationClaims(token string) (*ActivationClaims, error) {
	v := ActivationClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (a *ActivationClaims) Payload() interface{} {
	return a.Avt
}

func (a *ActivationClaims) Valid() error {
	if err := a.ClaimsData.Valid(); err != nil {
		return err
	}
	if err := a.Avt.Valid(); err != nil {
		return err
	}
	return nil
}

func (a *ActivationClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteAccount, nkeys.PrefixByteOperator}
}

func (a *ActivationClaims) Claims() *ClaimsData {
	return &a.ClaimsData
}

func (a *ActivationClaims) String() string {
	return a.ClaimsData.String(a)
}
