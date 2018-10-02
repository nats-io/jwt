package jwt

import "github.com/nats-io/nkeys"

type GenericClaims struct {
	ClaimsData
	Data map[string]interface{} `json:"nats,omitempty"`
}

// NewClaims creates a Claims
func NewGenericClaims() *GenericClaims {
	c := GenericClaims{}
	c.Data = make(map[string]interface{})
	return &c
}

func DecodeGeneric(token string) (*GenericClaims, error) {
	v := GenericClaims{}
	if err := Decode(token, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (gc *GenericClaims) Claims() *ClaimsData {
	return &gc.ClaimsData
}

func (a *GenericClaims) Payload() interface{} {
	return &a.Data
}

func (gc *GenericClaims) Encode(pair nkeys.KeyPair) (string, error) {
	return gc.ClaimsData.encode(pair, gc)
}

func (gc *GenericClaims) Valid() error {
	if err := gc.ClaimsData.Valid(); err != nil {
		return err
	}
	return nil
}

func (gc *GenericClaims) String() string {
	return gc.ClaimsData.String(gc)
}

func (gc *GenericClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return nil
}
