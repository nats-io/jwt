package jwt

import (
	"encoding/base64"
	"encoding/json"
)

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	//FIXME: JKU would be useful here - URLs to the certificates
}

func ParseHeader(s string) (*Header, error) {
	h, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	header := Header{}
	if err := json.Unmarshal(h, &header); err != nil {
		return nil, err
	}
	return &header, nil
}

func (h *Header) Valid() (bool) {
	return h.Algorithm == "nkey"
}
