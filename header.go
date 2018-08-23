package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// The type of JWT token
const TokenTypeJwt = "JWT"

// The algorithm supported by JWT tokens encoded and decoded by this library
const AlgorithmNkey = "NKEY"

// A JWT Jose Header
type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

// Parses a header JWT token
func parseHeaders(s string) (*Header, error) {
	h, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	header := Header{}
	if err := json.Unmarshal(h, &header); err != nil {
		return nil, err
	}

	if err := header.Valid(); err != nil {
		return nil, err
	}
	return &header, nil
}

// Returns nil if the Header is a JWT header, and the algorithm used
// is the NKEY algorithm.
func (h *Header) Valid() error {
	if TokenTypeJwt != h.Type {
		return fmt.Errorf("not supported type %q", h.Type)
	}

	if AlgorithmNkey != h.Algorithm {
		return fmt.Errorf("unexpected %q algorithm", h.Algorithm)
	}
	return nil
}
