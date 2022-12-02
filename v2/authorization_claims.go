/*
 * Copyright 2022 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import (
	"errors"

	"github.com/nats-io/nkeys"
)

// ServerID is basic static info for a NATS server.
type ServerID struct {
	Name string `json:"name"`
	Host string `json:"host"`
	ID   string `json:"id"`
}

// ClientInformation is information about a client that is trying to authorize.
type ClientInformation struct {
	Host    string  `json:"host,omitempty"`
	ID      uint64  `json:"id,omitempty"`
	User    string  `json:"user,omitempty"`
	Name    string  `json:"name,omitempty"`
	Tags    TagList `json:"tags,omitempty"`
	NameTag string  `json:"name_tag,omitempty"`
	Kind    string  `json:"kind,omitempty"`
	Type    string  `json:"type,omitempty"`
	MQTT    string  `json:"mqtt_id,omitempty"`
	Nonce   string  `json:"nonce,omitempty"`
}

// ConnectOptions represents options that were set in the CONNECT protocol from the client
// during authorization.
type ConnectOptions struct {
	JWT         string `json:"jwt,omitempty"`
	Nkey        string `json:"nkey,omitempty"`
	SignedNonce string `json:"sig,omitempty"`
	Token       string `json:"auth_token,omitempty"`
	Username    string `json:"user,omitempty"`
	Password    string `json:"pass,omitempty"`
	Name        string `json:"name,omitempty"`
	Lang        string `json:"lang,omitempty"`
	Version     string `json:"version,omitempty"`
	Protocol    int    `json:"protocol"`
}

// ClientTLS is information about TLS state if present, including client certs.
// If the client certs were present and verified they will be under verified chains
// with the client peer cert being VerifiedChains[0]. These are complete and pem encoded.
// If they were not verified, they will be under certs.
type ClientTLS struct {
	Version        string       `json:"version,omitempty"`
	Cipher         string       `json:"cipher,omitempty"`
	Certs          StringList   `json:"certs,omitempty"`
	VerifiedChains []StringList `json:"verified_chains,omitempty"`
}

// AuthorizationRequest represents all the information we know about the client that
// will be sent to an external authorization service.
type AuthorizationRequest struct {
	Server            ServerID          `json:"server_id"`
	ClientInformation ClientInformation `json:"client_info"`
	ConnectOptions    ConnectOptions    `json:"connect_opts"`
	TLS               *ClientTLS        `json:"client_tls,omitempty"`
	GenericFields
}

// AuthorizationRequestClaims defines an external auth request JWT.
// These wil be signed by a NATS server.
type AuthorizationRequestClaims struct {
	ClaimsData
	AuthorizationRequest `json:"nats"`
}

// NewAuthorizationRequestClaims creates an auth request JWT with the specific subject/public key.
func NewAuthorizationRequestClaims(subject string) *AuthorizationRequestClaims {
	if subject == "" {
		return nil
	}
	var ac AuthorizationRequestClaims
	ac.Subject = subject
	return &ac
}

// Validate checks the generic and specific parts of the auth request jwt.
func (ac *AuthorizationRequestClaims) Validate(vr *ValidationResults) {
	ac.ClaimsData.Validate(vr)
}

// Encode tries to turn the auth request claims into a JWT string.
func (ac *AuthorizationRequestClaims) Encode(pair nkeys.KeyPair) (string, error) {
	ac.Type = AuthorizationRequestClaim
	return ac.ClaimsData.encode(pair, ac)
}

// DecodeAuthorizationRequestClaims tries to parse an auth request claims from a JWT string
func DecodeAuthorizationRequestClaims(token string) (*AuthorizationRequestClaims, error) {
	claims, err := Decode(token)
	if err != nil {
		return nil, err
	}
	ac, ok := claims.(*AuthorizationRequestClaims)
	if !ok {
		return nil, errors.New("not an authorization request claim")
	}
	return ac, nil
}

// ExpectedPrefixes defines the types that can encode an auth request jwt, servers.
func (ac *AuthorizationRequestClaims) ExpectedPrefixes() []nkeys.PrefixByte {
	return []nkeys.PrefixByte{nkeys.PrefixByteServer}
}

func (ac *AuthorizationRequestClaims) ClaimType() ClaimType {
	return ac.Type
}

// Claims returns the accounts claims data.
func (ac *AuthorizationRequestClaims) Claims() *ClaimsData {
	return &ac.ClaimsData
}

// Payload pulls the request specific payload out of the claims.
func (ac *AuthorizationRequestClaims) Payload() interface{} {
	return &ac.AuthorizationRequest
}

func (ac *AuthorizationRequestClaims) String() string {
	return ac.ClaimsData.String(ac)
}

func (ac *AuthorizationRequestClaims) updateVersion() {
	ac.GenericFields.Version = libVersion
}
