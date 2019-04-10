/*
 * Copyright 2018 The NATS Authors
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
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// Import describes a mapping from another account into this one
type Import struct {
	Account       string     `json:"account,omitempty"`
	LocalSubject  Subject    `json:"local_subject,omitempty"`
	Name          string     `json:"name,omitempty"`
	RemoteSubject Subject    `json:"remote_subject,omitempty"`
	Token         string     `json:"token,omitempty"`
	Type          ExportType `json:"type,omitempty"`
	// Deprecated: use Local/Remote
	Subject Subject `json:"subject,omitempty"`
	// Deprecated: use Local/Remote
	To       Subject `json:"to,omitempty"`
	migrated bool
}

// IsService returns true if the import is of type service
func (i *Import) IsService() bool {
	return i.Type == Service
}

// IsStream returns true if the import is of type stream
func (i *Import) IsStream() bool {
	return i.Type == Stream
}

// Validate checks if an import is valid for the wrapping account
func (i *Import) Validate(actPubKey string, vr *ValidationResults) {
	if !i.IsService() && !i.IsStream() {
		vr.AddError("invalid import type: %q", i.Type)
	}

	if i.Account == "" {
		vr.AddWarning("account to import from is not specified")
	}

	i.RemoteSubject.Validate(vr)

	var act *ActivationClaims

	if i.Token != "" {
		// Check to see if its an embedded JWT or a URL.
		if u, err := url.Parse(i.Token); err == nil && u.Scheme != "" {
			c := &http.Client{Timeout: 5 * time.Second}
			resp, err := c.Get(u.String())
			if err != nil {
				vr.AddWarning("import %s contains an unreachable token URL %q", i.RemoteSubject, i.Token)
			}

			if resp != nil {
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					vr.AddWarning("import %s contains an unreadable token URL %q", i.RemoteSubject, i.Token)
				} else {
					act, err = DecodeActivationClaims(string(body))
					if err != nil {
						vr.AddWarning("import %s contains a url %q with an invalid activation token", i.RemoteSubject, i.Token)
					}
				}
			}
		} else {
			var err error
			act, err = DecodeActivationClaims(i.Token)
			if err != nil {
				vr.AddWarning("import %q contains an invalid activation token", i.RemoteSubject)
			}
		}
	}

	if act != nil {
		if act.Issuer != i.Account {
			vr.AddWarning("activation token doesn't match account for import %q", i.RemoteSubject)
		}

		if act.ClaimsData.Subject != actPubKey {
			vr.AddWarning("activation token doesn't match account it is being included in, %q", i.RemoteSubject)
		}
	} else {
		vr.AddWarning("no activation provided for import %s", i.RemoteSubject)
	}

}

// Imports is a list of import structs
type Imports []*Import

// Validate checks if an import is valid for the wrapping account
func (i *Imports) Validate(acctPubKey string, vr *ValidationResults) {
	for _, v := range *i {
		v.Validate(acctPubKey, vr)
	}
}

// Add is a simple way to add imports
func (i *Imports) Add(a ...*Import) {
	*i = append(*i, a...)
}
