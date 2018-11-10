package jwt

import (
	"io/ioutil"
	"net/http"
	"net/url"
)

// Import describes a mapping from another account into this one
type Import struct {
	NamedSubject
	Account  string  `json:"account,omitempty"`
	Token    string  `json:"token_jwt,omitempty"`
	TokenURL string  `json:"token_url,omitempty"`
	To       Subject `json:"to,omitempty"`
	Type     string  `json:"type,omitempty"`
}

// IsService returns true if the import is of type service
func (i *Import) IsService() bool {
	return i.Type == ServiceType
}

// IsStream returns true if the import is of type stream
func (i *Import) IsStream() bool {
	return i.Type == StreamType
}

// Validate checks if an import is valid for the wrapping account
func (i *Import) Validate(actPubKey string, vr *ValidationResults) {
	if !i.IsService() && !i.IsStream() {
		vr.AddError("invalid import type: %q", i.Type)
	}

	if i.Account == "" {
		vr.AddWarning("account to import from is not specified")
	}

	i.NamedSubject.Validate(vr)

	if i.IsService() {
		if i.NamedSubject.Subject.HasWildCards() {
			vr.AddWarning("services cannot have wildcard subject: %q", i.Subject)
		}
	}

	var act *ActivationClaims

	if i.Token != "" {
		var err error
		act, err = DecodeActivationClaims(i.Token)
		if err != nil {
			vr.AddWarning("import %s contains an invalid activation token", i.Subject)
		}
	}

	if i.TokenURL != "" {
		url, err := url.Parse(i.TokenURL)

		if err != nil {
			vr.AddWarning("import %s contains an invalid token URL %q", i.Subject, i.TokenURL)
		} else {
			resp, err := http.Get(url.String())
			if err != nil {
				vr.AddWarning("import %s contains an unreachable token URL %q", i.Subject, i.TokenURL)
			}

			if resp != nil {
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					vr.AddWarning("import %s contains an unreadable token URL %q", i.Subject, i.TokenURL)
				} else {
					act, err = DecodeActivationClaims(string(body))
					if err != nil {
						vr.AddWarning("import %s contains a url %q with an invalid activation token", i.Subject, i.TokenURL)
					}
				}
			}
		}
	}

	if act != nil {
		if act.Issuer != i.Account {
			vr.AddWarning("activation token doesn't match account for import %s", i.Subject)
		}

		if act.Subject != actPubKey {
			vr.AddWarning("activation token doesn't match account it is being included in, %s", i.Subject)
		}

		if !act.Exports.HasExportContainingSubject(i.Subject) {
			vr.AddWarning("activation token include the subject trying to be imported, %s", i.Subject)
		}
	} else {
		vr.AddWarning("no activation provided for import %s", i.Subject)
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
