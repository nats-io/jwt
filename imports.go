package jwt

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
func (i *Import) Validate(acct *AccountClaims, vr *ValidationResults) {
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

	if act != nil {
		if act.Issuer != i.Account {
			vr.AddWarning("activation token doesn't match account for import %s", i.Subject)
		}

		if act.Subject != acct.Subject {
			vr.AddWarning("activation token doesn't match account it is being included in, %s", i.Subject)
		}
	} else {
		vr.AddWarning("no activation provided for import %s", i.Subject)
	}

	//FIXME: validate token URL
	//FIXME: check subjects
}

// Imports is a list of import structs
type Imports []*Import

// Validate checks if an import is valid for the wrapping account
func (i *Imports) Validate(acct *AccountClaims, vr *ValidationResults) {
	for _, v := range *i {
		v.Validate(acct, vr)
	}
}

// Add is a simple way to add imports
func (i *Imports) Add(a ...*Import) {
	*i = append(*i, a...)
}
