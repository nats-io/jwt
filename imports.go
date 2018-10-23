package jwt

import (
	"fmt"
)

type NamedSubject struct {
	Name    string  `json:"name,omitempty"`
	Subject Subject `json:"subject,omitempty"`
}

const ServiceType = "service"
const StreamType = "stream"

func (ns *NamedSubject) Valid() error {
	return ns.Subject.Valid()
}

type Import struct {
	NamedSubject
	Auth   string  `json:"auth,omitempty"`
	To     Subject `json:"to,omitempty"`
	Prefix Subject `json:"prefix,omitempty"`
	Type   string  `json:"type,omitempty"`
}

func (i *Import) IsService() bool {
	return i.Type == ServiceType
}

func (i *Import) IsStream() bool {
	return i.Type == StreamType
}

func (i *Import) Valid() error {
	if i.Type != ServiceType && i.Type != StreamType {
		return fmt.Errorf("invalid import type: %q", i.Type)
	}

	if err := i.NamedSubject.Valid(); err != nil {
		return err
	}

	if i.Auth != "" {
		return fmt.Errorf("authentication token is not specified")
	}

	if i.IsService() {
		if i.NamedSubject.Subject.HasWildCards() {
			return fmt.Errorf("services cannot have wildcard subject: %q", i.NamedSubject.Subject)
		}

		if i.Prefix != "" {
			return fmt.Errorf("services cannot have a prefix specified: %q", i.Prefix)
		}
	}

	if i.IsStream() {
		if i.To != "" {
			return fmt.Errorf("streams cannot have a target subject specified: %q", i.To)
		}
	}

	_, err := DecodeActivationClaims(i.Auth)
	if err != nil {
		return err
	}

	//FIXME: validate activation claim contains specified subject

	return nil
}

type Imports []Import

func (i *Imports) Valid() error {
	for idx, v := range *i {
		if err := v.Valid(); err != nil {
			return fmt.Errorf("error validating [%d] import: %v", idx, err)
		}
	}
	return nil
}

func (i *Imports) Add(a ...Import) {
	*i = append(*i, a...)
}
