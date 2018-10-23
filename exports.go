package jwt

import (
	"fmt"
)

type Export struct {
	NamedSubject
	Type string `json:"type,omitempty"`
	Limits
}

func (e *Export) IsService() bool {
	return e.Type == ServiceType
}

func (e *Export) IsStream() bool {
	return e.Type == StreamType
}

func (e *Export) Valid() error {
	if e.Type != ServiceType && e.Type != StreamType {
		return fmt.Errorf("invalid export type: %q", e.Type)
	}

	if err := e.NamedSubject.Valid(); err != nil {
		return err
	}

	if e.IsService() {
		if e.NamedSubject.Subject.HasWildCards() {
			return fmt.Errorf("services cannot have wildcard subject: %q", e.NamedSubject.Subject)
		}
	}

	return e.NamedSubject.Valid()
}

type Exports []Export

func (e *Exports) Add(i ...Export) {
	*e = append(*e, i...)
}

func (e *Exports) Valid() error {
	for _, v := range *e {
		if err := v.Valid(); err != nil {
			return err
		}
	}
	return nil
}

func (e *Exports) HasExportWithSubject(subject string) bool {
	for _, s := range *e {
		if string(s.Subject) == subject {
			return true
		}
	}
	return false
}
