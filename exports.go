package jwt

import (
	"fmt"
)

// Export represents a single export
type Export struct {
	NamedSubject
	Type ExportType
	Limits
}

// IsService returns true if an export is for a service
func (e *Export) IsService() bool {
	return e.Type == Service
}

// IsStream returns true if an export is for a stream
func (e *Export) IsStream() bool {
	return e.Type == Stream
}

// Validate appends validation issues to the passed in results list
func (e *Export) Validate(vr *ValidationResults) {
	if !e.IsService() && !e.IsStream() {
		vr.AddError("invalid export type: %q", e.Type)
	}

	if e.IsService() {
		if e.NamedSubject.Subject.HasWildCards() {
			vr.AddWarning("services cannot have wildcard subject: %q", e.NamedSubject.Subject)
		}
	}

	e.NamedSubject.Validate(vr)
}

// Exports is an array of exports
type Exports []*Export

// Add appends exports to the list
func (e *Exports) Add(i ...*Export) {
	*e = append(*e, i...)
}

// Validate calls validate on all of the exports
func (e *Exports) Validate(vr *ValidationResults) error {
	var subjects []NamedSubject
	for _, v := range *e {
		subjects = append(subjects, v.NamedSubject)
		v.Validate(vr)
	}
	// collect all the subjects, and validate that no subject is a subset
	m := make(map[string]string)
	for i, ns := range subjects {
		for j, s := range subjects {
			if i == j {
				continue
			}
			if ns.Subject.IsContainedIn(s.Subject) {
				str := string(s.Subject)
				_, ok := m[str]
				if !ok {
					m[str] = string(ns.Subject)
				}
			}
		}
	}

	if len(m) != 0 {
		for k, v := range m {
			var vi ValidationIssue
			vi.Blocking = true
			vi.Description = fmt.Sprintf("export subject %q already exports %q", k, v)
			vr.Add(&vi)
		}
	}

	return nil
}

// HasExportContainingSubject checks if the export list has an export with the provided subject
func (e *Exports) HasExportContainingSubject(subject Subject) bool {
	for _, s := range *e {
		if subject.IsContainedIn(s.Subject) {
			return true
		}
	}
	return false
}
