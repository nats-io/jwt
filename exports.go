package jwt

// Export represents a single export
type Export struct {
	NamedSubject
	Type string `json:"type,omitempty"`
	Limits
}

// IsService returns true if an export is for a service
func (e *Export) IsService() bool {
	return e.Type == ServiceType
}

// IsStream returns true if an export is for a stream
func (e *Export) IsStream() bool {
	return e.Type == StreamType
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
	for _, v := range *e {
		v.Validate(vr)
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
