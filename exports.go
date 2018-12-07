package jwt

// Export represents a single export
type Export struct {
	Name     string     `json:"name,omitempty"`
	Subject  Subject    `json:"subject,omitempty"`
	Type     ExportType `json:"type,omitempty"`
	TokenReq bool       `json:"token_req,omitempty"`
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
		if e.Subject.HasWildCards() {
			vr.AddWarning("services cannot have wildcard subject: %q", e.Subject)
		}
	}

	e.Subject.Validate(vr)
}

// Exports is an array of exports
type Exports []*Export

// Add appends exports to the list
func (e *Exports) Add(i ...*Export) {
	*e = append(*e, i...)
}

// Validate calls validate on all of the exports
func (e *Exports) Validate(vr *ValidationResults) error {
	var subjects []Subject
	for _, v := range *e {
		subjects = append(subjects, v.Subject)
		v.Validate(vr)
	}
	return nil
}
