package jwt

import (
	"strings"
)

// Subject is a string that represents a NATS subject
type Subject string

// Validate checks that a subject string is valid, ie not empty and without spaces
func (s Subject) Validate(vr *ValidationResults) {
	v := string(s)
	if v == "" {
		vr.AddError("subject cannot be empty")
	}
	if strings.Index(v, " ") != -1 {
		vr.AddError("subject %q cannot have spaces", v)
	}
}

// HasWildCards is used to check if a subject contains a > or *
func (s Subject) HasWildCards() bool {
	v := string(s)
	return strings.HasSuffix(v, ".>") ||
		strings.Contains(v, ".*.") ||
		strings.HasSuffix(v, ".*") ||
		strings.HasPrefix(v, "*.") ||
		v == "*" ||
		v == ">"
}
