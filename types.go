package jwt

import (
	"strings"
)

// ServiceType defines the type field value for a service "service"
const ServiceType = "service"

// StreamType defines the type field value for a stream "stream"
const StreamType = "stream"

// NamedSubject is the combination of a subject and a name for it
type NamedSubject struct {
	Name    string  `json:"name,omitempty"`
	Subject Subject `json:"subject,omitempty"`
}

// Validate checks the subject
func (ns *NamedSubject) Validate(vr *ValidationResults) {
	ns.Subject.Validate(vr)
}

// Limits are used to control acccess for users and importing accounts
type Limits struct {
	Max     int64   `json:"max,omitempty"`
	Payload int64   `json:"payload,omitempty"`
	Src     string  `json:"src,omitempty"`
	Times   []int64 `json:"times,omitempty"`
}

// Validate checks the values in a limit struct
func (l *Limits) Validate(vr *ValidationResults) {
	if l.Max < 0 {
		vr.AddError("limits cannot contain a negative maximum, %d", l.Max)
	}
	if l.Payload < 0 {
		vr.AddError("limits cannot contain a negative payload, %d", l.Payload)
	}
	// Fixme validate source and times
}

// Permission defines allow/deny subjects
type Permission struct {
	Allow StringList `json:"allow,omitempty"`
	Deny  StringList `json:"deny,omitempty"`
}

// Validate the allow, deny elements of a permission
func (p *Permission) Validate(vr *ValidationResults) {
	// Fixme - validate permission
}

// Permissions are used to restrict subject access, either on a user or for everyone on a server by default
type Permissions struct {
	Pub Permission `json:"pub,omitempty"`
	Sub Permission `json:"sub,omitempty"`
}

// Validate the pub and sub fields in the permissions list
func (p *Permissions) Validate(vr *ValidationResults) {
	p.Pub.Validate(vr)
	p.Sub.Validate(vr)
}

// StringList is a wrapper for an array of strings
type StringList []string

// Contains returns true if the list contains the string
func (u *StringList) Contains(p string) bool {
	for _, t := range *u {
		if t == p {
			return true
		}
	}
	return false
}

// Add appends 1 or more strings to a list
func (u *StringList) Add(p ...string) {
	for _, v := range p {
		if !u.Contains(v) && v != "" {
			*u = append(*u, v)
		}
	}
}

// Remove removes 1 or more strings from a list
func (u *StringList) Remove(p ...string) {
	for _, v := range p {
		for i, t := range *u {
			if t == v {
				a := *u
				*u = append(a[:i], a[i+1:]...)
				break
			}
		}
	}
}

// TagList is a unique array of lower case strings
// All tag list methods lower case the strings in the arguments
type TagList []string

// Contains returns true if the list contains the tags
func (u *TagList) Contains(p string) bool {
	p = strings.ToLower(p)
	for _, t := range *u {
		if t == p {
			return true
		}
	}
	return false
}

// Add appends 1 or more tags to a list
func (u *TagList) Add(p ...string) {
	for _, v := range p {
		v = strings.ToLower(v)
		if !u.Contains(v) && v != "" {
			*u = append(*u, v)
		}
	}
}

// Remove removes 1 or more tags from a list
func (u *TagList) Remove(p ...string) {
	for _, v := range p {
		v = strings.ToLower(v)
		for i, t := range *u {
			if t == v {
				a := *u
				*u = append(a[:i], a[i+1:]...)
				break
			}
		}
	}
}

// Identity is used to associate an account or operator with a real entity
type Identity struct {
	ID    string `json:"id,omitempty"`
	Proof string `json:"proof,omitempty"`
}

// Validate checks the values in an Identity
func (u *Identity) Validate(vr *ValidationResults) {
}
