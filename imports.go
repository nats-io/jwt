package jwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nkeys"
)

type NamedSubject struct {
	Name    string `json:"name,omitempty"`
	Subject string `json:"subject,omitempty"`
}

func (ns *NamedSubject) Valid() error {
	if ns.Subject == "" {
		return errors.New("subject cannot be empty")
	}

	return nil
}

type ImportDescriptor struct {
	NamedSubject
	Auth   string `json:"auth,omitempty"`
	To     string `json:"to,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

func (a *ImportDescriptor) Valid() error {
	if err := a.NamedSubject.Valid(); err != nil {
		return err
	}
	if a.Auth != "public" && !nkeys.IsValidPublicAccountKey(a.Auth) {
		return fmt.Errorf("account %q is not a valid account public key", a.Auth)
	}

	return nil
}

type ImportedService struct {
	ImportDescriptor
}

type ImportedServices []ImportedService

func (s *ImportedServices) Valid() error {
	for _, t := range *s {
		if err := t.Valid(); err != nil {
			return err
		}
	}
	return nil
}

func (s *ImportedService) Valid() error {
	if err := s.ImportDescriptor.Valid(); err != nil {
		return err
	}
	if strings.HasSuffix(s.Subject, ".>") ||
		strings.HasSuffix(s.Subject, ".*") ||
		strings.Contains(s.Subject, ".*.") {
		return fmt.Errorf("services cannot contain wildcards: %q", s.Subject)
	}
	return nil
}

type ImportedStream struct {
	ImportDescriptor
}

type ImportedStreams []ImportedStream

func (s *ImportedStreams) Valid() error {
	for _, t := range *s {
		if err := t.Valid(); err != nil {
			return err
		}
	}
	return nil
}

func (s *ImportedStream) Valid() error {
	return s.ImportDescriptor.Valid()
}

type Imports struct {
	Streams  ImportedStreams  `json:"streams,omitempty"`
	Services ImportedServices `json:"services,omitempty"`
	Act      []string         `json:"act,omitempty"`
}

func (i *Imports) AppendActivation(act string) {
	i.Act = append(i.Act, act)
}

func (i *Imports) Activations() ([]*ActivationClaims, error) {
	var buf []*ActivationClaims
	for i, s := range i.Act {
		ac, err := DecodeActivationClaims(s)
		if err != nil {
			return nil, fmt.Errorf("error decoding activation [%d]: %v", i, err)
		}
		buf = append(buf, ac)
	}
	return buf, nil
}

func (i *Imports) Valid(subject string) error {
	if err := i.Streams.Valid(); err != nil {
		return err
	}
	if err := i.Services.Valid(); err != nil {
		return err
	}

	activations, err := i.Activations()
	if err != nil {
		return err
	}

	m := make(map[string][]*ActivationClaims)

	for i, t := range activations {
		if !strings.EqualFold("public", t.Subject) && t.Subject != subject {
			return fmt.Errorf("activation [%d] has a subject of %q - which is not 'public' or matching %q", i, t.Subject, subject)
		}

		a, ok := m[t.Issuer]
		if !ok {
			a = make([]*ActivationClaims, 0, 0)
			m[t.Issuer] = a
		}
		a = append(a, t)
	}

	for _, t := range i.Streams {
		actvs := m[t.Auth]
		if actvs == nil || len(actvs) == 0 {
			return fmt.Errorf("imported stream references account %q - but provides no matching activation", t.Auth)
		}
		found := false
		for _, act := range actvs {
			if act.Exports.HasStreamWithSubject(t.Subject) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("an export for %q in a stream from account %q was not included", t.Subject, t.Auth)
		}
	}

	for _, t := range i.Services {
		actvs := m[t.Auth]
		if actvs == nil || len(actvs) == 0 {
			return fmt.Errorf("imported service references account %q - but provides no matching activation", t.Auth)
		}
		found := false
		for _, act := range actvs {
			if act.Exports.HasServiceWithSubject(t.Subject) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("an export for %q in a service from account %q was not included", t.Subject, t.Auth)
		}
	}

	return nil
}
