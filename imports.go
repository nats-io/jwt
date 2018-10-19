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
	Account string `json:"account,omitempty"`
	To      string `json:"to,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
}

func (a *ImportDescriptor) Valid() error {
	if err := a.NamedSubject.Valid(); err != nil {
		return err
	}
	if a.Account != "public" && !nkeys.IsValidPublicAccountKey(a.Account) {
		return fmt.Errorf("account %q is not a valid account public key", a.Account)
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

func (i *Imports) Valid() error {
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

	tokenMap := make(map[string]bool)
	tokenMap["public"] = true

	for _, t := range activations {
		tokenMap[t.Name] = true
	}

	for _, t := range i.Streams {
		if !tokenMap[t.Account] {
			return fmt.Errorf("imported stream references account %q - but provides no matching activation", t.Account)
		}
	}

	for _, t := range i.Streams {
		if !tokenMap[t.Account] {
			return fmt.Errorf("import service references account %q - but provides no matching activation", t.Account)
		}
	}

	return nil
}
