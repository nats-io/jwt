package jwt

import (
	"fmt"
	"strings"
)

type Export struct {
	NamedSubject
}

func (e *Export) Valid() error {
	return e.NamedSubject.Valid()
}

type ExportedStream struct {
	Export
}

func (es *ExportedStream) Valid() error {
	return es.Export.Valid()
}

type ExportedStreams []ExportedStream

func (es *ExportedStreams) Valid() error {
	for _, v := range *es {
		if err := v.Valid(); err != nil {
			return err
		}
	}
	return nil
}

type ExportedService struct {
	Export
}

func (es *ExportedService) Valid() error {
	if err := es.NamedSubject.Valid(); err != nil {
		return err
	}
	if strings.HasSuffix(es.Subject, ".>") ||
		strings.HasSuffix(es.Subject, ".*") ||
		strings.Contains(es.Subject, ".*.") {
		return fmt.Errorf("services cannot contain wildcards: %q", es.Subject)
	}
	return nil
}

type ExportedServices []ExportedService

func (es *ExportedServices) Valid() error {
	for _, v := range *es {
		if err := v.Valid(); err != nil {
			return err
		}
	}
	return nil
}

type Exports struct {
	Streams  ExportedStreams  `json:"streams,omitempty"`
	Services ExportedServices `json:"services,omitempty"`
}
