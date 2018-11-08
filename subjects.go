package jwt

import (
	"errors"
	"strings"
)

type Subject string

func (s Subject) Valid() error {
	v := string(s)
	if v == "" {
		return errors.New("subject cannot be empty")
	}
	if strings.Index(v, " ") != -1 {
		return errors.New("subject cannot have spaces")
	}
	return nil
}

func (s Subject) HasWildCards() bool {
	v := string(s)
	return strings.HasSuffix(v, ".>") ||
		strings.Contains(v, ".*.") ||
		strings.HasSuffix(v, ".*") ||
		strings.HasPrefix(v, "*.") ||
		v == "*" ||
		v == ">"
}
