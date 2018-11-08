package jwt

import "testing"

func TestSubjectValid(t *testing.T) {
	var s Subject

	s = ""
	err := s.Valid()
	if err == nil {
		t.Fatalf("Empty string is not a valid subjects")
	}

	s = "has spaces"
	err = s.Valid()
	if err == nil {
		t.Fatalf("Subjects cannot contain spaces")
	}

	s = "has.spa ces.and.tokens"
	err = s.Valid()
	if err == nil {
		t.Fatalf("Subjects cannot have spaces")
	}

	s = "one"
	err = s.Valid()
	if err != nil {
		t.Fatalf("%s is a valid subject", s)
	}

	s = "one.two.three"
	err = s.Valid()
	if err != nil {
		t.Fatalf("%s is a valid subject", s)
	}
}

func TestHasWildCards(t *testing.T) {
	var s Subject

	s = "one"
	AssertEquals(false, s.HasWildCards(), t)

	s = "one.two.three"
	AssertEquals(false, s.HasWildCards(), t)

	s = "*"
	AssertEquals(true, s.HasWildCards(), t)

	s = "one.*.three"
	AssertEquals(true, s.HasWildCards(), t)

	s = "*.two.three"
	AssertEquals(true, s.HasWildCards(), t)

	s = "one.two.*"
	AssertEquals(true, s.HasWildCards(), t)

	s = "one.>"
	AssertEquals(true, s.HasWildCards(), t)

	s = "one.two.>"
	AssertEquals(true, s.HasWildCards(), t)

	s = ">"
	AssertEquals(true, s.HasWildCards(), t)
}
