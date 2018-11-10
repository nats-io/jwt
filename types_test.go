package jwt

import (
	"strings"
	"testing"
)

func TestTimeRangeValidation(t *testing.T) {
	tr := TimeRange{
		Start: "hello",
		End:   "03:15:00",
	}

	vr := CreateValidationResults()
	tr.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad start should be invalid")
	}

	if !strings.Contains(vr.Issues[0].Error(), tr.Start) {
		t.Error("error should contain the faulty value")
	}

	tr = TimeRange{
		Start: "15:43:22",
		End:   "27:11:11",
	}

	vr = CreateValidationResults()
	tr.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad end should be invalid")
	}

	if !strings.Contains(vr.Issues[0].Error(), tr.End) {
		t.Error("error should contain the faulty value")
	}

	tr = TimeRange{
		Start: "",
		End:   "03:15:00",
	}

	vr = CreateValidationResults()
	tr.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad start should be invalid")
	}

	tr = TimeRange{
		Start: "15:43:22",
		End:   "",
	}

	vr = CreateValidationResults()
	tr.Validate(vr)

	if vr.IsEmpty() || len(vr.Issues) != 1 || !vr.IsBlocking(true) {
		t.Error("bad end should be invalid")
	}
}

func TestTagList(t *testing.T) {
	tags := TagList{}

	tags.Add("one")

	AssertEquals(true, tags.Contains("one"), t)
	AssertEquals(true, tags.Contains("ONE"), t)
	AssertEquals("one", tags[0], t)

	tags.Add("TWO")

	AssertEquals(true, tags.Contains("two"), t)
	AssertEquals(true, tags.Contains("TWO"), t)
	AssertEquals("two", tags[1], t)

	tags.Remove("ONE")
	AssertEquals("two", tags[0], t)
	AssertEquals(false, tags.Contains("one"), t)
	AssertEquals(false, tags.Contains("ONE"), t)
}

func TestStringList(t *testing.T) {
	slist := StringList{}

	slist.Add("one")

	AssertEquals(true, slist.Contains("one"), t)
	AssertEquals(false, slist.Contains("ONE"), t)
	AssertEquals("one", slist[0], t)

	slist.Add("TWO")

	AssertEquals(false, slist.Contains("two"), t)
	AssertEquals(true, slist.Contains("TWO"), t)
	AssertEquals("TWO", slist[1], t)

	slist.Remove("ONE")
	AssertEquals("one", slist[0], t)
	AssertEquals(true, slist.Contains("one"), t)
	AssertEquals(false, slist.Contains("ONE"), t)

	slist.Add("ONE")
	AssertEquals(true, slist.Contains("one"), t)
	AssertEquals(true, slist.Contains("ONE"), t)
	AssertEquals(3, len(slist), t)

	slist.Remove("one")
	AssertEquals("TWO", slist[0], t)
	AssertEquals(false, slist.Contains("one"), t)
	AssertEquals(true, slist.Contains("ONE"), t)
}

func TestSubjectValid(t *testing.T) {
	var s Subject

	s = ""
	vr := CreateValidationResults()
	s.Validate(vr)
	if !vr.IsBlocking(false) {
		t.Fatalf("Empty string is not a valid subjects")
	}

	s = "has spaces"
	vr = CreateValidationResults()
	s.Validate(vr)
	if !vr.IsBlocking(false) {
		t.Fatalf("Subjects cannot contain spaces")
	}

	s = "has.spa ces.and.tokens"
	vr = CreateValidationResults()
	s.Validate(vr)
	if !vr.IsBlocking(false) {
		t.Fatalf("Subjects cannot have spaces")
	}

	s = "one"
	vr = CreateValidationResults()
	s.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatalf("%s is a valid subject", s)
	}

	s = "one.two.three"
	vr = CreateValidationResults()
	s.Validate(vr)
	if !vr.IsEmpty() {
		t.Fatalf("%s is a valid subject", s)
	}
}

func TestSubjectHasWildCards(t *testing.T) {
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

func TestSubjectContainment(t *testing.T) {
	var s Subject
	var o Subject

	s = "one.two.three"
	o = "one.two.three"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.two.three"
	o = "one.two.*"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.two.three"
	o = "one.*.three"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.two.three"
	o = "*.two.three"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.two.three"
	o = "one.two.>"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.two.three"
	o = "one.>"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.two.three"
	o = ">"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.two.three"
	o = "one.two"
	AssertEquals(false, s.IsContainedIn(o), t)

	s = "one"
	o = "one.two"
	AssertEquals(false, s.IsContainedIn(o), t)
}
