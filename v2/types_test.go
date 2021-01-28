/*
 * Copyright 2018 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import (
	"crypto/rand"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	// Semantic versioning
	verRe := regexp.MustCompile(`\d+.\d+.\d+(-\S+)?`)
	if !verRe.MatchString(Version) {
		t.Fatalf("Version not compatible with semantic versioning: %q", Version)
	}
}

func TestVersionMatchesTag(t *testing.T) {
	tag := os.Getenv("TRAVIS_TAG")
	if tag == "" {
		t.SkipNow()
	}
	// We expect a tag of the form vX.Y.Z. If that's not the case,
	// we need someone to have a look. So fail if first letter is not
	// a `v`
	if len(tag) < 2 || tag[0] != 'v' {
		t.Fatalf("Expect tag to start with `v`, tag is: %s", tag)
	}
	// Look only at tag from current 'v', that is v1 for this file.
	if tag[1] != '2' {
		// Ignore, it is not a v2 tag.
		return
	}
	// Strip the `v` from the tag for the version comparison.
	if Version != tag[1:] {
		t.Fatalf("Version (%s) does not match tag (%s)", Version, tag[1:])
	}
}

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
	s := Subject("one")
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
	o = "one.*.three"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.*.three"
	o = "one.*.three"
	AssertEquals(true, s.IsContainedIn(o), t)

	s = "one.*.three"
	o = "one.two.three"
	AssertEquals(false, s.IsContainedIn(o), t)

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

func TestPermissions_Validate(t *testing.T) {
	p := Permissions{
		Pub:  Permission{},
		Sub:  Permission{},
		Resp: nil,
	}
	vr := ValidationResults{}
	resetAndValidate := func() {
		vr = ValidationResults{}
		p.Validate(&vr)
	}
	resetAndValidate()
	AssertTrue(vr.IsEmpty(), t)

	p.Resp = &ResponsePermission{
		MaxMsgs: 0,
		Expires: 0,
	}
	resetAndValidate()
	AssertTrue(vr.IsEmpty(), t)

	p.Pub.Allow.Add("foo")
	p.Pub.Deny.Add("bar")
	resetAndValidate()
	AssertTrue(vr.IsEmpty(), t)

	p.Pub.Allow.Add("foo queue")
	p.Pub.Deny.Add("bar queue")
	resetAndValidate()
	AssertTrue(!vr.IsEmpty(), t)
	AssertTrue(vr.IsBlocking(false), t)
	AssertTrue(len(vr.Errors()) == 2, t)

	p.Pub = Permission{}

	p.Sub.Allow.Add("1")
	p.Sub.Deny.Add("2")
	resetAndValidate()
	AssertTrue(vr.IsEmpty(), t)

	p.Sub.Allow.Add("3 queue")
	p.Sub.Deny.Add("4 queue")
	resetAndValidate()
	AssertTrue(vr.IsEmpty(), t)

	p.Sub.Allow.Add("5.* queue.*.foo")
	p.Sub.Deny.Add("6.* queue.*.bar")
	resetAndValidate()
	AssertTrue(vr.IsEmpty(), t)

	p.Sub.Allow.Add("7.> queue.>")
	p.Sub.Deny.Add("8.> queue.>")
	resetAndValidate()
	AssertTrue(vr.IsEmpty(), t)

	p.Sub.Allow.Add("9 too many spaces")
	p.Sub.Deny.Add("0 too many spaces")
	resetAndValidate()
	AssertTrue(!vr.IsEmpty(), t)
	AssertTrue(vr.IsBlocking(false), t)
	AssertTrue(len(vr.Errors()) == 2, t)
}

func TestRenamingSubject_ToSubject(t *testing.T) {
	AssertEquals(RenamingSubject("foo.$2.$1.bar").ToSubject(), Subject("foo.*.*.bar"), t)
	AssertEquals(RenamingSubject("foo.*.bar").ToSubject(), Subject("foo.*.bar"), t)
	AssertEquals(RenamingSubject("foo.$2.*.bar").ToSubject(), Subject("foo.*.*.bar"), t)
}

func TestRenamigSubject_Validate(t *testing.T) {
	for from, to := range map[string]string{
		"foo":      ">",
		"bar":      "*",
		"foo.*":    "*.*",
		"foo.>":    "*.*",
		"bar.>":    "*.>",
		"bar.*.*>": "*.>",
		"*.bar":    "$2",
	} {
		vr := ValidationResults{}
		RenamingSubject(to).Validate(Subject(from), &vr)
		if !vr.IsBlocking(false) {
			t.Fatalf("expected blocking issue %q:%q", to, from)
		}
	}
	for from, to := range map[string]string{
		"foo":     "bar",
		"foo.bar": "baz",
		"x":       "x.y.z",
		">":       "foo.>",
		"*":       "$1.foo",
		"*.*":     "$1.foo.$2",
		"*.bar":   "$1",
	} {
		vr := ValidationResults{}
		RenamingSubject(to).Validate(Subject(from), &vr)
		if !vr.IsEmpty() {
			t.Fatalf("expected no issue %q:%q got: %v", to, from, vr.Issues)
		}
	}
}

func TestInvalidInfo(t *testing.T) {
	tooLong := [MaxInfoLength + 21]byte{}
	rand.Read(tooLong[:])
	for _, info := range []Info{{
		Description: "",
		InfoURL:     "/bad",
	}, {
		Description: string(tooLong[:]),
		InfoURL:     "http://localhost/foo/bar",
	}, {
		Description: "",
		InfoURL: `http://1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901
234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901
23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890`,
	}} {
		vr := CreateValidationResults()
		info.Validate(vr)
		if vr.IsEmpty() {
			t.Errorf("info should not validate cleanly")
		}
		if !vr.IsBlocking(true) {
			t.Errorf("invalid info needs to be blocking")
		}
	}
}
