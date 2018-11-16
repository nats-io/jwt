package jwt

import (
	"testing"
)

func TestSimpleExportValidation(t *testing.T) {
	e := &Export{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Type: StreamType,
	}

	vr := CreateValidationResults()
	e.Validate(vr)

	if !vr.IsEmpty() {
		t.Errorf("simple export should validate cleanly")
	}

	e.Type = StreamType
	vr = CreateValidationResults()
	e.Validate(vr)

	if !vr.IsEmpty() {
		t.Errorf("simple export should validate cleanly")
	}
}

func TestInvalidExportType(t *testing.T) {
	i := &Export{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Type: "foo",
	}

	vr := CreateValidationResults()
	i.Validate(vr)

	if vr.IsEmpty() {
		t.Errorf("export with bad type should not validate cleanly")
	}

	if !vr.IsBlocking(true) {
		t.Errorf("invalid type is blocking")
	}
}

func TestServiceExportWithWildcard(t *testing.T) {
	i := &Export{
		NamedSubject: NamedSubject{
			Subject: "foo.*",
		},
		Type: ServiceType,
	}

	vr := CreateValidationResults()
	i.Validate(vr)

	if len(vr.Issues) != 1 {
		t.Errorf("export with service wildcard shoudl have one failure")
	}

	if vr.IsBlocking(true) {
		t.Errorf("export with wildcard should not be blocking")
	}
}

func TestExportsValidation(t *testing.T) {
	i := &Export{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Type: StreamType,
	}
	i2 := &Export{
		NamedSubject: NamedSubject{
			Subject: "foo.*",
		},
		Type: ServiceType,
	}

	exports := &Exports{}
	exports.Add(i, i2)

	vr := CreateValidationResults()
	exports.Validate(vr)

	if len(vr.Issues) != 1 {
		t.Errorf("export with wildcard should warn")
	}

	if vr.IsBlocking(true) {
		t.Errorf("export with wildcard should not be blocking")
	}

	if !exports.HasExportContainingSubject("foo") {
		t.Errorf("Export list has the subject, and should say so")
	}

	if !exports.HasExportContainingSubject("foo.*") {
		t.Errorf("Export list has the subject, and should say so")
	}

	if exports.HasExportContainingSubject("bar.*") {
		t.Errorf("Export list does not has the subject, and should say so")
	}
}

func TestOverlappingExports(t *testing.T) {
	i := &Export{
		NamedSubject: NamedSubject{
			Subject: "bar.foo",
		},
		Type: StreamType,
	}
	i2 := &Export{
		NamedSubject: NamedSubject{
			Subject: "bar.*",
		},
		Type: StreamType,
	}

	exports := &Exports{}
	exports.Add(i, i2)

	vr := CreateValidationResults()
	exports.Validate(vr)

	if len(vr.Issues) != 1 {
		t.Errorf("export has overlapping subjects")
	}
}
