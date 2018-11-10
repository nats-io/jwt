package jwt

import "testing"

func TestSimpleImportValidation(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Account: akp,
		To:      Subject("bar"),
		Type:    StreamType,
	}

	vr := CreateValidationResults()
	i.Validate(nil, vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	i.Type = ServiceType
	vr = CreateValidationResults()
	i.Validate(nil, vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}
}

func TestInvalidImportType(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Account: akp,
		To:      Subject("bar"),
		Type:    "foo",
	}

	vr := CreateValidationResults()
	i.Validate(nil, vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if !vr.IsBlocking(true) {
		t.Errorf("invalid type is blocking")
	}
}

func TestMissingAccountInImport(t *testing.T) {
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		To:   Subject("bar"),
		Type: StreamType,
	}

	vr := CreateValidationResults()
	i.Validate(nil, vr)

	if len(vr.Issues) != 2 {
		t.Errorf("imports without token or url should warn the caller, as should missing account")
	}

	if vr.IsBlocking(true) {
		t.Errorf("Missing Account is not blocking, must import failures are warnings")
	}
}

func TestServiceImportWithWildcard(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo.*",
		},
		Account: akp,
		To:      Subject("bar"),
		Type:    ServiceType,
	}

	vr := CreateValidationResults()
	i.Validate(nil, vr)

	if len(vr.Issues) != 2 {
		t.Errorf("imports without token or url should warn the caller, as should wildcard service")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}
}

func TestImportsValidation(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Account: akp,
		To:      Subject("bar"),
		Type:    StreamType,
	}
	i2 := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo.*",
		},
		Account: akp,
		To:      Subject("bar"),
		Type:    ServiceType,
	}

	imports := &Imports{}
	imports.Add(i, i2)

	vr := CreateValidationResults()
	imports.Validate(nil, vr)

	if len(vr.Issues) != 3 {
		t.Errorf("imports without token or url should warn the caller x2, wildcard service as well")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}
}
