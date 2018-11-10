package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestImportValidation(t *testing.T) {
	ak := createAccountNKey(t)
	ak2 := createAccountNKey(t)
	akp := publicKey(ak, t)
	akp2 := publicKey(ak2, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "test",
		},
		Account: akp2,
		To:      Subject("bar"),
		Type:    StreamType,
	}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	i.Type = ServiceType
	vr = CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.Exports = Exports{}
	activation.Exports.Add(
		&Export{
			NamedSubject: NamedSubject{
				Subject: "test",
			},
			Type: StreamType,
		})
	actJWT := encode(activation, ak2, t)

	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with token should be valid")
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
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if !vr.IsBlocking(true) {
		t.Errorf("invalid type is blocking")
	}
}

func TestInvalidImportToken(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Account: akp,
		Token:   "bad token",
		To:      Subject("bar"),
		Type:    "stream",
	}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports with a bad token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("invalid type shouldnt be blocking")
	}
}

func TestInvalidImportURL(t *testing.T) {
	ak := createAccountNKey(t)
	akp := publicKey(ak, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "foo",
		},
		Account:  akp,
		TokenURL: "bad token url",
		To:       Subject("bar"),
		Type:     "stream",
	}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports with a bad token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("invalid type shouldnt be blocking")
	}
}

func TestInvalidImportTokenValuesValidation(t *testing.T) {
	ak := createAccountNKey(t)
	ak2 := createAccountNKey(t)
	akp := publicKey(ak, t)
	akp2 := publicKey(ak2, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "test",
		},
		Account: akp2,
		To:      Subject("bar"),
		Type:    StreamType,
	}

	vr := CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	i.Type = ServiceType
	vr = CreateValidationResults()
	i.Validate("", vr)

	if vr.IsEmpty() {
		t.Errorf("imports without token or url should warn the caller")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}

	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.Exports = Exports{}
	activation.Exports.Add(
		&Export{
			NamedSubject: NamedSubject{
				Subject: "test",
			},
			Type: StreamType,
		})
	actJWT := encode(activation, ak2, t)

	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with token should be valid")
	}

	actJWT = encode(activation, ak, t) // wrong issuer
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with wrong issuer")
	}

	activation.Subject = akp2           // wrong subject
	actJWT = encode(activation, ak2, t) // right issuer
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with wrong issuer")
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
	i.Validate("", vr)

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
	i.Validate("", vr)

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
	imports.Validate("", vr)

	if len(vr.Issues) != 3 {
		t.Errorf("imports without token or url should warn the caller x2, wildcard service as well")
	}

	if vr.IsBlocking(true) {
		t.Errorf("imports without token or url should not be blocking")
	}
}

func TestTokenURLImportValidation(t *testing.T) {
	ak := createAccountNKey(t)
	ak2 := createAccountNKey(t)
	akp := publicKey(ak, t)
	akp2 := publicKey(ak2, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "test",
		},
		Account: akp2,
		To:      Subject("bar"),
		Type:    StreamType,
	}

	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.Exports = Exports{}
	activation.Exports.Add(
		&Export{
			NamedSubject: NamedSubject{
				Subject: "test",
			},
			Type: StreamType,
		})
	actJWT := encode(activation, ak2, t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(actJWT))
	}))
	defer ts.Close()

	i.TokenURL = ts.URL
	vr := CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with token url should be valid")
	}

	i.TokenURL = "Bad URL"
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with bad token url should be valid")
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bad jwt"))
	}))
	defer ts.Close()

	i.TokenURL = ts.URL
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with token url pointing to bad JWT")
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	i.TokenURL = ts.URL
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with token url pointing to bad url")
	}
}

func TestImportSubjectValidation(t *testing.T) {
	ak := createAccountNKey(t)
	ak2 := createAccountNKey(t)
	akp := publicKey(ak, t)
	akp2 := publicKey(ak2, t)
	i := &Import{
		NamedSubject: NamedSubject{
			Subject: "one.two",
		},
		Account: akp2,
		To:      Subject("bar"),
		Type:    StreamType,
	}

	activation := NewActivationClaims(akp)
	activation.Max = 1024 * 1024
	activation.Expires = time.Now().Add(time.Duration(time.Hour)).UTC().Unix()
	activation.Exports = Exports{}
	activation.Exports.Add(
		&Export{
			NamedSubject: NamedSubject{
				Subject: "one.*",
			},
			Type: StreamType,
		})

	actJWT := encode(activation, ak2, t)
	i.Token = actJWT
	vr := CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with valid contains subject should be valid")
	}

	activation.Exports[0].Subject = "two"
	actJWT = encode(activation, ak2, t)
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if vr.IsEmpty() {
		t.Errorf("imports with non-contains subject should be valid")
	}

	activation.Exports[0].Subject = ">"
	actJWT = encode(activation, ak2, t)
	i.Token = actJWT
	vr = CreateValidationResults()
	i.Validate(akp, vr)

	if !vr.IsEmpty() {
		t.Errorf("imports with valid contains subject should be valid")
	}
}
