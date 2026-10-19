package receiver

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestARegistrationsAboutWithoutASecretIsKeptByteForByte pins the about a registration
// sent, without qak_ or qrk_, as its body has it, its member order and escapes among
// them, and an about with one rewritten.
func TestARegistrationsAboutWithoutASecretIsKeptByteForByte(t *testing.T) {
	const runID = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	body := func(about string) []byte {
		return []byte(`{"version":1,"run_id":"` + runID + `","about":` + about + `,"time":"2026-10-19T00:00:00Z"}`)
	}
	clean := `{"title":"t","kind":"k","details":{"u":"a\/b","e":"é"}}`
	reg, err := readRegistration(body(clean))
	if err != nil {
		t.Fatal(err)
	}
	if string(reg.About) != clean {
		t.Errorf("the about kept is %s, want %s", reg.About, clean)
	}
	reg, err = readRegistration(body(`{"title":"qak_FAKE","kind":"k"}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"k","title":"(a name that contains an access key secret)"}`; string(reg.About) != want {
		t.Errorf("the about kept is %s, want %s", reg.About, want)
	}
}

// TestAStoreFileErrorPrintsAPhraseForASecret pins the error of a store file whose path
// contains qrk_: a phrase, the error it wraps still found by errors.Is.
func TestAStoreFileErrorPrintsAPhraseForASecret(t *testing.T) {
	_, err := OpenFile(filepath.Join(t.TempDir(), "qrk_FAKE", "events.jsonl"))
	if err == nil {
		t.Fatal("a file in a missing directory opened")
	}
	if low := strings.ToLower(err.Error()); strings.Contains(low, "qrk_") {
		t.Errorf("the error %v contains a run key's prefix", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the error %v does not wrap fs.ErrNotExist", err)
	}
}

// TestAStoreFileCloseErrorPrintsAPhraseForASecret pins the error of closing a store
// file twice whose name contains qak_: a phrase, the error it wraps still found by
// errors.Is.
func TestAStoreFileCloseErrorPrintsAPhraseForASecret(t *testing.T) {
	f, err := OpenFile(filepath.Join(t.TempDir(), "qak_FAKE.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err == nil {
		t.Fatal("a second close succeeded")
	}
	if low := strings.ToLower(err.Error()); strings.Contains(low, "qak_") {
		t.Errorf("the error %v contains an access key secret's prefix", err)
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("the error %v does not wrap os.ErrClosed", err)
	}
}
