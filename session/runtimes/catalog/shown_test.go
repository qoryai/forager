package catalog_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qoryai/forager/session/runtimes/catalog"
)

// TestLookupPrintsAPhraseForASecret pins the errors of Lookup: a runtime's name or a
// descriptor's path that contains qak_ or qrk_ is the phrase, and a clean one prints
// as before.
func TestLookupPrintsAPhraseForASecret(t *testing.T) {
	for name, want := range map[string]string{
		"qak_x": "runtime (a name that contains an access key secret) is not a name: a lower-case letter, then up to 63 lower-case letters, digits and dashes",
		"Bad":   `runtime "Bad" is not a name: a lower-case letter, then up to 63 lower-case letters, digits and dashes`,
	} {
		if _, err := catalog.Lookup(name, ""); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	base := t.TempDir()
	for _, dir := range []string{filepath.Join(base, "QRK_y"), filepath.Join(base, "clean")} {
		if err := os.MkdirAll(filepath.Join(dir, "amp.yaml"), 0o755); err != nil {
			t.Fatal(err)
		}
		want := "Make the runtime descriptor " + filepath.Join(dir, "amp.yaml") + " a readable regular file of at most 1 MiB, or remove it. It could not be read: it is not a regular file"
		if filepath.Base(dir) == "QRK_y" {
			want = "Make the runtime descriptor (a value that contains a run key) a readable regular file of at most 1 MiB, or remove it. It could not be read: it is not a regular file"
		}
		if _, err := catalog.Lookup("amp", dir); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", dir, err, want)
		}
	}
}
