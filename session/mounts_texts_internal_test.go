package session

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAPlaceThatResolvesOutsideAWritablePlaceItIsLookedUpInIsNoRun pins the text of the
// refusal of a place that is looked up inside a writable place and resolves outside
// it, when the link on the way cannot be found: the fix names the place as given, and
// the cause names the kind and the path of the place, then of the writable place, and
// ends with the reason.
func TestAPlaceThatResolvesOutsideAWritablePlaceItIsLookedUpInIsNoRun(t *testing.T) {
	top := t.TempDir()
	w, p := filepath.Join(top, "w"), filepath.Join(top, "p")
	for _, d := range []string{w, p} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out := shown{path: w, what: "the mount", writable: true, at: splitPath{exists: w}}
	in := shown{path: p, what: "the workspace", at: splitPath{exists: p},
		looks: []lookup{{dir: w, rest: []string{"n"}, at: splitPath{exists: w}}}}
	want := "List the path that the workspace " + p + " resolves to, in place of the path given. " +
		"The path is looked up inside the mount " + w + " and resolves outside it: " +
		"no link on the way lies inside it"
	if err := throughLink(in, out); err == nil || err.Error() != want {
		t.Errorf("got %v\nwant %q", err, want)
	}
}
