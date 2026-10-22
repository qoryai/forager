package session

import (
	"strings"
	"testing"

	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/runtimes"
)

// TestTheLaunchLineIsMasked pins the line of Report of a run with a run key: the
// values of this machine, with the run's masker's placeholder in place of a
// forwarder's password and the run key's phrase in place of a value that contains
// qrk_.
func TestTheLaunchLineIsMasked(t *testing.T) {
	password := strings.Repeat("p", 43)
	r := &Run{dir: "/srv/runs/r1", masker: &mask.Masker{}}
	r.masker.AddProxy(proxyUser, password)
	spec := runSpec{SessionSpec: SessionSpec{Dir: "/srv/work", HarnessHome: "/srv/home", InputsDir: "/srv/in"}}
	line := r.launchLine(spec, 2, runtimes.Launch{Command: "/usr/bin/agent", Args: []string{"--proxy", "http://qory:" + password + "@127.0.0.1:1", "qrk_example"}})
	host := hostname()
	want := `session 2 starts on this machine: host ` + host + `, dir "/srv/work", home "/srv/home", inputs "/srv/in", command "/usr/bin/agent", ` +
		`args ["--proxy" "http://qory:` + mask.ProxyPassword + `@127.0.0.1:1" "` + rkValue + `"]`
	if line != want {
		t.Errorf("the line\n%s\nwant\n%s", line, want)
	}
}

// TestNeutralPathsReplaceTheLongerFirst pins the order of neutralPaths: of two paths
// where one contains the other the longer is replaced, and the home's and the inputs'
// paths inside the enclosure are replaced as well as those on this machine.
func TestNeutralPathsReplaceTheLongerFirst(t *testing.T) {
	r := &Run{dir: "/srv/runs/r1"}
	inside := func(s string) string { return translate(s, "/srv", workspaceInside) }
	for _, c := range []struct{ home, inputs, in, want string }{
		{"/srv/runs/r1/home", "/srv/runs/r1/in", "/srv/runs/r1/home/a /srv/runs/r1/in/b /srv/runs/r1/c", "<home>/a <inputs>/b <run>/c"},
		{"/srv", "/x/in", "/srv/runs/r1/c /srv/d /x/in", "<run>/c <home>/d <inputs>"},
		{"/srv/home", "/srv/in", "/workspace/home/a --dir=/workspace/in", "<home>/a --dir=<inputs>"},
	} {
		if got := r.neutralPaths(c.home, c.inputs, inside).Replace(c.in); got != c.want {
			t.Errorf("home %s, inputs %s: %q is %q, want %q", c.home, c.inputs, c.in, got, c.want)
		}
	}
}
