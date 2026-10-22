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

// TestNeutralPathsReplaceWholeComponents pins neutralPaths: a path is replaced at
// whole path components, after its trailing slash is cleaned, and not in a sibling or
// a URL that contains its text; of two paths where one contains the other the longer
// is replaced; the home's, the inputs' and the working directory's paths inside the
// enclosure are replaced as well as those on this machine.
func TestNeutralPathsReplaceWholeComponents(t *testing.T) {
	r := &Run{dir: "/srv/runs/r1"}
	inside := func(s string) string { return translate(s, "/srv", workspaceInside) }
	same := func(s string) string { return s }
	for _, c := range []struct {
		home, inputs, dir string
		inside            func(string) string
		in, want          string
	}{
		{"/srv/runs/r1/home", "/srv/runs/r1/in", "", same, "/srv/runs/r1/home/a /srv/runs/r1/in/b /srv/runs/r1/c", "<home>/a <inputs>/b <run>/c"},
		{"/srv", "/x/in", "", same, "/srv/runs/r1/c /srv/d /x/in", "<run>/c <home>/d <inputs>"},
		{"/srv/home", "/srv/in", "", inside, "/workspace/home/a --dir=/workspace/in", "<home>/a --dir=<inputs>"},
		{"/home/u/app", "", "", same, "/home/u/app-old/f /home/u/app/f /home/u/apps", "/home/u/app-old/f <home>/f /home/u/apps"},
		{"/h", "", "", same, "https://git.example/h/x /h/x 'h/x'", "https://git.example/h/x <home>/x 'h/x'"},
		{"", "/srv/in/", "", same, "--add-dir /srv/in --x=/srv/in/a /srv/in:/srv/inx", "--add-dir <inputs> --x=<inputs>/a <inputs>:/srv/inx"},
		{"/srv/home", "", "/srv/work", same, "cd /srv/work/sub; cat /srv/home/a /srv/workshop", "cd /workspace/sub; cat <home>/a /srv/workshop"},
		{"", "", "/srv/work", inside, "/workspace/work/sub", "/workspace/sub"},
	} {
		if got := r.neutralPaths(c.home, c.inputs, c.dir, c.inside)(c.in); got != c.want {
			t.Errorf("home %q, inputs %q, dir %q: %q is %q, want %q", c.home, c.inputs, c.dir, c.in, got, c.want)
		}
	}
}

// TestNeutralRecordWritesCwdAndPromptAlone pins neutralRecord: cwd of
// runtime.started and prompt of runtime.prompt_submitted are rewritten, a tool's input
// and every other member and event are as the runtime wrote them, and the data passed
// in is left as it is.
func TestNeutralRecordWritesCwdAndPromptAlone(t *testing.T) {
	text := func(s string) string { return strings.ReplaceAll(s, "/srv", "<x>") }
	started := map[string]any{"session_id": "s", "cwd": "/srv/a", "model": "/srv/m"}
	if got := neutralRecord("dev.qory.runtime.started", started, text); got["cwd"] != "<x>/a" || got["model"] != "/srv/m" || started["cwd"] != "/srv/a" {
		t.Errorf("runtime.started %v, from %v", got, started)
	}
	if got := neutralRecord("dev.qory.runtime.prompt_submitted", map[string]any{"prompt": "read /srv/a"}, text); got["prompt"] != "read <x>/a" {
		t.Errorf("runtime.prompt_submitted %v", got)
	}
	tool := map[string]any{"tool": "Read", "input": map[string]any{"file_path": "/srv/a"}, "cwd": "/srv/a"}
	if got := neutralRecord("dev.qory.runtime.tool_started", tool, text); got["input"].(map[string]any)["file_path"] != "/srv/a" || got["cwd"] != "/srv/a" {
		t.Errorf("runtime.tool_started %v", got)
	}
}
