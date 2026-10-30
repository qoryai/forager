package session

import (
	"strings"
	"testing"

	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/runtimes"
)

// TestTheLaunchLineIsMasked pins the line of Report of a run with a run key: the
// values of this machine, with the run key's phrase in place of a value that contains
// qrk_, and, once the run's masker replaces in it as OpenSpec.Report does, the
// masker's placeholder in place of a forwarder's password. launchLine itself leaves the
// password, so the line is masked once.
func TestTheLaunchLineIsMasked(t *testing.T) {
	password := strings.Repeat("p", 43)
	r := &Run{dir: "/srv/runs/r1", masker: &mask.Masker{}}
	r.masker.AddProxy(proxyUser, password)
	spec := runSpec{SessionSpec: SessionSpec{Dir: "/srv/work", HarnessHome: "/srv/home", InputsDir: "/srv/in"}}
	raw := r.launchLine(spec, 2, runtimes.Launch{Command: "/usr/bin/agent", Args: []string{"--proxy", "http://qory:" + password + "@127.0.0.1:1", "qrk_example"}})
	if !strings.Contains(raw, password) {
		t.Errorf("launchLine replaced the password itself: %s", raw)
	}
	line := r.masker.Replace(raw)
	host := hostname()
	want := `session 2 starts on this machine: host ` + host + `, dir "/srv/work", home "/srv/home", inputs "/srv/in", command "/usr/bin/agent", ` +
		`args ["--proxy" "http://qory:` + mask.ProxyPassword + `@127.0.0.1:1" "` + rkValue + `"]`
	if line != want {
		t.Errorf("the line\n%s\nwant\n%s", line, want)
	}
}

// TestNeutralPathsReplaceWholeComponents pins neutralPaths: a path is replaced, after
// its trailing slash is cleaned, wherever it is not part of a longer name, such as
// after @, [, {, * or }, before ., ?, ! or ) at the end of a sentence and after
// file://, and not in a sibling, a name with a suffix, a path below another or a URL
// that contains its text; of two paths where one contains the other the longer is
// replaced, and the text written in its place is not replaced again; the home's, the
// inputs' and the working directory's paths inside the enclosure are replaced as well
// as those on this machine.
func TestNeutralPathsReplaceWholeComponents(t *testing.T) {
	r := &Run{dir: "/srv/runs/r1"}
	inside := func(s string) string { return translate(s, "/srv", workspaceInside) }
	atWork := func(s string) string { return translate(s, "/srv/work", workspaceInside) }
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
		{"/srv/home", "/srv/in", "", same, "Put the result in /srv/in.", "Put the result in <inputs>."},
		{"/srv/home", "/srv/in", "", same, "Is it in /srv/home? Yes!", "Is it in <home>? Yes!"},
		{"/srv/home", "/srv/in", "", same, "See /srv/runs/r1.", "See <run>."},
		{"/srv/home", "/srv/in", "", same, "dir=/srv/in]", "dir=<inputs>]"},
		{"/srv/home", "/srv/in", "", same, "Use /srv/home! Then /srv/in, and ${X:=/srv/in}", "Use <home>! Then <inputs>, and ${X:=<inputs>}"},
		{"/srv/home", "/srv/in", "", same, "/srv/in.bak /srv/in.d/a /srv/home?x=1 /srv/in.\t/srv/home?\n", "/srv/in.bak /srv/in.d/a /srv/home?x=1 <inputs>.\t<home>?\n"},
		{"/srv/work", "", "/srv/work/app", atWork, "/workspace/app /srv/work/app /workspace/x /srv/work/x", "/workspace /workspace <home>/x <home>/x"},
		{"", "/srv/work", "/srv/work/app", atWork, "/workspace/app/f /workspace/f", "/workspace/f <inputs>/f"},
		{"/home/u/app", "", "", same, "file:///home/u/app/f file:///home/u/apps xfile:///home/u/app", "file://<home>/f file:///home/u/apps xfile://<home>"},
		{"/srv/home", "/srv/in", "", same, "Read @/srv/in/issue.md", "Read @<inputs>/issue.md"},
		{"/srv/home", "/srv/in", "", same, "[/srv/in/issue.md](/srv/in/issue.md)", "[<inputs>/issue.md](<inputs>/issue.md)"},
		{"/srv/home", "/srv/in", "", same, "[/srv/in/a](/srv/in/a)", "[<inputs>/a](<inputs>/a)"},
		{"/srv/home", "/srv/in", "", same, "{/srv/in}", "{<inputs>}"},
		{"/srv/home", "/srv/in", "", same, "**/srv/in**", "**<inputs>**"},
		{"/srv/home", "/srv/in", "", same, "/srv/in...", "<inputs>..."},
		{"/srv/home", "/srv/in", "", same, "/srv/in.)", "<inputs>.)"},
		{"/srv/home", "/srv/in", "", same, "Is it /srv/in?", "Is it <inputs>?"},
		{"/srv/home", "/srv/in", "", same, "${BASE}/srv/in/x $(pwd)/srv/in", "${BASE}<inputs>/x $(pwd)<inputs>"},
		{"/srv/home", "/srv/in", "", same, "https://host/srv/home /a/srv/home //srv/home /srv/in-old /srv/in~ /srv/in_x ./srv/in /srv/in..x",
			"https://host/srv/home /a/srv/home //srv/home /srv/in-old /srv/in~ /srv/in_x ./srv/in /srv/in..x"},
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
