package session

import "testing"

// TestTranslateIsAtWholeComponents pins how a path of the workspace's bind is written
// as the enclosure sees it: where the path starts a word or follows file://, and ends
// at a slash, at the word's end, before ] or } or before ., ? or ! at the end of a
// sentence, never inside another name, another path or after ${A}.
func TestTranslateIsAtWholeComponents(t *testing.T) {
	for in, want := range map[string]string{
		"/work":                       "/workspace",
		"/work/app":                   "/workspace/app",
		"/workshop":                   "/workshop",
		"/a/work/app":                 "/a/work/app",
		"work/app":                    "work/app",
		"--dir=/work/app":             "--dir=/workspace/app",
		"/work/bin:/usr/bin:/work":    "/workspace/bin:/usr/bin:/workspace",
		"sh '/work/hook.sh' /work2":   "sh '/workspace/hook.sh' /work2",
		`node "/work/x.js";/work/y`:   `node "/workspace/x.js";/workspace/y`,
		"cd /work && make":            "cd /workspace && make",
		"/work-other /work/../etc":    "/work-other /workspace/../etc",
		"${A}/work/x":                 "${A}/work/x",
		"[/work/x] {/work}":           "[/work/x] {/work}",
		"x=/work] y=/work}":           "x=/workspace] y=/workspace}",
		"file:///work/x":              "file:///workspace/x",
		"In /work. Or /work? /work!":  "In /workspace. Or /workspace? /workspace!",
		"/work.bak /work?x=1 /work.)": "/work.bak /work?x=1 /work.)",
		"":                            "",
	} {
		if got := translate(in, "/work", "/workspace"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	// / is replaced only where it stands alone: every other path starts with / and a
	// component after it.
	if got := translate("/ //x --a=/ /usr/bin", "/", "<home>"); got != "<home> <home>/x --a=<home> /usr/bin" {
		t.Errorf("/: %q", got)
	}
	if got := translate("/work/app", "", "/workspace"); got != "/work/app" {
		t.Errorf("no root: %q", got)
	}
}
