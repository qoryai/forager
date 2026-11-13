package session

import (
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
)

// homeResume is the resume of a runtime written as data with home_var AMP_HOME, prefix
// ${AMP_HOME}/<tail> and path ${AMP_HOME}/<tail><below>, as a session whose launch's
// environment is env resolves it.
func homeResume(t *testing.T, tail, below string, env []string) *sessionResume {
	t.Helper()
	d := "version: 1\nruntime: r\nruntime_version: \"1\"\nsources:\n  output: {format: jsonl}\n" +
		"resume:\n  home_var: AMP_HOME\n  path: '${AMP_HOME}/" + tail + below + "'\n  prefix: '${AMP_HOME}/" + tail + "'\n  args: [resume, '{session_id}']\n" +
		"rules:\n  - source: output\n    match: {type: start}\n    type: dev.qory.runtime.started\n    data: {session_id: session_id}\n"
	rt, err := runtimes.Described("r.yaml", []byte(d), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resumeOf(rt, env)
}

// TestTheHomeVariableResolvesFromTheLaunchsEnvironment pins resumeOf: the last value of
// home_var in the environment replaces ${<home_var>} in the prefix and the path, / as
// the value included; a value that is unset, empty, relative, not in its shortest form,
// or has a . or .. name, a space, a newline, a *, a $, a { or a } leaves the resume
// unset, with the fix first and the variable's name in it, and the value quoted in the
// cause.
func TestTheHomeVariableResolvesFromTheLaunchsEnvironment(t *testing.T) {
	const below = "*/rollout-*-{session_id}.jsonl"
	for value, prefix := range map[string]string{
		"/var/lib/amp": "/var/lib/amp/sessions/",
		"/":            "/sessions/",
	} {
		rs := homeResume(t, "sessions/", below, []string{"AMP_HOME=/first", "AMP_HOME=" + value})
		if rs.unset != nil || rs.Prefix != prefix || rs.Path != prefix+below || rs.prefix != "${AMP_HOME}/sessions/" {
			t.Errorf("%q: %+v, unset %+v; want prefix %s", value, rs.Resume, rs.unset, prefix)
		}
	}
	for _, env := range [][]string{
		nil, {"AMP_HOME="}, {"AMP_HOME=rel"}, {"AMP_HOME=/a/../b"}, {"AMP_HOME=/a/./b"}, {"AMP_HOME=/a/"}, {"AMP_HOME=/a//b"},
		{"AMP_HOME=/a b"}, {"AMP_HOME=/a\nb"}, {"AMP_HOME=/a*"}, {"AMP_HOME=/a$b"}, {"AMP_HOME=/{session_id}"}, {"AMP_HOME=/a/}"},
		{"AMP_HOME=/ok", "AMP_HOME=rel"},
	} {
		rs := homeResume(t, "sessions/", below, env)
		if u := rs.unset; u == nil || !strings.HasPrefix(u.Fix, "Set AMP_HOME to an absolute path") || !strings.HasPrefix(u.Cause, "AMP_HOME is ") ||
			strings.Contains(u.Cause, "\n") || !strings.HasSuffix(u.Cause, ", so the session cannot find resume.prefix ${AMP_HOME}/sessions/") {
			t.Errorf("%q: unset %+v", env, u)
		}
	}
}

// TestAPausedRunsPathMovesBelowThisRunsHome pins sessionResume.moved: a path below the
// paused run's value of home_var keeps its names below the prefix, as many as the
// descriptor's path has, under this session's resolved prefix, with a prefix that is
// the home itself too; a relative path, one with a . or .. name or an empty one, one
// with fewer names, and one without the prefix's names above them do not move.
func TestAPausedRunsPathMovesBelowThisRunsHome(t *testing.T) {
	rs := homeResume(t, "sessions/", "*/*/rollout-*-{session_id}.jsonl", []string{"AMP_HOME=/new"})
	for p, want := range map[string]string{
		"/old/home/sessions/2025/01/rollout-p-x.jsonl": "/new/sessions/2025/01/rollout-p-x.jsonl",
		"/sessions/2025/01/rollout-p-x.jsonl":          "/new/sessions/2025/01/rollout-p-x.jsonl",
	} {
		if got, ok := rs.moved(p); !ok || got != want {
			t.Errorf("%s moved to %q, %v; want %s", p, got, ok, want)
		}
	}
	for _, p := range []string{
		"old/sessions/2025/01/rollout-p-x.jsonl",
		"~/sessions/2025/01/rollout-p-x.jsonl",
		"/old/sessions/../01/rollout-p-x.jsonl",
		"/old/sessions//2025/01/rollout-p-x.jsonl",
		"/old/sessions/2025/./rollout-p-x.jsonl",
		"/2025/01/rollout-p-x.jsonl",
		"/old/other/2025/01/rollout-p-x.jsonl",
		"/old/sessions/x/2025/01/rollout-p-x.jsonl/",
	} {
		if got, ok := rs.moved(p); ok {
			t.Errorf("%s moved to %q", p, got)
		}
	}
	top := homeResume(t, "", "{session_id}.jsonl", []string{"AMP_HOME=/new"})
	if got, ok := top.moved("/old/home/x.jsonl"); !ok || got != "/new/x.jsonl" {
		t.Errorf("a prefix that is the home: %q, %v", got, ok)
	}
	deep := homeResume(t, "a/b/", "{session_id}.jsonl", []string{"AMP_HOME=/new"})
	if got, ok := deep.moved("/old/a/b/x.jsonl"); !ok || got != "/new/a/b/x.jsonl" {
		t.Errorf("a prefix two names below the home: %q, %v", got, ok)
	}
	if _, ok := deep.moved("/old/b/a/x.jsonl"); ok {
		t.Error("a path below other names moved")
	}
	plain := resumeOf(describedRuntime(t), nil)
	if got, ok := plain.moved("~/.claude/projects/s/x.jsonl"); !ok || got != "~/.claude/projects/s/x.jsonl" {
		t.Errorf("a descriptor without home_var: %q, %v", got, ok)
	}
}

// describedRuntime is a runtime written as data with Claude Code's resume.
func describedRuntime(t *testing.T) runtimes.Runtime {
	t.Helper()
	d := "version: 1\nruntime: r\nruntime_version: \"1\"\nsources:\n  output: {format: jsonl}\n" +
		"resume:\n  path_from: transcript_path\n  path: '~/.claude/projects/{cwd_slug}/{session_id}.jsonl'\n  prefix: ~/.claude/projects/\n  args: [--resume, '{session_id}']\n" +
		"rules:\n  - source: output\n    match: {type: start}\n    type: dev.qory.runtime.started\n    data: {session_id: session_id}\n"
	rt, err := runtimes.Described("r.yaml", []byte(d), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}
