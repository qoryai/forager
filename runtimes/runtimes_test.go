package runtimes_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/runner/runtimes"
	"github.com/qoryai/runner/runtimes/runtimetest"
)

// other is a runtime that is not Claude Code, written as data alone: it prints JSON
// lines, takes no hooks, and leaves on SIGINT.
const other = `version: 1
runtime: other-agent
runtime_version: "0.3"
sources:
  output: {format: jsonl}
stop: {signal: SIGINT, grace: 45s}
rules:
  - source: output
    match: {kind: done}
    type: dev.qory.session.result
    data: {result: text}
`

func TestARuntimeWrittenAsDataAlone(t *testing.T) {
	rt, err := runtimes.Described("other-agent.yaml", []byte(other), nil)
	if err != nil {
		t.Fatal(err)
	}
	runtimetest.Conforms(t, rt)
	if rt.Name() != "other-agent" || rt.Version() != "0.3" || !rt.ReadsOutput() {
		t.Errorf("%s %s %v", rt.Name(), rt.Version(), rt.ReadsOutput())
	}
	if s := rt.Stop(); s.Signal != "SIGINT" || s.Grace != 45*time.Second {
		t.Errorf("stop %+v", s)
	}
	typ, data, ok := rt.Map(runtimes.Record{Source: runtimes.SourceOutput, Record: map[string]any{"kind": "done", "text": "ok"}})
	if !ok || typ != "dev.qory.session.result" || data["result"] != "ok" {
		t.Errorf("%v %s %v", ok, typ, data)
	}
	// With a forwarder and no hooks source there is still nothing to install.
	launch := runtimes.Launch{Command: "other", Args: []string{"run"}}
	got, err := rt.Prepare(runtimes.Attach{Launch: launch, RunDir: t.TempDir(), Forwarder: []string{"q"}})
	if err != nil || got.Command != "other" || len(got.Args) != 1 {
		t.Errorf("%+v %v", got, err)
	}
}

func TestADescriptorNamesAnInstallerAndNeverBringsOne(t *testing.T) {
	doc := strings.Replace(other, "  output: {format: jsonl}\n", "  hooks: {install: claude-settings, events: [Stop]}\n", 1)
	if _, err := runtimes.Described("other-agent.yaml", []byte(doc), nil); err == nil || !strings.Contains(err.Error(), "not one this runner implements") {
		t.Errorf("an installer the caller does not give: %v", err)
	}
	called := false
	rt, err := runtimes.Described("other-agent.yaml", []byte(doc), map[string]runtimes.Installer{
		"claude-settings": func(events []string, a runtimes.Attach) (runtimes.Launch, error) {
			called = len(events) == 1 && events[0] == "Stop"
			return a.Launch, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Prepare(runtimes.Attach{RunDir: t.TempDir(), Forwarder: []string{"q"}}); err != nil || !called {
		t.Errorf("the installer was not asked: %v", err)
	}
	for _, bad := range []string{"stop: {signal: SIGKILL}", "stop: {grace: soon}", "stop: {}", "stop: {signal: SIGINT, then: SIGTERM}"} {
		if _, err := runtimes.Described("other-agent.yaml", []byte(strings.Replace(other, "stop: {signal: SIGINT, grace: 45s}", bad, 1)), nil); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
}

func TestABareRuntimeIsRunAndNotRead(t *testing.T) {
	rt := runtimes.Bare("codex")
	runtimetest.Conforms(t, rt)
	if rt.Name() != "codex" || rt.Version() != "" || rt.ReadsOutput() || rt.Stop() != (runtimes.Stop{}) {
		t.Errorf("%+v", rt)
	}
	if rt.Headless([]string{"-p", "hi"}) {
		t.Error("a bare runtime knows nothing of its arguments, so none is headless")
	}
}

// TestTheDescriptorSaysWhichArgumentsMeanHeadless pins the matching rule: a short
// argument is the whole token, a long one the token or its --name=value form, tokens
// are compared one by one, and no flag grammar is parsed. A descriptor without the
// section leaves the decision to the caller.
func TestTheDescriptorSaysWhichArgumentsMeanHeadless(t *testing.T) {
	doc := strings.Replace(other, "stop: {signal: SIGINT, grace: 45s}\n", "headless: {args: [\"-p\", \"--print\"]}\n", 1)
	rt, err := runtimes.Described("other-agent.yaml", []byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	runtimetest.Conforms(t, rt)
	for _, c := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"-p"}, true},
		{[]string{"-p", "Reply pong"}, true},
		{[]string{"--model", "opus", "-p", "hi"}, true},
		{[]string{"--print"}, true},
		{[]string{"--print=x"}, true},
		{[]string{"--print="}, true},
		{[]string{"-print"}, false},
		{[]string{"--printer"}, false},
		{[]string{"-px"}, false},
		{[]string{"-p="}, false},
		{[]string{"Reply pong"}, false},
		{[]string{"--", "-p"}, true},
		// A value that spells a named argument counts: tokens are compared, not parsed.
		{[]string{"--model", "-p"}, true},
	} {
		if got := rt.Headless(c.args); got != c.want {
			t.Errorf("Headless(%q) = %v", c.args, got)
		}
	}
	without, err := runtimes.Described("other-agent.yaml", []byte(other), nil)
	if err != nil {
		t.Fatal(err)
	}
	if without.Headless([]string{"-p"}) {
		t.Error("a descriptor without the section infers nothing")
	}
	for _, bad := range []string{"headless: {}", "headless: {args: []}", "headless: {args: [\"-p\", \"-p\"]}", "headless: {args: [\"\"]}", "headless: {args: [\"-p\"], env: [X]}"} {
		if _, err := runtimes.Described("other-agent.yaml", []byte(strings.Replace(other, "stop: {signal: SIGINT, grace: 45s}", bad, 1)), nil); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
}

// TestADescriptorDeclaresItsSecretsThroughTheOptionalInterface pins the Go API of a
// runtime's secrets: a described runtime implements runtimes.Secrets with its
// descriptor's section, empty when it has none; a bare one does not; and what a caller
// does to the lists it receives changes nothing of the runtime's.
func TestADescriptorDeclaresItsSecretsThroughTheOptionalInterface(t *testing.T) {
	doc := other + `secrets:
  declares:
    - {id: key, title: A key, name: OTHER_KEY, hosts: [api.example.com], paths: [/v2/*], auth: {scheme: header, header: x-key}}
    - {id: login, title: A login, name: OTHER_LOGIN, hosts: [api.example.com], auth: {scheme: bearer}}
  one_of:
    - {id: credential, required: true, of: [key, login]}
  reserves: [OTHER_SESSION]
  denies: [OTHER_BASE_URL]
  credential_files: [~/.other/login.json]
`
	rt, err := runtimes.Described("other-agent.yaml", []byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := rt.(runtimes.Secrets)
	if !ok {
		t.Fatal("a described runtime does not implement runtimes.Secrets")
	}
	want := runtimes.Declarations{
		Declares: []runtimes.Declaration{
			{ID: "key", Title: "A key", Name: "OTHER_KEY", Hosts: []string{"api.example.com"}, Paths: []string{"/v2/*"}, Auth: runtimes.Auth{Scheme: "header", Header: "x-key"}},
			{ID: "login", Title: "A login", Name: "OTHER_LOGIN", Hosts: []string{"api.example.com"}, Auth: runtimes.Auth{Scheme: "bearer"}},
		},
		OneOf:           []runtimes.Group{{ID: "credential", Required: true, Of: []string{"key", "login"}}},
		Reserves:        []string{"OTHER_SESSION"},
		Denies:          []string{"OTHER_BASE_URL"},
		CredentialFiles: []string{"~/.other/login.json"},
	}
	got := s.Secrets()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("secrets\n%+v\nwant\n%+v", got, want)
	}
	got.Declares[0].Hosts[0] = "changed.example.com"
	got.OneOf[0].Of[0] = "changed"
	got.Reserves[0] = "CHANGED"
	if again := s.Secrets(); !reflect.DeepEqual(again, want) {
		t.Errorf("a change to the lists returned reached the runtime: %+v", again)
	}

	plain, err := runtimes.Described("other-agent.yaml", []byte(other), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := plain.(runtimes.Secrets); !ok || !reflect.DeepEqual(s.Secrets(), runtimes.Declarations{}) {
		t.Errorf("a descriptor without secrets declares %v", s)
	}
	if _, ok := runtimes.Bare("other-agent").(runtimes.Secrets); ok {
		t.Error("a bare runtime declares secrets")
	}
}
