package catalog_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/catalog"
	"github.com/qoryai/forager/session/runtimes/runtimetest"
)

// TestLookupIsTheMachinesDescriptorThenTheContractsThenBare pins where a runtime comes
// from by its name, and that a name is a lower-case letter and then up to 63 lower-case
// letters, digits and dashes.
func TestLookupIsTheMachinesDescriptorThenTheContractsThenBare(t *testing.T) {
	rt, err := catalog.Lookup("claude", "")
	if err != nil || rt.Version() == "" || !rt.ReadsOutput() {
		t.Fatalf("the contract's: %+v %v", rt, err)
	}
	runtimetest.Conforms(t, rt)

	rt, err = catalog.Lookup("codex", t.TempDir())
	if err != nil || rt.Name() != "codex" || rt.ReadsOutput() {
		t.Fatalf("a name nothing describes: %+v %v", rt, err)
	}

	dir := t.TempDir()
	doc := "version: 1\nruntime: codex\nruntime_version: \"9\"\nsources:\n  output: {format: jsonl}\nstop: {signal: SIGHUP}\nrules:\n  - {source: output, match: {type: end}, type: dev.qory.session.ended, data: {reason: why}}\n"
	if err := os.WriteFile(filepath.Join(dir, "codex.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, err = catalog.Lookup("codex", dir)
	if err != nil || rt.Version() != "9" || rt.Stop().Signal != "SIGHUP" {
		t.Fatalf("the machine's: %+v %v", rt, err)
	}
	runtimetest.Conforms(t, rt)

	if err := os.WriteFile(filepath.Join(dir, "claude.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Lookup("claude", dir); err == nil || !strings.Contains(err.Error(), `describes "codex"`) {
		t.Errorf("a descriptor of another runtime: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "amp.yaml"), []byte("version: 1\nrules: compute\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Lookup("amp", dir); err == nil {
		t.Error("a descriptor the schema refuses was read")
	}
	for _, bad := range []string{"", "../claude", "Claude", "a b", "a" + strings.Repeat("b", 64)} {
		if _, err := catalog.Lookup(bad, dir); err == nil {
			t.Errorf("%q is a name", bad)
		}
	}
	long := "a" + strings.Repeat("b", 63)
	if rt, err := catalog.Lookup(long, dir); err != nil || rt.Name() != long {
		t.Errorf("a name of 64 characters: %v", err)
	}
}

// TestLookupReadsOnlyAPlainDescriptor pins what Lookup reads of a descriptor in dir:
// never through a link as its last part, only a regular file and at most 1 MiB; a
// refusal names the descriptor.
func TestLookupReadsOnlyAPlainDescriptor(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	doc := "version: 1\nruntime: codex\nruntime_version: \"9\"\nsources:\n  output: {format: jsonl}\nrules:\n  - {source: output, match: {type: end}, type: dev.qory.session.ended, data: {reason: why}}\n"
	target := filepath.Join(elsewhere, "codex.yaml")
	if err := os.WriteFile(target, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "codex.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "amp.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pi.yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := doc + "# " + strings.Repeat("x", 1<<20) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "big.yaml"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"codex": "Make the runtime descriptor " + filepath.Join(dir, "codex.yaml") + " a readable regular file of at most 1 MiB, or remove it. It could not be read: it is a link",
		"amp":   "Make the runtime descriptor " + filepath.Join(dir, "amp.yaml") + " a readable regular file of at most 1 MiB, or remove it. It could not be read: it is not a regular file",
		"pi":    "Make the runtime descriptor " + filepath.Join(dir, "pi.yaml") + " a readable regular file of at most 1 MiB, or remove it. It could not be read: it is not a regular file",
		"big":   "Make the runtime descriptor " + filepath.Join(dir, "big.yaml") + " a readable regular file of at most 1 MiB, or remove it. It could not be read: it is larger than 1048576 bytes",
	} {
		if _, err := catalog.Lookup(name, dir); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	if rt, err := catalog.Lookup("codex", elsewhere); err != nil || rt.Name() != "codex" {
		t.Errorf("the descriptor the link leads to: %v", err)
	}
}

// TestClaudeSaysWhereItsModelGoes pins what qory reads of Claude Code through Lookup:
// the runtime implements runtimes.Model, and its model section is the contract
// descriptor's.
func TestClaudeSaysWhereItsModelGoes(t *testing.T) {
	rt, err := catalog.Lookup("claude", "")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := rt.(runtimes.Model)
	if !ok {
		t.Fatal("Claude Code does not implement runtimes.Model")
	}
	efforts := []string{"low", "medium", "high", "xhigh", "max"}
	want := runtimes.ModelPlaces{
		Formats: []string{"anthropic-messages"},
		Model:   runtimes.Place{Flag: "--model"},
		Effort: &runtimes.Effort{
			Run:   runtimes.ValuedPlace{Place: runtimes.Place{Flag: "--effort"}, Values: efforts},
			Agent: &runtimes.AgentPlace{Frontmatter: "effort", Values: efforts},
		},
		Endpoint: runtimes.Endpoint{Variable: "ANTHROPIC_BASE_URL"},
		Keys: []runtimes.Key{
			{Format: "anthropic-messages", Auth: runtimes.Auth{Scheme: "header", Header: "x-api-key"}, Variable: "ANTHROPIC_API_KEY"},
			{Format: "anthropic-messages", Auth: runtimes.Auth{Scheme: "bearer"}, Variable: "ANTHROPIC_AUTH_TOKEN"},
			{Format: "anthropic-messages", Auth: runtimes.Auth{Scheme: "bearer", OAuth: true}, Variable: "CLAUDE_CODE_OAUTH_TOKEN"},
		},
		Overrides: []string{
			"ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
			"ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_FABLE_MODEL", "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL",
			"CLAUDE_CODE_SUBAGENT_MODEL_FORCE", "CLAUDE_CODE_AUTO_MODE_MODEL", "CLAUDE_CODE_EFFORT_LEVEL", "CLAUDE_CODE_EXTRA_BODY",
		},
	}
	if got, ok := m.Model(); !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("model %v\n%+v\nwant\n%+v", ok, got, want)
	}
}
