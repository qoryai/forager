package policy_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/policy"
)

// fixture is the bytes of a contract fixture.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAbsentPolicyObservesEverything pins that no document means observe with an
// empty list, source none.
func TestAbsentPolicyObservesEverything(t *testing.T) {
	l := policy.None()
	if l.Source != "none" || l.Policy.Egress.Mode != policy.Observe || len(l.Policy.Egress.Allow) != 0 {
		t.Errorf("absent policy loaded as %+v", l)
	}
}

// TestFixturesReadWithDigest pins that every accepted fixture reads, with a digest and
// the mode it states, and that the digest is the document's, not the bytes': the same
// policy as YAML and as JSON has one digest.
func TestFixturesReadWithDigest(t *testing.T) {
	for name, mode := range map[string]policy.Mode{"observe.yaml": policy.Observe, "enforce.yaml": policy.Enforce, "enforce-nothing.yaml": policy.Enforce, "observe-deny.yaml": policy.Observe} {
		l, err := policy.Read(name, fixture(t, "fixtures/policy/"+name))
		if err != nil {
			t.Fatal(err)
		}
		if l.Source != "config" || len(l.Digest) != 64 || l.Policy.Egress.Mode != mode {
			t.Errorf("%s: read as %+v", name, l)
		}
	}
	yaml, err := policy.Read("enforce.yaml", fixture(t, "fixtures/policy/enforce.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	js, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"enforce","allow":["api.anthropic.com","*.github.com","github.com","registry.npmjs.org"],"deny":["gist.github.com"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if yaml.Digest != js.Digest {
		t.Errorf("digests differ: %s %s", yaml.Digest, js.Digest)
	}
}

// TestInvalidPolicyIsAnError pins the rule that a configured policy that does not
// read means no run: a refused document is a *policy.Error naming the document.
func TestInvalidPolicyIsAnError(t *testing.T) {
	for _, name := range []string{"fixtures/invalid/policy-mode-log.yaml", "fixtures/invalid/policy-allow-widens.yaml", "fixtures/invalid/policy-deny-port.yaml"} {
		_, err := policy.Read(name, fixture(t, name))
		var pe *policy.Error
		if !errors.As(err, &pe) || pe.Name != name {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"log"}}`)); err == nil {
		t.Error("mode log was accepted")
	}
}

// TestMatchFollowsTheGrammar pins name, pattern and IP matching, and that a pattern
// never matches its apex.
func TestMatchFollowsTheGrammar(t *testing.T) {
	allow := []string{"api.anthropic.com", "*.github.com", "127.0.0.1"}
	for _, c := range []struct {
		host string
		rule string
		ok   bool
	}{
		{"api.anthropic.com", "api.anthropic.com", true},
		{"API.Anthropic.com.", "api.anthropic.com", true},
		{"anthropic.com", "", false},
		{"api.github.com", "*.github.com", true},
		{"a.b.github.com", "*.github.com", true},
		{"github.com", "", false},
		{"evilgithub.com", "", false},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.2", "", false},
	} {
		rule, ok := policy.Match(allow, c.host)
		if rule != c.rule || ok != c.ok {
			t.Errorf("Match(%q) = %q, %v; want %q, %v", c.host, rule, ok, c.rule, c.ok)
		}
	}
}

// TestCoversFollowsTheGrammar pins what stands above what: a name under the same name
// or a suffix above it, a pattern under the same pattern or a suffix above it, and a
// suffix never covers its own apex.
func TestCoversFollowsTheGrammar(t *testing.T) {
	for _, c := range []struct {
		entry, other string
		want         bool
	}{
		{"api.github.com", "api.github.com", true}, {"api.github.com", "API.github.com", true},
		{"*.github.com", "api.github.com", true}, {"*.github.com", "*.api.github.com", true},
		{"*.github.com", "github.com", false}, {"api.github.com", "*.github.com", false},
		{"*.github.com", "*.github.com", true}, {"github.com", "api.github.com", false},
	} {
		if got := policy.Covers(c.entry, c.other); got != c.want {
			t.Errorf("Covers(%q, %q) = %v", c.entry, c.other, got)
		}
	}
}

// TestDenyReadsInAllowsGrammar pins the deny list: read when present, nil when absent,
// refused by the schema when an entry is not in allow's grammar, and matched by Match
// like the allow list, first entry first.
func TestDenyReadsInAllowsGrammar(t *testing.T) {
	l, err := policy.Read("observe-deny.yaml", fixture(t, "fixtures/policy/observe-deny.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Policy.Egress.Mode != policy.Observe || strings.Join(l.Policy.Egress.Deny, " ") != "tracker.example *.ads.example" || strings.Join(l.Policy.Egress.Allow, " ") != "api.example *.example" {
		t.Errorf("observe-deny read as %+v", l.Policy.Egress)
	}
	if rule, ok := policy.Match(l.Policy.Egress.Deny, "banner.ads.example"); !ok || rule != "*.ads.example" {
		t.Errorf("Match(deny, banner.ads.example) = %q, %v", rule, ok)
	}
	if rule, ok := policy.Match(l.Policy.Egress.Deny, "api.example"); ok {
		t.Errorf("Match(deny, api.example) = %q, %v", rule, ok)
	}
	plain, err := policy.Read("observe.yaml", fixture(t, "fixtures/policy/observe.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Policy.Egress.Deny != nil {
		t.Errorf("observe.yaml read with a deny list %v", plain.Policy.Egress.Deny)
	}
	for _, doc := range []string{
		`{"version":1,"egress":{"mode":"observe","deny":["tracker.example:443"]}}`,
		`{"version":1,"egress":{"mode":"enforce","deny":["https://tracker.example"]}}`,
		`{"version":1,"egress":{"mode":"observe","deny":["Tracker.example"]}}`,
		`{"version":1,"egress":{"mode":"observe","deny":["tracker.example","tracker.example"]}}`,
	} {
		if _, err := policy.Read("policy", []byte(doc)); err == nil {
			t.Errorf("%s was accepted", doc)
		}
	}
	if _, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"observe","deny":[]}}`)); err != nil {
		t.Errorf("an empty deny list was refused: %v", err)
	}
}

// TestEveryFixtureReadsAsAPolicy pins the round trip: every accepted policy fixture
// reads, and the security_policy of every run configuration fixture reads the way a
// reload reads it, the deny fixture with its deny list.
func TestEveryFixtureReadsAsAPolicy(t *testing.T) {
	docs, err := fs.ReadDir(contracts.FS, "fixtures/policy")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		if _, err := policy.Read(d.Name(), fixture(t, path.Join("fixtures/policy", d.Name()))); err != nil {
			t.Errorf("%s: %v", d.Name(), err)
		}
	}
	confs, err := fs.ReadDir(contracts.FS, "fixtures/run-configuration")
	if err != nil {
		t.Fatal(err)
	}
	denies := 0
	for _, d := range confs {
		var rc struct {
			SecurityPolicy json.RawMessage `json:"security_policy"`
		}
		if err := json.Unmarshal(fixture(t, path.Join("fixtures/run-configuration", d.Name())), &rc); err != nil {
			t.Fatal(err)
		}
		if rc.SecurityPolicy == nil {
			// A run configuration without a policy leaves the node's in force.
			continue
		}
		l, err := policy.Read("run-configuration", rc.SecurityPolicy)
		if err != nil {
			t.Errorf("%s: %v", d.Name(), err)
			continue
		}
		if d.Name() == "observe-deny.json" {
			denies++
			if l.Policy.Egress.Mode != policy.Observe || strings.Join(l.Policy.Egress.Deny, " ") != "tracker.example *.ads.example" {
				t.Errorf("%s read as %+v", d.Name(), l.Policy.Egress)
			}
		}
	}
	if denies != 1 {
		t.Error("fixtures/run-configuration has no observe-deny.json")
	}
}

// TestAPolicySelectsAnImageByName pins that a policy names the machine's image by the
// machine's name for it and never by a reference, and that the selection is part of
// what the digest pins.
func TestAPolicySelectsAnImageByName(t *testing.T) {
	l, err := policy.Read("enforce-image.yaml", fixture(t, "fixtures/policy/enforce-image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Policy.Image != "with-docker" {
		t.Errorf("the image read as %q", l.Policy.Image)
	}
	without, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"enforce","allow":["api.anthropic.com","registry-1.docker.io"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if without.Policy.Image != "" || without.Digest == l.Digest {
		t.Errorf("a policy selecting no image read as %q, digest %s against %s", without.Policy.Image, without.Digest, l.Digest)
	}
	if _, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"enforce"},"image":"registry.example.com/agent:1"}`)); err == nil {
		t.Error("a reference was read as an image's name")
	}
}

// TestAnArgumentHasAtMost4096Characters pins the cap on a credential's and a tool's
// argument: 4096 characters read, room for several repositories in one argument, and
// 4097 are refused. The fixtures hold the same two lengths.
func TestAnArgumentHasAtMost4096Characters(t *testing.T) {
	l, err := policy.Read("enforce-long-argument.yaml", fixture(t, "fixtures/policy/enforce-long-argument.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Policy.Credentials) != 1 || len(l.Policy.Credentials[0].Argument) != 4096 ||
		len(l.Policy.Tools) != 1 || len(l.Policy.Tools[0].Argument) != 4096 {
		t.Errorf("the fixture's arguments are not 4096 characters: %+v", l.Policy)
	}
	for _, name := range []string{"fixtures/invalid/policy-credential-argument-too-long.yaml", "fixtures/invalid/policy-tool-argument-too-long.yaml"} {
		if _, err := policy.Read(name, fixture(t, name)); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	for _, kind := range []string{"credentials", "tools"} {
		for n, ok := range map[int]bool{4096: true, 4097: false} {
			doc := `{"version":1,"egress":{"mode":"enforce"},"` + kind + `":[{"name":"acme","argument":"` + strings.Repeat("a", n) + `"}]}`
			if _, err := policy.Read("policy", []byte(doc)); (err == nil) != ok {
				t.Errorf("%s: an argument of %d characters: %v", kind, n, err)
			}
		}
	}
}
