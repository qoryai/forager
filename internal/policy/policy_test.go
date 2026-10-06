package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/policy"
	"github.com/qoryai/runner/internal/refusal"
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
// or a suffix above it, a pattern under the same pattern or a suffix above it, a suffix
// never covers its own apex, and an IP literal stands under an identical entry alone,
// as Match matches it.
func TestCoversFollowsTheGrammar(t *testing.T) {
	for _, c := range []struct {
		entry, other string
		want         bool
	}{
		{"api.github.com", "api.github.com", true}, {"api.github.com", "API.github.com", true},
		{"*.github.com", "api.github.com", true}, {"*.github.com", "*.api.github.com", true},
		{"*.github.com", "github.com", false}, {"api.github.com", "*.github.com", false},
		{"*.github.com", "*.github.com", true}, {"github.com", "api.github.com", false},
		{"*.0.0.1", "10.0.0.1", false}, {"10.0.0.1", "10.0.0.1", true},
		{"*.0.0.1", "*.10.0.0.1", true}, {"::1", "::1", true}, {"*.1", "::1", false},
	} {
		if _, matched := policy.Match([]string{c.entry}, c.other); matched != c.want && !strings.HasPrefix(c.other, "*.") {
			t.Errorf("Match([%q], %q) = %v, Covers wants %v", c.entry, c.other, matched, c.want)
		}
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

// read reads a policy document of the test's own.
func read(t *testing.T, doc string) *policy.Loaded {
	t.Helper()
	l, err := policy.Read("policy", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// fetched reads a server's policy as a run configuration brings it.
func fetched(t *testing.T, doc string) *policy.Loaded {
	t.Helper()
	l := read(t, doc)
	l.Source, l.URL, l.RunConfiguration = "fetched", "https://qory.example/v1/run-configuration", "sha256="+strings.Repeat("0", 64)
	return l
}

func narrowed(t *testing.T, server, node string) *policy.Loaded {
	t.Helper()
	l, err := policy.Narrowed(fetched(t, server), read(t, node))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestNarrowedModeIsEnforceWhenEitherSideIs pins the mode row: enforce when either side
// sets enforce, else observe.
func TestNarrowedModeIsEnforceWhenEitherSideIs(t *testing.T) {
	for _, tc := range []struct {
		server, node string
		want         policy.Mode
	}{
		{"observe", "observe", policy.Observe},
		{"enforce", "observe", policy.Enforce},
		{"observe", "enforce", policy.Enforce},
		{"enforce", "enforce", policy.Enforce},
	} {
		l := narrowed(t, `{"version":1,"egress":{"mode":"`+tc.server+`"}}`, `{"version":1,"egress":{"mode":"`+tc.node+`"}}`)
		if l.Policy.Egress.Mode != tc.want {
			t.Errorf("server %s, node %s: %s", tc.server, tc.node, l.Policy.Egress.Mode)
		}
	}
}

// TestNarrowedAllowIsWhatBothSidesAllow pins the allow row: under enforce on both
// sides, the entries of each side the other side's list covers, the server's first and
// each once, which are exactly the hosts both allow; under enforce on one side, that
// side's entries, since a side under observe allows every host; under observe on both,
// the server's.
func TestNarrowedAllowIsWhatBothSidesAllow(t *testing.T) {
	server := `["api.example","*.github.com","sentry.io"]`
	node := `["api.github.com","api.example","other.example"]`
	for _, tc := range []struct {
		server, node string
		want         []string
	}{
		{"enforce", "enforce", []string{"api.example", "api.github.com"}},
		{"enforce", "observe", []string{"api.example", "*.github.com", "sentry.io"}},
		{"observe", "enforce", []string{"api.github.com", "api.example", "other.example"}},
		{"observe", "observe", []string{"api.example", "*.github.com", "sentry.io"}},
	} {
		l := narrowed(t, `{"version":1,"egress":{"mode":"`+tc.server+`","allow":`+server+`}}`, `{"version":1,"egress":{"mode":"`+tc.node+`","allow":`+node+`}}`)
		if !slices.Equal(l.Policy.Egress.Allow, tc.want) {
			t.Errorf("server %s, node %s: %q, want %q", tc.server, tc.node, l.Policy.Egress.Allow, tc.want)
		}
	}
	l := narrowed(t, `{"version":1,"egress":{"mode":"enforce","allow":["*.example"]}}`, `{"version":1,"egress":{"mode":"enforce","allow":["*.example","a.b.example"]}}`)
	if want := []string{"*.example", "a.b.example"}; !slices.Equal(l.Policy.Egress.Allow, want) {
		t.Errorf("an entry both sides list: %q, want %q", l.Policy.Egress.Allow, want)
	}
	l = narrowed(t, `{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, `{"version":1,"egress":{"mode":"enforce"}}`)
	if l.Policy.Egress.Allow == nil || len(l.Policy.Egress.Allow) != 0 {
		t.Errorf("a node that allows nothing: %q", l.Policy.Egress.Allow)
	}
}

// TestNarrowedAllowTakesNoIPLiteralUnderAPattern pins the narrowing of a node's IP
// literal under a server's pattern that ends like it: a server allow of *.0.0.1 does
// not allow 10.0.0.1, so the hosts both allow are none, and a request to 10.0.0.1 is
// denied.
func TestNarrowedAllowTakesNoIPLiteralUnderAPattern(t *testing.T) {
	l := narrowed(t, `{"version":1,"egress":{"mode":"enforce","allow":["*.0.0.1"]}}`, `{"version":1,"egress":{"mode":"enforce","allow":["10.0.0.1"]}}`)
	if len(l.Policy.Egress.Allow) != 0 {
		t.Errorf("allow %q, want none", l.Policy.Egress.Allow)
	}
	if _, ok := policy.Match(l.Policy.Egress.Allow, "10.0.0.1"); ok {
		t.Error("10.0.0.1 is allowed")
	}
}

// TestNarrowedDenyIsTheUnion pins the deny row: both sides' entries, the server's
// first, each once, whatever the modes.
func TestNarrowedDenyIsTheUnion(t *testing.T) {
	l := narrowed(t, `{"version":1,"egress":{"mode":"observe","deny":["gist.github.com","tracker.example"]}}`, `{"version":1,"egress":{"mode":"observe","deny":["tracker.example","*.ads.example"]}}`)
	if want := []string{"gist.github.com", "tracker.example", "*.ads.example"}; !slices.Equal(l.Policy.Egress.Deny, want) {
		t.Errorf("deny %q, want %q", l.Policy.Egress.Deny, want)
	}
	l = narrowed(t, `{"version":1,"egress":{"mode":"observe"}}`, `{"version":1,"egress":{"mode":"observe"}}`)
	if l.Policy.Egress.Deny != nil {
		t.Errorf("no deny on either side: %q", l.Policy.Egress.Deny)
	}
}

// TestNarrowedPathsKeepBothSides pins the paths row as the policy carries it: the run's
// paths are the server's, which the record reports, and the node's go beside them, with
// the node's digest, for the proxy to require both.
func TestNarrowedPathsKeepBothSides(t *testing.T) {
	node := read(t, `{"version":1,"egress":{"mode":"enforce","allow":["api.github.com"],"paths":{"api.github.com":["/repos/acme/*"]}}}`)
	l, err := policy.Narrowed(fetched(t, `{"version":1,"egress":{"mode":"enforce","allow":["api.github.com"],"paths":{"api.github.com":["/repos/*"],"github.com":["/acme/*"]}}}`), node)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Policy.Egress.Paths) != 2 || l.Policy.Egress.Paths["api.github.com"][0] != "/repos/*" {
		t.Errorf("the run's paths %v", l.Policy.Egress.Paths)
	}
	if l.Node == nil || l.Node.Digest != node.Canonical || l.Node.Paths["api.github.com"][0] != "/repos/acme/*" {
		t.Errorf("the node's side %+v", l.Node)
	}
	if l.Source != "fetched" || l.URL == "" || l.RunConfiguration == "" || l.Digest == node.Digest {
		t.Errorf("the narrowed policy lost the server's stamps: %+v", l)
	}
}

// TestNarrowedToolsAreTheServersWithinTheNodes pins the tools row: without a tools
// member the node leaves the server's selection as it is; with one, each selected tool
// must be listed by name, and by argument when the node's entry has one, so an empty
// list allows none, and a tool outside it is tool_unknown with its name. The
// credentials are bounded the same way.
func TestNarrowedToolsAreTheServersWithinTheNodes(t *testing.T) {
	server := `{"version":1,"egress":{"mode":"observe"},"tools":[{"name":"files","argument":"acme/shop"},{"name":"search"}]}`
	for _, tc := range []struct {
		node    string
		unknown []string
	}{
		{`{"version":1,"egress":{"mode":"observe"}}`, nil},
		{`{"version":1,"egress":{"mode":"observe"},"tools":[{"name":"files"},{"name":"search"},{"name":"other"}]}`, nil},
		{`{"version":1,"egress":{"mode":"observe"},"tools":[{"name":"files","argument":"acme/shop"},{"name":"search"}]}`, nil},
		{`{"version":1,"egress":{"mode":"observe"},"tools":[{"name":"files","argument":"acme/lib"},{"name":"search"}]}`, []string{"files"}},
		{`{"version":1,"egress":{"mode":"observe"},"tools":[{"name":"files"}]}`, []string{"search"}},
		{`{"version":1,"egress":{"mode":"observe"},"tools":[]}`, []string{"files", "search"}},
	} {
		l, err := policy.Narrowed(fetched(t, server), read(t, tc.node))
		if tc.unknown == nil {
			if err != nil || len(l.Policy.Tools) != 2 || l.Policy.Tools[0].Argument != "acme/shop" {
				t.Errorf("%s: %+v %v", tc.node, l, err)
			}
			continue
		}
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.ToolUnknown || !slices.Equal(r.Names, tc.unknown) {
			t.Errorf("%s: %v, want tool_unknown %q", tc.node, err, tc.unknown)
		}
	}
	if _, err := policy.Narrowed(fetched(t, `{"version":1,"egress":{"mode":"observe"},"credentials":[{"name":"model"}]}`), read(t, `{"version":1,"egress":{"mode":"observe"},"credentials":[]}`)); err == nil {
		t.Error("a credential the node's empty list leaves out was selected")
	}
}

// TestNarrowedImageIsOneBothAgreeOn pins the image row: the one both select, or the one
// a side selects, or none, the machine's default; two different ones are
// image_unknown.
func TestNarrowedImageIsOneBothAgreeOn(t *testing.T) {
	doc := func(image string) string {
		if image == "" {
			return `{"version":1,"egress":{"mode":"observe"}}`
		}
		return `{"version":1,"egress":{"mode":"observe"},"image":"` + image + `"}`
	}
	for _, tc := range []struct{ server, node, want string }{
		{"agent", "agent", "agent"},
		{"agent", "", "agent"},
		{"", "agent", "agent"},
		{"", "", ""},
	} {
		if l := narrowed(t, doc(tc.server), doc(tc.node)); l.Policy.Image != tc.want {
			t.Errorf("server %q, node %q: %q", tc.server, tc.node, l.Policy.Image)
		}
	}
	_, err := policy.Narrowed(fetched(t, doc("agent")), read(t, doc("other")))
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != refusal.ImageUnknown || !slices.Equal(r.Names, []string{"agent"}) {
		t.Errorf("two images: %v", err)
	}
}

// TestCanonicalIsTheRFC8785Digest pins the digest a node's policy is reported by:
// sha256= and the hex SHA-256 of the document's RFC 8785 serialisation, the same for
// the document as YAML and as JSON in any member order.
func TestCanonicalIsTheRFC8785Digest(t *testing.T) {
	js := read(t, `{"egress":{"allow":["api.example"],"mode":"enforce"},"version":1,"tools":[]}`)
	yaml, err := policy.Read("node.yaml", []byte("version: 1\ntools: []\negress:\n  mode: enforce\n  allow: [api.example]\n"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(`{"egress":{"allow":["api.example"],"mode":"enforce"},"tools":[],"version":1}`))
	want := "sha256=" + hex.EncodeToString(sum[:])
	if js.Canonical != want || yaml.Canonical != want {
		t.Errorf("JSON %s, YAML %s, want %s", js.Canonical, yaml.Canonical, want)
	}
}
