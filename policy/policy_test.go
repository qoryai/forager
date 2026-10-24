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

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
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

// TestReadHoldsEveryEntryToTheHostForm pins that a policy whose allow, deny or paths
// entry naming a host is neither a host name nor an IPv4 address in canonical form is
// refused when it is read, as a *policy.Error naming the document, and that one whose
// entries all are reads.
func TestReadHoldsEveryEntryToTheHostForm(t *testing.T) {
	for _, egress := range []string{
		`"mode":"observe","deny":["127.1"]`,
		`"mode":"observe","deny":["0x7f.0.0.1"]`,
		`"mode":"observe","deny":["2130706433"]`,
		`"mode":"observe","deny":["0177.0.0.1"]`,
		`"mode":"observe","deny":["127.000.0.1"]`,
		`"mode":"observe","deny":["api.example","0x7f.1"]`,
		`"mode":"enforce","allow":["127.0.0.1.1"]`,
		`"mode":"enforce","allow":["api.1"]`,
		`"mode":"enforce","allow":["example.0x1f"]`,
		`"mode":"observe","deny":["example.0x"]`,
		`"mode":"enforce","allow":["[::ffff:127.0.0.1]"]`,
		`"mode":"enforce","allow":["::ffff:127.0.0.1"]`,
		`"mode":"enforce","allow":["2001:0db8::1"]`,
		`"mode":"enforce","allow":["2001:db8::1"]`,
		`"mode":"enforce","allow":["api.example"],"paths":{"127.1":["/x"]}`,
		`"mode":"enforce","allow":["api.example"],"paths":{"api.example":["/x"],"0x7f.0.0.1":[]}`,
	} {
		doc := `{"version":1,"egress":{` + egress + `}}`
		_, err := policy.Read("policy", []byte(doc))
		var pe *policy.Error
		if !errors.As(err, &pe) || pe.Name != "policy" {
			t.Errorf("%s: %v, want a *policy.Error", doc, err)
		}
		if _, err := policy.Parse("policy", []byte(doc)); err == nil {
			t.Errorf("%s: parsed", doc)
		}
	}
	doc := `{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1","10.0.0.255","0x7f.example","127.example","*.example","*.1.example"],"deny":["192.168.0.1","deadbeef.example"],"paths":{"127.0.0.1":["/x"],"*.example":[]}}}`
	if _, err := policy.Read("policy", []byte(doc)); err != nil {
		t.Errorf("%s: %v", doc, err)
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

// TestHostHasOneForm pins the form of a host: a name of ASCII letters, digits, hyphens
// and dots, lower-cased, without one trailing dot and with no empty label; an IPv4
// address of four decimal parts with no leading zero, where a host is read as one when
// it ends in a number: its last label is all digits, or 0x and hex digits or none; an
// IPv6 address in RFC 5952's form with no zone, and not in ::/96 (except ::1),
// ::ffff:0:0/96, ::ffff:0:0:0/96 or 64:ff9b::/96. Any other host has none.
func TestHostHasOneForm(t *testing.T) {
	for _, c := range []struct{ host, form string }{
		{"api.example", "api.example"},
		{"API.Example.", "api.example"},
		{"localhost", "localhost"},
		{"a-b.example", "a-b.example"},
		{"0x7f.example", "0x7f.example"},
		{"127.example", "127.example"},
		{"1.2.3.example", "1.2.3.example"},
		{"deadbeef", "deadbeef"},
		{"0x7g", "0x7g"},
		{"1.2.3.0xg", "1.2.3.0xg"},
		{"example.0x1g", "example.0x1g"},
		{"0x1f.example", "0x1f.example"},
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1.", "127.0.0.1"},
		{"10.0.0.255", "10.0.0.255"},
		{"::1", "::1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"::1:0:0", "::1:0:0"},
		{"::fffe:ffff:ffff", "::fffe:ffff:ffff"},
		{"::1:0:0:0", "::1:0:0:0"},
		{"::ffff:1:0:0", "::ffff:1:0:0"},
		{"::fffe:ffff:ffff:ffff", "::fffe:ffff:ffff:ffff"},
		{"64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", "64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"64:ff9b::1:0:0", "64:ff9b::1:0:0"},
		{"2002::", "2002::"},
		{"2002:7f00:1::", "2002:7f00:1::"},
		{"2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2600::1", "2600::1"},
		{"2001::1", "2001::1"},
		{"64:ff9b:1::1", "64:ff9b:1::1"},
		{"64:ff9b:1::7f00:1", "64:ff9b:1::7f00:1"},
		{"::", ""},
		{"::2", ""},
		{"::7f00:1", ""},
		{"::ffff:ffff", ""},
		{"::ffff:0.0.0.0", ""},
		{"::ffff:255.255.255.255", ""},
		{"::ffff:0:0:0", ""},
		{"::ffff:0:7f00:1", ""},
		{"::ffff:0:ffff:ffff", ""},
		{"64:ff9b::", ""},
		{"64:ff9b::7f00:1", ""},
		{"64:FF9B::7F00:1", ""},
		{"64:ff9b::ffff:ffff", ""},
		{"", ""},
		{".", ""},
		{"api.example..", ""},
		{".api.example", ""},
		{"api..example", ""},
		{"ａｐｉ.example", ""},
		{"a­pi.example", ""},
		{"Key.example", ""},
		{"%EF%BD%81pi.example", ""},
		{"%61pi.example", ""},
		{"a_b.example", ""},
		{"a b.example", ""},
		{"api.example:443", ""},
		{"127.1", ""},
		{"2130706433", ""},
		{"0x7f000001", ""},
		{"0x7f", ""},
		{"0X7F", ""},
		{"0x7f.0.0.1", ""},
		{"0x7f.1", ""},
		{"0177.0.0.1", ""},
		{"127.000.0.1", ""},
		{"127.0.0.1.1", ""},
		{"256.0.0.1", ""},
		{"api.1", ""},
		{"0x", ""},
		{"0X1F", ""},
		{"example.0x1f", ""},
		{"example.0X1F", ""},
		{"example.0x", ""},
		{"example.0X.", ""},
		{"1.2.3.0x4", ""},
		{"::ffff:127.0.0.1", ""},
		{"::FFFF:7f00:1", ""},
		{"::1.2.3.4", ""},
		{"0:0:0:0:0:0:0:1", ""},
		{"2001:0db8::1", ""},
		{"2001:db8:0:0:0:0:0:1", ""},
		{"fe80::1%en0", ""},
		{"[::1]", ""},
	} {
		form, ok := policy.Host(c.host)
		if form != c.form || ok != (c.form != "") {
			t.Errorf("Host(%q) = %q, %v; want %q", c.host, form, ok, c.form)
		}
	}
}

// TestEndpointHostReadsAnHTTPSBaseURL pins the host read from a base URL: the scheme
// https, no user information, a host in the form Host gives, no port or one from 1 to
// 65535. Every other base URL has no host. The host does not depend on the path, query
// or fragment, but a bad percent escape in the path or fragment leaves the URL with none.
func TestEndpointHostReadsAnHTTPSBaseURL(t *testing.T) {
	for _, c := range []struct{ raw, host string }{
		{"https://api.anthropic.com", "api.anthropic.com"},
		{"https://api.anthropic.com/", "api.anthropic.com"},
		{"https://API.Anthropic.COM/v1", "api.anthropic.com"},
		{"HTTPS://api.anthropic.com", "api.anthropic.com"},
		{"https://api.anthropic.com./v1", "api.anthropic.com"},
		{"https://api.anthropic.com:8443", "api.anthropic.com"},
		{"https://api.anthropic.com:443/v1", "api.anthropic.com"},
		{"https://api.anthropic.com:", "api.anthropic.com"},
		{"https://api.anthropic.com/v1?beta=1#part", "api.anthropic.com"},
		{"https://api.anthropic.com?%zz", "api.anthropic.com"},
		{"https://api.anthropic.com/%zz", ""},
		{"https://api.anthropic.com#%zz", ""},
		{"https://api.anthropic.com/v 1", "api.anthropic.com"},
		{"https://api.anthropic.com:1", "api.anthropic.com"},
		{"https://api.anthropic.com:65535", "api.anthropic.com"},
		{"https://[::1]:65535", "::1"},
		{"https://127.0.0.1:8443", "127.0.0.1"},
		{"https://[::1]:8443/", "::1"},
		{"https://[2001:DB8::1]/v1", "2001:db8::1"},
		{"https://api.anthropic.com@evil.example/", ""},
		{"https://user:secret@api.anthropic.com/", ""},
		{"https://@api.anthropic.com/", ""},
		{"http://api.anthropic.com", ""},
		{"wss://api.anthropic.com", ""},
		{"https://", ""},
		{"https:///v1", ""},
		{"https://:8443", ""},
		{"api.anthropic.com", ""},
		{"//api.anthropic.com", ""},
		{"/v1", ""},
		{"https:api.anthropic.com", ""},
		{"", ""},
		{"https://api.anthropic.com..", ""},
		{"https://127.1", ""},
		{"https://0x7f000001", ""},
		{"https://[::ffff:127.0.0.1]", ""},
		{"https://[fe80::1%25en0]", ""},
		{"https://[2001:0db8::1]", ""},
		{"https://ａｐｉ.anthropic.com", ""},
		{"https://api_x.anthropic.com", ""},
		{"https://api%2Eanthropic.com", ""},
		{"https://%61pi.anthropic.com", ""},
		{"https://api.anthropic.com%25", ""},
		{"https://%EF%BD%81pi.anthropic.com", ""},
		{" https://api.anthropic.com", ""},
		{"\thttps://api.anthropic.com", ""},
		{"https://api.anthropic.com ", ""},
		{"https://api .anthropic.com", ""},
		{"https://api.anthropic.com\n", ""},
		{"https:// api.anthropic.com", ""},
		{"https://api.anthropic.com:84 43", ""},
		{"https://api.anthropic.com:http", ""},
		{"https://api.anthropic.com:99999", ""},
		{"https://api.anthropic.com:65536", ""},
		{"https://api.anthropic.com:0", ""},
		{"https://api.anthropic.com:00", ""},
		{"https://api.anthropic.com:+443", ""},
		{"https://api.anthropic.com:-443", ""},
		{"https://api.anthropic.com:99999999999999999999", ""},
		{"https://[::1]:0", ""},
	} {
		host, ok := policy.EndpointHost(c.raw)
		if host != c.host || ok != (c.host != "") {
			t.Errorf("EndpointHost(%q) = %q, %v; want %q", c.raw, host, ok, c.host)
		}
	}
}

// TestCredentialForMatchesAsTheProxyDoes pins the hosts a credential covers: the host's
// form under Host, then Match against the credential's hosts. A host with no form is
// covered by none, though a pattern's suffix would match it.
func TestCredentialForMatchesAsTheProxyDoes(t *testing.T) {
	for _, c := range []struct {
		hosts []string
		host  string
		ok    bool
	}{
		{[]string{"api.anthropic.com"}, "api.anthropic.com", true},
		{[]string{"api.anthropic.com"}, "API.Anthropic.com.", true},
		{[]string{"API.Anthropic.com"}, "api.anthropic.com", true},
		{[]string{"api.anthropic.com"}, "anthropic.com", false},
		{[]string{"api.anthropic.com"}, "x.api.anthropic.com", false},
		{[]string{"api.anthropic.com"}, "api.anthropic.com:443", false},
		{[]string{"*.github.com"}, "api.github.com", true},
		{[]string{"*.github.com"}, "a.b.github.com", true},
		{[]string{"*.github.com"}, "github.com", false},
		{[]string{"*.github.com"}, "evilgithub.com", false},
		{[]string{"*.github.com"}, "a b.github.com", false},
		{[]string{"*.github.com"}, "%61pi.github.com", false},
		{[]string{"*.github.com"}, "a_b.github.com", false},
		{[]string{"api.anthropic.com", "*.github.com"}, "uploads.github.com", true},
		{[]string{"127.0.0.1"}, "127.0.0.1", true},
		{[]string{"127.0.0.1"}, "127.0.0.2", false},
		{[]string{"*.0.0.1"}, "127.0.0.1", false},
		{[]string{"::1"}, "::1", true},
		{[]string{"2001:db8::1"}, "2001:DB8::1", true},
		{[]string{"api.anthropic.com"}, "", false},
		{nil, "api.anthropic.com", false},
	} {
		if ok := policy.CredentialFor(c.hosts, c.host); ok != c.ok {
			t.Errorf("CredentialFor(%q, %q) = %v; want %v", c.hosts, c.host, ok, c.ok)
		}
	}
}

// TestCredentialForGivesAPrivateHostOnlyAnExactEntry pins the private hosts: an IP
// literal in a private range, a name of one label and a name that ends in ".local",
// ".internal" or ".home.arpa" are each covered only by an entry equal to them, never by
// a "*." pattern, while any other name is still covered by a pattern.
func TestCredentialForGivesAPrivateHostOnlyAnExactEntry(t *testing.T) {
	for _, c := range []struct {
		hosts []string
		host  string
		ok    bool
	}{
		{[]string{"*.local"}, "litellm.local", false},
		{[]string{"*.local"}, "a.litellm.local", false},
		{[]string{"*.litellm.local"}, "a.litellm.local", false},
		{[]string{"litellm.local"}, "litellm.local", true},
		{[]string{"LiteLLM.local"}, "litellm.local", true},
		{[]string{"litellm.local"}, "LiteLLM.Local.", true},
		{[]string{"*.local", "litellm.local"}, "litellm.local", true},
		{[]string{"litellm.local"}, "other.local", false},
		{[]string{"*.example.com"}, "api.example.com", true},
		{[]string{"*.local.example.com"}, "api.local.example.com", true},
		{[]string{"*.example.com"}, "api.example.com.local", false},
		{[]string{"10.0.0.5"}, "10.0.0.5", true},
		{[]string{"10.0.0.6"}, "10.0.0.5", false},
		{[]string{"*.0.0.5"}, "10.0.0.5", false},
		{[]string{"10.0.0.0/8"}, "10.0.0.5", false},
		{[]string{"172.16.0.1"}, "172.16.0.1", true},
		{[]string{"192.168.1.10"}, "192.168.1.10", true},
		{[]string{"litellm"}, "litellm", true},
		{[]string{"LiteLLM"}, "litellm.", true},
		{[]string{"*.litellm"}, "litellm", false},
		{[]string{"litellm.local"}, "litellm", false},
		{[]string{"fd00::5"}, "fd00::5", true},
		{[]string{"fd00::5"}, "FD00::5", true},
		{[]string{"fd00::6"}, "fd00::5", false},
		{[]string{"fc00::1"}, "fc00::1", true},
		{[]string{"*.local"}, "fd00::5", false},
		{[]string{"*.internal"}, "x.internal", false},
		{[]string{"x.internal"}, "x.internal", true},
		{[]string{"*.internal"}, "internal", false},
		{[]string{"internal"}, "internal", true},
		{[]string{"*.home.arpa"}, "x.home.arpa", false},
		{[]string{"x.home.arpa"}, "x.home.arpa", true},
		{[]string{"*.arpa"}, "x.home.arpa", false},
		{[]string{"*.lan"}, "x.lan", true},
	} {
		if ok := policy.CredentialFor(c.hosts, c.host); ok != c.ok {
			t.Errorf("CredentialFor(%q, %q) = %v; want %v", c.hosts, c.host, ok, c.ok)
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
// machine's name for it, never by a reference with a tag, and that the selection is
// part of what the digest pins.
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
		{imageRef, imageRef, imageRef},
		{"", imageRef, imageRef},
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
	// A name and a reference are two strings, never the same image, whatever the name
	// stands for on the machine.
	_, err = policy.Narrowed(fetched(t, doc(imageRef)), read(t, doc("agent")))
	if !errors.As(err, &r) || r.Code != refusal.ImageUnknown || !slices.Equal(r.Names, []string{imageRef}) {
		t.Errorf("a reference and a name: %v", err)
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

// TestHostPathsTakesTheMostSpecificEntry pins which entry of a policy's path rules
// holds a host several entries match: the host's name itself before any "*." entry,
// and of "*." entries the one with the longest suffix, whatever order a map is read
// in; an empty list is held as no path; and a host no entry matches is held by none.
func TestHostPathsTakesTheMostSpecificEntry(t *testing.T) {
	paths := map[string][]string{
		"example":         {"/apex/*"},
		"*.example":       {"/v1/*"},
		"api.example":     {"/v2/*"},
		"*.api.example":   {"/v3/*"},
		"*.b.api.example": {"/v4/*"},
		"closed.example":  {},
		"10.0.0.1":        {"/ip/*"},
		"*.0.0.1":         {"/never/*"},
	}
	for range 200 {
		for _, tc := range []struct{ host, entry, rule string }{
			{"api.example", "api.example", "/v2/*"},
			{"API.Example.", "api.example", "/v2/*"},
			{"example", "example", "/apex/*"},
			{"other.example", "*.example", "/v1/*"},
			{"a.api.example", "*.api.example", "/v3/*"},
			{"a.b.api.example", "*.b.api.example", "/v4/*"},
			{"b.api.example", "*.api.example", "/v3/*"},
			{"10.0.0.1", "10.0.0.1", "/ip/*"},
		} {
			entry, rules, ok := policy.HostPaths(paths, tc.host)
			if !ok || entry != tc.entry || len(rules) != 1 || rules[0] != tc.rule {
				t.Fatalf("%s: held by %q %v %v, want %q", tc.host, entry, rules, ok, tc.entry)
			}
		}
		if entry, rules, ok := policy.HostPaths(paths, "closed.example"); !ok || entry != "closed.example" || rules == nil || len(rules) != 0 {
			t.Fatalf("closed.example: held by %q %v %v", entry, rules, ok)
		}
		for _, host := range []string{"example.org", "10.0.0.2", "0.0.1"} {
			if entry, _, ok := policy.HostPaths(paths, host); ok {
				t.Fatalf("%s: held by %q", host, entry)
			}
		}
	}
	if _, _, ok := policy.HostPaths(nil, "api.example"); ok {
		t.Error("no rules hold a host")
	}
}

// TestANarrowingRefusalPrintsAPhraseForASecret pins the two refusals of a server's
// selection the node's policy does not list, of tools and of credentials: a name that
// contains qak_ or qrk_ in any case prints the name's phrase, in the text and in a
// refusal's names, each phrase once, and a clean name prints as it is.
func TestANarrowingRefusalPrintsAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
	read := func(doc string) *policy.Loaded {
		t.Helper()
		l, err := policy.Read("x.json", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	node := read(`{"version":1,"egress":{"mode":"observe","allow":[]},"tools":[],"credentials":[]}`)
	for _, c := range []struct {
		names   []string
		shown   string
		refused []string
	}{
		{[]string{"qak_a"}, ak, []string{ak}},
		{[]string{"a.qrk_b"}, rk, []string{rk}},
		{[]string{"qrk_a.qak_b"}, ak, []string{ak}},
		{[]string{"files", "qak_a", "qak_b", "qrk_c"}, "files, " + ak + ", " + rk, []string{rk, ak, "files"}},
		{[]string{"files", "more"}, "files, more", []string{"files", "more"}},
	} {
		var entries []string
		for _, n := range c.names {
			entries = append(entries, `{"name":"`+n+`"}`)
		}
		list := "[" + strings.Join(entries, ",") + "]"
		_, err := policy.Narrowed(read(`{"version":1,"egress":{"mode":"observe","allow":[]},"tools":`+list+`}`), node)
		var r *accesskey.Refusal
		if want := "the server's policy selects the tools " + c.shown + ", which the node's policy does not list: tool_unknown: " + strings.Join(c.refused, ", "); !errors.As(err, &r) || err.Error() != want {
			t.Errorf("tools %v:\n got %v\nwant %s", c.names, err, want)
			continue
		}
		if !slices.Equal(r.Names, c.refused) {
			t.Errorf("tools %v: the names %q, want %q", c.names, r.Names, c.refused)
		}
		tools := err.Error()
		_, err = policy.Narrowed(read(`{"version":1,"egress":{"mode":"observe","allow":[]},"credentials":`+list+`}`), node)
		if want := "the server's policy selects the credentials " + c.shown + ", which the node's policy does not list"; err == nil || err.Error() != want {
			t.Errorf("credentials %v:\n got %v\nwant %s", c.names, err, want)
			continue
		}
		for _, text := range []string{tools, err.Error()} {
			if lower := strings.ToLower(text); strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") {
				t.Errorf("%v: a secret's prefix in %s", c.names, text)
			}
		}
	}
}

// TestAnImageRefusalOfANarrowingPrintsAPhraseForASecret pins the image_unknown of a
// server's policy whose image is not the node's: an image that contains qak_ or qrk_ in
// any case prints the name's phrase in the detail and the names, and a clean image
// prints as it is.
func TestAnImageRefusalOfANarrowingPrintsAPhraseForASecret(t *testing.T) {
	read := func(image string) *policy.Loaded {
		t.Helper()
		l, err := policy.Read("x.json", []byte(`{"version":1,"egress":{"mode":"observe"},"image":"`+image+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	for _, c := range []struct{ server, node, want string }{
		{"qak_a", "base", "the server's policy selects the image (a name that contains an access key secret) and the node's policy the image base: image_unknown: (a name that contains an access key secret)"},
		{"base", "a.qrk_b", "the server's policy selects the image base and the node's policy the image (a name that contains a run key): image_unknown: base"},
		{"base", "other", "the server's policy selects the image base and the node's policy the image other: image_unknown: base"},
	} {
		_, err := policy.Narrowed(read(c.server), read(c.node))
		if err == nil || err.Error() != c.want {
			t.Errorf("%s, %s:\n got %v\nwant %s", c.server, c.node, err, c.want)
		}
	}
}

// TestAPolicyErrorPrintsAPhraseForASecret pins a policy document's error: a name or an
// error's text that contains qak_ or qrk_ in any case prints the value's phrase, and
// the error still wraps its cause.
func TestAPolicyErrorPrintsAPhraseForASecret(t *testing.T) {
	_, err := policy.Read("qak_policy.json", []byte(`{"version":1,"egress":{"mode":"observe"},"qrk_x":1}`))
	if want := "policy (a value that contains an access key secret): (a value that contains a run key)"; err == nil || err.Error() != want {
		t.Errorf("Read = %v, want %s", err, want)
	}
	cause := errors.New("no")
	if e := (&policy.Error{Name: "p.json", Err: cause}); e.Error() != "policy p.json: no" || !errors.Is(e, cause) {
		t.Errorf("a clean error: %v", e)
	}
}

// TestNarrowKeepsWhatTheNodeAllows pins the node's narrowing of a host list such as a
// run configuration's stack_hosts: a name the node allows stays, one it does not is
// taken away; a *. entry stays when the node allows every host below it, and under
// enforce the node's entries below one it does not take its place; nothing is added.
func TestNarrowKeepsWhatTheNodeAllows(t *testing.T) {
	list := []string{"git.example", "*.cdn.example", "other.example", "10.0.0.1"}
	for _, tc := range []struct {
		name string
		node policy.Egress
		want []string
	}{
		{"observe", policy.Egress{Mode: policy.Observe}, list},
		{"observe with a deny", policy.Egress{Mode: policy.Observe, Deny: []string{"other.example", "a.cdn.example"}}, []string{"git.example", "10.0.0.1"}},
		{"enforce", policy.Egress{Mode: policy.Enforce, Allow: []string{"git.example", "*.example"}}, []string{"git.example", "*.cdn.example", "other.example"}},
		{"enforce below a pattern", policy.Egress{Mode: policy.Enforce, Allow: []string{"git.example", "a.cdn.example"}, AllowFirst: []string{"10.0.0.1"}}, []string{"git.example", "10.0.0.1", "a.cdn.example"}},
		{"enforce with a deny below", policy.Egress{Mode: policy.Enforce, Allow: []string{"*.example"}, Deny: []string{"b.cdn.example"}}, []string{"git.example", "other.example"}},
		{"enforce with nothing", policy.Egress{Mode: policy.Enforce}, nil},
	} {
		if got := tc.node.Narrow(list); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
