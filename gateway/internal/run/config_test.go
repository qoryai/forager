package run_test

import (
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway/internal/run"
)

// The tests of this file are session_test.go's TestPolicyUnderACeilingNarrowsOnly and
// TestPolicyUnderACeilingKeepsBothDenyLists, and image_test.go's
// TestReadPolicyAndUnderKeepThePolicysImage, on this package's copies of the types.

func TestPolicyUnderACeilingNarrowsOnly(t *testing.T) {
	enforce := func(allow ...string) *run.Policy {
		return &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: allow}}
	}
	observe := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}}
	p := enforce("api.github.com", "pypi.org")
	if got := p.Under(nil); got != p {
		t.Errorf("under no ceiling %+v", got)
	}
	if got := p.Under(observe); got != p {
		t.Errorf("under an observing ceiling %+v", got)
	}
	got := p.Under(enforce("*.github.com", "api.anthropic.com"))
	if got.Egress.Mode != "enforce" || len(got.Egress.Allow) != 1 || got.Egress.Allow[0] != "api.github.com" {
		t.Errorf("under an enforcing ceiling %+v", got)
	}
	if got := observe.Under(enforce("api.anthropic.com")); got.Egress.Mode != "enforce" || len(got.Egress.Allow) != 1 {
		t.Errorf("an observing policy under an enforcing ceiling %+v", got)
	}
	if _, err := run.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: enforce\n  allow: [api.github.com]\n")); err != nil {
		t.Error(err)
	}
	if _, err := run.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: enforce\n  allow: [\"api.github.com:443\"]\n")); err == nil {
		t.Error("an allow entry with a port was read")
	}
}

func TestPolicyUnderACeilingKeepsBothDenyLists(t *testing.T) {
	mk := func(mode string, allow, deny []string) *run.Policy {
		return &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: mode, Allow: allow, Deny: deny}}
	}
	join := func(p *run.Policy) string {
		return p.Egress.Mode + " " + strings.Join(p.Egress.Allow, ",") + " " + strings.Join(p.Egress.Deny, ",")
	}
	for _, c := range []struct {
		name       string
		p, ceiling *run.Policy
		want       string
	}{
		{"observe ceiling with a deny", mk("observe", nil, []string{"tracker.example"}), mk("observe", nil, []string{"*.ads.example"}), "observe  *.ads.example,tracker.example"},
		{"observe ceiling without a deny", mk("enforce", []string{"api.example"}, []string{"tracker.example"}), mk("observe", nil, nil), "enforce api.example tracker.example"},
		{"enforce ceiling, enforce run", mk("enforce", []string{"api.example"}, []string{"tracker.example"}), mk("enforce", []string{"*.example"}, []string{"*.ads.example", "tracker.example"}), "enforce api.example *.ads.example,tracker.example"},
		{"enforce ceiling, observe run", mk("observe", nil, []string{"tracker.example"}), mk("enforce", []string{"*.example"}, nil), "enforce *.example tracker.example"},
		{"no deny anywhere", mk("enforce", []string{"api.example"}, nil), mk("enforce", []string{"*.example"}, nil), "enforce api.example "},
	} {
		if got := join(c.p.Under(c.ceiling)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := mk("enforce", []string{"api.example"}, nil).Under(mk("enforce", []string{"*.example"}, nil)); got.Egress.Deny != nil {
		t.Errorf("a deny list from nowhere: %v", got.Egress.Deny)
	}
	p, err := run.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: observe\n  deny: [tracker.example]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Egress.Deny, " ") != "tracker.example" {
		t.Errorf("deny read as %v", p.Egress.Deny)
	}
	if _, err := run.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: observe\n  deny: [\"tracker.example:443\"]\n")); err == nil {
		t.Error("a deny entry with a port was read")
	}
}

func TestReadPolicyAndUnderKeepThePolicysImage(t *testing.T) {
	p, err := run.ReadPolicy("policy.yaml", []byte("version: 1\negress:\n  mode: enforce\n  allow: [api.anthropic.com]\nimage: media\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Image != "media" {
		t.Fatalf("read as %q", p.Image)
	}
	observe := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe", Allow: []string{"api.anthropic.com"}}}
	for name, ceiling := range map[string]*run.Policy{
		"no ceiling":              nil,
		"an observing ceiling":    {Version: 1, Egress: run.PolicyEgress{Mode: "observe"}},
		"an observing deny":       {Version: 1, Egress: run.PolicyEgress{Mode: "observe", Deny: []string{"gist.github.com"}}},
		"an enforcing ceiling":    {Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"*.anthropic.com", "api.anthropic.com"}}},
		"a ceiling with an image": {Version: 1, Egress: run.PolicyEgress{Mode: "enforce"}, Image: "other"},
	} {
		if got := p.Under(ceiling).Image; got != "media" {
			t.Errorf("%s: the image under it is %q", name, got)
		}
		o := *observe
		o.Image = "media"
		if got := o.Under(ceiling).Image; got != "media" {
			t.Errorf("%s: an observing policy's image under it is %q", name, got)
		}
	}
}

// TestADefinitionThatCannotBeOneIsRefused pins that the copies check as the gateway's
// definitions do.
func TestADefinitionThatCannotBeOneIsRefused(t *testing.T) {
	if err := (run.Credential{Name: "model", Env: "MODEL_SOURCE", Hosts: []string{"api.model.example"}, Scheme: "bearer"}).Check(); err != nil {
		t.Errorf("a whole credential was refused: %v", err)
	}
	if err := (run.Credential{Name: "model", Env: "MODEL_SOURCE", File: "/a/file", Hosts: []string{"api.model.example"}, Scheme: "bearer"}).Check(); err == nil {
		t.Error("a credential with two sources was accepted")
	}
	if err := (run.Tool{Name: "files", Command: []string{"/bin/true"}, Serves: []string{"files.internal"}}).Check(); err != nil {
		t.Errorf("a whole tool was refused: %v", err)
	}
	if err := (run.Tool{Name: "files", Serves: []string{"files.internal"}}).Check(); err == nil {
		t.Error("a tool with no command was accepted")
	}
}
