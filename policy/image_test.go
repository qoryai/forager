package policy_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
)

// imageRef is an image named by its reference pinned by digest, as the fixtures name one.
const imageRef = "registry.example/agents/app@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

// digest is a digest's part of a reference, @sha256: and 64 hexadecimal digits.
const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestTheImageGrammarIsTheSchemas pins that a reference Go reads as pinned is one
// policy.schema.json accepts, and one Go refuses is one the schema refuses: a policy
// file and a fetched security_policy are held to one grammar.
func TestTheImageGrammarIsTheSchemas(t *testing.T) {
	for _, c := range []struct {
		ref    string
		pinned bool
	}{
		{"app" + digest, true},
		{"registry.example/agents/app" + digest, true},
		{"registry.example:5000/agents/app" + digest, true},
		{"localhost:5000/a__b/c---d/e.f_g" + digest, true},
		{strings.Repeat("a", 255) + digest, true},
		{strings.Repeat("a", 256) + digest, false},
		{"registry.example/agents/app:1" + digest, false},
		{"registry.example/agents/app:1", false},
		{"registry.example/agents/app", false},
		{"registry.example/Agents/app" + digest, false},
		{"registry.example/agents/app" + strings.ToUpper(digest), false},
		{"registry.example/agents/app@sha256:0123", false},
		{"-app" + digest, false},
		{"app_" + digest, false},
		{"app___b" + digest, false},
		{"user:secret@registry.example/app" + digest, false},
		{"registry.example:123456/app" + digest, false},
	} {
		if got := policy.ImageReference(c.ref); got != c.pinned {
			t.Errorf("%s: pinned %v, want %v", c.ref, got, c.pinned)
		}
		doc, _ := json.Marshal(map[string]any{"version": 1, "egress": map[string]any{"mode": "observe"}, "image": c.ref})
		_, err := policy.Read("policy", doc)
		if (err == nil) != c.pinned {
			t.Errorf("%s: read with %v, want pinned %v", c.ref, err, c.pinned)
		}
	}
}

// TestAReferenceNotPinnedIsRunConfigurationInvalid pins the code of a policy's image
// written as a reference with a tag, in upper case or without a digest:
// run_configuration_invalid, with no names, whichever reads the policy; a name and a
// value that is neither are left to the schema, which gives no code.
func TestAReferenceNotPinnedIsRunConfigurationInvalid(t *testing.T) {
	for _, f := range []string{"policy-image-reference.yaml", "policy-image-reference-tag-and-digest.yaml", "policy-image-reference-upper-case.yaml"} {
		_, err := policy.Read(f, fixture(t, "fixtures/invalid/"+f))
		var r *accesskey.Refusal
		var pe *policy.Error
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || len(r.Names) != 0 || !errors.As(err, &pe) {
			t.Errorf("%s: %v, want a policy error with run_configuration_invalid and no names", f, err)
		}
		if _, err := policy.Parse(f, fixture(t, "fixtures/invalid/"+f)); !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid {
			t.Errorf("%s: Parse gave %v", f, err)
		}
	}
	for _, image := range []string{"Base", "a b"} {
		_, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"observe"},"image":"`+image+`"}`))
		var r *accesskey.Refusal
		if err == nil || errors.As(err, &r) {
			t.Errorf("%q: %v, want the schema's refusal", image, err)
		}
	}
	l, err := policy.Read("enforce-image-reference.yaml", fixture(t, "fixtures/policy/enforce-image-reference.yaml"))
	if err != nil || l.Policy.Image != imageRef {
		t.Errorf("the fixture with a reference read as %v, %v", l, err)
	}
}

// TestAnAllowEntryCoversAReferenceAtAWholePart pins the matching of images.allow: an
// entry covers a reference that starts with it when the entry ends in / or @, or the
// reference goes on with / or @, and nothing is normalised.
func TestAnAllowEntryCoversAReferenceAtAWholePart(t *testing.T) {
	for _, c := range []struct {
		entry, ref string
		covers     bool
	}{
		{"registry.example/agents", "registry.example/agents/app" + digest, true},
		{"registry.example/agents/", "registry.example/agents/app" + digest, true},
		{"registry.example/agents/app", "registry.example/agents/app" + digest, true},
		{"registry.example/agents/app@", "registry.example/agents/app" + digest, true},
		{"registry.example", "registry.example/agents/app" + digest, true},
		{"registry.example/agents", "registry.example/agents-other/app" + digest, false},
		{"registry.example/agents/ap", "registry.example/agents/app" + digest, false},
		{"registry.example", "registry.example:5000/agents/app" + digest, false},
		{"registry.example", "registry.example.evil/agents/app" + digest, false},
		{"docker.io/library/", "ubuntu" + digest, false},
		{"", "registry.example/agents/app" + digest, false},
	} {
		entry, ok := policy.ImageAllowed([]string{c.entry}, c.ref)
		if ok != c.covers || (ok && entry != c.entry) {
			t.Errorf("%q over %s: %q, %v; want %v", c.entry, c.ref, entry, ok, c.covers)
		}
	}
	if _, ok := policy.ImageAllowed(nil, imageRef); ok {
		t.Error("no list allowed a reference")
	}
}

// TestAnAllowEntryIsTheStartOfAReference pins what images.allow refuses: an empty
// entry, *, and one that is not the start of a reference in lower case up to a whole
// part of it.
func TestAnAllowEntryIsTheStartOfAReference(t *testing.T) {
	for _, entry := range []string{"registry.example", "registry.example/", "registry.example:5000", "registry.example:5000/agents/",
		"registry.example/agents/app", "registry.example/agents/app@", "localhost:5000/walltest/"} {
		if err := policy.CheckImagePrefix(entry); err != nil {
			t.Errorf("%q: %v", entry, err)
		}
	}
	for _, entry := range []string{"", "*", "registry.example/*", "Registry.example", "registry.example//", "/", "@", "registry.example/agents/app:1",
		"registry.example/agents/app@sha256:", "registry.example/agents/app" + digest, "-registry.example", " registry.example"} {
		if err := policy.CheckImagePrefix(entry); err == nil {
			t.Errorf("%q was taken as a prefix", entry)
		}
	}
}
