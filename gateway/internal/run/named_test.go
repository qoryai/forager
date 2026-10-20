package run_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/server"
)

// named is a run configuration that names the image, beside the security_policy given,
// none when it is empty.
func named(image, securityPolicy string, d string) *run.Fetched {
	f := &run.Fetched{URL: runURL, Digest: d, Document: &server.RunConfiguration{Version: 1, Image: image}}
	if securityPolicy != "" {
		f.Document.SecurityPolicy = []byte(securityPolicy)
	}
	return f
}

// allowing are the machine's images with a list that allows pinned.
var allowing = run.Images{Default: "base", Defined: images, Allow: []string{"registry.example/agents/"}}

// TestARunConfigurationNamesTheImage pins a run configuration's image: without a
// security_policy the node's policy is in force as it is, with the image its selection;
// beside one it is the policy's selection; under none of images.allow it is
// image_not_allowed; and without a wall it is no run.
func TestARunConfigurationNamesTheImage(t *testing.T) {
	node := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"api.model.example"}}}
	r, err := run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Node: node, Fetched: named(pinned, "", digest('1'))})
	if err != nil {
		t.Fatal(err)
	}
	pol := r.Policy()
	if want := (run.Image{Ref: pinned, Reference: true}); r.Image() != want || pol.Policy.Image != pinned {
		t.Errorf("the image %+v, the policy's %q; want %+v", r.Image(), pol.Policy.Image, want)
	}
	if pol.Source != "config" || pol.Policy.Egress.Mode != "enforce" || !slices.Equal(pol.Policy.Egress.Allow, []string{"api.model.example"}) || pol.RunConfiguration != digest('1') {
		t.Errorf("the policy in force is not the node's: %+v", pol)
	}

	r, err = run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Fetched: named(pinned, `{"version":1,"egress":{"mode":"observe"}}`, digest('1'))})
	if err != nil || r.Image().Ref != pinned || r.Policy().Source != "fetched" {
		t.Errorf("beside a security_policy: %+v, %v", r, err)
	}
	if r, err := run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Fetched: named(pinned, "", digest('1'))}); err != nil || r.Image().Ref != pinned || r.Policy().Source != "none" {
		t.Errorf("with no policy: %v", err)
	}

	_, err = run.Decide(run.Config{RunID: runID, Wall: true, Images: run.Images{Default: "base", Defined: images, Allow: []string{"registry.example/other/"}}, Fetched: named(pinned, "", digest('1'))})
	if code, names := refusalOf(err); code != "image_not_allowed" || !slices.Equal(names, []string{pinned}) {
		t.Errorf("under no prefix: %v", err)
	}
	if _, err := run.Decide(run.Config{RunID: runID, Server: true, Fetched: named(pinned, "", digest('1'))}); err == nil || !strings.Contains(err.Error(), "image") {
		t.Errorf("without a wall: %v", err)
	}
}

// TestTheImageIsTheSameWhereverTwoNameOne pins the agreement of the run
// configuration's image with the server's policy and the node's: the same string on
// both sides is a run; another image, a name of the machine's for the same build
// among them, is image_unknown, the server's policy's or the node's named.
func TestTheImageIsTheSameWhereverTwoNameOne(t *testing.T) {
	other := strings.Replace(pinned, "agents/app", "agents/other", 1)
	withImage := func(image string) string {
		return fmt.Sprintf(`{"version":1,"egress":{"mode":"observe"},"image":%q}`, image)
	}
	nodeWith := func(image string) *run.Policy {
		return &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Image: image}
	}
	if _, err := run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Node: nodeWith(pinned), Fetched: named(pinned, withImage(pinned), digest('1'))}); err != nil {
		t.Errorf("the same on every side: %v", err)
	}
	for _, c := range []struct {
		what   string
		node   *run.Policy
		server string
		want   string
	}{
		{"the server's policy", nil, withImage(other), "the run configuration names the image " + pinned + ", and the server's policy the image " + other},
		{"the server's policy by name", nil, withImage("base"), "the run configuration names the image " + pinned + ", and the server's policy the image base"},
		{"the node's policy", nodeWith(other), "", "the run configuration names the image " + pinned + ", and the node's policy the image " + other},
		{"the node's policy beside the server's", nodeWith("with-docker"), `{"version":1,"egress":{"mode":"observe"}}`, "the run configuration names the image " + pinned + ", and the node's policy the image with-docker"},
	} {
		_, err := run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Node: c.node, Fetched: named(pinned, c.server, digest('1'))})
		if code, names := refusalOf(err); code != "image_unknown" || !slices.Equal(names, []string{pinned}) || err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (%q, %q), want image_unknown with %q", c.what, err, code, names, c.want)
		}
	}
}

// TestARunConfigurationsImageIsAReference pins that a run configuration's image is a
// reference pinned by digest, the machine's name for an image and a tag being
// run_configuration_invalid, and the image named in the refusal.
func TestARunConfigurationsImageIsAReference(t *testing.T) {
	for _, image := range []string{"base", "registry.example/agents/app:1", "Registry.example/agents/app@sha256:" + strings.Repeat("b", 64), "registry.example/agents/app"} {
		_, err := run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Fetched: named(image, "", digest('1'))})
		want := "run configuration " + runURL + ": the image " + image + " is not a reference pinned by digest"
		if code, _ := refusalOf(err); code != "run_configuration_invalid" || !strings.HasPrefix(err.Error(), want+":") {
			t.Errorf("%s: %v (%q), want run_configuration_invalid and %q", image, err, code, want)
		}
	}
}

// TestAReloadKeepsTheImageTheRunConfigurationNamed pins that a run configuration's
// image is fixed when the run starts: the same one takes effect, and one that differs,
// appears or disappears fails the reload, the policy in force staying, even when it
// resolves to the image the run started in.
func TestAReloadKeepsTheImageTheRunConfigurationNamed(t *testing.T) {
	other := strings.Replace(pinned, "agents/app", "agents/other", 1)
	observe := `{"version":1,"egress":{"mode":"observe"}}`
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Images: allowing, Fetched: named(pinned, "", digest('1'))})
	d, err := reload(t, r, named(pinned, `{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}}`, digest('2')))
	if err != nil || d.Image != r.Image() || d.Policy.Policy.Image != pinned {
		t.Fatalf("the same image: %+v, %v", d, err)
	}
	r.Commit(d)
	for _, c := range []struct {
		what string
		f    *run.Fetched
		want string
	}{
		{"another", named(other, "", digest('3')), "the run configuration names the image " + other + ", and the run started in " + pinned},
		{"none", named("", fmt.Sprintf(`{"version":1,"egress":{"mode":"observe"},"image":%q}`, pinned), digest('3')), "the run configuration names no image, and the run started in " + pinned},
	} {
		if _, err := reload(t, r, c.f); err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasSuffix(err.Error(), "the policy in force stays") {
			t.Errorf("%s: %v, want %q", c.what, err, c.want)
		}
	}
	if r.RunConfiguration() != digest('2') {
		t.Errorf("the run configuration in force is %q", r.RunConfiguration())
	}

	r = open(t, run.Config{RunID: runID, Wall: true, Server: true, Images: allowing, Fetched: served(fmt.Sprintf(`{"version":1,"egress":{"mode":"observe"},"image":%q}`, pinned), digest('1'))})
	if _, err := reload(t, r, named(pinned, observe, digest('2'))); err == nil || !strings.Contains(err.Error(), "the run configuration names the image "+pinned+", and the run started in "+pinned) {
		t.Errorf("one that appears: %v", err)
	}
	r = open(t, run.Config{RunID: runID, Server: true, Fetched: served(observe, digest('1'))})
	if _, err := reload(t, r, named(pinned, "", digest('2'))); err == nil || !strings.Contains(err.Error(), "needs a wall") {
		t.Errorf("one without a wall: %v", err)
	}
}
