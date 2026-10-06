package session_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/wall"
)

// TestAnImageDefinitionThatCannotBeOneIsRefused pins what a machine's image definition
// must hold: a name in the policy's grammar, a reference, and, for a Docker of the
// agent's own, a runtime that runs one.
func TestAnImageDefinitionThatCannotBeOneIsRefused(t *testing.T) {
	if err := (session.Image{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true}).Check(); err != nil {
		t.Errorf("a whole definition was refused: %v", err)
	}
	for name, img := range map[string]session.Image{
		"a name in capitals":           {Name: "Base", Ref: "example.com/agent:1"},
		"a reference as the name":      {Name: "example.com/agent:1", Ref: "example.com/agent:1"},
		"no name":                      {Ref: "example.com/agent:1"},
		"no reference":                 {Name: "base"},
		"a Docker without its runtime": {Name: "with-docker", Ref: "example.com/agent:1-docker", Docker: true},
	} {
		if err := img.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestReadPolicyAndUnderKeepThePolicysImage pins that the image is the policy's own: it
// is read from the document, and a ceiling of the machine's, which selects no image,
// leaves it whatever the modes.
func TestReadPolicyAndUnderKeepThePolicysImage(t *testing.T) {
	p, err := session.ReadPolicy("policy.yaml", []byte("version: 1\negress:\n  mode: enforce\n  allow: [api.anthropic.com]\nimage: media\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Image != "media" {
		t.Fatalf("read as %q", p.Image)
	}
	observe := &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe", Allow: []string{"api.anthropic.com"}}}
	for name, ceiling := range map[string]*session.Policy{
		"no ceiling":              nil,
		"an observing ceiling":    {Version: 1, Egress: session.PolicyEgress{Mode: "observe"}},
		"an observing deny":       {Version: 1, Egress: session.PolicyEgress{Mode: "observe", Deny: []string{"gist.github.com"}}},
		"an enforcing ceiling":    {Version: 1, Egress: session.PolicyEgress{Mode: "enforce", Allow: []string{"*.anthropic.com", "api.anthropic.com"}}},
		"a ceiling with an image": {Version: 1, Egress: session.PolicyEgress{Mode: "enforce"}, Image: "other"},
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

// images are the machine's definitions the tests below select among.
var images = []session.Image{
	{Name: "base", Ref: "example.com/agent:1"},
	{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true},
}

// TestTheImageIsTheOneThePolicySelects pins which image the wall is asked for: the one
// the policy selects by name, the machine's default by name or by reference when it
// selects none, and what the record says of each.
func TestTheImageIsTheOneThePolicySelects(t *testing.T) {
	for name, c := range map[string]struct {
		selected, def string
		want          wall.Request
		wantName      string
	}{
		"selected":               {"with-docker", "base", wall.Request{Image: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true}, "with-docker"},
		"the default by name":    {"", "base", wall.Request{Image: "example.com/agent:1"}, "base"},
		"the default, reference": {"", "example.com/other:2", wall.Request{Image: "example.com/other:2"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			w := &openWall{}
			pol := &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}, Image: c.selected}
			sp := spec(t, pol, "FAKE_EXIT=0")
			sp.Wall, sp.Image, sp.Images = w, c.def, images
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if w.req.Image != c.want.Image || w.req.Runtime != c.want.Runtime || w.req.Docker != c.want.Docker {
				t.Errorf("the wall was asked for %+v, want %+v", w.req, c.want)
			}
			evs := events(t, res)
			started := data(ofType(evs, "dev.qory.run.started")[0])
			if started["image"] != c.want.Image || fmt.Sprint(started["image_name"]) != fmt.Sprint(orNil(c.wantName)) ||
				fmt.Sprint(started["container_runtime"]) != fmt.Sprint(orNil(c.want.Runtime)) || (started["docker"] == true) != c.want.Docker {
				t.Errorf("run.started %v", started)
			}
			applied := data(ofType(evs, "dev.qory.run.policy_applied")[0])
			if fmt.Sprint(applied["image"]) != fmt.Sprint(orNil(c.selected)) {
				t.Errorf("policy_applied names the image %v, want %q", applied["image"], c.selected)
			}
		})
	}
}

// orNil is what a field absent from an event decodes to when want is empty.
func orNil(want string) any {
	if want == "" {
		return nil
	}
	return want
}

// TestARunWhoseImageCannotHoldDoesNotStart pins what stops a run before its wall is
// built: an image selected without a wall, an image the machine does not define, a
// definition that cannot be one, and a name defined twice.
func TestARunWhoseImageCannotHoldDoesNotStart(t *testing.T) {
	for name, c := range map[string]struct {
		change func(*session.Spec)
		want   string
	}{
		"no wall":                    {func(s *session.Spec) { s.Wall = nil }, "needs a wall"},
		"an image nobody defined":    {func(s *session.Spec) { s.Policy.Image = "nobody-defined" }, "does not define"},
		"a definition that is none":  {func(s *session.Spec) { s.Images = []session.Image{{Name: "with-docker", Ref: "i", Docker: true}} }, "needs a runtime"},
		"a name defined twice":       {func(s *session.Spec) { s.Images = append(s.Images, images[0]) }, "defined twice"},
		"a default that is no image": {func(s *session.Spec) { s.Policy.Image, s.Image = "", "" }, "wall open"},
	} {
		w := &failWall{}
		pol := &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}, Image: "with-docker"}
		sp := spec(t, pol, "FAKE_EXIT=0")
		sp.Wall, sp.Image, sp.Images = w, "base", append([]session.Image(nil), images...)
		c.change(&sp)
		if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// failWall refuses an empty image as the Docker adapter does, and records nothing.
type failWall struct{ openWall }

func (w *failWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	if req.Image == "" {
		return nil, fmt.Errorf("wall open: %q is not an image reference", req.Image)
	}
	return w.openWall.Prepare(ctx, req)
}

// TestAReloadKeepsTheRunsImage pins that a run's image is fixed when it starts: a run
// configuration that selects another fails the reload and the policy in force stays,
// and one that selects the same takes effect and names it again.
func TestAReloadKeepsTheRunsImage(t *testing.T) {
	c := newControl(t)
	withImage := `{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"%s]},"image":"%s"}`
	c.serve(fmt.Sprintf(withImage, "", "with-docker"), digest('1'))
	w := &openWall{}
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.Wall, sp.Image, sp.Images = w, "base", images
	run := startWaiting(t, sp)
	waitFor(t, func() bool { return run.applied() == 1 })
	if w.req.Image != "example.com/agent:1-docker" {
		t.Errorf("the run started in %q", w.req.Image)
	}

	c.serve(fmt.Sprintf(withImage, "", "base"), digest('2'))
	waitFor(t, func() bool { return run.reported("another image than the run started in") })

	c.serve(fmt.Sprintf(withImage, `,"git.example.com"`, "with-docker"), digest('3'))
	waitFor(t, func() bool { return run.applied() == 2 })

	pa := ofType(run.finish(), "dev.qory.run.policy_applied")
	if then := data(pa[1]); then["image"] != "with-docker" || then["run_configuration"] != digest('3') {
		t.Errorf("the second policy_applied %v", then)
	}
}

// TestAReloadComparesTheImageItResolvesTo pins that a reload is refused for another
// image, not for another way of naming the same: naming the machine's default, or no
// longer naming it, takes effect.
func TestAReloadComparesTheImageItResolvesTo(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}}`, digest('1'))
	w := &openWall{}
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.Wall, sp.Image, sp.Images = w, "base", images
	run := startWaiting(t, sp)
	waitFor(t, func() bool { return run.applied() == 1 })

	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"image":"base"}`, digest('2'))
	waitFor(t, func() bool { return run.applied() == 2 })
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","git.example.com"]}}`, digest('3'))
	waitFor(t, func() bool { return run.applied() == 3 })
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"image":"with-docker"}`, digest('4'))
	waitFor(t, func() bool { return run.reported("another image than the run started in") })

	pa := ofType(run.finish(), "dev.qory.run.policy_applied")
	if len(pa) != 3 || data(pa[1])["image"] != "base" || data(pa[2])["image"] != nil {
		t.Errorf("the policies applied: %v", pa)
	}
}
