package session_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
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

// images are the machine's definitions the tests below select among.
var images = []session.Image{
	{Name: "base", Ref: "example.com/agent:1"},
	{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true},
}

// selecting makes the gateway answer the image the policy selects by name, resolved
// against the run request's images as the gateway resolves it, or the default.
func selecting(g *linktest.Fake, selected string) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		if selected != "" {
			for _, d := range req.Images.Definitions {
				if d.Name == selected {
					img := map[string]any{"name": d.Name, "ref": d.Ref}
					if d.Runtime != "" {
						img["runtime"] = d.Runtime
					}
					if d.Docker {
						img["docker"] = true
					}
					a["image"] = img
				}
			}
			a["applied"].(map[string]any)["image"] = selected
		}
		return linktest.Reply{Status: 200, Body: a}
	})
}

// TestTheImageIsTheOneTheGatewayAnswers pins which image the wall is asked for: the
// one the gateway's run answer gives, which the policy selects by name or the machine's
// default by name or by reference when it selects none, and what the record says of
// each. The run request carries the machine's image table.
func TestTheImageIsTheOneTheGatewayAnswers(t *testing.T) {
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
			sp, g := specGateway(t, "FAKE_EXIT=0")
			selecting(g, c.selected)
			sp.Wall, sp.Image, sp.Images = w, c.def, images
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if w.req.Image != c.want.Image || w.req.Runtime != c.want.Runtime || w.req.Docker != c.want.Docker {
				t.Errorf("the wall was asked for %+v, want %+v", w.req, c.want)
			}
			req := g.Requests()[0]
			if !req.Wall || req.Images == nil || req.Images.Default != c.def || len(req.Images.Definitions) != 2 ||
				req.Images.Definitions[1] != (server.LinkImage{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true}) {
				t.Errorf("the run request's images %+v", req.Images)
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
	// Without a wall the run request carries no images.
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.Forwarder = nil
	sp.Image, sp.Images = "base", images
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if req := g.Requests()[0]; req.Wall || req.Images != nil {
		t.Errorf("an unwalled run request %+v", req)
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
// built: an image selected without a wall, the gateway's wall_required, which the
// session words as it always has; an image the machine does not define, the
// gateway's image_unknown; a definition that cannot be one and a name defined twice,
// which the session refuses before the gateway hears of the run; and a default that
// is no image, which the wall refuses.
func TestARunWhoseImageCannotHoldDoesNotStart(t *testing.T) {
	refuse := func(code string, names ...string) func(*linktest.Fake) {
		return func(g *linktest.Fake) {
			g.OnRun(func(server.LinkRunRequest) linktest.Reply {
				return linktest.Reply{Status: 403, Body: linktest.Refusal(code, "gateway", names...)}
			})
		}
	}
	for name, c := range map[string]struct {
		change  func(*session.Spec)
		gateway func(*linktest.Fake)
		want    string
		asked   bool
	}{
		"no wall": {func(s *session.Spec) { s.Wall = nil }, refuse("wall_required", "image=with-docker"),
			`the policy selects the image "with-docker", which needs a wall: without one the runtime is this machine's process`, true},
		"an image nobody defined":    {func(*session.Spec) {}, refuse("image_unknown", "nobody-defined"), "image_unknown (status 403): nobody-defined", true},
		"a definition that is none":  {func(s *session.Spec) { s.Images = []session.Image{{Name: "with-docker", Ref: "i", Docker: true}} }, nil, "needs a runtime", false},
		"a name defined twice":       {func(s *session.Spec) { s.Images = append(s.Images, images[0]) }, nil, "defined twice", false},
		"a default that is no image": {func(s *session.Spec) { s.Image = "" }, nil, "wall open", true},
	} {
		w := &failWall{}
		sp, g := specGateway(t, "FAKE_EXIT=0")
		if c.gateway != nil {
			c.gateway(g)
		}
		sp.Wall, sp.Image, sp.Images = w, "base", append([]session.Image(nil), images...)
		c.change(&sp)
		if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		if asked := len(g.Requests()) > 0; asked != c.asked {
			t.Errorf("%s: the gateway was asked %v, want %v", name, asked, c.asked)
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
