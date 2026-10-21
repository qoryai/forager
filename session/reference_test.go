package session_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/internal/linktest"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// pinned is an image a policy names by its reference pinned by digest.
const pinned = "registry.example/agents/app@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

// targetWall is an open wall that shows a mount at its Target, as the Docker adapter
// does: the launch it returns starts in the workspace's directory on this machine. It
// fetched the image, as an adapter does for a run whose image is named by reference,
// and calls the request's Fetched then, or refuses with what refuse holds.
type targetWall struct {
	openWall
	refuse error
}

func (w *targetWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	if w.refuse != nil {
		return nil, w.refuse
	}
	if req.Pull && req.Fetched != nil {
		req.Fetched()
	}
	return w, nil
}

func (w *targetWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	got, err := w.openWall.Wrap(ctx, l)
	for _, m := range l.Mounts {
		if rest, ok := strings.CutPrefix(l.Dir, m.Target); m.Target != "" && ok {
			got.Dir = m.Path + rest
		}
	}
	return got, err
}

// byReference makes the gateway answer the image by reference, as it resolves one
// images.allow covers: under the default's runtime, marked as a reference, with the
// default's reference for the relay.
func byReference(g *linktest.Fake) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["image"] = map[string]any{"ref": pinned, "reference": true}
		a["relay_image"] = "example.com/agent:1"
		a["applied"].(map[string]any)["image"] = pinned
		return linktest.Reply{Status: 200, Body: a}
	})
}

// TestARunInAnImageByReference pins a run whose policy names its image by reference:
// the wall is asked to fetch it, with the default's image for the relay; the bind that
// holds the workspace is shown at /workspace and the working directory is under it;
// what Forager puts inside names the workspace there, the harness's values, its home,
// the preparation's words and the settings it copies, and what the run, the machine
// and the inherited environment set is left as it is; and the record says the
// working directory inside, how long the fetch took, and no name for the image.
func TestARunInAnImageByReference(t *testing.T) {
	w := &targetWall{}
	sp, g := specGateway(t, "FAKE_EXIT=0")
	byReference(g)
	dir := sp.Dir
	// The settings lie outside the workspace, a place the session reads no file from;
	// what they name in it is written as the enclosure sees it.
	settings := filepath.Join(t.TempDir(), "settings-with-a-hook.json")
	hook := `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"sh ` + dir + `/hook.sh"}]}]},"note":"` + dir + `shop"}`
	if err := os.WriteFile(settings, []byte(hook), 0o644); err != nil {
		t.Fatal(err)
	}
	sp.Args = []string{"--settings", settings}
	sp.Wall, sp.Image, sp.Images, sp.ImagesAllow = w, "base", images, []string{"registry.example/agents/"}
	sp.HarnessHome = dir + "/home"
	sp.LaunchFixed = []string{"TOOLS_DIR=" + dir + "/tools"}
	sp.LaunchDefaults = []string{"CACHE_PATH=" + dir + "/cache:" + dir + "x"}
	sp.Variables.Run = []string{"MINE=" + dir}
	sp.Env = append(sp.Env, "INHERITED="+dir)
	sp.Preparation = []string{"true", dir + "/prepare.sh"}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	got := w.req
	if got.Fetched == nil {
		t.Error("the wall was asked for a fetch with no Fetched")
	}
	got.Fetched = nil
	if want := (wall.Request{RunID: res.RunID, Image: pinned, RelayImage: "example.com/agent:1", Pull: true}); !reflect.DeepEqual(got, want) {
		t.Errorf("the wall was asked for %+v, want %+v", got, want)
	}
	if req := g.Requests()[0]; !slices.Equal(req.Images.Allow, sp.ImagesAllow) {
		t.Errorf("the run request's images %+v", req.Images)
	}
	if w.got.Dir != "/workspace" {
		t.Errorf("the working directory inside is %q", w.got.Dir)
	}
	for _, m := range w.got.Mounts {
		if (m.Target == "/workspace") != (m.Path == filepath.Clean(dir)) || (m.Target != "" && m.Target != "/workspace") {
			t.Errorf("the mount %+v", m)
		}
	}
	for _, want := range []string{"QORY_HARNESS_HOME=/workspace/home", "TOOLS_DIR=/workspace/tools", "CACHE_PATH=/workspace/cache:" + dir + "x", "MINE=" + dir, "INHERITED=" + dir} {
		if !slices.Contains(w.got.Env, want) {
			t.Errorf("the enclosure's environment lacks %s: %v", want, w.got.Env)
		}
	}
	script, err := os.ReadFile(filepath.Join(res.SessionDir, session.PreparationScript))
	if err != nil || !strings.Contains(string(script), "'true' '/workspace/prepare.sh'") {
		t.Errorf("the preparation script: %s, %v", script, err)
	}
	copied, err := os.ReadFile(filepath.Join(res.SessionDir, "settings.json"))
	if err != nil || !strings.Contains(string(copied), `"sh /workspace/hook.sh"`) || !strings.Contains(string(copied), `"`+dir+`shop"`) {
		t.Errorf("the settings copied: %s, %v", copied, err)
	}
	evs := events(t, res)
	started := data(ofType(evs, "dev.qory.session.started")[0])
	if started["dir"] != "/workspace" || started["image"] != pinned || started["image_name"] != nil || started["container_runtime"] != nil ||
		started["docker"] != nil || started["image_fetch_ms"] != nil {
		t.Errorf("session.started %v", started)
	}
	// The fetch is the image step, after session.started, and the rest of the wall's
	// start the wall step.
	want := []string{"step 1 join join session 1", "step 1 succeeded -1", "session 1 started",
		"step 2 image " + pinned, "step 2 succeeded -1", "step 3 wall start the wall", "step 3 succeeded -1", "session 1 exited", "run exited"}
	if got := stepOrder(evs); !slices.Equal(got, want) {
		t.Errorf("the steps:\n%q\nwant\n%q", got, want)
	}
}

// TestASettingsFileInTheWorkspaceIsJudgedOnThisMachine pins that a run whose workspace
// is at /workspace inside judges the settings file by its path on this machine: one in
// the workspace is refused, named by that path, before anything is written inside.
func TestASettingsFileInTheWorkspaceIsJudgedOnThisMachine(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	byReference(g)
	settings := filepath.Join(sp.Dir, "launch-settings.json")
	if err := os.WriteFile(settings, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	sp.Args = []string{"--settings", settings}
	sp.Wall, sp.Image, sp.Images, sp.ImagesAllow = &targetWall{}, "base", images, []string{"registry.example/agents/"}
	want := "runtime claude: Move " + settings + " to a directory no walled run can write, or pass the settings as a " +
		"JSON object. This launch passes --settings " + settings + ", which lies in " + sp.Dir +
		", a place a walled run can write, so the run does not start."
	if _, err := run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("the run: %v, want %q", err, want)
	}
}

// TestARunInAnImageByNameKeepsItsPaths pins that a run in an image the machine defines
// sees its workspace at the same path as before, the default's reference being the
// relay's image, and that the record has no fetch.
func TestARunInAnImageByNameKeepsItsPaths(t *testing.T) {
	w := &targetWall{}
	sp, g := specGateway(t, "FAKE_EXIT=0")
	selecting(g, "")
	sp.Wall, sp.Image, sp.Images = w, "base", images
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if w.req.Pull || w.got.Dir == "/workspace" || slices.ContainsFunc(w.got.Mounts, func(m wall.Mount) bool { return m.Target != "" }) {
		t.Errorf("a run by name: %+v, %+v", w.req, w.got)
	}
	if started := data(ofType(events(t, res), "dev.qory.session.started")[0]); started["image_fetch_ms"] != nil || started["dir"] != sp.Dir {
		t.Errorf("session.started %v", started)
	}
}

// refusedIn is the dev.qory.run.refused of the session's record of a run that did not
// start.
func refusedIn(t *testing.T, sp runSpec) map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(sp.RunsDir, sp.RunID, "session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for s := bufio.NewScanner(f); s.Scan(); {
		var e map[string]any
		if json.Unmarshal(s.Bytes(), &e) == nil && e["type"] == "dev.qory.run.refused" {
			return data(e)
		}
	}
	return nil
}

// TestARunWhoseImageByReferenceCannotHoldDoesNotStart pins what stops a run in an image
// by reference: an allow list that cannot be one, before the gateway hears of the run;
// the gateway's image_not_allowed; the wall's image_user_root, after the session's
// start, the code as the reason of its session.exited, recorded and posted;
// and a place of the run's at /workspace, before the wall is asked.
func TestARunWhoseImageByReferenceCannotHoldDoesNotStart(t *testing.T) {
	for name, change := range map[string]func(*runSpec){
		"an entry of *":          func(s *runSpec) { s.ImagesAllow = []string{"*"} },
		"an empty entry":         func(s *runSpec) { s.ImagesAllow = []string{""} },
		"a tag in an entry":      func(s *runSpec) { s.ImagesAllow = []string{"registry.example/app:1"} },
		"a list with no default": func(s *runSpec) { s.Image, s.Images = "", nil },
	} {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image, sp.Images, sp.ImagesAllow = &openWall{}, "base", images, []string{"registry.example/"}
		change(&sp)
		if _, err := run(context.Background(), sp); err == nil {
			t.Errorf("%s: the run started", name)
		}
		if len(g.Requests()) > 0 {
			t.Errorf("%s: the gateway was asked", name)
		}
	}

	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.OnRun(func(server.LinkRunRequest) linktest.Reply {
		return linktest.Reply{Status: 403, Body: linktest.Refusal(refusals.ImageNotAllowed, "gateway", pinned)}
	})
	w := &targetWall{}
	sp.Wall, sp.Image, sp.ImagesAllow, sp.RunID = w, "example.com/agent:1", []string{"registry.example/other/"}, event.NewRunID()
	_, err := run(context.Background(), sp)
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != refusals.ImageNotAllowed || w.req.Image != "" {
		t.Errorf("image_not_allowed: %v; the wall was asked for %+v", err, w.req)
	}
	if d := refusedIn(t, sp); d["code"] != refusals.ImageNotAllowed {
		t.Errorf("the record's run.refused %v", d)
	}

	sp, g = specGateway(t, "FAKE_EXIT=0")
	byReference(g)
	w = &targetWall{refuse: refusals.New(refusals.ImageUserRoot, []string{pinned}, "the image %s runs as root; a run's image runs as the wall's user", pinned)}
	sp.Wall, sp.Image, sp.ImagesAllow, sp.RunID = w, "example.com/agent:1", []string{"registry.example/"}, event.NewRunID()
	if _, err = run(context.Background(), sp); !errors.As(err, &r) || r.Code != refusals.ImageUserRoot {
		t.Errorf("image_user_root: %v", err)
	}
	if !errors.As(err, &r) || !slices.Equal(r.Names, []string{pinned}) {
		t.Errorf("image_user_root names %v", err)
	}
	startedThenExited(t, "the record", events(t, &session.Result{Dir: filepath.Join(sp.RunsDir, sp.RunID)}), refusals.ImageUserRoot)
	startedThenExited(t, "the link", g.Events(), refusals.ImageUserRoot)

	sp, g = specGateway(t, "FAKE_EXIT=0")
	byReference(g)
	w = &targetWall{}
	sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
	sp.Mounts = []wall.Mount{{Path: "/workspace/tools", ReadOnly: true}}
	if _, err := run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "overlaps /workspace") || w.req.Image != "" {
		t.Errorf("a mount at /workspace: %v; the wall was asked for %+v", err, w.req)
	}
}

// anyStrings are the strings of a decoded JSON array.
func anyStrings(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

// TestTheServersImageByReferenceIsTheOneTheWallPulls pins a run whose image the
// server's run configuration names by reference, by its image member or in its
// security_policy, the node's policy naming none, through a real gateway: the request
// the session gives the wall is that reference, to pull, with the default's image for
// the relay, so the server's answer is in force before the wall fetches anything.
func TestTheServersImageByReferenceIsTheOneTheWallPulls(t *testing.T) {
	for _, doc := range []string{
		`{"version":1,"image":"` + pinned + `"}`,
		`{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"},"image":"` + pinned + `"}}`,
	} {
		c := newControl(t)
		c.serveDocument(doc)
		w := &targetWall{}
		sp := spec(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image, sp.Images, sp.ImagesAllow = w, "base", images, []string{"registry.example/agents/"}
		rg := startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
		res, err := run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		rg.close(t)
		got := w.req
		got.Fetched = nil
		if want := (wall.Request{RunID: res.RunID, Image: pinned, RelayImage: "example.com/agent:1", Pull: true}); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: the wall was asked for %+v, want %+v", doc, got, want)
		}
	}
}

// TestAPluginLinkToTheWorkspaceInsideIsNoRun pins that a run whose workspace is at
// /workspace inside refuses a plugin directory with a link that leads to /workspace,
// which no place of this machine's is, before the wall is asked.
func TestAPluginLinkToTheWorkspaceInsideIsNoRun(t *testing.T) {
	w := &targetWall{}
	sp, g := specGateway(t, "FAKE_EXIT=0")
	byReference(g)
	plugin := mkdirs(t, filepath.Join(t.TempDir(), "plugin", "skills"))
	plugin = filepath.Dir(plugin)
	symlink(t, "/workspace/harness/skills/review", filepath.Join(plugin, "skills", "review"))
	sp.Args = append(sp.Args, "--plugin-dir", plugin)
	sp.Wall, sp.Image, sp.Images, sp.ImagesAllow = w, "base", images, []string{"registry.example/agents/"}
	want := "runtime claude: Replace the link " + filepath.Join(plugin, "skills", "review") + " with a copy, " +
		"or move what it leads to out of /workspace. This launch passes --plugin-dir " + plugin +
		", and that link leads into /workspace, which a walled run can write, so the run does not start."
	if _, err := run(context.Background(), sp); err == nil || err.Error() != want {
		t.Errorf("the run: %v, want %q", err, want)
	}
	if w.req.RunID != "" {
		t.Errorf("the wall was asked: %+v", w.req)
	}
}
