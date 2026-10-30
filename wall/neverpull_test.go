package wall

import (
	"context"
	"strings"
	"testing"
)

// neverPulls reports whether the docker command line runs with --pull=never ahead of
// its image, which follows --entrypoint and the entrypoint.
func neverPulls(line string) bool {
	never, entry := strings.Index(line, " --pull=never "), strings.Index(line, " --entrypoint ")
	return never >= 0 && entry >= 0 && never < entry
}

// startAll runs every command of an enclosure that creates or runs a container: the
// relay, the setup container, the agent's container and, for a relay of another image,
// the container of the run's image that is never started. It returns the commands the
// engine got and the agent's docker run.
func startAll(t *testing.T, req Request) ([]string, string) {
	t.Helper()
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, HoldArgs: []string{"hold"}, sys: rec}
	if err := d.Pull(context.Background(), req, nil, nil); err != nil {
		t.Fatal(err)
	}
	e, err := d.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.(*dockerEnclosure).StartSetup(ctx, setupLaunch()); err != nil {
		t.Fatal(err)
	}
	wrapped, err := e.Wrap(ctx, launch())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	return rec.lines, words(wrapped.Args)
}

// TestDockerNeverPullsUnderAnEngineProxy pins NeverPull: every container the enclosure
// creates or runs, the relay, the container of the run's image that is never started,
// the setup container and the agent's, runs with --pull=never ahead of its image, for an
// image the machine defines and for an image by reference alike. Without NeverPull a
// container of an image the machine defines runs as before, with no --pull, and so does
// the relay of a run in an image by reference.
func TestDockerNeverPullsUnderAnEngineProxy(t *testing.T) {
	for _, c := range []struct {
		name string
		req  Request
	}{
		{"a machine's image", Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1"}},
		{"an image by reference", Request{RunID: runID, Image: byReference, RelayImage: "example.com/relay:1", Pull: true}},
	} {
		for _, never := range []bool{true, false} {
			req := c.req
			req.NeverPull = never
			lines, agent := startAll(t, req)
			for _, kind := range []string{"relay", "image", "setup"} {
				i := at(lines, "docker create --name qory-"+runID+"-"+kind+" ")
				if kind == "setup" {
					i = at(lines, "docker run --detach --name qory-"+runID+"-setup ")
				}
				if i < 0 {
					t.Errorf("%s, NeverPull %t: no %s container:\n%s", c.name, never, kind, strings.Join(lines, "\n"))
					continue
				}
				want := never || (req.Pull && kind != "relay")
				if neverPulls(lines[i]) != want || (!want && strings.Contains(lines[i], "--pull")) {
					t.Errorf("%s, NeverPull %t: the %s container with --pull=never %t, want %t:\n%s", c.name, never, kind, neverPulls(lines[i]), want, lines[i])
				}
			}
			if want := never || req.Pull; neverPulls(agent) != want {
				t.Errorf("%s, NeverPull %t: the agent's container with --pull=never %t, want %t:\n%s", c.name, never, neverPulls(agent), want, agent)
			}
		}
	}
}

// TestDockerFailsARunWhoseMachineImageIsMissing pins what a container of an image the
// machine defines that the engine does not have fails with under NeverPull, from Docker
// Engine 26 to 29: the engine prints "No such image: " and the reference for a docker
// create or a docker run with --pull=never. The error says first to pull the image
// before the engine proxy is set, and names the image. Any other failure, the same
// answer without NeverPull, and a run's image by reference keep the engine's error.
func TestDockerFailsARunWhoseMachineImageIsMissing(t *testing.T) {
	const missing = "Pull the image on this machine before you set the engine proxy: the engine has no image %s, and under an engine proxy the wall pulls only in a run's image step."
	for _, c := range []struct {
		name, fail, out string
		req             Request
		want            string
	}{
		{"the relay's image", "-relay ", "Error response from daemon: No such image: example.com/relay:1",
			Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1", NeverPull: true},
			strings.Replace(missing, "%s", "example.com/relay:1", 1)},
		{"the run's image", "-image ", "Error response from daemon: No such image: example.com/agent:1",
			Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1", NeverPull: true},
			strings.Replace(missing, "%s", "example.com/agent:1", 1)},
		{"the run's image as the relay's", "-relay ", "Error response from daemon: No such image: example.com/agent:1",
			Request{RunID: runID, Image: "example.com/agent:1", NeverPull: true},
			strings.Replace(missing, "%s", "example.com/agent:1", 1)},
		{"the setup container's image", "-setup ", "docker: Error response from daemon: No such image: example.com/agent:1\n\nRun 'docker run --help' for more information",
			Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1", NeverPull: true},
			strings.Replace(missing, "%s", "example.com/agent:1", 1)},
		{"Podman's answer", "-relay ", "Error: example.com/relay:1: image not known",
			Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1", NeverPull: true},
			strings.Replace(missing, "%s", "example.com/relay:1", 1)},
		{"another failure", "-relay ", "Error response from daemon: Conflict. The container name is already in use",
			Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1", NeverPull: true},
			"wall docker: docker create --name: exit status 1: Error response from daemon: Conflict. The container name is already in use"},
		{"no engine proxy", "-relay ", "Error response from daemon: No such image: example.com/relay:1",
			Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1"},
			"wall docker: docker create --name: exit status 1: Error response from daemon: No such image: example.com/relay:1"},
	} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, fail: c.fail, failOut: c.out}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, HoldArgs: []string{"hold"}, sys: rec}
		e, err := d.Prepare(context.Background(), c.req)
		if err != nil {
			t.Fatal(err)
		}
		err = e.(*dockerEnclosure).StartSetup(context.Background(), setupLaunch())
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
		if err := e.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	// A run's image by reference that the engine does not have when its container is
	// created keeps the engine's error: Pull fetched it, so the fix is not a pull on
	// this machine.
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`, fail: "-image ", failOut: "Error response from daemon: No such image: " + byReference}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, HoldArgs: []string{"hold"}, sys: rec}
	req := Request{RunID: runID, Image: byReference, RelayImage: "example.com/relay:1", Pull: true, NeverPull: true}
	if err := d.Pull(context.Background(), req, nil, nil); err != nil {
		t.Fatal(err)
	}
	e, err := d.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	want := "wall docker: docker create --name: exit status 1: Error response from daemon: No such image: " + byReference
	if err := e.(*dockerEnclosure).StartSetup(context.Background(), setupLaunch()); err == nil || err.Error() != want {
		t.Errorf("an image by reference: %v, want %s", err, want)
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
