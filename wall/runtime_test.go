package wall

import (
	"context"
	"strings"
	"testing"
)

// TestDockerBindsTheInstalledRuntimeReadOnly pins the bind of a launch's installed
// runtime folder: read-only at /qory/runtime/<runtime>, and none for a launch without
// one. A folder that is not absolute and clean, one with a comma, and a name that is no
// runtime's are refused before the agent's container is made.
func TestDockerBindsTheInstalledRuntimeReadOnly(t *testing.T) {
	const want = "--mount type=bind,src=/opt/runtimes/claude/2.1.320,dst=/qory/runtime/claude,readonly "
	for name, c := range map[string]struct {
		folder RuntimeFolder
		bound  bool
	}{
		"bound":            {RuntimeFolder{Path: "/opt/runtimes/claude/2.1.320", Name: "claude"}, true},
		"none":             {RuntimeFolder{}, false},
		"relative":         {RuntimeFolder{Path: "opt/runtimes/claude", Name: "claude"}, false},
		"not clean":        {RuntimeFolder{Path: "/opt/runtimes/../claude", Name: "claude"}, false},
		"a comma":          {RuntimeFolder{Path: "/opt/runtimes,dst=/x/claude", Name: "claude"}, false},
		"no path":          {RuntimeFolder{Name: "claude"}, false},
		"no name":          {RuntimeFolder{Path: "/opt/runtimes/claude"}, false},
		"a name with ..":   {RuntimeFolder{Path: "/opt/runtimes/claude", Name: ".."}, false},
		"a name with /":    {RuntimeFolder{Path: "/opt/runtimes/claude", Name: "claude/x"}, false},
		"an uppercase one": {RuntimeFolder{Path: "/opt/runtimes/claude", Name: "Claude"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
			e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			l := launch()
			l.Command, l.Runtime = "/qory/runtime/claude/bin/claude", c.folder
			wrapped, err := e.Wrap(context.Background(), l)
			ok := c.bound || c.folder == (RuntimeFolder{})
			switch {
			case !ok && err == nil:
				t.Fatalf("the launch was wrapped: %s", words(wrapped.Args))
			case !ok:
				if strings.Contains(strings.Join(rec.lines, "\n"), " run --rm ") {
					t.Errorf("the agent's container was made: %v", err)
				}
				return
			case err != nil:
				t.Fatal(err)
			}
			line := words(wrapped.Args) + " "
			if got := strings.Contains(line, want); got != c.bound {
				t.Errorf("bound %v, want %v: %s", got, c.bound, line)
			}
			if c.bound && strings.Count(line, "dst=/qory/runtime") != 1 {
				t.Errorf("the runtime is bound more than once: %s", line)
			}
		})
	}
}

// TestDockerRefusesAMountShownUnderQory pins that /qory is the wall's whatever shows a
// mount there: a mount with no Target whose path is, holds or lies under /qory is
// refused, as one with such a Target is.
func TestDockerRefusesAMountShownUnderQory(t *testing.T) {
	for _, path := range []string{"/qory", "/qory/runtime", "/qory/runtime/claude", "/qory/qory", "/"} {
		t.Run(path, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
			e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			l := launch()
			l.Mounts = append(l.Mounts, Mount{Path: path, ReadOnly: true})
			if _, err := e.Wrap(context.Background(), l); err == nil {
				t.Errorf("the mount %s was bound", path)
			} else if !strings.Contains(err.Error(), "overlaps /qory") {
				t.Errorf("the error is %v", err)
			}
		})
	}
}
