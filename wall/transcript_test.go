package wall

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// transcriptLaunch is launch with the session's transcript directory, at
// .claude/projects below the home inside, and env added.
func transcriptLaunch(env ...string) Launch {
	l := launch()
	l.Env = append(l.Env, env...)
	l.Transcript = Transcript{Path: "/home/dev/.qory/runs/" + runID + "/transcripts/1", Under: ".claude/projects"}
	return l
}

// TestTheTranscriptDirectoryIsBoundWritableAtTheHome pins the bind of a launch's
// transcript directory: writable, at Under below the home inside, which is the launch's
// HOME, else the image's, else the home /etc/passwd of the image gives the wall's user,
// else /; and the directory among the enclosure's binds, writable.
func TestTheTranscriptDirectoryIsBoundWritableAtTheHome(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000::/home/agent:/bin/sh\n"
	for name, c := range map[string]struct {
		env       []string
		imageHome string
		passwd    string
		want      string
	}{
		"the launch's HOME":   {[]string{"HOME=/srv/one", "HOME=/srv/agent"}, "/image", passwd, "/srv/agent"},
		"the image's HOME":    {nil, "/image/home", passwd, "/image/home"},
		"the passwd's home":   {nil, "", passwd, "/home/agent"},
		"a user with no line": {nil, "", "root:x:0:0:root:/root:/bin/sh\n", "/"},
		"no passwd":           {nil, "", "", "/"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, imageHome: c.imageHome, files: map[string]string{}}
			if c.passwd != "" {
				rec.files["/etc/passwd"] = c.passwd
			}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
			e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			l := transcriptLaunch(c.env...)
			wrapped, err := e.Wrap(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			want := "type=bind,src=" + l.Transcript.Path + ",dst=" + strings.TrimSuffix(c.want, "/") + "/.claude/projects"
			if !slices.Contains(wrapped.Args, want) {
				t.Errorf("the agent's docker run %q; want --mount %s", wrapped.Args, want)
			}
			binds, err := e.(Binder).Binds(l)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(binds, Bind{Path: l.Transcript.Path}) {
				t.Errorf("binds %+v; want the transcript directory, writable", binds)
			}
		})
	}
}

// TestALaunchWithNoTranscriptDirectoryBindsNone pins a launch without one: no bind, and
// no read of the image's home.
func TestALaunchWithNoTranscriptDirectoryBindsNone(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	wrapped, err := e.Wrap(context.Background(), launch())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(wrapped.Args, " "), "transcripts") || slices.ContainsFunc(rec.lines, func(l string) bool { return strings.Contains(l, "/etc/passwd") || strings.Contains(l, "image inspect") }) {
		t.Errorf("commands %q, the agent's docker run %q", rec.lines, wrapped.Args)
	}
}

// TestATranscriptDirectoryThatOverlapsAMountIsRefused pins the refusals: a directory
// that lies inside a mount, holds one or is not clean, a place below the home with a ..
// name or that is absolute, and a home where the place inside overlaps a mount's place
// inside or /qory.
func TestATranscriptDirectoryThatOverlapsAMountIsRefused(t *testing.T) {
	for name, change := range map[string]func(*Launch){
		"inside the workspace":   func(l *Launch) { l.Transcript.Path = "/work/.claude" },
		"holds a mount":          func(l *Launch) { l.Transcript.Path = "/home/dev" },
		"the socket's directory": func(l *Launch) { l.Transcript.Path = "/tmp/qory-run-1" },
		"not clean":              func(l *Launch) { l.Transcript.Path = "/runs/x/../work" },
		"relative":               func(l *Launch) { l.Transcript.Path = "runs/x" },
		"a .. name below home":   func(l *Launch) { l.Transcript.Under = "../.ssh" },
		"absolute below home":    func(l *Launch) { l.Transcript.Under = "/etc" },
		"a home in a mount":      func(l *Launch) { l.Env = append(l.Env, "HOME=/work") },
		"a home that holds one":  func(l *Launch) { l.Env = append(l.Env, "HOME=/"); l.Transcript.Under = "work" },
		"a home under /qory":     func(l *Launch) { l.Env = append(l.Env, "HOME=/qory") },
		"a relative home":        func(l *Launch) { l.Env = append(l.Env, "HOME=home") },
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
			e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			l := transcriptLaunch()
			change(&l)
			if _, err := e.Wrap(context.Background(), l); err == nil {
				t.Error("the launch was wrapped")
			} else if slices.ContainsFunc(rec.lines, func(l string) bool { return strings.Contains(l, " run --rm ") }) {
				t.Errorf("the agent's container started: %v", err)
			}
		})
	}
}
