package wall

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
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
			want := "--mount type=bind,src=" + l.Transcript.Path + ",dst=" + strings.TrimSuffix(c.want, "/") + "/.claude/projects "
			if create := agentCreate(rec); !strings.Contains(create, want) {
				t.Errorf("the agent's docker create %q; want %s", create, want)
			}
			if got := words(wrapped.Args); got != "start --attach --interactive qory-"+runID+"-agent" {
				t.Errorf("the launch is %q; want the docker start of the agent's container", got)
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
			} else if slices.ContainsFunc(rec.lines, func(l string) bool { return strings.Contains(l, " run --rm ") || strings.Contains(l, " create --rm ") }) {
				t.Errorf("the agent's container was made: %v", err)
			}
		})
	}
}

// agentCreate is the docker create of the agent's container among the recorder's
// commands, empty for none.
func agentCreate(rec *recorder) string {
	for _, l := range rec.lines {
		if strings.HasPrefix(l, "docker create --rm --interactive ") {
			return l
		}
	}
	return ""
}

// copiedDirs are the entries of the tar the last docker cp wrote into a container: each
// name, type, mode, uid and gid.
func copiedDirs(t *testing.T, rec *recorder) []tar.Header {
	t.Helper()
	var out []tar.Header
	r := tar.NewReader(bytes.NewReader(rec.copied))
	for {
		h, err := r.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tar.Header{Name: h.Name, Typeflag: h.Typeflag, Mode: h.Mode, Uid: h.Uid, Gid: h.Gid})
	}
}

// TestTheTranscriptBindsParentIsMadeForTheAgentsUser pins the parents of the
// transcript bind's place: each one the image does not have is written into the agent's
// container after its docker create, as a directory of mode 0700 owned by the container's
// user, with docker cp --archive, so the engine does not make it owned by root at the
// start. One the image has is left as it is, and nested Docker's container user is
// root.
func TestTheTranscriptBindsParentIsMadeForTheAgentsUser(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000::/home/agent:/bin/sh\n"
	for name, c := range map[string]struct {
		under  string
		dirs   []string
		docker bool
		want   []tar.Header
	}{
		"none in the image": {".claude/projects", nil, false,
			[]tar.Header{{Name: "home/agent/.claude/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}}},
		"the image has it": {".claude/projects", []string{"/home/agent/.claude"}, false, nil},
		"the image has the first of two": {"a/b/projects", []string{"/home/agent/a"}, false,
			[]tar.Header{{Name: "home/agent/a/b/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}}},
		"none of two in the image": {"a/b/projects", nil, false, []tar.Header{
			{Name: "home/agent/a/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000},
			{Name: "home/agent/a/b/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}}},
		"nested Docker": {".claude/projects", nil, true,
			[]tar.Header{{Name: "home/agent/.claude/", Typeflag: tar.TypeDir, Mode: 0o700}}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, files: map[string]string{"/etc/passwd": passwd}, dirs: map[string]bool{}}
			for _, d := range c.dirs {
				rec.dirs[d] = true
			}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, NestArgs: []string{"nest"}, sys: rec}
			req := Request{RunID: runID, Image: "example.com/agent:1"}
			if c.docker {
				req.Runtime, req.Docker = "sysbox-runc", true
			}
			e, err := d.Prepare(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			l := transcriptLaunch("HOME=/home/agent")
			l.Transcript.Under = c.under
			if _, err := e.Wrap(context.Background(), l); err != nil {
				t.Fatal(err)
			}
			created := slices.IndexFunc(rec.lines, func(l string) bool { return strings.HasPrefix(l, "docker create --rm --interactive ") })
			copied := slices.Index(rec.lines, "docker cp --archive - qory-"+runID+"-agent:/")
			stat := slices.IndexFunc(rec.lines, func(l string) bool { _, ok := statPath(l); return ok })
			if created < 0 || stat < 0 {
				t.Fatalf("commands %q; want the agent's docker create and a check of the image's path", rec.lines)
			}
			if c.want == nil {
				if copied >= 0 {
					t.Errorf("a docker cp into the agent's container, of %+v; want none for a path the image has", copiedDirs(t, rec))
				}
				return
			}
			if copied < created {
				t.Fatalf("commands %q; want a docker cp --archive into the agent's container after its docker create", rec.lines)
			}
			if got := copiedDirs(t, rec); !slices.EqualFunc(got, c.want, func(a, b tar.Header) bool {
				return a.Name == b.Name && a.Typeflag == b.Typeflag && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
			}) {
				t.Errorf("the tar has %+v; want %+v", got, c.want)
			}
		})
	}
}

// TestAFailedCheckOfTheImagesPathFailsTheWrap pins a check of the image's path that
// fails for another reason than a missing path: the wrap fails, and nothing is written
// into the agent's container.
func TestAFailedCheckOfTheImagesPathFailsTheWrap(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, fail: "docker cp qory-"}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	if _, err := e.Wrap(context.Background(), transcriptLaunch("HOME=/home/agent")); err == nil || !strings.Contains(err.Error(), "told to fail") {
		t.Errorf("the wrap: %v; want the check's failure", err)
	}
	if slices.ContainsFunc(rec.lines, func(l string) bool { return strings.Contains(l, "cp --archive") }) {
		t.Errorf("commands %q; want no docker cp into the agent's container", rec.lines)
	}
}
