package wall

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
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
// HOME, else the image's, else the home of the wall's user in the image's /etc/passwd,
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
// that lies inside a mount, contains one or is not clean, a place below the home with a ..
// name, an absolute place that is /, is not clean or overlaps a mount's place inside or
// /qory, and a home where the place inside overlaps a mount's place inside or /qory.
func TestATranscriptDirectoryThatOverlapsAMountIsRefused(t *testing.T) {
	for name, change := range map[string]func(*Launch){
		"inside the workspace":     func(l *Launch) { l.Transcript.Path = "/work/.claude" },
		"contains a mount":         func(l *Launch) { l.Transcript.Path = "/home/dev" },
		"the socket's directory":   func(l *Launch) { l.Transcript.Path = "/tmp/qory-run-1" },
		"not clean":                func(l *Launch) { l.Transcript.Path = "/runs/x/../work" },
		"relative":                 func(l *Launch) { l.Transcript.Path = "runs/x" },
		"a .. name below home":     func(l *Launch) { l.Transcript.Under = "../.ssh" },
		"the root":                 func(l *Launch) { l.Transcript.Under = "/" },
		"absolute, not clean":      func(l *Launch) { l.Transcript.Under = "/var/../etc" },
		"absolute, in a mount":     func(l *Launch) { l.Transcript.Under = "/work/.sessions" },
		"absolute, around a mount": func(l *Launch) { l.Transcript.Under = "/home/dev/.qory" },
		"absolute, under /qory":    func(l *Launch) { l.Transcript.Under = "/qory/sessions" },
		"a home in a mount":        func(l *Launch) { l.Env = append(l.Env, "HOME=/work") },
		"a home that contains one": func(l *Launch) { l.Env = append(l.Env, "HOME=/"); l.Transcript.Under = "work" },
		"a home under /qory":       func(l *Launch) { l.Env = append(l.Env, "HOME=/qory") },
		"a relative home":          func(l *Launch) { l.Env = append(l.Env, "HOME=home") },
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
// container after its docker create, as a directory of mode 0700 owned by the agent's
// user and group, with docker cp and no --archive, so the engine takes the owner from
// the tar and does not make it owned by root at the start. One the image has is left as
// it is. With nested Docker the agent's user is the wall's too, not the container's
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
		"the image has it": {".claude/projects", []string{"/home", "/home/agent", "/home/agent/.claude"}, false, nil},
		"the image has the first of two": {"a/b/projects", []string{"/home", "/home/agent", "/home/agent/a"}, false,
			[]tar.Header{{Name: "home/agent/a/b/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}}},
		"none of two in the image": {"a/b/projects", nil, false, []tar.Header{
			{Name: "home/agent/a/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000},
			{Name: "home/agent/a/b/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}}},
		"nested Docker": {".claude/projects", nil, true,
			[]tar.Header{{Name: "home/agent/.claude/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}}},
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
			copied := slices.Index(rec.lines, "docker cp - qory-"+runID+"-agent:/")
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
				t.Fatalf("commands %q; want a docker cp into the agent's container after its docker create", rec.lines)
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
	if slices.ContainsFunc(rec.lines, func(l string) bool { return strings.HasPrefix(l, "docker cp - ") }) {
		t.Errorf("commands %q; want no docker cp into the agent's container", rec.lines)
	}
}

// untarred is a recorder whose docker cp out of a container exits 0 with out, which
// has no complete tar header.
type untarred struct {
	*recorder
	out []byte
}

func (u untarred) stdout(_ context.Context, argv, env []string) (io.ReadCloser, error) {
	if _, ok := statPath(words(argv)); !ok {
		return u.recorder.stdout(context.Background(), argv, env)
	}
	return io.NopCloser(bytes.NewReader(u.out)), nil
}

func (u untarred) run(ctx context.Context, argv, env []string) ([]byte, error) {
	if _, ok := statPath(words(argv)); !ok {
		return u.recorder.run(ctx, argv, env)
	}
	u.lines = append(u.lines, words(argv))
	return u.out, nil
}

// TestACheckOfTheImagesPathWithNoTarShowsTheTarError pins a docker cp out of the image
// that exits 0 with no tar header: an empty output and a header cut short. The check's
// error wraps the tar's error, and its text is complete.
func TestACheckOfTheImagesPathWithNoTarShowsTheTarError(t *testing.T) {
	for _, c := range []struct {
		name string
		out  []byte
		want error
	}{
		{"no output", nil, io.EOF},
		{"a header cut short", headTar(tar.Header{Name: "agent/", Typeflag: tar.TypeDir, Mode: 0o755})[:100], io.ErrUnexpectedEOF},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: untarred{rec, c.out}}
			enc, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			defer enc.Close(context.Background())
			h, err := enc.(*dockerEnclosure).imageHeader(context.Background(), "/home/agent")
			want := "wall docker: the check for \"/home/agent\" in the image: reading the tar of docker cp: " + c.want.Error()
			if h != nil || err == nil || err.Error() != want {
				t.Errorf("imageHeader: %v, %v; want %q", h, err, want)
			}
			if !errors.Is(err, c.want) {
				t.Errorf("the error %v does not match %v", err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "%!") {
				t.Errorf("the error %q has a formatting fault", err)
			}
		})
	}
}

// TestATranscriptPlaceTheAgentCannotUseIsUnbound pins the launches whose transcript
// directory the agent's container does not bind: CheckTranscript returns the fix and the
// cause, and Wrap of the same launch fails before the agent's container is made. A wall's
// user that is another uid or a name cannot write the directory, which is mode 0700 and
// the session's uid's. With nested Docker the agent runs as the wall's user under root's
// home, which mode 0700 keeps from it. A symbolic link on the way to the bind's place, and
// a file that is no directory, would have the engine bind elsewhere.
func TestATranscriptPlaceTheAgentCannotUseIsUnbound(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000::/home/agent:/bin/sh\n"
	root := tar.Header{Name: "root/", Typeflag: tar.TypeDir, Mode: 0o700}
	link := func(name string) tar.Header {
		return tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: "/work", Mode: 0o777}
	}
	dir := tar.Header{Typeflag: tar.TypeDir, Mode: 0o755}
	for name, c := range map[string]struct {
		user   string
		docker bool
		env    []string
		heads  map[string]tar.Header
		want   string
	}{
		"another uid":           {"2000:2000", false, []string{"HOME=/home/agent"}, nil, "the agent runs as \"2000:2000\", and the session's transcript directory is mode 0700 and owned by uid 1000"},
		"a name":                {"agent", false, []string{"HOME=/home/agent"}, nil, "the agent runs as \"agent\""},
		"nested under /root":    {"", true, nil, map[string]tar.Header{"/root": root}, "\"/root\" has mode 0700 and owner 0:0 in the image, so the agent, 1000:1000, cannot reach"},
		"a home that is a link": {"", false, []string{"HOME=/home/agent"}, map[string]tar.Header{"/home": dir, "/home/agent": link("agent")}, "\"/home/agent\" is a symbolic link in the image"},
		"a parent that is a link": {"", false, []string{"HOME=/home/agent"},
			map[string]tar.Header{"/home": dir, "/home/agent": dir, "/home/agent/.claude": link(".claude")}, "\"/home/agent/.claude\" is a symbolic link in the image"},
		"the place is a link": {"", false, []string{"HOME=/home/agent"},
			map[string]tar.Header{"/home": dir, "/home/agent": dir, "/home/agent/.claude": dir, "/home/agent/.claude/projects": link("projects")}, "\"/home/agent/.claude/projects\" is a symbolic link"},
		"a parent that is a file": {"", false, []string{"HOME=/home/agent"},
			map[string]tar.Header{"/home": dir, "/home/agent": dir, "/home/agent/.claude": {Name: ".claude", Typeflag: tar.TypeReg, Mode: 0o644}}, "\"/home/agent/.claude\" is no directory in the image"},
		"a parent of root's": {"", false, []string{"HOME=/home/agent"},
			map[string]tar.Header{"/home": dir, "/home/agent": {Typeflag: tar.TypeDir, Mode: 0o750, Gid: 50}}, "\"/home/agent\" has mode 0750 and owner 0:50"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, files: map[string]string{"/etc/passwd": passwd}, heads: c.heads}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, NestArgs: []string{"nest"}, User: c.user, sys: rec}
			req := Request{RunID: runID, Image: "example.com/agent:1"}
			if c.docker {
				req.Runtime, req.Docker = "sysbox-runc", true
			}
			e, err := d.Prepare(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			l := transcriptLaunch(c.env...)
			unbound, err := e.(TranscriptChecker).CheckTranscript(context.Background(), l.Env, l.Transcript)
			if err != nil || unbound == nil || !strings.Contains(unbound.Cause, c.want) || unbound.Fix == "" {
				t.Fatalf("CheckTranscript: %+v, %v; want a cause with %q", unbound, err, c.want)
			}
			if _, err := e.Wrap(context.Background(), l); err == nil || !strings.Contains(err.Error(), unbound.Fix) {
				t.Errorf("the wrap: %v; want the fix %q", err, unbound.Fix)
			}
			if agentCreate(rec) != "" {
				t.Errorf("the agent's container was created: %q", agentCreate(rec))
			}
		})
	}
}

// TestATranscriptPlaceTheAgentReachesIsBound pins the homes the agent's user reaches: by
// the owner's bit, the group's or the others', and with nested Docker a home the image
// sets. CheckTranscript returns nil, and Wrap, which reads nothing of the image again,
// binds the directory and makes ~/.claude owned by the agent's user and group.
func TestATranscriptPlaceTheAgentReachesIsBound(t *testing.T) {
	for name, c := range map[string]struct {
		docker bool
		home   tar.Header
	}{
		"the owner's bit":     {false, tar.Header{Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}},
		"the group's bit":     {false, tar.Header{Typeflag: tar.TypeDir, Mode: 0o710, Uid: 0, Gid: 1000}},
		"the others' bit":     {false, tar.Header{Typeflag: tar.TypeDir, Mode: 0o711}},
		"nested, the image's": {true, tar.Header{Typeflag: tar.TypeDir, Mode: 0o1777}},
		"nested, the owner's": {true, tar.Header{Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}},
	} {
		t.Run(name, func(t *testing.T) {
			heads := map[string]tar.Header{"/srv": {Typeflag: tar.TypeDir, Mode: 0o755}, "/srv/agent": c.home}
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, imageHome: "/srv/agent", heads: heads}
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
			l := transcriptLaunch()
			if unbound, err := e.(TranscriptChecker).CheckTranscript(context.Background(), l.Env, l.Transcript); unbound != nil || err != nil {
				t.Fatalf("CheckTranscript: %+v, %v; want nil", unbound, err)
			}
			checks := len(rec.lines)
			if _, err := e.Wrap(context.Background(), l); err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(rec.lines[checks:], func(l string) bool { _, ok := statPath(l); return ok }) {
				t.Errorf("commands after the check %q; want no second read of the image's paths", rec.lines[checks:])
			}
			if create := agentCreate(rec); !strings.Contains(create, "dst=/srv/agent/.claude/projects ") {
				t.Errorf("the agent's docker create %q; want the bind at /srv/agent/.claude/projects", create)
			}
			want := []tar.Header{{Name: "srv/agent/.claude/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000}}
			if got := copiedDirs(t, rec); !slices.EqualFunc(got, want, func(a, b tar.Header) bool {
				return a.Name == b.Name && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
			}) {
				t.Errorf("the tar has %+v; want %+v", got, want)
			}
		})
	}
}

// TestTheAgentsGroupComesFromTheWallsUserOrTheImage pins the group in the tar of the
// bind's parents: the wall's user's group by number, by name from the image's
// /etc/group, or, for a uid alone, the image's /etc/passwd's, else 0.
func TestTheAgentsGroupComesFromTheWallsUserOrTheImage(t *testing.T) {
	files := map[string]string{"/etc/passwd": "agent:x:1000:300::/home/agent:/bin/sh\n", "/etc/group": "dev:x:400:\n"}
	for user, want := range map[string]int{"1000:500": 500, "1000:dev": 400, "1000": 300, "1000:none": 0} {
		t.Run(user, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, files: files}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, User: user, sys: rec}
			e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			if _, err := e.Wrap(context.Background(), transcriptLaunch("HOME=/home/agent")); err != nil {
				t.Fatal(err)
			}
			if got := copiedDirs(t, rec); len(got) != 1 || got[0].Uid != 1000 || got[0].Gid != want {
				t.Errorf("the tar has %+v; want uid 1000 and gid %d", got, want)
			}
		})
	}
}

// TestAnAbsoluteTranscriptPlaceIsBoundThere pins a transcript directory whose place is
// absolute, an absolute resume.prefix: the wall binds it there, whatever HOME is, makes
// no directory between a home and the place, and checks each directory from / down to
// it in the image, with a fix that names the directory alone when one cannot be
// searched.
func TestAnAbsoluteTranscriptPlaceIsBoundThere(t *testing.T) {
	dir := tar.Header{Typeflag: tar.TypeDir, Mode: 0o755}
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, heads: map[string]tar.Header{"/var": dir, "/var/lib": dir}}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	l := transcriptLaunch("HOME=/home/agent")
	l.Transcript.Under = "/var/lib/agent-home/sessions"
	if unbound, err := e.(TranscriptChecker).CheckTranscript(context.Background(), l.Env, l.Transcript); unbound != nil || err != nil {
		t.Fatalf("CheckTranscript: %+v, %v; want nil", unbound, err)
	}
	if _, err := e.Wrap(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if create := agentCreate(rec); !strings.Contains(create, "--mount type=bind,src="+l.Transcript.Path+",dst=/var/lib/agent-home/sessions ") {
		t.Errorf("the agent's docker create %q; want the bind at /var/lib/agent-home/sessions", create)
	}
	if got := copiedDirs(t, rec); len(got) != 0 {
		t.Errorf("the tar has %+v; want no directory", got)
	}

	locked := tar.Header{Typeflag: tar.TypeDir, Mode: 0o700}
	rec = &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000"`, heads: map[string]tar.Header{"/var": dir, "/var/lib": locked}}
	d = &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
	e, err = d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	unbound, err := e.(TranscriptChecker).CheckTranscript(context.Background(), l.Env, l.Transcript)
	if err != nil || unbound == nil || unbound.Fix != `Let uid 1000 search "/var/lib" in the image` {
		t.Errorf("CheckTranscript: %+v, %v; want the fix that names /var/lib", unbound, err)
	}
}
