package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// The phrases accesskey prints in place of a value or a name that contains qak_ or
// qrk_ in any case.
const (
	akValue = "(a value that contains an access key secret)"
	rkValue = "(a value that contains a run key)"
	akName  = "(a name that contains an access key secret)"
	rkName  = "(a name that contains a run key)"
)

// leaks reports whether text contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_ or qeci_ in
// any case.
func leaks(text string) bool {
	l := strings.ToLower(text)
	return strings.Contains(l, "qak_") || strings.Contains(l, "qrk_") || strings.Contains(l, "qecr_") || strings.Contains(l, "qecn_") || strings.Contains(l, "qecp_") || strings.Contains(l, "qecg_") || strings.Contains(l, "qeci_")
}

// mkdir makes the directory of the names joined, and returns its path.
func mkdir(t *testing.T, names ...string) string {
	t.Helper()
	p := filepath.Join(names...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// filesWall is a wall with files, for checkMounts alone: it prepares nothing.
type filesWall struct {
	name  string
	files []string
}

func (w filesWall) Name() string { return w.name }

func (w filesWall) Prepare(context.Context, wall.Request) (wall.Enclosure, error) {
	return nil, errors.New("filesWall prepares nothing")
}

func (w filesWall) Files() []string { return w.files }

// TestAMountRefusalPrintsAPhraseForASecretInAPath pins the names and the Detail of the
// refusals of checkMounts: a path that contains qak_ or qrk_ is the name's phrase among
// the names, each phrase once, as run.refused's names are, and the value's phrase in
// Detail; a clean path prints as before.
func TestAMountRefusalPrintsAPhraseForASecretInAPath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	base := t.TempDir()
	ws, runs := mkdir(t, base, "workspace"), mkdir(t, base, "runs")
	refused := func(t *testing.T, spec runSpec) *Refusal {
		t.Helper()
		_, err := checkMounts(spec, filepath.Join(runs, "run"), filepath.Join(runs, "run", SessionsDir, "1"))
		var r *Refusal
		if !errors.As(err, &r) {
			t.Fatalf("want a refusal, got %v", err)
		}
		return r
	}
	for _, c := range []struct {
		name, mount, file string
		names             []string
		detail            string
	}{
		{
			name: "a secret in both paths", mount: mkdir(t, base, "qak_x"),
			file:  mkdir(t, base, "qak_x", ".config", "qory"),
			names: []string{akName}, detail: "the mount " + akValue + " contains " + akValue + ", one of Forager's files",
		},
		{
			name: "two secrets", mount: mkdir(t, base, "QRK_y", "qak_x"), file: filepath.Join(base, "QRK_y"),
			names: []string{akName, rkName}, detail: "the mount " + akValue + " lies inside " + rkValue + ", one of Forager's files",
		},
		{
			name: "clean paths", mount: mkdir(t, base, "clean"), file: mkdir(t, base, "clean", ".config", "qory"),
			names: []string{filepath.Join(base, "clean"), filepath.Join(base, "clean", ".config", "qory")},
			detail: "the mount " + filepath.Join(base, "clean") + " contains " +
				filepath.Join(base, "clean", ".config", "qory") + ", one of Forager's files",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := refused(t, runSpec{OpenSpec: OpenSpec{
				Wall:    filesWall{name: "open"},
				RunsDir: runs,
			},
				SessionSpec: SessionSpec{
					Dir:          ws,
					Mounts:       []wall.Mount{{Path: c.mount, ReadOnly: true}},
					ForagerFiles: []string{c.file},
				},
			})
			if !slices.Equal(r.Names, c.names) || r.Detail != c.detail {
				t.Errorf("names %q, detail %q; want %q, %q", r.Names, r.Detail, c.names, c.detail)
			}
		})
	}

	t.Run("a secret in the wall's name", func(t *testing.T) {
		mount := mkdir(t, base, "wallmount")
		file := mkdir(t, mount, "file")
		r := refused(t, runSpec{OpenSpec: OpenSpec{
			Wall:    filesWall{name: "qak_wall", files: []string{file}},
			RunsDir: runs,
		},
			SessionSpec: SessionSpec{
				Dir:    ws,
				Mounts: []wall.Mount{{Path: mount, ReadOnly: true}},
			},
		})
		want := "the mount " + mount + " contains " + file + ", one of the " + akName + " wall's files"
		if r.Detail != want {
			t.Errorf("detail %q, want %q", r.Detail, want)
		}
	})

	t.Run("a mode conflict", func(t *testing.T) {
		inner := mkdir(t, ws, "QRK_y")
		r := refused(t, runSpec{OpenSpec: OpenSpec{
			Wall:    filesWall{name: "open"},
			RunsDir: runs,
		},
			SessionSpec: SessionSpec{
				Dir:    ws,
				Mounts: []wall.Mount{{Path: inner, ReadOnly: true}},
			},
		})
		want := "the mount " + rkValue + " (read-only) lies inside the workspace " + ws +
			" (writable): a part of a writable place can't be read-only"
		if !slices.Equal(r.Names, []string{rkName, ws}) || r.Detail != want {
			t.Errorf("names %q, detail %q; want %q", r.Names, r.Detail, want)
		}
	})

	t.Run("a Forager file that is not absolute", func(t *testing.T) {
		for file, want := range map[string]string{
			"qak_x/rel": "the Forager file " + akValue + " is not an absolute path",
			"rel":       `the Forager file "rel" is not an absolute path`,
		} {
			_, err := checkMounts(runSpec{SessionSpec: SessionSpec{
				ForagerFiles: []string{file},
			},
			}, "", "")
			if err == nil || err.Error() != want {
				t.Errorf("%s: %v, want %q", file, err, want)
			}
		}
	})
}

// TestAWalledRunsCheckPrintsAPhraseForASecretInAPath pins the errors and refusals of
// the check of a walled run's binds against another run's: a path that contains qak_
// or qrk_ is the value's phrase in the sentence and the name's phrase among the names,
// and a clean path prints as before.
func TestAWalledRunsCheckPrintsAPhraseForASecretInAPath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const otherID = "0b6f1f9e-3c2a-4d5e-8f70-1a2b3c4d5e6f"
	still := " of the walled run " + otherID + ", which is still going: "
	at := func(t *testing.T, p string) splitPath {
		t.Helper()
		s, err := split(p, 0)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("a directory of Forager's inside another run's writable bind", func(t *testing.T) {
		dir := t.TempDir()
		for _, c := range []struct{ own, other, want string }{
			{filepath.Join(dir, "qak_x"), filepath.Join(dir, "QRK_y"),
				"Forager's directory " + akValue + " lies inside the writable bind " + rkValue + still +
					"a walled agent of that run can change it"},
			{filepath.Join(dir, "own"), filepath.Join(dir, "other"),
				"Forager's directory " + filepath.Join(dir, "own") + " lies inside the writable bind " +
					filepath.Join(dir, "other") + still + "a walled agent of that run can change it"},
		} {
			binds, err := bindSources([]wall.Bind{{Path: c.own}})
			if err != nil {
				t.Fatal(err)
			}
			other := bindSource{Path: c.other, Resolved: dir, Writable: true, at: at(t, dir)}
			if err := shared(binds[0], otherID, other); err == nil || err.Error() != c.want {
				t.Errorf("%v, want %q", err, c.want)
			}
		}
	})

	t.Run("a run directory that is another run's", func(t *testing.T) {
		base := t.TempDir()
		for _, c := range []struct {
			runs, otherPath string
			names           []string
			shown           string
		}{
			{filepath.Join(base, "QAK_runs"), "/elsewhere/qrk_y", []string{akName, otherID, rkName}, akValue},
			{filepath.Join(base, "runs"), "/elsewhere/other", nil, ""},
		} {
			runDir := filepath.Join(c.runs, "run")
			plan, err := checkMounts(runSpec{OpenSpec: OpenSpec{
				Wall:    filesWall{name: "open"},
				RunsDir: c.runs,
			},
				SessionSpec: SessionSpec{
					Dir: mkdir(t, base, "ws"),
				},
			}, runDir, filepath.Join(runDir, SessionsDir, "1"))
			if err != nil {
				t.Fatal(err)
			}
			run := plan.sources[len(plan.sources)-1]
			other := bindSource{Path: c.otherPath, Resolved: runDir, Kind: kindRun, at: at(t, runDir)}
			names, shown := c.names, c.shown
			if names == nil {
				names, shown = []string{c.runs, otherID, c.otherPath}, runDir
			}
			want := "the run directory " + shown + " (read-only) is the run directory " + shown + still +
				"a run directory is its session's alone"
			err = shared(run, otherID, other)
			var r *Refusal
			if !errors.As(err, &r) || !slices.Equal(r.Names, names) || r.Detail != want {
				t.Errorf("%v: names %q, want %q and %q", err, r.Names, names, want)
			}
		}
	})

	t.Run("an engine that cannot be reached", func(t *testing.T) {
		for _, c := range []struct {
			dir   string
			names []string
		}{
			{"/state/qak_x", []string{otherID, akName}},
			{"/state/clean", []string{otherID, "/state/clean/" + otherID}},
		} {
			file := c.dir + "/" + otherID
			r := engineUnreachable(otherID, file, startsNot, fmt.Errorf("open %s: denied", file))
			want := "The check for a container of the walled run " + otherID +
				" failed, so this run does not start: open " + file + ": denied"
			if leaks(c.dir) {
				want = "The check for a container of the walled run " + otherID +
					" failed, so this run does not start: " + akValue
			}
			if !slices.Equal(r.Names, c.names) || r.Detail != want {
				t.Errorf("names %q, detail %q; want %q, %q", r.Names, r.Detail, c.names, want)
			}
		}
	})

	t.Run("a registry that cannot be made", func(t *testing.T) {
		for _, state := range []string{filepath.Join(t.TempDir(), "QAK_x"), filepath.Join(t.TempDir(), "clean")} {
			t.Setenv("XDG_STATE_HOME", state)
			if err := os.MkdirAll(state, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, "qory-forager"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := openRegistry()
			if err == nil || !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("%s: %v, want an error that wraps ENOTDIR", state, err)
			}
			if leaks(state) == strings.Contains(err.Error(), state) || leaks(err.Error()) {
				t.Errorf("%s: %q", state, err)
			}
		}
	})

	t.Run("a path that is not absolute", func(t *testing.T) {
		for p, want := range map[string]string{
			"qak_x/rel": "the path " + akValue + " is not absolute",
			"rel":       `the path "rel" is not absolute`,
		} {
			if _, err := RunsBinding(context.Background(), nil, p); err == nil || err.Error() != want {
				t.Errorf("%s: %v, want %q", p, err, want)
			}
		}
	})

	t.Run("a plan that changed", func(t *testing.T) {
		for dir, want := range map[string]string{
			"/a/qak_x": "the working directory inside was " + akValue + " when the run started and is /b now",
			"/a/clean": "the working directory inside was /a/clean when the run started and is /b now",
		} {
			if err := samePlan(mountPlan{Dir: dir}, mountPlan{Dir: "/b"}); err == nil || err.Error() != want {
				t.Errorf("%s: %v, want %q", dir, err, want)
			}
		}
	})
}

// TestAFileReadPrintsAPhraseForASecretInAPlace pins the refusal of a file a walled run
// could have written: a place that contains qak_ or qrk_ is the phrase, and a clean
// place prints as before.
func TestAFileReadPrintsAPhraseForASecretInAPlace(t *testing.T) {
	base := t.TempDir()
	for place, want := range map[string]string{
		mkdir(t, base, "QRK_y"): "it lies in " + rkValue + ", which a walled run can write",
		mkdir(t, base, "clean"): "it lies in " + filepath.Join(base, "clean") + ", which a walled run can write",
	} {
		read := readable(func() ([]string, error) { return []string{place}, nil })
		if _, err := read(filepath.Join(place, "file")); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", place, err, want)
		}
	}
}

// TestAVariablesCheckPrintsAPhraseForASecret pins the errors of checkVariables and
// checkHarnessHome: a name or a value that contains qak_ or qrk_ is the phrase, and a
// clean one prints as before.
func TestAVariablesCheckPrintsAPhraseForASecret(t *testing.T) {
	for _, c := range []struct {
		v    Variables
		want string
	}{
		{Variables{Run: []string{"qak_x"}}, "the run's variable " + akName + " has no value: each is NAME=value"},
		{Variables{Run: []string{"FOO"}}, "the run's variable FOO has no value: each is NAME=value"},
		{Variables{Machine: []string{"QRK_y=a\nb"}}, "the machine's variable " + rkName +
			" holds a NUL, a carriage return or a line feed, which a variable's value does not"},
		{Variables{Machine: []string{"FOO=a\nb"}}, "the machine's variable FOO" +
			" holds a NUL, a carriage return or a line feed, which a variable's value does not"},
		{Variables{Unwalled: "qak_x"}, "variables.unwalled is " + akValue + ", neither accept nor ignore"},
		{Variables{Unwalled: "maybe"}, `variables.unwalled is "maybe", neither accept nor ignore`},
	} {
		if err := checkVariables(c.v); err == nil || err.Error() != c.want {
			t.Errorf("%+v: %v, want %q", c.v, err, c.want)
		}
	}
	for home, want := range map[string]string{
		"qrk_y/home": "the harness home " + rkValue + " is not an absolute path",
		"home":       `the harness home "home" is not an absolute path`,
	} {
		if err := checkHarnessHome(home); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", home, err, want)
		}
	}
}

// TestAnImageCheckPrintsAPhraseForASecretInItsName pins the errors of an image's
// definition: a name that contains qak_ or qrk_ is the phrase, and a clean one prints
// as before.
func TestAnImageCheckPrintsAPhraseForASecretInItsName(t *testing.T) {
	for _, c := range []struct {
		image Image
		want  string
	}{
		{Image{Name: "QAK_x"}, "the image name " + akName + " is not 1 to 64 of a-z, 0-9, underscore, dot and dash"},
		{Image{Name: "Bad"}, `the image name "Bad" is not 1 to 64 of a-z, 0-9, underscore, dot and dash`},
		{Image{Name: "qak_x"}, "image " + akName + ": the reference is empty"},
		{Image{Name: "agent"}, "image agent: the reference is empty"},
		{Image{Name: "qrk_y", Ref: "r", Docker: true}, "image " + rkName +
			": nested Docker needs a runtime that runs it without privileges, such as sysbox-runc"},
	} {
		if err := c.image.Check(); err == nil || err.Error() != c.want {
			t.Errorf("%+v: %v, want %q", c.image, err, c.want)
		}
	}
	for name, want := range map[string]string{"qak_x": "the image " + akName + " is defined twice", "agent": "the image agent is defined twice"} {
		twice := []Image{{Name: name, Ref: "r"}, {Name: name, Ref: "r"}}
		if err := checkImages(OpenSpec{Images: twice}); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
}

// TestExecPrintsAPhraseForASecretInItsProgram pins what the helper's exec writes to
// stderr for a program it does not run: a program that contains qak_ or qrk_ is the
// phrase, the error included, and a clean one prints as before.
func TestExecPrintsAPhraseForASecretInItsProgram(t *testing.T) {
	dir := mkdir(t, t.TempDir(), "qak_x")
	for _, c := range []struct {
		program string
		code    int
		want    string
	}{
		{"qrk_y-no-such-program", 127, "exec: " + rkValue + ": not found\n"},
		{"no-such-program-of-forager", 127, "exec: no-such-program-of-forager: not found\n"},
		{dir, 126, "exec: " + akValue + ": cannot be executed: " + akValue + "\n"},
	} {
		var stderr bytes.Buffer
		if code := Exec([]string{"--", c.program}, &stderr); code != c.code || stderr.String() != c.want {
			t.Errorf("%s: %d, %q; want %d, %q", c.program, code, stderr.String(), c.code, c.want)
		}
	}
}

// TestALocalGatewayPrintsAPhraseForASecretInItsSocket pins how fmt prints a local
// gateway: a socket that contains qak_ or qrk_ is the phrase, and a clean one prints
// as before.
func TestALocalGatewayPrintsAPhraseForASecretInItsSocket(t *testing.T) {
	for socket, want := range map[string]string{
		"/tmp/qak_x/sock": "session.Gateway{" + akValue + "}",
		"/tmp/clean/sock": "session.Gateway{/tmp/clean/sock}",
	} {
		g := LocalGateway(link.Local{Socket: socket})
		if got := fmt.Sprintf("%v %s %#v", g, g, g); got != want+" "+want+" "+want {
			t.Errorf("%s: %q, want %q three times", socket, got, want)
		}
	}
}

// TestARefusalThroughALinkListsANamePhraseForASecret pins the names of the refusals of a
// link inside a writable place: a path that contains qak_ or qrk_ is the name's phrase
// among the names, as run.refused's names are, and the value's phrase in Detail.
func TestARefusalThroughALinkListsANamePhraseForASecret(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	base := t.TempDir()
	ws, runs, outside := mkdir(t, base, "workspace"), mkdir(t, base, "runs"), mkdir(t, base, "outside")
	refused := func(t *testing.T, spec runSpec) *Refusal {
		t.Helper()
		_, err := checkMounts(spec, filepath.Join(runs, "run"), filepath.Join(runs, "run", SessionsDir, "1"))
		var r *Refusal
		if !errors.As(err, &r) {
			t.Fatalf("want a refusal, got %v", err)
		}
		return r
	}

	t.Run("a link on the way to a Forager file", func(t *testing.T) {
		link := filepath.Join(ws, "qak_FAKE")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(link)
		r := refused(t, runSpec{OpenSpec: OpenSpec{
			Wall:    filesWall{name: "open"},
			RunsDir: runs,
		},
			SessionSpec: SessionSpec{
				Dir:          ws,
				ForagerFiles: []string{filepath.Join(link, "file")},
			},
		})
		if want := []string{ws, akName}; r.Code != "mount_contains_forager_files" || !slices.Equal(r.Names, want) {
			t.Errorf("%s names %q, want %q", r.Code, r.Names, want)
		}
		if leaks(r.Detail) || !strings.Contains(r.Detail, akValue) {
			t.Errorf("detail %q", r.Detail)
		}
	})

	t.Run("a mount reached through a link", func(t *testing.T) {
		link := filepath.Join(ws, "QRK_FAKE")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(link)
		r := refused(t, runSpec{OpenSpec: OpenSpec{
			Wall:    filesWall{name: "open"},
			RunsDir: runs,
		},
			SessionSpec: SessionSpec{
				Dir:    ws,
				Mounts: []wall.Mount{{Path: link, ReadOnly: true}},
			},
		})
		if want := []string{rkName, ws}; r.Code != "mount_through_link" || !slices.Equal(r.Names, want) {
			t.Errorf("%s names %q, want %q", r.Code, r.Names, want)
		}
		if leaks(r.Detail) || !strings.Contains(r.Detail, rkValue) {
			t.Errorf("detail %q", r.Detail)
		}
	})
}

// phrased fails the test unless err is an error whose text has no qak_ or qrk_ in any
// case and that wraps target.
func phrased(t *testing.T, what string, err, target error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error", what)
	}
	if leaks(err.Error()) || !errors.Is(err, target) {
		t.Errorf("%s: %q, want a phrase that wraps %v", what, err, target)
	}
}

// TestAResendOfARecordThatIsAGatewaysPrintsAPhraseForASecret pins the error of a resend
// of a directory that holds the run's stream: a directory that contains qak_ or qrk_ is
// the phrase, and the error still wraps fs.ErrExist.
func TestAResendOfARecordThatIsAGatewaysPrintsAPhraseForASecret(t *testing.T) {
	for _, secret := range []string{"qak_FAKE", "QRK_FAKE"} {
		dir := mkdir(t, t.TempDir(), secret, "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f")
		if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Resend(context.Background(), ResendSpec{Dir: dir})
		phrased(t, secret, err, fs.ErrExist)
	}
}

// bindsFail is an enclosure whose Binds fails with the error err.
type bindsFail struct {
	wall.Enclosure
	err error
}

func (b bindsFail) Binds(wall.Launch) ([]wall.Bind, error) { return nil, b.err }

// TestTheSessionsFileErrorsPrintAPhraseForASecretInAPath pins the errors of the run
// directory's files, the lock, the setup's script, the socket, the registry's walk and a
// wall's binds: a path that contains qak_ or qrk_ is the phrase, and each error still
// wraps the error of the file system.
func TestTheSessionsFileErrorsPrintAPhraseForASecretInAPath(t *testing.T) {
	const runID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	for _, secret := range []string{"qak_FAKE", "QRK_FAKE"} {
		base := mkdir(t, t.TempDir(), secret)
		missing := filepath.Join(base, "missing", runID)
		file := filepath.Join(base, "file")
		if err := os.WriteFile(file, nil, 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := Resend(context.Background(), ResendSpec{Dir: missing})
		phrased(t, "a resend of a directory that does not exist", err, fs.ErrNotExist)
		_, err = lock(missing)
		phrased(t, "the lock", err, fs.ErrNotExist)
		phrased(t, "the mark", markBehindGateway(missing), fs.ErrNotExist)
		_, err = BehindGateway(filepath.Join(file, "run"))
		phrased(t, "the mark's read", err, syscall.ENOTDIR)
		_, err = sessionRecord(filepath.Join(missing, "session.jsonl"))
		phrased(t, "the record", err, fs.ErrNotExist)
		_, err = withSetup(missing, []string{"runner"}, []SetupCommand{{Name: "install", Args: []string{"true"}}}, runtimes.Launch{Command: "agent"})
		phrased(t, "the setup's script", err, fs.ErrNotExist)
		_, err = RunsBinding(context.Background(), nil, filepath.Join(file, "child"))
		phrased(t, "the registry's walk", err, syscall.ENOTDIR)
		_, err = wallBinds(bindsFail{err: &fs.PathError{Op: "open", Path: filepath.Join(base, "bind"), Err: fs.ErrPermission}}, "", nil)
		phrased(t, "a wall's binds", err, fs.ErrPermission)

		t.Run(secret+" socket", func(t *testing.T) {
			t.Setenv("TMPDIR", filepath.Join(base, "missing"))
			_, err := socket.Listen(0)
			phrased(t, "the socket", err, fs.ErrNotExist)
		})

		// A record whose delivered.log cannot be read.
		dir := mkdir(t, base, "runs", runID)
		if err := os.WriteFile(filepath.Join(dir, "session.jsonl"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		mkdir(t, dir, "delivered.log")
		_, err = Resend(context.Background(), ResendSpec{Dir: dir})
		phrased(t, "a delivered.log that is a directory", err, syscall.EISDIR)
	}
}
