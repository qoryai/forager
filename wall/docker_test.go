package wall

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/runner/accesskey"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// recorder is a machine with no Docker: it records every command and answers the two
// the adapter reads.
type recorder struct {
	// containers is what the engine lists of a run's containers, engineID its id and
	// context the context the command shows; env are the variables it was asked with.
	containers string
	engineID   string
	context    string
	env        []string
	// envs are the selections the adapter's commands ran with, one per command.
	envs     [][]string
	relayEnv string
	t        *testing.T
	gateway  string
	local_   bool
	uid      int
	lines    []string
	fail     string
}

func (r *recorder) run(_ context.Context, argv, env []string) ([]byte, error) {
	r.envs = append(r.envs, env)
	argv = append([]string{}, argv...)
	for i, a := range argv {
		// The relay's environment file is in a directory of the test's; its content is
		// what matters, and it is kept for the test to read.
		if a == "--env-file" {
			if b, err := os.ReadFile(argv[i+1]); err == nil {
				r.relayEnv = string(b)
			}
			argv[i+1] = "RELAYENVFILE"
		}
	}
	line := words(argv)
	r.lines = append(r.lines, line)
	switch {
	case r.fails(line):
		return []byte("Error response from daemon: told to fail"), errors.New("exit status 1")
	case strings.Contains(line, "network inspect"):
		return []byte(r.gateway + " \n"), nil
	case strings.Contains(line, " inspect --format {{.State"):
		return []byte("true\n"), nil
	case strings.Contains(line, " logs "):
		return []byte(RelayReady + "\n"), nil
	}
	return nil, nil
}
func (r *recorder) output(_ context.Context, argv, env []string) ([]byte, error) {
	r.lines, r.envs = append(r.lines, words(argv)), append(r.envs, env)
	return nil, errors.New("no such file")
}

// fails reports whether the recorder fails the command: fail holds substrings of the
// commands that fail, separated by "|".
func (r *recorder) fails(line string) bool {
	if r.fail == "" {
		return false
	}
	return slices.ContainsFunc(strings.Split(r.fail, "|"), func(f string) bool {
		return strings.Contains(line, f)
	})
}

func (r *recorder) engine(_ context.Context, argv, env []string) ([]byte, error) {
	line := words(argv)
	r.lines, r.env = append(r.lines, line), env
	switch {
	case r.fails(line):
		return nil, errors.New("exit status 1: Cannot connect to the Docker daemon")
	case strings.Contains(line, " info "):
		return []byte(r.engineID + "\n"), nil
	case strings.Contains(line, " context show"):
		return []byte(r.context + "\n"), nil
	}
	return []byte(r.containers), nil
}
func (r *recorder) local(string) bool        { return r.local_ }
func (r *recorder) tempDir() (string, error) { return r.t.TempDir(), nil }
func (r *recorder) ids() (int, int)          { return r.uid, 1000 }
func (r *recorder) checkHelper(string) error { return nil }
func (r *recorder) socket(p string) bool     { return strings.HasSuffix(p, ".sock") }

const runID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"

func launch() Launch {
	return Launch{
		Command: "claude", Args: []string{"--settings", "/work/.qory/runs/" + runID + "/settings.json", "-p", "say hi"},
		Env: []string{"ANTHROPIC_API_KEY=not-a-real-key", "QORY_RUN_ID=" + runID}, Dir: "/work",
		Proxy: "127.0.0.1:50123", ProxyToken: "not-a-real-token", Socket: "/tmp/qory-run-1/sock", Mounts: []Mount{{Path: "/work"}, {Path: "/home/dev/.qory/homes/work", ReadOnly: true}, {Path: "/work/.qory/runs/" + runID, ReadOnly: true}},
	}
}

// words writes a command the way a shell would read it back.
func words(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if out[i] = a; strings.ContainsAny(a, " {") {
			out[i] = "'" + a + "'"
		}
	}
	return strings.Join(out, " ")
}

// golden compares got with the file, or rewrites the file under -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	file := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs; run go test ./wall -update and read the diff\ngot:\n%s\nwant:\n%s", file, got, want)
	}
}

// TestDockerCommandLines pins every command the adapter runs, in order, from Prepare to
// Close, the command it hands back and the environment file, on the two kinds of
// machine: a Linux host that holds the network's gateway address, where the proxy binds
// it, and an engine in a virtual machine, where the proxy stays on loopback and the
// relay reaches it by name.
func TestDockerCommandLines(t *testing.T) {
	for _, c := range []struct {
		name        string
		local       bool
		interactive bool
		proxyAddr   string
	}{
		{"linux-host", true, false, "172.30.0.1:0"},
		{"engine-in-vm", false, true, "127.0.0.1:0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", local_: c.local, uid: 1000}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, sys: rec}
			e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			if e.ProxyAddr() != c.proxyAddr {
				t.Errorf("the proxy is told to listen on %s, want %s", e.ProxyAddr(), c.proxyAddr)
			}
			l := launch()
			l.Interactive = c.interactive
			if c.local {
				l.Proxy = "172.30.0.1:50123"
			}
			wrapped, err := e.Wrap(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			// The docker command gets the runner's environment without the access key's
			// variables; no engine is recorded here, so no selection replaces any.
			if !slices.Equal(wrapped.Env, accesskey.WithoutVariables(os.Environ())) {
				t.Errorf("the docker command gets an environment of %d variables of its own",
					len(wrapped.Env))
			}
			envFile := ""
			for i, a := range wrapped.Args {
				if a == "--env-file" {
					envFile = wrapped.Args[i+1]
					wrapped.Args[i+1] = "ENVFILE"
				}
			}
			env, err := os.ReadFile(envFile)
			if err != nil {
				t.Fatal(err)
			}
			if info, _ := os.Stat(envFile); info.Mode().Perm() != 0o600 {
				t.Errorf("the environment file's mode is %v", info.Mode().Perm())
			}
			if err := e.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(envFile); err == nil {
				t.Error("Close left the environment file")
			}
			got := strings.Join(rec.lines, "\n") + "\n\nwrapped:\n" + words(append([]string{wrapped.Command}, wrapped.Args...)) + "\n\nenvironment:\n" + string(env)
			if rec.relayEnv != RelayTokenEnv+"=not-a-real-token\n" || strings.Contains(got, "not-a-real-token") {
				t.Errorf("the proxy's token belongs in the relay's environment file and nowhere else; the file holds %q", rec.relayEnv)
			}
			if strings.Contains(strings.Join(rec.lines, "\n")+strings.Join(wrapped.Args, " "), "not-a-real-key") {
				t.Error("a value of the environment is on a command line")
			}
			golden(t, c.name, got)
		})
	}
}

// TestDockerRefuses pins what stops a wall before anything is created.
func TestDockerRefuses(t *testing.T) {
	ok := func() *Docker {
		return &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: &recorder{t: t, uid: 1000}}
	}
	req := Request{RunID: runID, Image: "i"}
	for name, c := range map[string]struct {
		d   *Docker
		req Request
	}{
		"no image":             {ok(), Request{RunID: runID}},
		"no helper":            {&Docker{RelayArgs: []string{"relay"}, sys: &recorder{t: t, uid: 1000}}, req},
		"root":                 {&Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: &recorder{t: t, uid: 0}}, req},
		"root by name":         {&Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: "root", sys: &recorder{t: t, uid: 1000}}, req},
		"not an ELF":           {&Docker{Helper: "docker_test.go", RelayArgs: []string{"relay"}}, req},
		"missing file":         {&Docker{Helper: "testdata/none", RelayArgs: []string{"relay"}}, req},
		"no relay args":        {&Docker{Helper: "/h", sys: &recorder{t: t, uid: 1000}}, req},
		"root as 00":           {&Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: "00:0", sys: &recorder{t: t, uid: 1000}}, req},
		"a flag as the user":   {&Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: "--privileged", sys: &recorder{t: t, uid: 1000}}, req},
		"a flag as the image":  {ok(), Request{RunID: runID, Image: "--privileged"}},
		"a flag as the run id": {ok(), Request{RunID: "-x", Image: "i"}},
	} {
		if _, err := c.d.Prepare(context.Background(), c.req); err == nil {
			t.Errorf("%s: a wall was prepared", name)
		} else if rec, ok := c.d.sys.(*recorder); ok && len(rec.lines) > 0 {
			t.Errorf("%s: commands ran before the refusal: %v", name, rec.lines)
		}
	}
}

// TestDockerRemovesWhatItMadeWhenAStepFails pins that a failure half way leaves
// nothing: Prepare cleans up after itself, and Close after a failed Wrap.
func TestDockerRemovesWhatItMadeWhenAStepFails(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, fail: "network inspect"}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "i"}); err == nil {
		t.Fatal("Prepare succeeded")
	}
	if got := strings.Join(rec.lines, "\n"); !strings.Contains(got, "network rm qory-"+runID+"-out") || !strings.Contains(got, "network rm qory-"+runID+"-in") {
		t.Errorf("the networks were left:\n%s", got)
	}

	rec = &recorder{t: t, gateway: "172.30.0.1", uid: 1000, fail: "start"}
	d = &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "i"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Wrap(context.Background(), launch()); err == nil {
		t.Fatal("Wrap succeeded")
	}
	e.Close(context.Background())
	if got := strings.Join(rec.lines, "\n"); !strings.Contains(got, "rm --force --volumes qory-"+runID+"-relay") {
		t.Errorf("the relay was left:\n%s", got)
	}
}

// TestDockerRefusesAPathItCannotMount pins that a comma in a path is an error, not a
// mount of something else.
func TestDockerRefusesAPathItCannotMount(t *testing.T) {
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: &recorder{t: t, gateway: "172.30.0.1", uid: 1000}}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "i"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	l := launch()
	l.Dir = "/work,dst=/etc"
	l.Mounts = append(l.Mounts, Mount{Path: l.Dir})
	if _, err := e.Wrap(context.Background(), l); err == nil {
		t.Error("a workspace with a comma was mounted")
	}
	for _, env := range []string{"A=one\nB=two", "AWS_SECRET_ACCESS_KEY", "#A=1", " A=1", "=1"} {
		l = launch()
		l.Env = []string{env}
		if _, err := e.Wrap(context.Background(), l); err == nil {
			t.Errorf("%q was written to the environment file", env)
		}
	}
}

// TestDockerLimitsTheAgentAndRefusesASocket pins that the run's limits reach the
// agent's command line and not the relay's, that a limit in no known shape is refused,
// and that a socket is never mounted.
func TestDockerLimitsTheAgentAndRefusesASocket(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "i"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	l := launch()
	l.Limits = Limits{CPUs: "1.5", Memory: "8g", PIDs: 4096, ShmSize: "2g"}
	got, err := e.Wrap(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if line := words(got.Args); !strings.Contains(line, "--cpus 1.5 --memory 8g --shm-size 2g --pids-limit 4096") {
		t.Errorf("the agent's command carries no limits: %s", line)
	}
	for _, line := range rec.lines {
		if strings.Contains(line, "--cpus") {
			t.Errorf("a limit on a command of the wall's own: %s", line)
		}
	}
	for name, lim := range map[string]Limits{
		"a flag as cpus":   {CPUs: "--privileged"},
		"a unit of t":      {Memory: "1t"},
		"a flag as shm":    {ShmSize: "-1"},
		"a negative count": {PIDs: -1},
	} {
		l = launch()
		l.Limits = lim
		if _, err := e.Wrap(context.Background(), l); err == nil {
			t.Errorf("%s: the limit was accepted", name)
		}
	}
	l = launch()
	l.Mounts = append(l.Mounts, Mount{Path: "/var/run/docker.sock"})
	if _, err := e.Wrap(context.Background(), l); err == nil {
		t.Error("the engine's socket was mounted")
	}
}

// TestDockerReapsWhatARunLeft pins that a reap asks by the run's label and removes the
// containers before the networks.
func TestDockerReapsWhatARunLeft(t *testing.T) {
	rec := &recorder{t: t, uid: 1000}
	d := &Docker{sys: rec}
	if _, err := d.Reap(context.Background(), "-x"); err == nil {
		t.Error("a flag was taken as a run id")
	}
	if _, err := d.Reap(context.Background(), runID); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rec.lines, "\n")
	ps, ls := strings.Index(got, "ps --all --quiet --filter label=dev.qory.run="+runID), strings.Index(got, "network ls --quiet --filter label=dev.qory.run="+runID)
	if ps < 0 || ls < ps {
		t.Errorf("the reap asked:\n%s", got)
	}
}

// TestDockerNestedCommandLine pins the agent's command for an image with a Docker of
// its own: under the named runtime, started as the enclosure's root with the helper as
// its entry point, which starts the daemon and then the launch as the run's user. The
// relay is the same as for any image.
func TestDockerNestedCommandLine(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", local_: true, uid: 1000}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, NestArgs: []string{"run", "nest"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true})
	if err != nil {
		t.Fatal(err)
	}
	l := launch()
	l.Proxy = "172.30.0.1:50123"
	wrapped, err := e.Wrap(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range wrapped.Args {
		if a == "--env-file" {
			wrapped.Args[i+1] = "ENVFILE"
		}
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	run := words(append([]string{wrapped.Command}, wrapped.Args...))
	for _, want := range []string{
		"--runtime sysbox-runc --user 0:0 --security-opt no-new-privileges --init --mount type=volume,dst=/var/lib/docker",
		"--entrypoint /qory/qory example.com/agent:1-docker run nest --user 1000:1000 -- claude --settings",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("the agent's command lacks %q:\n%s", want, run)
		}
	}
	if strings.Contains(run, "--cap-drop") || strings.Contains(run, "--privileged") {
		t.Errorf("the agent's command drops the capabilities the daemon needs, or asks for privileges:\n%s", run)
	}
	for _, line := range rec.lines {
		if strings.Contains(line, "create --name") && (!strings.Contains(line, "--user 1000:1000 --cap-drop ALL --security-opt no-new-privileges --init") || strings.Contains(line, "--runtime")) {
			t.Errorf("the relay is not hardened as for any image, or runs under the image's runtime:\n%s", line)
		}
	}
	golden(t, "nested", strings.Join(rec.lines, "\n")+"\n\nwrapped:\n"+run+"\n")
}

// TestDockerRefusesANestWithoutItsRuntime pins that a Docker of the agent's own is
// refused before anything is created without a runtime that nests without privileges,
// without the helper's arguments that start it, and with a runtime named as a flag.
func TestDockerRefusesANestWithoutItsRuntime(t *testing.T) {
	for name, c := range map[string]struct {
		nest []string
		req  Request
	}{
		"no runtime":          {[]string{"nest"}, Request{RunID: runID, Image: "i", Docker: true}},
		"no nest args":        {nil, Request{RunID: runID, Image: "i", Runtime: "sysbox-runc", Docker: true}},
		"a flag as a runtime": {[]string{"nest"}, Request{RunID: runID, Image: "i", Runtime: "--privileged"}},
	} {
		rec := &recorder{t: t, uid: 1000}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, NestArgs: c.nest, sys: rec}
		if _, err := d.Prepare(context.Background(), c.req); err == nil {
			t.Errorf("%s: a wall was prepared", name)
		} else if len(rec.lines) > 0 {
			t.Errorf("%s: commands ran before the refusal: %v", name, rec.lines)
		}
	}
}

// TestTheDockerCLIReceivesNoAccessKeyVariable pins that a command the wall runs on the
// machine, the docker CLI and the credential helpers it starts, has the runner's
// environment without the access key's variables.
func TestTheDockerCLIReceivesNoAccessKeyVariable(t *testing.T) {
	t.Setenv("QORY_ACCESS_KEY_SECRET", "qak_not-a-real-one")
	t.Setenv("QORY_ACCESS_KEY_ID", "ak_f1xt0re000000000")
	t.Setenv("QORY_APIARY_PUBLIC_KEY", "[]")
	t.Setenv("DOCKER_SEES", "yes")
	out, err := hostSystem{}.output(context.Background(), []string{"env"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "QORY_ACCESS_KEY_") || strings.Contains(string(out), "QORY_APIARY_") || !strings.Contains(string(out), "DOCKER_SEES=yes") {
		t.Errorf("the command's environment:\n%s", out)
	}
	// With the engine's selection, the same, the runner's DOCKER_CONTEXT replaced.
	t.Setenv("DOCKER_CONTEXT", "the-runners")
	out, err = hostSystem{}.output(context.Background(), []string{"env"},
		[]string{"DOCKER_CONTEXT=pinned"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "QORY_ACCESS_KEY_") ||
		strings.Contains(string(out), "the-runners") ||
		!strings.Contains(string(out), "DOCKER_CONTEXT=pinned") ||
		!strings.Contains(string(out), "DOCKER_SEES=yes") {
		t.Errorf("the command's environment with a selection:\n%s", out)
	}
}

// TestDockerFilesAreItsProgramsAndConfiguration pins the adapter's own files: the
// directory of the docker command as PATH finds it and of the file a link to it leads
// to, the helper's directory, and the command's configuration directory, DOCKER_CONFIG
// or else ~/.docker.
func TestDockerFilesAreItsProgramsAndConfiguration(t *testing.T) {
	bin, libexec, helpers, conf, home := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(libexec, "docker"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(libexec, "docker"), filepath.Join(bin, "docker")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("HOME", home)
	t.Setenv("DOCKER_CONFIG", conf)
	d := &Docker{Helper: filepath.Join(helpers, "qory"), RelayArgs: []string{"relay"}}
	files := d.Files()
	resolved, err := filepath.EvalSymlinks(libexec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{bin, resolved, helpers, conf} {
		if !slices.Contains(files, want) {
			t.Errorf("files %q lack %s", files, want)
		}
	}
	t.Setenv("DOCKER_CONFIG", "")
	if files := d.Files(); !slices.Contains(files, filepath.Join(home, ".docker")) || slices.Contains(files, conf) {
		t.Errorf("without DOCKER_CONFIG, files %q", files)
	}
	var _ Filer = d
}

// TestTempDirsMatchesWhatTheAdapterMakes pins that the pattern of the adapter's private
// directories matches the one it makes.
func TestTempDirsMatchesWhatTheAdapterMakes(t *testing.T) {
	dir, err := hostSystem{}.tempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if ok, _ := filepath.Match(TempDirs(), dir); !ok {
		t.Errorf("%s does not match %s", dir, TempDirs())
	}
}

// TestDockerBindsTheWorkspaceThroughItsMount pins one bind for a checkout: a workspace
// below a mount is the working directory inside and gets no bind of its own, by whole
// components of the paths; a launch whose workspace no mount holds is refused, since
// the adapter binds nothing the launch does not list.
func TestDockerBindsTheWorkspaceThroughItsMount(t *testing.T) {
	for _, c := range []struct {
		name, dir string
		mounts    []Mount
		binds     []string
	}{
		{"below the mount", "/work/src/app", []Mount{{Path: "/work"}},
			[]string{"type=bind,src=/work,dst=/work"}},
		{"the mount itself", "/work", []Mount{{Path: "/work/"}},
			[]string{"type=bind,src=/work/,dst=/work/"}},
		{"beside the mount", "/workshop", []Mount{{Path: "/work", ReadOnly: true}}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
			req := Request{RunID: runID, Image: "example.com/agent:1"}
			e, err := d.Prepare(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			l := launch()
			l.Dir, l.Mounts, l.Socket = c.dir, c.mounts, ""
			wrapped, err := e.Wrap(context.Background(), l)
			if c.binds == nil {
				want := "lies in none of the launch's mounts"
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("a workspace no mount holds: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var binds []string
			workdir := ""
			for i, a := range wrapped.Args {
				switch {
				case a == "--workdir":
					workdir = wrapped.Args[i+1]
				case a == "--mount" && strings.HasPrefix(wrapped.Args[i+1], "type=bind,src=/work"):
					binds = append(binds, wrapped.Args[i+1])
				}
			}
			if !slices.Equal(binds, c.binds) || workdir != c.dir || wrapped.Dir != c.dir {
				t.Errorf("binds %q, working directory %q, dir %q", binds, workdir, wrapped.Dir)
			}
		})
	}
}

// TestDockerListsItsOwnBinds pins the adapter's own binds: the helper, read-only, the
// hook socket's directory, writable, and the private directory it writes the run's
// files in, read-only, the one Wrap then writes them in.
func TestDockerListsItsOwnBinds(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
	req := Request{RunID: runID, Image: "example.com/agent:1"}
	e, err := d.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	l := launch()
	l.CA = []byte("-----BEGIN CERTIFICATE-----\n")
	binds, err := e.(Binder).Binds(l)
	if err != nil {
		t.Fatal(err)
	}
	temp := e.(*dockerEnclosure).temp
	want := []Bind{
		{Path: "/opt/qory/qory-linux", ReadOnly: true, Helper: true},
		{Path: "/tmp/qory-run-1"},
		{Path: temp, ReadOnly: true},
	}
	if temp == "" || !slices.Equal(binds, want) {
		t.Fatalf("binds %+v, want %+v", binds, want)
	}
	wrapped, err := e.Wrap(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	bundle := "type=bind,src=" + filepath.Join(temp, "ca-bundle.pem") +
		",dst=" + BundlePath + ",readonly"
	if !slices.Contains(wrapped.Args, bundle) {
		t.Errorf("the bundle is not bound from %s: %q", temp, wrapped.Args)
	}
}

// TestTheEngineIsAskedForARunsContainersInEveryState pins the liveness query: by the
// run's label, in every state, with the command and the variables recorded, and
// whether any container is listed.
func TestTheEngineIsAskedForARunsContainersInEveryState(t *testing.T) {
	e := Engine{Wall: "docker", Command: "/opt/engine/docker", Pinned: true,
		Env: []string{"DOCKER_HOST=unix:///run/other.sock", "DOCKER_CONTEXT=other"}}
	for _, c := range []struct {
		listed string
		exists bool
	}{{"", false}, {"\n", false}, {"3f2a9c1b7d4e\n", true}} {
		rec := &recorder{t: t, containers: c.listed}
		exists, err := runContainersExist(context.Background(), rec, e, runID)
		if err != nil || exists != c.exists {
			t.Errorf("listed %q: exists %v, %v", c.listed, exists, err)
		}
		want := "/opt/engine/docker ps --all --quiet --filter label=dev.qory.run=" + runID
		if len(rec.lines) != 1 || rec.lines[0] != want || !slices.Equal(rec.env, e.Env) {
			t.Errorf("asked %q with %q", rec.lines, rec.env)
		}
	}
	rec := &recorder{t: t, fail: " ps "}
	if _, err := runContainersExist(context.Background(), rec, e, runID); err == nil ||
		!strings.Contains(err.Error(), "Cannot connect to the Docker daemon") {
		t.Errorf("an engine that fails: %v", err)
	}
	for _, bad := range []Engine{
		{Wall: "other", Command: "docker"},
		{Wall: "docker"},
		{Wall: "docker", Command: "docker", Env: []string{"PATH=/tmp"}},
	} {
		if _, err := runContainersExist(context.Background(), rec, bad, runID); err == nil {
			t.Errorf("%+v was asked", bad)
		}
	}
}

// unsetEngine leaves no variable that selects an engine in the test's environment.
func unsetEngine(t *testing.T) {
	for _, name := range engineVariables {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
}

// TestTheEngineRecordedHoldsNoPassword pins what a run records of its engine: the
// command and the variables that select it, a password in an address left out; with
// DOCKER_HOST set, the selection is pinned and no context is asked.
func TestTheEngineRecordedHoldsNoPassword(t *testing.T) {
	unsetEngine(t)
	t.Setenv("DOCKER_HOST", "tcp://builder:not-a-real-password@engine.example:2376")
	t.Setenv("DOCKER_CONFIG", "conf")
	rec := &recorder{t: t, engineID: "4c1f0a2e-engine", context: "other"}
	e := (&Docker{Command: "/opt/engine/docker", sys: rec}).Engine(context.Background())
	conf, _ := filepath.Abs("conf")
	want := []string{"DOCKER_HOST=tcp://builder@engine.example:2376",
		"DOCKER_CONFIG=" + conf}
	if e.Wall != "docker" || e.Command != "/opt/engine/docker" ||
		!slices.Equal(e.Env, want) || e.ID != "4c1f0a2e-engine" || !e.Pinned {
		t.Errorf("engine %+v", e)
	}
	for _, line := range rec.lines {
		if strings.Contains(line, "context show") {
			t.Errorf("a context was pinned beside DOCKER_HOST: %q", rec.lines)
		}
	}
}

// TestAnUnreadableAddressLeavesTheEngineUnpinned pins an engine-selecting address that
// cannot be read: it is left out whole, password and all, and the selection is not
// pinned. Neither the context nor the id is asked, since without the address the
// command reaches another engine; a later question is no answer.
func TestAnUnreadableAddressLeavesTheEngineUnpinned(t *testing.T) {
	for _, name := range []string{"DOCKER_HOST", "CONTAINER_HOST"} {
		unsetEngine(t)
		t.Setenv(name, "ssh://builder:not-a-real-password@%zz/run/engine.sock")
		rec := &recorder{t: t, engineID: "4c1f0a2e-engine", context: "orbstack"}
		d := &Docker{Command: "/opt/engine/docker", sys: rec}
		e := d.Engine(context.Background())
		if e.Pinned || e.ID != "" || len(rec.lines) != 0 ||
			strings.Contains(strings.Join(e.Env, " "), "not-a-real-password") {
			t.Errorf("%s: engine %+v, asked %q", name, e, rec.lines)
		}
		// The adapter's commands keep the runner's own environment, and the id is not
		// asked later either.
		if sel := d.selected(); sel != nil {
			t.Errorf("%s: the adapter's commands run with %q", name, sel)
		}
		if id, err := d.EngineID(context.Background()); err == nil || id != "" {
			t.Errorf("%s: the id was asked later: %q", name, id)
		}
		if _, err := runContainersExist(context.Background(), rec, e, runID); err == nil {
			t.Errorf("%s: an unpinned engine without an id was asked", name)
		}
	}
}

// TestTheEngineIsPinnedWhenNothingSelectsIt pins a run with no variable that selects
// the engine: the context the command shows and the configuration directory are
// recorded, so a later `context use` does not change the engine asked; the engine's id
// is asked through them.
func TestTheEngineIsPinnedWhenNothingSelectsIt(t *testing.T) {
	unsetEngine(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &recorder{t: t, engineID: "4c1f0a2e-engine", context: "orbstack"}
	e := (&Docker{Command: "/opt/engine/docker", sys: rec}).Engine(context.Background())
	want := []string{"DOCKER_CONFIG=" + filepath.Join(home, ".docker"),
		"DOCKER_CONTEXT=orbstack"}
	if !slices.Equal(e.Env, want) || e.ID != "4c1f0a2e-engine" ||
		!slices.Equal(rec.env, want) {
		t.Errorf("engine %+v, asked with %q", e, rec.env)
	}
}

// TestAnEngineReachedElsewhereIsNoAnswer pins the id: an engine that answers with
// another id, or none, is not the one the run was in, so the question fails and the
// containers are not listed there.
func TestAnEngineReachedElsewhereIsNoAnswer(t *testing.T) {
	e := Engine{Wall: "docker", Command: "/opt/engine/docker", ID: "4c1f0a2e-engine"}
	for _, other := range []string{"9d7b3e10-other", ""} {
		rec := &recorder{t: t, engineID: other}
		exists, err := runContainersExist(context.Background(), rec, e, runID)
		if err == nil || exists {
			t.Errorf("engine %q: exists %v, %v", other, exists, err)
		}
		for _, line := range rec.lines {
			if strings.Contains(line, " ps ") {
				t.Errorf("engine %q was asked for containers: %q", other, rec.lines)
			}
		}
	}
	rec := &recorder{t: t, engineID: "4c1f0a2e-engine", containers: "3f2a9c1b7d4e\n"}
	if exists, err := runContainersExist(context.Background(), rec, e, runID); !exists ||
		err != nil || len(rec.lines) != 2 {
		t.Errorf("the same engine: exists %v, %v, asked %q", exists, err, rec.lines)
	}
}

// TestAnEngineWithNeitherPinNorIDIsNoAnswer pins an engine recorded with neither a
// pinned selection nor an id: podman with nothing set, which shows no context and gives
// no id, and a docker whose context show fails and that gives no id. The run starts,
// recorded so, and a later question is no answer, so its entry is never removed on an
// answer that may be another engine's. The adapter is docker whichever command it runs.
func TestAnEngineWithNeitherPinNorIDIsNoAnswer(t *testing.T) {
	for _, command := range []string{"podman", "/opt/engine/docker"} {
		unsetEngine(t)
		rec := &recorder{t: t, fail: " context show| info "}
		e := (&Docker{Command: command, sys: rec}).Engine(context.Background())
		if e.Wall != "docker" || e.ID != "" || e.Pinned {
			t.Fatalf("%s: engine %+v", command, e)
		}
		rec = &recorder{t: t, containers: "3f2a9c1b7d4e\n"}
		_, err := runContainersExist(context.Background(), rec, e, runID)
		if err == nil || len(rec.lines) != 0 {
			t.Errorf("%s: %v, asked %q", command, err, rec.lines)
		}
	}
}

// TestTheIDIsAskedAgainThroughTheSelection pins the second question: an engine that
// gave no id when the run started is asked again through the selection recorded, with
// the command recorded.
func TestTheIDIsAskedAgainThroughTheSelection(t *testing.T) {
	unsetEngine(t)
	t.Setenv("DOCKER_CONTEXT", "orbstack")
	rec := &recorder{t: t, fail: " info "}
	d := &Docker{Command: "/opt/engine/docker", sys: rec}
	if e := d.Engine(context.Background()); e.ID != "" || !e.Pinned {
		t.Fatalf("engine %+v", e)
	}
	rec.fail, rec.engineID = "", "4c1f0a2e-engine"
	id, err := d.EngineID(context.Background())
	if err != nil || id != "4c1f0a2e-engine" ||
		!strings.HasPrefix(rec.lines[len(rec.lines)-1], "/opt/engine/docker info ") ||
		!slices.Contains(rec.env, "DOCKER_CONTEXT=orbstack") {
		t.Errorf("id %q, %v, asked %q with %q", id, err, rec.lines, rec.env)
	}
	if _, err := (&Docker{sys: rec}).EngineID(context.Background()); err == nil {
		t.Error("an adapter with no engine recorded was asked for its id")
	}
}

// TestOnlyTheCommandsOwnVariablesPin pins Pinned to the variables the command reads:
// podman's CONTAINER_HOST and CONTAINER_CONNECTION, any other command's DOCKER_HOST and
// DOCKER_CONTEXT or the context it shows. A variable of the other command's stays
// recorded and never pins, so podman with DOCKER_HOST alone, and no id, is no answer
// later; docker with CONTAINER_HOST alone is pinned by the context it shows, and is
// unpinned when it shows none.
func TestOnlyTheCommandsOwnVariablesPin(t *testing.T) {
	for _, c := range []struct {
		name, command, variable, value, fail string
		pinned, shown                        bool
	}{
		{"podman with DOCKER_HOST", "podman", "DOCKER_HOST",
			"unix:///run/docker.sock", " info ", false, false},
		{"podman with DOCKER_CONTEXT", "podman", "DOCKER_CONTEXT",
			"builder", " info ", false, false},
		{"podman with CONTAINER_CONNECTION", "podman", "CONTAINER_CONNECTION",
			"builder", " info ", true, false},
		{"docker with CONTAINER_HOST", "/opt/engine/docker", "CONTAINER_HOST",
			"unix:///run/podman.sock", " info ", true, true},
		{"docker with CONTAINER_HOST, no context", "/opt/engine/docker", "CONTAINER_HOST",
			"unix:///run/podman.sock", " context show| info ", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			unsetEngine(t)
			t.Setenv(c.variable, c.value)
			rec := &recorder{t: t, context: "orbstack", fail: c.fail}
			e := (&Docker{Command: c.command, sys: rec}).Engine(context.Background())
			asked := slices.ContainsFunc(rec.lines, func(l string) bool {
				return strings.Contains(l, "context show")
			})
			if e.Pinned != c.pinned || e.ID != "" ||
				!slices.Contains(e.Env, c.variable+"="+c.value) ||
				asked != (c.command != "podman") ||
				slices.Contains(e.Env, "DOCKER_CONTEXT=orbstack") != c.shown {
				t.Fatalf("engine %+v, asked %q", e, rec.lines)
			}
			rec = &recorder{t: t, containers: "3f2a9c1b7d4e\n"}
			exists, err := runContainersExist(context.Background(), rec, e, runID)
			if c.pinned && (!exists || err != nil) || !c.pinned && (err == nil ||
				len(rec.lines) != 0) {
				t.Errorf("exists %v, %v, asked %q", exists, err, rec.lines)
			}
		})
	}
}

// TestAPinnedEngineWithoutAnIDIsAskedByItsSelection pins an engine pinned by its
// selection that gives no id: the question goes by the selection alone.
func TestAPinnedEngineWithoutAnIDIsAskedByItsSelection(t *testing.T) {
	unsetEngine(t)
	t.Setenv("CONTAINER_HOST", "unix:///run/user/1000/podman/podman.sock")
	rec := &recorder{t: t, fail: " info "}
	e := (&Docker{Command: "podman", sys: rec}).Engine(context.Background())
	if e.Wall != "docker" || e.ID != "" || !e.Pinned {
		t.Fatalf("engine %+v", e)
	}
	rec = &recorder{t: t, containers: "3f2a9c1b7d4e\n"}
	exists, err := runContainersExist(context.Background(), rec, e, runID)
	if !exists || err != nil || len(rec.lines) != 1 ||
		!strings.Contains(rec.lines[0], " ps ") {
		t.Errorf("exists %v, %v, asked %q", exists, err, rec.lines)
	}
}

// TestTheAdaptersCommandsRunWithTheRecordedSelection pins that once the engine is
// recorded, every engine command of the run's, and the launch, runs with the recorded
// selection, the context pinned where none was set, so the containers are on the
// engine recorded.
func TestTheAdaptersCommandsRunWithTheRecordedSelection(t *testing.T) {
	unsetEngine(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, engineID: "4c1f0a2e-engine",
		context: "orbstack"}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"relay"}, sys: rec}
	d.Engine(context.Background())
	e, err := d.Prepare(context.Background(),
		Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := e.Wrap(context.Background(), launch())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"DOCKER_CONFIG=" + filepath.Join(home, ".docker"),
		"DOCKER_CONTEXT=orbstack"}
	if len(rec.envs) == 0 {
		t.Fatal("no command ran")
	}
	for i, env := range rec.envs {
		if !slices.Equal(env, want) {
			t.Errorf("command %d ran with %q", i, env)
		}
	}
	if !slices.Contains(wrapped.Env, "DOCKER_CONTEXT=orbstack") {
		t.Errorf("the launch runs with %q", wrapped.Env)
	}
}
