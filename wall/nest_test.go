package wall

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestNestReadsItsArguments pins the one shape Nest takes: the user, then the launch
// after --.
func TestNestReadsItsArguments(t *testing.T) {
	user, argv, err := parseNest([]string{"--user", "1000:1000", "--", "claude", "-p", "hi"})
	if err != nil || user != "1000:1000" || len(argv) != 3 || argv[0] != "claude" {
		t.Errorf("got %q %v %v", user, argv, err)
	}
	for _, args := range [][]string{nil, {"--user", "1000"}, {"--user", "1000", "claude"}, {"--user", "1000", "--"}, {"--user", "1000", "--", ""}, {"-u", "1000", "--", "claude"}} {
		if _, _, err := parseNest(args); err == nil {
			t.Errorf("%q was read", args)
		}
	}
}

// TestNestFindsTheAgentsIDs pins how the agent's user and group are found: numbers as
// given, names in the image's files, and a number with no group only for a user of the
// image's, since the daemon's socket goes to that group. Root is refused either way.
func TestNestFindsTheAgentsIDs(t *testing.T) {
	image := func(kind, key string) (int, int, bool) {
		switch kind + ":" + key {
		case "name:agent", "uid:1000":
			return 1000, 1001, true
		case "group:docker":
			return 0, 2375, true
		case "name:root", "uid:0":
			return 0, 0, true
		}
		return 0, 0, false
	}
	for spec, want := range map[string][2]int{
		"1000:1000":    {1000, 1000},
		"agent":        {1000, 1001},
		"1000":         {1000, 1001},
		"agent:docker": {1000, 2375},
		"1000:2375":    {1000, 2375},
		"5000:5000":    {5000, 5000},
	} {
		uid, gid, err := nestIDs(spec, image)
		if err != nil || uid != want[0] || gid != want[1] {
			t.Errorf("%s: got %d:%d %v, want %d:%d", spec, uid, gid, err, want[0], want[1])
		}
	}
	for _, spec := range []string{"5000", "nobody", "1000:nogroup", "0:0", "root", "1000:0", "0"} {
		if uid, gid, err := nestIDs(spec, image); err == nil {
			t.Errorf("%s: got %d:%d", spec, uid, gid)
		}
	}
}

// TestNestGivesTheInnerContainersTheProxyByAddress pins the agent's docker
// configuration: the proxy the enclosure's environment names, its name resolved, since
// the containers the agent starts do not resolve it, with NO_PROXY carried; nothing
// when there is no proxy; an error when the name does not resolve.
func TestNestGivesTheInnerContainersTheProxyByAddress(t *testing.T) {
	resolve := func(name string) ([]string, error) {
		if name == "qory-proxy" {
			return []string{"172.25.0.2"}, nil
		}
		return nil, errors.New("no such host")
	}
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	proxies := func(b []byte) map[string]string {
		t.Helper()
		var c struct {
			Proxies struct{ Default map[string]string } `json:"proxies"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		return c.Proxies.Default
	}

	b, err := nestProxies(env(map[string]string{"HTTPS_PROXY": "http://qory-proxy:3128", "NO_PROXY": "localhost,127.0.0.1"}), resolve)
	if err != nil {
		t.Fatal(err)
	}
	if p := proxies(b); p["httpProxy"] != "http://172.25.0.2:3128" || p["httpsProxy"] != "http://172.25.0.2:3128" || p["noProxy"] != "localhost,127.0.0.1" {
		t.Errorf("got %v", p)
	}
	b, err = nestProxies(env(map[string]string{"HTTP_PROXY": "http://10.0.0.5:3128"}), resolve)
	if err != nil {
		t.Fatal(err)
	}
	if p := proxies(b); p["httpsProxy"] != "http://10.0.0.5:3128" || p["noProxy"] != "" {
		t.Errorf("an address is kept as it is: got %v", p)
	}
	if b, err := nestProxies(env(nil), resolve); b != nil || err != nil {
		t.Errorf("no proxy, and a configuration: %s %v", b, err)
	}
	if _, err := nestProxies(env(map[string]string{"HTTPS_PROXY": "http://elsewhere:3128"}), resolve); err == nil {
		t.Error("a name that does not resolve was written")
	}
	if _, err := nestProxies(env(map[string]string{"HTTPS_PROXY": "::"}), resolve); err == nil {
		t.Error("a proxy that is not a URL was written")
	}
}

// TestNestNeedsAUserNamespace pins that a Docker of the agent's own starts only where
// the enclosure's root is not the machine's: a map that says otherwise, or cannot be
// read, is refused.
func TestNestNeedsAUserNamespace(t *testing.T) {
	for _, tc := range []struct {
		uidMap string
		ok     bool
	}{
		{"         0     100000      65536\n", true},
		{"0 100000 65536\n65536 200000 1000\n", true},
		{"         0          0 4294967295\n", false},
		{"1000 1000 1\n", false},
		{"", false},
		{"not a map", false},
		{"0 100000 0", false},
	} {
		if err := userNamespaced(tc.uidMap); (err == nil) != tc.ok {
			t.Errorf("%q: %v, want accepted %v", tc.uidMap, err, tc.ok)
		}
	}
}

// TestNestFindsTheDaemonInTheSystemDirectories pins that dockerd is looked for in the
// directories given, in order, and only as an executable file.
func TestNestFindsTheDaemonInTheSystemDirectories(t *testing.T) {
	first, second, empty := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(first, "dockerd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "dockerd"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := findDaemon([]string{empty, first, second}); err == nil {
		t.Error("a directory, or a file that is not executable, is taken for the daemon")
	}
	if err := os.Chmod(filepath.Join(second, "dockerd"), 0o755); err != nil {
		t.Fatal(err)
	}
	third := t.TempDir()
	if err := os.WriteFile(filepath.Join(third, "dockerd"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := findDaemon([]string{empty, first, second, third}); err != nil || got != filepath.Join(second, "dockerd") {
		t.Errorf("found %q, %v; want the first executable, in %s", got, err, second)
	}
	for i, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if daemonDirs[i] != d {
			t.Errorf("the daemon is looked for in %v", daemonDirs)
			break
		}
	}
}

// TestNestGivesTheAgentItsDockerConfigurationAlone pins the owners and modes of the
// agent's docker configuration: the directory above it is root's with mode 0755, so the
// agent's user passes through it and writes nothing there, whatever the umask or the
// image made it; the configuration's directory and file are the agent's, 0700 and 0600,
// and the file is written anew. A link where either directory goes is refused, and what
// it points at is left as it was. As root the test gives the agent another user; as
// anyone else it can give only its own, and the owners it checks are that one.
func TestNestGivesTheAgentItsDockerConfigurationAlone(t *testing.T) {
	root := nestOwner{os.Getuid(), os.Getgid()}
	agent := root
	if root.uid == 0 {
		agent = nestOwner{1000, 1001}
	}
	defer syscall.Umask(syscall.Umask(0o077))
	is := func(p string, mode fs.FileMode, o nestOwner) {
		t.Helper()
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm() != mode || int(st.Uid) != o.uid || int(st.Gid) != o.gid {
			t.Errorf("%s is %v %d:%d, want %v %d:%d", p, info.Mode().Perm(), st.Uid, st.Gid, mode, o.uid, o.gid)
		}
	}
	config := []byte(`{"proxies":{"default":{"httpProxy":"http://172.25.0.2:3128"}}}`)
	written := func(dir string) {
		t.Helper()
		is(filepath.Dir(dir), 0o755, root)
		is(dir, 0o700, agent)
		is(filepath.Join(dir, "config.json"), 0o600, agent)
		if b, err := os.ReadFile(filepath.Join(dir, "config.json")); err != nil || string(b) != string(config) {
			t.Errorf("the configuration is %q, %v", b, err)
		}
	}

	// Nothing there, not even /run, under a umask that would close all of it.
	dir := filepath.Join(t.TempDir(), "run", "qory", "docker")
	if err := writeNestConfig(dir, config, root, agent); err != nil {
		t.Fatal(err)
	}
	written(dir)

	// The image holds /run/qory narrower, the configuration's directory wider, and a
	// configuration of its own.
	dir = filepath.Join(t.TempDir(), "run", "qory", "docker")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"auths":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for p, mode := range map[string]fs.FileMode{filepath.Dir(dir): 0o700, dir: 0o777, filepath.Join(dir, "config.json"): 0o644} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeNestConfig(dir, config, root, agent); err != nil {
		t.Fatal(err)
	}
	written(dir)

	// A link where either directory goes.
	for _, link := range []string{"qory", "qory/docker"} {
		run := filepath.Join(t.TempDir(), "run")
		elsewhere := filepath.Join(filepath.Dir(run), "elsewhere")
		for _, d := range []string{elsewhere, filepath.Dir(filepath.Join(run, link))} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(elsewhere, filepath.Join(run, link)); err != nil {
			t.Fatal(err)
		}
		if err := writeNestConfig(filepath.Join(run, "qory", "docker"), config, root, agent); err == nil {
			t.Errorf("run/%s as a link was taken", link)
		}
		is(elsewhere, 0o700, root)
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Errorf("run/%s as a link: %d entries written where it points", link, len(entries))
		}
	}
}

// TestNestGivesTheDaemonNoneOfTheRunsEnvironmentButTheProxy pins what the daemon, and
// everything it starts as the enclosure's root, runs with: the system directories as
// PATH whatever the run's names, the proxy in both cases, and the wall's bundle when the
// run has one. What the run sets for the agent, a PATH into the workspace, a library to
// preload, where the daemon keeps things, stays the agent's.
func TestNestGivesTheDaemonNoneOfTheRunsEnvironmentButTheProxy(t *testing.T) {
	run := map[string]string{
		"PATH":              "/work/node_modules/.bin:/work/bin:/usr/bin:/bin",
		"LD_PRELOAD":        "/work/preload.so",
		"LD_LIBRARY_PATH":   "/work/lib",
		"XTABLES_LIBDIR":    "/work/xtables",
		"DOCKER_TMPDIR":     "/work/tmp",
		"DOCKER_DRIVER":     "vfs",
		"DOCKER_HOST":       "tcp://0.0.0.0:2375",
		"DOCKER_CERT_PATH":  "/work/certs",
		"DOCKER_TLS_VERIFY": "1",
		"SSL_CERT_FILE":     "/work/ca.pem",
		"HOME":              "/work",
		"TMPDIR":            "/work/tmp",
		"HTTP_PROXY":        "http://qory-proxy:3128",
		"HTTPS_PROXY":       "http://qory-proxy:3128",
		"NO_PROXY":          "localhost,127.0.0.1,::1",
		"http_proxy":        "http://qory-proxy:3128",
		"https_proxy":       "http://qory-proxy:3128",
		"no_proxy":          "localhost,127.0.0.1,::1",
	}
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	system := "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	proxies := []string{
		"HTTP_PROXY=http://qory-proxy:3128", "HTTPS_PROXY=http://qory-proxy:3128", "NO_PROXY=localhost,127.0.0.1,::1",
		"http_proxy=http://qory-proxy:3128", "https_proxy=http://qory-proxy:3128", "no_proxy=localhost,127.0.0.1,::1",
	}
	for _, tc := range []struct {
		vars   map[string]string
		bundle string
		want   []string
	}{
		{run, BundlePath, append(append([]string{system}, proxies...), "SSL_CERT_FILE="+BundlePath)},
		{run, "", append([]string{system}, proxies...)},
		{map[string]string{"PATH": "/work/bin", "LD_PRELOAD": "/work/preload.so"}, "", []string{system}},
	} {
		if got := daemonEnv(env(tc.vars), tc.bundle); strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("bundle %q: got\n%s\nwant\n%s", tc.bundle, strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
		}
	}
}
