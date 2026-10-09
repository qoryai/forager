package wall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Where things are inside an enclosure with a Docker of the agent's own.
const (
	// NestSocket is the inner daemon's socket, where a docker command looks first. It
	// is the only address the daemon listens on: never a port of the enclosure's
	// network, which the relay's side reaches.
	NestSocket = "/var/run/docker.sock"
	// NestLog is where the daemon's output goes, so it is not the session's.
	NestLog = "/var/log/qory-dockerd.log"
	// nestStore is the daemon's store, a volume of the run's.
	nestStore = "/var/lib/docker"
	// nestConfig is the agent's docker configuration, DOCKER_CONFIG, unless the run
	// sets a non-empty one: the proxy for the containers the agent starts. It is the
	// agent's alone, in a directory of root's that the agent passes through.
	nestConfig = "/run/qory/docker"
)

// nestWait is how long the daemon has to answer on its socket.
const nestWait = 2 * 60

// Nest is the program that starts an enclosure with a Docker of the agent's own. It
// runs as the enclosure's root, which the runtime maps to a user of the machine's that
// is not root: it starts dockerd on [NestSocket] alone, in a session of its own so the
// terminal's signals do not reach it, with its socket in the agent's group and none of
// the run's environment but the proxy; waits until the daemon answers; writes the
// agent's docker configuration, which sets the proxy for the containers the agent
// starts by its address, since they do not resolve its name; then drops every
// capability, the bounding set included, becomes the agent's user and executes the
// launch with the run's environment. It returns only on an error.
//
// Its arguments are --user, uid:gid or a name of the image's, then -- and the launch.
// The caller's binary runs it in a hidden mode, as it runs [Relay].
//
// Experimental: see contracts/forager/v1/README.md §The wall.
func Nest(args []string) error {
	user, argv, err := parseNest(args)
	if err != nil {
		return err
	}
	return nest(user, argv)
}

// parseNest reads Nest's arguments.
func parseNest(args []string) (string, []string, error) {
	if len(args) < 4 || args[0] != "--user" || args[2] != "--" || args[3] == "" {
		return "", nil, errors.New("nest: want --user uid:gid -- command [args]")
	}
	return args[1], args[3:], nil
}

// userNamespaced reports whether a uid_map, /proc/self/uid_map's content, maps the
// enclosure's root to a user of the machine's that is not root: the one thing that makes
// a root inside it no root outside. A map that cannot be read is no such map.
func userNamespaced(uidMap string) error {
	for _, line := range strings.Split(strings.TrimSpace(uidMap), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			return fmt.Errorf("nest: the user map %q cannot be read", strings.TrimSpace(uidMap))
		}
		inside, err1 := strconv.ParseUint(f[0], 10, 32)
		outside, err2 := strconv.ParseUint(f[1], 10, 32)
		count, err3 := strconv.ParseUint(f[2], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil || count == 0 {
			return fmt.Errorf("nest: the user map %q cannot be read", strings.TrimSpace(uidMap))
		}
		if inside == 0 {
			if outside == 0 {
				return errors.New("nest: the enclosure's root is the machine's root; a Docker of the agent's own needs a runtime that maps it to a user of the machine's that is not root, such as sysbox-runc")
			}
			return nil
		}
	}
	return errors.New("nest: the user map does not map the enclosure's root")
}

// daemonDirs are where [Nest] looks for dockerd, and the daemon's PATH, where it looks
// for what it starts, containerd, runc and iptables among them: the image's system
// directories, never the run's PATH, which may list a directory of the workspace.
var daemonDirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// daemonEnv is the daemon's environment, which the programs it starts as the enclosure's
// root inherit: [daemonDirs] as PATH; the proxy the enclosure's environment defines,
// env's HTTP_PROXY, HTTPS_PROXY and NO_PROXY in either case, for its pulls; and bundle
// as SSL_CERT_FILE when the run has one, so it trusts the hosts the proxy answers as.
// Nothing else of the run's environment reaches it: the run sets that for the agent,
// and a variable such as LD_PRELOAD, LD_LIBRARY_PATH, XTABLES_LIBDIR or DOCKER_TMPDIR
// would choose, from the workspace, what root loads or where it writes.
func daemonEnv(env func(string) string, bundle string) []string {
	out := []string{"PATH=" + strings.Join(daemonDirs, ":")}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		if v := env(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	if bundle != "" {
		out = append(out, "SSL_CERT_FILE="+bundle)
	}
	return out
}

// findDaemon is the first executable dockerd in dirs.
func findDaemon(dirs []string) (string, error) {
	for _, d := range dirs {
		p := filepath.Join(d, "dockerd")
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("nest: the image holds no dockerd in " + strings.Join(dirs, ", ") + "; an image with a Docker of the agent's own carries the daemon")
}

// nestIDs are the agent's user and group, from uid:gid, or from the image's own users
// and groups when named. A user named by number alone must be one of the image's, for
// its group: the daemon's socket is given to that group.
func nestIDs(spec string, lookup func(kind, key string) (int, int, bool)) (int, int, error) {
	name, group, hasGroup := strings.Cut(spec, ":")
	uid, err := strconv.Atoi(name)
	gid := -1
	if err != nil {
		u, g, ok := lookup("name", name)
		if !ok {
			return 0, 0, fmt.Errorf("nest: the image has no user %q", name)
		}
		uid, gid = u, g
	} else if !hasGroup {
		_, g, ok := lookup("uid", name)
		if !ok {
			return 0, 0, fmt.Errorf("nest: the user %d is not the image's; name the group as uid:gid", uid)
		}
		gid = g
	}
	if hasGroup {
		if gid, err = strconv.Atoi(group); err != nil {
			_, g, ok := lookup("group", group)
			if !ok {
				return 0, 0, fmt.Errorf("nest: the image has no group %q", group)
			}
			gid = g
		}
	}
	if uid == 0 || gid == 0 {
		return 0, 0, errors.New("nest: the agent does not run as root")
	}
	return uid, gid, nil
}

// passwd looks a user up by name or uid, or a group by name, in the image's files.
func passwd(kind, key string) (int, int, bool) {
	file, match, idCol := "/etc/passwd", 0, 2
	switch kind {
	case "uid":
		match = 2
	case "group":
		file = "/etc/group"
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 || f[match] != key {
			continue
		}
		id, err := strconv.Atoi(f[idCol])
		if err != nil {
			return 0, 0, false
		}
		if kind == "group" {
			return 0, id, true
		}
		if len(f) < 4 {
			return 0, 0, false
		}
		gid, err := strconv.Atoi(f[3])
		return id, gid, err == nil
	}
	return 0, 0, false
}

// nestProxies is the agent's docker configuration: the proxy the enclosure's
// environment names, by the address its name resolves to, for every container the
// agent starts and every build. Empty when the environment names no proxy.
func nestProxies(env func(string) string, resolve func(string) ([]string, error)) ([]byte, error) {
	raw := env("HTTPS_PROXY")
	if raw == "" {
		raw = env("HTTP_PROXY")
	}
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("nest: the proxy %q is not a URL", raw)
	}
	if net.ParseIP(u.Hostname()) == nil {
		addrs, err := resolve(u.Hostname())
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("nest: the proxy's name %s does not resolve: %v", u.Hostname(), err)
		}
		u.Host = net.JoinHostPort(addrs[0], u.Port())
	}
	p := map[string]string{"httpProxy": u.String(), "httpsProxy": u.String()}
	if no := env("NO_PROXY"); no != "" {
		p["noProxy"] = no
	}
	return json.MarshalIndent(map[string]any{"proxies": map[string]any{"default": p}}, "", "  ")
}

// nestAgentEnv is the agent's environment: environ, the run's, with the agent's docker
// configuration when the run sets none of its own. The run sets its own with a
// DOCKER_CONFIG that is not empty in environ's first entry for it, the one getenv reads;
// the docker command reads an empty DOCKER_CONFIG as none set. Otherwise write writes
// the configuration and reports whether it wrote one, which it does when the run has a
// proxy. When it wrote one, every DOCKER_CONFIG entry of environ is dropped and
// DOCKER_CONFIG=[nestConfig] is appended, so the environment contains one, the wall's:
// an empty entry left before it would be the one getenv reads. An error of write's is
// returned as it is.
//
// os.Environ already keeps only the first entry for a name, so the environ [Nest] reads
// contains at most one DOCKER_CONFIG; the function drops every one all the same, for an
// environ built elsewhere.
func nestAgentEnv(environ []string, write func() (bool, error)) ([]string, error) {
	for _, e := range environ {
		if v, ok := strings.CutPrefix(e, "DOCKER_CONFIG="); ok {
			if v != "" {
				return environ, nil
			}
			break
		}
	}
	wrote, err := write()
	if err != nil || !wrote {
		return environ, err
	}
	out := make([]string, 0, len(environ)+1)
	for _, e := range environ {
		if !strings.HasPrefix(e, "DOCKER_CONFIG=") {
			out = append(out, e)
		}
	}
	return append(out, "DOCKER_CONFIG="+nestConfig), nil
}

// nestOwner is a user and a group, by id: the owner a file is set to.
type nestOwner struct{ uid, gid int }

// writeNestConfig writes the agent's docker configuration, config.json in dir, for the
// agent alone: dir is owned by agent with mode 0700 and the file with mode 0600, since
// the docker command reads its configuration as the agent's user and writes to it as
// well. The directory above dir, /run/qory, is Forager's: it is owned by root, the
// enclosure's root, with mode 0755, so the agent's user passes through it to dir and
// writes nothing in it. Were it narrower, the docker command could not read the
// configuration and would start the agent's containers without a proxy.
//
// Both modes are set whatever the umask, and whatever the image contains there: a
// directory the image made narrower, or set to another owner, is changed rather than
// refused, since Forager keeps nothing else in it and a narrower mode only hides the
// agent's configuration from the agent. A link or a file in either place is refused,
// since the owner and the mode would land where it points. The file is written anew.
func writeNestConfig(dir string, config []byte, root, agent nestOwner) error {
	forager := filepath.Dir(dir)
	if err := os.MkdirAll(filepath.Dir(forager), 0o755); err != nil {
		return err
	}
	if err := nestDir(forager, 0o755, root); err != nil {
		return err
	}
	if err := nestDir(dir, 0o700, agent); err != nil {
		return err
	}
	file := filepath.Join(dir, "config.json")
	if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(config)
	if err == nil {
		err = f.Chown(agent.uid, agent.gid)
	}
	if err == nil {
		err = f.Chmod(0o600)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// nestDir makes dir, or uses the directory already in the image, and sets its owner to
// o and its mode to mode, after the umask has narrowed what Mkdir made. A link or a
// file at dir is refused.
func nestDir(dir string, mode fs.FileMode, o nestOwner) error {
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory but %v", dir, info.Mode().Type())
	}
	if err := os.Chown(dir, o.uid, o.gid); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}
