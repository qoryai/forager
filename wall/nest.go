package wall

import (
	"encoding/json"
	"errors"
	"fmt"
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
	// names one: the proxy for the containers the agent starts.
	nestConfig = "/run/qory/docker"
)

// nestWait is how long the daemon has to answer on its socket.
const nestWait = 2 * 60

// Nest is the program that starts an enclosure with a Docker of the agent's own. It
// runs as the enclosure's root, which the runtime maps to a user of the machine's that
// is not root: it starts dockerd on [NestSocket] alone, in a session of its own so the
// terminal's signals do not reach it, with its socket in the agent's group; waits until
// the daemon answers; writes the agent's docker configuration, which gives the
// containers the agent starts the proxy by its address, since they do not resolve its
// name; then drops every capability, the bounding set included, becomes the agent's
// user and executes the launch. It returns only on an error.
//
// Its arguments are --user, uid:gid or a name of the image's, then -- and the launch.
// The caller's binary runs it in a hidden mode, as it runs [Relay].
//
// Experimental: see contracts/runner/v1/README.md §The wall.
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

// daemonDirs are where [Nest] looks for dockerd: the image's system directories, never
// the run's PATH, which may name a directory of the workspace.
var daemonDirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

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

// writeNestConfig writes the agent's docker configuration, owned by the agent, and
// returns its directory.
func writeNestConfig(config []byte, uid, gid int) (string, error) {
	if err := os.MkdirAll(nestConfig, 0o700); err != nil {
		return "", err
	}
	file := filepath.Join(nestConfig, "config.json")
	if err := os.WriteFile(file, config, 0o600); err != nil {
		return "", err
	}
	for _, p := range []string{nestConfig, file} {
		if err := os.Chown(p, uid, gid); err != nil {
			return "", err
		}
	}
	return nestConfig, nil
}
