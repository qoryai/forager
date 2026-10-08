package wall

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/internal/program"
	"github.com/qoryai/runner/internal/proxy"
	"github.com/qoryai/runner/internal/socket"
)

// Where things are inside a Docker enclosure.
const (
	// HelperPath is where the helper binary is mounted, read-only. A caller names it in
	// the hook forwarder's command, since the host's own path does not exist inside.
	HelperPath = "/qory/qory"
	// hooksDir is where the directory holding the hook socket is mounted.
	hooksDir = "/qory/hooks"
	// BundlePath is where the enclosure finds the authorities it trusts when the run has
	// one of its own: the image's bundle and the run's certificate, in one file.
	BundlePath = "/qory/ca-bundle.pem"
	// relayAlias is the name the agent reaches the relay by, and relayPort the port the
	// relay forwards to the proxy.
	relayAlias = "qory-proxy"
	relayPort  = 3128
	// hostName is the name an ordinary container reaches the engine's host by.
	hostName = "host.docker.internal"
)

// Docker is the wall built with the docker command, and with podman or nerdctl when the
// conformance suite passes for them. It uses the command and no library, and serves
// whatever engine that command reaches.
//
// A run gets two networks and two containers. The agent's container is on a network
// created with --internal and on nothing else, so it has no route out and its resolver
// knows only that network; the network's bridge gets no address, so the engine's host is
// not on it either. The relay's container is on that network and on an ordinary
// one; it runs [Relay], forwarding one port to the session runner's proxy, and is the
// one peer the agent can reach. Both run as a user that is not root, with every
// capability dropped and no new privileges.
type Docker struct {
	// Command is the program to run; empty means docker.
	Command string
	// Helper is the path on this machine of a static Linux build, for the engine's
	// architecture, of the binary that runs the relay and the hook forwarder. It is
	// mounted read-only at [HelperPath] in both containers.
	Helper string
	// RelayArgs are the arguments that make Helper run [Relay]; the forwards follow
	// them.
	RelayArgs []string
	// NestArgs are the arguments that make Helper run [Nest], for an image with a Docker
	// of the agent's own; the user and the launch follow them. Without them such an
	// image is refused. Experimental: see contracts/runner/v1/README.md §The wall.
	NestArgs []string
	// CAEnv names the variables that point a program at [BundlePath] when the run has
	// an authority of its own; nil means [DefaultCAEnv]. A program that reads another
	// is served by naming it here.
	CAEnv []string
	// User is the uid:gid both containers run as; empty means this process's own, so
	// the workspace's files keep their owner. Root is refused.
	User string

	sys system

	// recorded is the engine's command and selection as [Docker.Engine] recorded them;
	// every engine command of the adapter's then runs with the selection. nil until
	// they are recorded, or when a variable was left out.
	selectionMu sync.Mutex
	recorded    *Engine
}

// selected is the engine's selection the adapter's commands run with, nil for the
// runner's own environment.
func (d *Docker) selected() []string {
	d.selectionMu.Lock()
	defer d.selectionMu.Unlock()
	if d.recorded == nil {
		return nil
	}
	return d.recorded.Env
}

// system is what the adapter asks of the machine, so a test records the commands and
// needs neither Docker nor Linux.
type system interface {
	// run runs a command and returns its output, standard error included. env, when
	// not nil, is the selection of the engine the command reaches, in place of the
	// runner's own.
	run(ctx context.Context, argv, env []string) ([]byte, error)
	// output runs a command and returns its standard output alone; env is as for run.
	output(ctx context.Context, argv, env []string) ([]byte, error)
	// local reports whether this machine holds the address.
	local(ip string) bool
	// tempDir makes a private directory.
	tempDir() (string, error)
	// ids are this process's user and group.
	ids() (int, int)
	// socket reports whether the path is a socket, or a directory that holds a
	// container runtime's.
	socket(path string) bool
	// checkHelper refuses a helper that cannot run in a Linux container.
	checkHelper(path string) error
	// engine runs a command against a recorded engine, with the variables that select
	// it, and returns its standard output; an error holds its standard error.
	engine(ctx context.Context, argv, env []string) ([]byte, error)
}

// Sets lists the variables the enclosure's environment receives from the adapter
// itself: the proxy's, the hook socket's and the ones that point a program at the
// run's bundle.
func (d *Docker) Sets() []string {
	names := d.CAEnv
	if names == nil {
		names = DefaultCAEnv
	}
	var out []string
	for _, kv := range proxy.EnvFor("") {
		name, _, _ := strings.Cut(kv, "=")
		out = append(out, name)
	}
	return append(append(out, socket.Env), names...)
}

// Files lists the adapter's own files on this machine: the directory of the docker
// command, found in PATH as the adapter runs it, the directory of the helper, each with
// the directory of the file a symbolic link leads to, and the command's configuration
// directory, DOCKER_CONFIG as the command reads it, else ~/.docker, whose context and
// credential helpers name programs the command starts.
func (d *Docker) Files() []string {
	out := program.Dirs(d.command())
	// The helper is a path, never looked up in PATH.
	if helper, err := filepath.Abs(d.Helper); d.Helper != "" && err == nil {
		out = append(out, program.Dirs(helper)...)
	}
	if conf := os.Getenv("DOCKER_CONFIG"); conf != "" {
		if abs, err := filepath.Abs(conf); err == nil {
			out = append(out, abs)
		}
	} else if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".docker"))
	}
	return out
}

// command is the program the adapter runs.
func (d *Docker) command() string {
	if d.Command == "" {
		return "docker"
	}
	return d.Command
}

// DefaultCAEnv are the variables the common programs read a bundle's path from:
// OpenSSL and Go, git, Node, Python's requests, curl, the AWS CLI and botocore.
var DefaultCAEnv = []string{"SSL_CERT_FILE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "AWS_CA_BUNDLE"}

// imageBundles are where an image keeps its authorities: Debian and Alpine, Red Hat,
// OpenSUSE, and the OpenSSL default.
var imageBundles = []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"}

// What goes on a command line is checked for its shape first, because a word that
// starts with a dash is a flag to the command that reads it: a run id names things, an
// image is a reference, a user is uid[:gid] or a name, a variable is NAME=value.
var (
	runIDShape   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	imageShape   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)
	runtimeShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	userShape    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?$`)
	envShape     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	cpusShape    = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
	bytesShape   = regexp.MustCompile(`^[0-9]+[bkmgBKMG]?$`)
)

// Name is docker, or the command's name when another was given.
func (d *Docker) Name() string {
	if d.Command == "" {
		return "docker"
	}
	return filepath.Base(d.Command)
}

// Prepare creates the run's two networks and decides where the proxy must listen: on
// the ordinary network's gateway when this machine holds that address, as on a Linux
// host, and on loopback otherwise, where the engine is in a virtual machine and reaches
// this machine's loopback by a name.
func (d *Docker) Prepare(ctx context.Context, req Request) (Enclosure, error) {
	sys := d.sys
	if sys == nil {
		sys = hostSystem{}
	}
	if !runIDShape.MatchString(req.RunID) {
		return nil, fmt.Errorf("wall docker: the run id %q cannot name a container", req.RunID)
	}
	if !imageShape.MatchString(req.Image) {
		return nil, fmt.Errorf("wall docker: %q is not an image reference", req.Image)
	}
	if req.Runtime != "" && !runtimeShape.MatchString(req.Runtime) {
		return nil, fmt.Errorf("wall docker: %q is not a container runtime's name", req.Runtime)
	}
	if req.Docker && req.Runtime == "" {
		return nil, errors.New("wall docker: a Docker of the agent's own needs a runtime that runs one without privileges, such as sysbox-runc; a privileged container is never an enclosure")
	}
	if req.Docker && len(d.NestArgs) == 0 {
		return nil, errors.New("wall docker: a Docker of the agent's own needs the helper's arguments that start it")
	}
	if d.Helper == "" || len(d.RelayArgs) == 0 {
		return nil, errors.New("wall docker: the helper binary and its relay arguments are required")
	}
	if err := sys.checkHelper(d.Helper); err != nil {
		return nil, fmt.Errorf("wall docker: helper %s: %w", d.Helper, err)
	}
	user := d.User
	if user == "" {
		uid, gid := sys.ids()
		user = fmt.Sprintf("%d:%d", uid, gid)
	}
	if !userShape.MatchString(user) {
		return nil, fmt.Errorf("wall docker: the user %q is not uid[:gid] or a name", user)
	}
	uid, _, _ := strings.Cut(user, ":")
	if n, err := strconv.Atoi(uid); uid == "root" || (err == nil && n == 0) {
		return nil, errors.New("wall docker: the agent does not run as root; name a user")
	}
	e := &dockerEnclosure{d: d, sys: sys, req: req, user: user, base: "qory-" + req.RunID,
		env: d.selected()}
	// What removes a thing is noted before the thing is asked for: a command cut off by
	// the context may still have been carried out by the engine.
	//
	// The inside network's bridge gets no address of the host's. With one, the network's
	// gateway is the engine's host, and what listens there on every address is a route
	// out of the enclosure.
	e.made = append(e.made, []string{"network", "rm", e.inside()})
	if _, err := e.docker(ctx, "network", "create", "--internal", "--opt", "com.docker.network.bridge.inhibit_ipv4=true", "--label", e.label(), e.inside()); err != nil {
		return nil, errors.Join(err, e.Close(context.WithoutCancel(ctx)))
	}
	e.made = append(e.made, []string{"network", "rm", e.outside()})
	if _, err := e.docker(ctx, "network", "create", "--label", e.label(), e.outside()); err != nil {
		return nil, errors.Join(err, e.Close(context.WithoutCancel(ctx)))
	}
	out, err := e.docker(ctx, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}", e.outside())
	if err != nil {
		return nil, errors.Join(err, e.Close(context.WithoutCancel(ctx)))
	}
	e.host = hostName
	for _, gw := range strings.Fields(string(out)) {
		if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil && sys.local(gw) {
			e.host = gw
			break
		}
	}
	return e, nil
}

// dockerEnclosure is one run's networks and containers.
type dockerEnclosure struct {
	d    *Docker
	sys  system
	req  Request
	user string
	base string
	// host is how the relay reaches this machine: the gateway's address, or hostName.
	host string
	// made holds the commands that remove what was created, in the order created.
	made [][]string
	temp string
	// env is the engine's selection every command of the run's runs with, nil for the
	// runner's own environment.
	env []string
}

func (e *dockerEnclosure) inside() string  { return e.base + "-in" }
func (e *dockerEnclosure) outside() string { return e.base + "-out" }
func (e *dockerEnclosure) relay() string   { return e.base + "-relay" }
func (e *dockerEnclosure) agent() string   { return e.base + "-agent" }
func (e *dockerEnclosure) label() string   { return "dev.qory.run=" + e.req.RunID }

// docker runs one docker command; a failure carries what the command printed.
func (e *dockerEnclosure) docker(ctx context.Context, args ...string) ([]byte, error) {
	argv := append([]string{e.command()}, args...)
	out, err := e.sys.run(ctx, argv, e.env)
	if err != nil {
		return out, fmt.Errorf("wall docker: %s: %w: %s", strings.Join(argv[:min(3, len(argv))], " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}

func (e *dockerEnclosure) command() string { return e.d.command() }

// ProxyAddr is the gateway's address when this machine holds it, else loopback.
func (e *dockerEnclosure) ProxyAddr() string {
	if e.host == hostName {
		return proxy.Loopback
	}
	return net.JoinHostPort(e.host, "0")
}

// hardening is what both containers run with: not root, no capabilities, no way to
// gain any, and an init that reaps and passes signals on.
func (e *dockerEnclosure) hardening() []string {
	return []string{"--user", e.user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--init"}
}

// relayWait is how long the relay has to listen, the image's pull included.
const relayWait = 5 * time.Minute

// Wrap starts the relay towards the proxy, waits until it listens, and returns the
// docker run that starts the launch in the agent's container: on the internal network
// only, the launch's mounts at their own paths, the workspace as the working directory
// inside one of them, the helper read-only,
// the socket's directory, and the launch's environment through a file, so no value is on a
// command line.
func (e *dockerEnclosure) Wrap(ctx context.Context, l Launch) (Launch, error) {
	_, port, err := net.SplitHostPort(l.Proxy)
	if err != nil {
		return Launch{}, fmt.Errorf("wall docker: the proxy's address: %w", err)
	}
	mounts, err := e.mounts(l)
	if err != nil {
		return Launch{}, err
	}
	helper, err := mount(e.d.Helper, HelperPath, true)
	if err != nil {
		return Launch{}, err
	}
	limits, err := limits(l.Limits)
	if err != nil {
		return Launch{}, err
	}
	// Everything that can be refused is, before anything is started.
	env := append([]string(nil), l.Env...)
	env = append(env, proxy.EnvFor(fmt.Sprintf("http://%s:%d", relayAlias, relayPort))...)
	if l.Socket != "" {
		env = append(env, socket.Env+"="+path.Join(hooksDir, filepath.Base(l.Socket)))
	}
	if len(l.CA) > 0 {
		names := e.d.CAEnv
		if names == nil {
			names = DefaultCAEnv
		}
		for _, n := range names {
			env = append(env, n+"="+BundlePath)
		}
	}
	envFile, err := e.envFile("env", env)
	if err != nil {
		return Launch{}, err
	}
	var relayEnv []string
	if l.ProxyToken != "" {
		relayEnv = []string{RelayTokenEnv + "=" + l.ProxyToken}
	}
	relayEnvFile, err := e.envFile("relay-env", relayEnv)
	if err != nil {
		return Launch{}, err
	}

	create := []string{"create", "--name", e.relay(), "--label", e.label(), "--network", e.outside()}
	if e.host == hostName {
		create = append(create, "--add-host", hostName+":host-gateway")
	}
	create = append(create, e.hardening()...)
	// The relay is on both networks, so it forwards no packet between them: what it
	// passes on is the connections it copies to the proxy, and nothing routed through it.
	create = append(create, "--sysctl", "net.ipv4.ip_forward=0", "--sysctl", "net.ipv6.conf.all.forwarding=0")
	create = append(create, "--env-file", relayEnvFile, "--read-only", "--mount", helper, "--entrypoint", HelperPath, e.req.Image)
	create = append(create, e.d.RelayArgs...)
	create = append(create, fmt.Sprintf("%d=%s", relayPort, net.JoinHostPort(e.host, port)))
	pull, cancel := context.WithTimeout(ctx, relayWait)
	defer cancel()
	e.made = append(e.made, []string{"rm", "--force", "--volumes", e.relay()})
	if _, err := e.docker(pull, create...); err != nil {
		return Launch{}, err
	}
	var bundle string
	if len(l.CA) > 0 {
		if bundle, err = e.bundle(ctx, l.CA); err != nil {
			return Launch{}, err
		}
	}
	if _, err := e.docker(ctx, "network", "connect", "--alias", relayAlias, e.inside(), e.relay()); err != nil {
		return Launch{}, err
	}
	if _, err := e.docker(ctx, "start", e.relay()); err != nil {
		return Launch{}, err
	}
	if err := e.relayListens(ctx); err != nil {
		return Launch{}, err
	}

	run := []string{"run", "--rm", "--interactive"}
	if l.Interactive {
		run = append(run, "--tty")
	}
	run = append(run, "--name", e.agent(), "--label", e.label(), "--network", e.inside())
	if e.req.Runtime != "" {
		run = append(run, "--runtime", e.req.Runtime)
	}
	if e.req.Docker {
		// The enclosure starts as its root, a user of the machine's that is not root,
		// with the capabilities the runtime gives it inside its user namespace: the
		// daemon needs them. The helper starts the daemon and then the agent as its
		// user, with none. The daemon's store is a volume of the run's, removed with the
		// container.
		run = append(run, "--user", "0:0", "--security-opt", "no-new-privileges", "--init", "--mount", "type=volume,dst="+nestStore)
	} else {
		run = append(run, e.hardening()...)
	}
	run = append(run, limits...)
	run = append(run, "--env-file", envFile, "--workdir", l.Dir, "--mount", helper)
	for _, m := range mounts {
		run = append(run, "--mount", m)
	}
	if bundle != "" {
		run = append(run, "--mount", bundle)
	}
	if e.req.Docker {
		run = append(run, "--entrypoint", HelperPath, e.req.Image)
		run = append(run, e.d.NestArgs...)
		run = append(run, "--user", e.user, "--", l.Command)
	} else {
		run = append(run, "--entrypoint", l.Command, e.req.Image)
	}
	run = append(run, l.Args...)
	e.made = append(e.made, []string{"rm", "--force", "--volumes", e.agent()})
	wrapped := Launch{Command: e.command(), Args: run, Dir: l.Dir}
	if e.env != nil {
		// The docker CLI that starts the agent's container reaches the engine recorded,
		// without the access key's variables, as every other command of the run's.
		wrapped.Env = withSelection(accesskey.WithoutVariables(os.Environ()), e.env)
	}
	return wrapped, nil
}

// Binds lists the adapter's own binds before an enclosure is prepared: the helper,
// read-only, and, read-only, the pattern of the private directories that hold a run's
// environment files and, with a CA, the bundle the enclosure binds.
func (d *Docker) Binds(Launch) ([]Bind, error) {
	if d.Helper == "" {
		return nil, errors.New("wall docker: the helper binary is required")
	}
	return []Bind{
		{Path: d.Helper, ReadOnly: true, Helper: true},
		{Path: TempDirs(), ReadOnly: true, Pattern: true},
	}, nil
}

// Binds lists the adapter's own binds for the launch: the helper, read-only, the hook
// socket's directory, writable, when the launch has a socket, and, read-only, the
// private directory that holds the run's environment files and, with a CA, the bundle
// the enclosure binds, which it makes now.
func (e *dockerEnclosure) Binds(l Launch) ([]Bind, error) {
	out := []Bind{{Path: e.d.Helper, ReadOnly: true, Helper: true}}
	if l.Socket != "" {
		out = append(out, Bind{Path: filepath.Dir(l.Socket)})
	}
	if err := e.makeTemp(); err != nil {
		return nil, err
	}
	return append(out, Bind{Path: e.temp, ReadOnly: true}), nil
}

// makeTemp makes the private directory that holds the run's environment files and
// bundle, once.
func (e *dockerEnclosure) makeTemp() error {
	if e.temp != "" {
		return nil
	}
	dir, err := e.sys.tempDir()
	if err != nil {
		return err
	}
	e.temp = dir
	return nil
}

// bundle writes the file the enclosure trusts: the image's own authorities, read out of
// the relay's container, which is the same image and exists by now, and the run's
// certificate after them. An image that keeps a bundle nowhere known gets the run's
// alone, which serves the hosts the proxy answers as and no other; that is the image's
// to mend. It returns the file's mount.
func (e *dockerEnclosure) bundle(ctx context.Context, ca []byte) (string, error) {
	var image []byte
	for _, p := range imageBundles {
		argv := []string{e.command(), "cp", "--follow-link", e.relay() + ":" + p, "-"}
		out, err := e.sys.output(ctx, argv, e.env)
		if err != nil {
			continue
		}
		if b, err := firstFile(out); err == nil && bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
			image = b
			break
		}
	}
	if err := e.makeTemp(); err != nil {
		return "", err
	}
	file := filepath.Join(e.temp, "ca-bundle.pem")
	if len(image) > 0 && !bytes.HasSuffix(image, []byte("\n")) {
		image = append(image, '\n')
	}
	if err := os.WriteFile(file, append(image, ca...), 0o644); err != nil {
		return "", err
	}
	return mount(file, BundlePath, true)
}

// firstFile is the content of the first file in a tar stream, what docker cp writes.
func firstFile(stream []byte) ([]byte, error) {
	r := tar.NewReader(bytes.NewReader(stream))
	for {
		h, err := r.Next()
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(r, 16<<20))
		}
	}
}

// mounts are the launch's own: what it lists and the socket's directory. The workspace
// is the working directory inside; a mount whose path holds it, by whole components,
// shows it, and a launch none of whose mounts does is refused: the adapter binds
// nothing of the caller's the launch does not list.
func (e *dockerEnclosure) mounts(l Launch) ([]string, error) {
	if !filepath.IsAbs(l.Dir) {
		return nil, fmt.Errorf("wall docker: the workspace %q is not an absolute path", l.Dir)
	}
	var binds []bind
	held := false
	for _, m := range l.Mounts {
		if !filepath.IsAbs(m.Path) {
			return nil, fmt.Errorf("wall docker: the mount %q is not an absolute path", m.Path)
		}
		if e.sys.socket(m.Path) {
			return nil, fmt.Errorf("wall docker: the mount %q is a socket or holds a container runtime's, which an enclosure never gets", m.Path)
		}
		binds = append(binds, bind{m.Path, m.Path, m.ReadOnly})
		held = held || under(m.Path, l.Dir)
	}
	if !held {
		return nil, fmt.Errorf("wall docker: the workspace %q lies in none of the "+
			"launch's mounts", l.Dir)
	}
	if l.Socket != "" {
		binds = append(binds, bind{filepath.Dir(l.Socket), hooksDir, false})
	}
	var out []string
	seen := map[string]bool{}
	for _, b := range binds {
		if seen[b.dst] {
			continue
		}
		seen[b.dst] = true
		m, err := mount(b.src, b.dst, b.readonly)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// under reports whether path is dir or lies below it, by whole components of the
// paths as written.
func under(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	up := ".." + string(filepath.Separator)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, up)
}

// limits are the agent's resource flags. The relay gets none: it is the runner's own.
func limits(l Limits) ([]string, error) {
	var out []string
	if l.CPUs != "" {
		if !cpusShape.MatchString(l.CPUs) {
			return nil, fmt.Errorf("wall docker: the cpus limit %q is not a decimal number", l.CPUs)
		}
		out = append(out, "--cpus", l.CPUs)
	}
	for _, f := range []struct{ flag, name, value string }{{"--memory", "memory", l.Memory}, {"--shm-size", "shm size", l.ShmSize}} {
		if f.value == "" {
			continue
		}
		if !bytesShape.MatchString(f.value) {
			return nil, fmt.Errorf("wall docker: the %s %q is not a number of bytes with a unit of b, k, m or g", f.name, f.value)
		}
		out = append(out, f.flag, f.value)
	}
	if l.PIDs < 0 {
		return nil, fmt.Errorf("wall docker: the pids limit %d is negative", l.PIDs)
	}
	if l.PIDs > 0 {
		out = append(out, "--pids-limit", strconv.Itoa(l.PIDs))
	}
	return out, nil
}

// bind is one directory or file of the host shown inside.
type bind struct {
	src, dst string
	readonly bool
}

// mount is one --mount value. The value is comma-separated fields, so a path holding a
// comma or a quote is refused rather than quoted wrongly.
func mount(src, dst string, readonly bool) (string, error) {
	for _, p := range []string{src, dst} {
		if strings.ContainsAny(p, ",\"\n") {
			return "", fmt.Errorf("wall docker: the path %q holds a comma or a quote and cannot be mounted", p)
		}
	}
	m := "type=bind,src=" + src + ",dst=" + dst
	if readonly {
		m += ",readonly"
	}
	return m, nil
}

// envFile writes the enclosure's environment where only this user reads it. The file's
// format is a line per variable with no quoting, so a value holding a newline cannot be
// passed.
func (e *dockerEnclosure) envFile(name string, env []string) (string, error) {
	var b strings.Builder
	for _, kv := range env {
		// A bare name in the file means the value of the docker command's own variable,
		// which is this machine's.
		if !envShape.MatchString(kv) {
			name, _, _ := strings.Cut(kv, "=")
			return "", fmt.Errorf("wall docker: the environment entry %q is not NAME=value", name)
		}
		if strings.ContainsAny(kv, "\n\r") {
			name, _, _ := strings.Cut(kv, "=")
			return "", fmt.Errorf("wall docker: the value of %s holds a line break and cannot be passed", name)
		}
		b.WriteString(kv + "\n")
	}
	if err := e.makeTemp(); err != nil {
		return "", err
	}
	file := filepath.Join(e.temp, name)
	return file, os.WriteFile(file, []byte(b.String()), 0o600)
}

// relayListens polls the relay's output for [RelayReady]. A relay that exited instead
// is an error carrying what it printed.
func (e *dockerEnclosure) relayListens(ctx context.Context) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, err := e.docker(ctx, "logs", e.relay())
		if err != nil {
			return err
		}
		if bytes.Contains(out, []byte(RelayReady)) {
			return nil
		}
		if state, err := e.docker(ctx, "inspect", "--format", "{{.State.Running}}", e.relay()); err == nil && strings.TrimSpace(string(state)) == "false" {
			return fmt.Errorf("wall docker: the relay exited: %s", bytes.TrimSpace(out))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wall docker: the relay did not listen: %s", bytes.TrimSpace(out))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// closeWait is how long removing everything may take.
const closeWait = 30 * time.Second

// Close removes the containers and the networks, newest first, and the environment
// file. What is already gone, or was never made, is not an error.
func (e *dockerEnclosure) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, closeWait)
	defer cancel()
	var errs []error
	for i := len(e.made) - 1; i >= 0; i-- {
		out, err := e.docker(ctx, e.made[i]...)
		if gone := bytes.ToLower(out); err != nil && !bytes.Contains(gone, []byte("no such")) && !bytes.Contains(gone, []byte("not found")) {
			errs = append(errs, err)
		}
	}
	e.made = nil
	if e.temp != "" {
		errs = append(errs, os.RemoveAll(e.temp))
		e.temp = ""
	}
	return errors.Join(errs...)
}

// Reap removes the containers and the networks that carry the run's label: what a
// runner that died left behind. The containers go first, since a network in use stays.
func (d *Docker) Reap(ctx context.Context, runID string) (int, error) {
	if !runIDShape.MatchString(runID) {
		return 0, fmt.Errorf("wall docker: the run id %q cannot name a container", runID)
	}
	sys := d.sys
	if sys == nil {
		sys = hostSystem{}
	}
	e := &dockerEnclosure{d: d, sys: sys, req: Request{RunID: runID}, env: d.selected()}
	ctx, cancel := context.WithTimeout(ctx, closeWait)
	defer cancel()
	removed := 0
	var errs []error
	for _, kind := range []struct{ list, remove []string }{
		{[]string{"ps", "--all", "--quiet"}, []string{"rm", "--force", "--volumes"}},
		{[]string{"network", "ls", "--quiet"}, []string{"network", "rm"}},
	} {
		out, err := e.docker(ctx, append(append([]string{}, kind.list...), "--filter", "label="+e.label())...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, id := range strings.Fields(string(out)) {
			if _, err := e.docker(ctx, append(append([]string{}, kind.remove...), id)...); err != nil {
				errs = append(errs, err)
				continue
			}
			removed++
		}
	}
	return removed, errors.Join(errs...)
}

// hostSystem is the machine itself.
type hostSystem struct{}

func (hostSystem) run(ctx context.Context, argv, env []string) ([]byte, error) {
	return selectedCommand(ctx, argv, env).CombinedOutput()
}

func (hostSystem) output(ctx context.Context, argv, env []string) ([]byte, error) {
	return selectedCommand(ctx, argv, env).Output()
}

// selectedCommand is hostCommand, with the engine's selection in place of the runner's
// own when env is not nil.
func selectedCommand(ctx context.Context, argv, env []string) *exec.Cmd {
	if env == nil {
		return hostCommand(ctx, argv)
	}
	return engineCommand(ctx, argv, env)
}

// hostCommand is a command of the machine's the wall runs, the docker CLI say, with
// the runner's environment without the access key's variables, which neither the CLI
// nor a credential helper it starts receives.
func hostCommand(ctx context.Context, argv []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = accesskey.WithoutVariables(os.Environ())
	return cmd
}

func (hostSystem) local(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.String() == ip {
			return true
		}
	}
	return false
}

func (hostSystem) tempDir() (string, error) { return os.MkdirTemp("", tempPrefix) }

// tempPrefix begins the name of the private directory the adapter writes a run's
// environment files in, the relay's with the proxy's secret among them.
const tempPrefix = "qory-wall-"

// TempDirs is the pattern of the private directories the Docker adapter writes the
// runs' environment files in, the system's temporary directory with qory-wall- and a
// random part: every run's, whichever wall a run has.
func TempDirs() string { return filepath.Join(os.TempDir(), tempPrefix+"*") }

// runtimeSockets are the names a container runtime's socket goes by.
var runtimeSockets = []string{"docker.sock", "podman/podman.sock", "containerd/containerd.sock", "crio/crio.sock"}

func (hostSystem) socket(p string) bool {
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSocket != 0 {
		return true
	}
	if !info.IsDir() {
		return false
	}
	for _, name := range runtimeSockets {
		if s, err := os.Stat(filepath.Join(p, name)); err == nil && s.Mode()&os.ModeSocket != 0 {
			return true
		}
	}
	return false
}

func (hostSystem) ids() (int, int) { return os.Getuid(), os.Getgid() }

// checkHelper opens the helper as the executable a Linux container needs: ELF, and
// static, because the container's image may hold no loader.
func (hostSystem) checkHelper(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("not a Linux executable: %w", err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("dynamically linked; build it with CGO_ENABLED=0")
		}
	}
	return nil
}
