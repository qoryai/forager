package wall

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/program"
	"github.com/qoryai/forager/refusal"
)

// Where things are inside a Docker enclosure.
const (
	// HelperPath is where the helper binary is mounted, read-only. A caller names it in
	// the hook forwarder's command, since the host's own path does not exist inside.
	HelperPath = "/qory/qory"
	// qoryDir holds what the adapter shows the enclosure, the helper, the hooks and the
	// bundle: no mount of the caller's is shown at it, or inside it.
	qoryDir = "/qory"
	// hooksDir is where the directory holding the hook socket is mounted.
	hooksDir = "/qory/hooks"
	// BundlePath is where the enclosure finds the authorities it trusts when the run has
	// one of its own: the image's bundle and the run's certificate, in one file.
	BundlePath = "/qory/ca-bundle.pem"
	// relayAlias is the name the agent reaches the relay by, and relayPort the port the
	// relay forwards to the proxy.
	relayAlias = "qory-proxy"
	relayPort  = 3128
	// setupAlias is the name the agent reaches the setup container by, on the inside
	// network.
	setupAlias = "qory-setup"
	// hostName is the name an ordinary container reaches the engine's host by.
	hostName = "host.docker.internal"
)

// Docker is the wall built with the docker command, and with podman or nerdctl when the
// conformance suite passes for them. It uses the command and no library, and serves
// whatever engine that command reaches.
//
// One *Docker serves one run at a time: [Docker.Engine] records that run's engine
// selection on it, and every engine command of the adapter's runs with it.
//
// A run gets two networks and the relay's container when it opens, the agent's
// container for each session, and, with setup outside, the setup container, which runs
// until the session removes it or the run closes. When the relay starts from another
// image, the wall reads the run's image's files out of a container of that image, never
// started and on no network. The agent's container and the setup container are on a
// network created with --internal and on nothing else, so they have no route out and
// their resolver knows only that network; the network's bridge gets no address, so the
// engine's host is not on it either. For any image the network has no IPv6 subnet, and
// the agent's container starts with no IPv6 address but loopback's. With nested Docker,
// which needs the docker command and Docker Engine 28 or later, the network has an IPv6
// subnet, the engine's choice, in Docker's isolated gateway mode: the bridge has IPv6 off and no
// address. The relay's container is on that network and on an ordinary one; it runs
// [Relay], forwarding one port to the gateway, listens on its addresses on the internal
// network alone, and is the one peer of the agent's with a way out. The agent reaches the
// setup container by its name, qory-setup. Each runs as a user that is not root, with
// every capability dropped and no new privileges.
type Docker struct {
	// Command is the program to run; empty means docker.
	Command string
	// Helper is the path on this machine of a static Linux build, for the engine's
	// architecture, of the binary that runs the relay and the hook forwarder. It is
	// mounted read-only at [HelperPath] in each container of the run's.
	Helper string
	// RelayArgs are the arguments that make Helper run [Relay]; the forwards follow
	// them.
	RelayArgs []string
	// NestArgs are the arguments that make Helper run [Nest], for an image with a Docker
	// of the agent's own; the user and the launch follow them. Without them such an
	// image is refused. Experimental: see contracts/forager/v1/README.md §The wall.
	NestArgs []string
	// HoldArgs are the arguments that make Helper run [Hold], the entrypoint of a run's
	// setup container, which keeps the container running until it is removed. Without
	// them the setup container does not start.
	HoldArgs []string
	// CAEnv names the variables that point a program at [BundlePath] when the run has
	// an authority of its own; nil means [DefaultCAEnv]. A program that reads another
	// is served by naming it here.
	CAEnv []string
	// User is the uid:gid each container of the run's runs as; empty means the uid:gid
	// of this process, so the workspace's files keep their owner. Root is refused.
	User string
	// CertsDir is the directory the engine reads a registry's authorities from, a
	// directory per registry host, such as /etc/docker/certs.d/registry.example; empty
	// means /etc/docker/certs.d. [Docker.Pull] writes the run's certificate there.
	CertsDir string

	sys system

	// recorded is the engine's command and selection as [Docker.Engine] recorded them;
	// every engine command of the adapter's then runs with the selection. nil until
	// they are recorded, or when a variable was left out.
	selectionMu sync.Mutex
	recorded    *Engine
}

// selected is the engine's selection the adapter's commands run with, nil for
// Forager's own environment.
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
	// not nil, is the selection of the engine the command reaches, in place of
	// Forager's own.
	run(ctx context.Context, argv, env []string) ([]byte, error)
	// output runs a command and returns its standard output alone; env is as for run.
	output(ctx context.Context, argv, env []string) ([]byte, error)
	// stdout starts a command and returns its standard output as it comes; env is as
	// for run. Close waits for the command, and kills it first when its output was not
	// read to the end, so a reader that stops early stops the command too.
	stdout(ctx context.Context, argv, env []string) (io.ReadCloser, error)
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
	// stream runs a command with its standard output and standard error going to stdout
	// and stderr as they come, and returns its exit status; env is as for run. An error
	// is a command that did not start or a signal that ended it.
	stream(ctx context.Context, argv, env []string, stdout, stderr io.Writer) (int, error)
	// input runs a command with stdin as its standard input and returns its output,
	// standard error included; env is as for run.
	input(ctx context.Context, argv, env []string, stdin []byte) ([]byte, error)
}

// Sets lists the variables the enclosure's environment receives from the adapter
// itself: the proxy's, the hook socket's and the ones that point a program at the
// run's bundle.
func (d *Docker) Sets() []string {
	var out []string
	for _, kv := range link.ProxyEnv("") {
		name, _, _ := strings.Cut(kv, "=")
		out = append(out, name)
	}
	return append(append(out, link.EnvRunSocket), d.SetsWithAuthority()...)
}

// SetsWithAuthority lists the variables of [Docker.Sets] the adapter sets only for a
// run with an authority: the ones that point a program at the run's bundle, CAEnv, or
// DefaultCAEnv when it is nil.
func (d *Docker) SetsWithAuthority() []string {
	if d.CAEnv != nil {
		return slices.Clone(d.CAEnv)
	}
	return slices.Clone(DefaultCAEnv)
}

// Files lists the adapter's own files on this machine: the directory of the docker
// command, found in PATH as the adapter runs it, the directory of the helper, each with
// the directory of the file a symbolic link leads to, the command's configuration
// directory, DOCKER_CONFIG as the command reads it, else ~/.docker, whose context and
// credential helpers name programs the command starts, and CertsDir, where a
// certificate an agent wrote would be one the engine trusts for a registry.
func (d *Docker) Files() []string {
	out := program.Dirs(d.command())
	certs := d.CertsDir
	if certs == "" {
		certs = defaultCertsDir
	}
	if abs, err := filepath.Abs(certs); err == nil {
		out = append(out, abs)
	}
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

// BundleFiles are the files, in order, where a system keeps its authorities as PEM:
// those the wall reads out of an image, which a machine without a wall keeps at the
// same paths, macOS's /etc/ssl/cert.pem among them.
func BundleFiles() []string { return slices.Clone(imageBundles) }

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
// this machine's loopback by a name. A request with Pull needs no image yet: the first
// container of the run's image finds it by its digest, which [Docker.Pull] fetched.
func (d *Docker) Prepare(ctx context.Context, req Request) (Enclosure, error) {
	sys, user, err := d.checked(req)
	if err != nil {
		return nil, err
	}
	e := &dockerEnclosure{d: d, sys: sys, req: req, user: user, base: "qory-" + req.RunID,
		env: d.selected()}
	if req.Docker {
		if err := e.nestEngine(ctx); err != nil {
			return nil, err
		}
	}
	return e.prepare(ctx)
}

// checked checks the request and the adapter before any command runs, for
// [Docker.Prepare] and [Docker.Pull] alike, and returns the system and the wall's user.
func (d *Docker) checked(req Request) (system, string, error) {
	sys := d.sys
	if sys == nil {
		sys = hostSystem{}
	}
	if !runIDShape.MatchString(req.RunID) {
		return nil, "", fmt.Errorf("wall docker: the run id %s cannot name a container", accesskey.ShownName(req.RunID, true))
	}
	if !imageShape.MatchString(req.Image) {
		return nil, "", fmt.Errorf("wall docker: %s is not an image reference", accesskey.ShownName(req.Image, true))
	}
	if req.RelayImage != "" && !imageShape.MatchString(req.RelayImage) {
		return nil, "", fmt.Errorf("wall docker: %s is not an image reference", accesskey.ShownName(req.RelayImage, true))
	}
	if req.Pull && req.Docker {
		return nil, "", errors.New("wall docker: an image a run names by its reference never gets nested Docker")
	}
	if req.Runtime != "" && !runtimeShape.MatchString(req.Runtime) {
		return nil, "", fmt.Errorf("wall docker: %s is not a container runtime's name", accesskey.ShownName(req.Runtime, true))
	}
	if req.Docker && req.Runtime == "" {
		return nil, "", errors.New("wall docker: nested Docker needs a runtime that runs it without privileges, such as sysbox-runc; a privileged container is never an enclosure")
	}
	if req.Docker && len(d.NestArgs) == 0 {
		return nil, "", errors.New("wall docker: nested Docker needs the helper's arguments that start it")
	}
	if d.Helper == "" || len(d.RelayArgs) == 0 {
		return nil, "", errors.New("wall docker: the helper binary and its relay arguments are required")
	}
	if err := sys.checkHelper(d.Helper); err != nil {
		return nil, "", fmt.Errorf("wall docker: helper %s: %w", accesskey.ShownValue(d.Helper, false), accesskey.ShownError(err))
	}
	user := d.User
	if user == "" {
		uid, gid := sys.ids()
		user = fmt.Sprintf("%d:%d", uid, gid)
	}
	if !userShape.MatchString(user) {
		return nil, "", fmt.Errorf("wall docker: the user %s is not uid[:gid] or a name", accesskey.ShownName(user, true))
	}
	uid, _, _ := strings.Cut(user, ":")
	if n, err := strconv.Atoi(uid); uid == "root" || (err == nil && n == 0) {
		return nil, "", errors.New("wall docker: the agent does not run as root; name a user")
	}
	// The engine reads a user's name, and a uid's group and groups, out of the image's
	// /etc/passwd and /etc/group, which an image a run names by its reference writes:
	// such an image runs only under a uid and a gid, neither 0, that it cannot remap.
	if req.Pull && !numericUser(user) {
		return nil, "", fmt.Errorf("wall docker: an image a run names by its reference needs the wall's user as uid:gid in numbers, neither of them 0, not %s, which the image's /etc/passwd or /etc/group would resolve", accesskey.ShownName(user, true))
	}
	// The relay of a run in an image by reference starts from the machine's image, never
	// from the run's, which may be anything.
	if req.Pull && req.RelayImage == "" {
		return nil, "", errors.New("wall docker: an image a run names by its reference needs the machine's image for the relay, RelayImage")
	}
	return sys, user, nil
}

// prepare makes the run's networks, once the request is checked and an image by
// reference found.
func (e *dockerEnclosure) prepare(ctx context.Context) (Enclosure, error) {
	req, sys := e.req, e.sys
	// What removes a thing is noted before the thing is asked for: a command cut off by
	// the context may still have been carried out by the engine.
	//
	// The inside network's bridge gets no address of the host's, so the network's
	// gateway is not the engine's host. For any image the network is created with no
	// IPv6 subnet, whatever the daemon's default. With nested Docker it is created with
	// an IPv6 subnet, the engine's choice, in the isolated gateway mode, where the bridge
	// has IPv6 off and no address.
	create := []string{"network", "create", "--internal"}
	if req.Docker {
		create = append(create, "--ipv6", "--opt", "com.docker.network.bridge.gateway_mode_ipv6=isolated")
	} else {
		create = append(create, "--ipv6=false")
	}
	create = append(create, "--opt", "com.docker.network.bridge.inhibit_ipv4=true", "--label", e.label(), e.inside())
	e.made = append(e.made, []string{"network", "rm", e.inside()})
	if _, err := e.docker(ctx, create...); err != nil {
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
	// The relay listens on its address in the inside network's subnets and on no other:
	// on the ordinary network, what reaches it would have its connections opened with
	// the proxy's secret. The engine gives the relay its address there only when it
	// starts, so the relay finds it by the subnet.
	out, err = e.docker(ctx, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", e.inside())
	if err != nil {
		return nil, errors.Join(err, e.Close(context.WithoutCancel(ctx)))
	}
	e.subnets = strings.Fields(string(out))
	if req.Docker && !slices.ContainsFunc(e.subnets, ipv6Subnet) {
		return nil, errors.Join(errors.New("wall docker: the inside network got no IPv6 subnet"), e.Close(context.WithoutCancel(ctx)))
	}
	return e, nil
}

// ipv6Subnet reports whether s, written as CIDR, is an IPv6 subnet.
func ipv6Subnet(s string) bool {
	ip, _, err := net.ParseCIDR(s)
	return err == nil && ip.To4() == nil
}

// nestFloor is the first major version of Docker Engine whose bridge networks take
// the isolated gateway mode, which nested Docker needs.
const nestFloor = 28

// engineVersion is the format that makes docker version print the version of the
// engine's Engine component alone, and engineVersionShape the shape of what it prints.
const engineVersion = `{{range .Server.Components}}{{if eq .Name "Engine"}}{{.Version}}{{end}}{{end}}`

var engineVersionShape = regexp.MustCompile(`^([0-9]+)\.[0-9]+(\.[0-9]+)?([-+~][0-9A-Za-z.+~-]*)?$`)

// nestEngine refuses an engine that cannot give nested Docker its inside network: a
// command other than docker, or a Docker Engine before [nestFloor]. It runs before
// anything is made.
func (e *dockerEnclosure) nestEngine(ctx context.Context) error {
	if name := e.d.Name(); name != "docker" {
		return fmt.Errorf("wall docker: nested Docker needs the docker command and Docker Engine 28 or later, not %s", accesskey.ShownValue(name, false))
	}
	out, err := e.sys.run(ctx, []string{e.command(), "version", "--format", engineVersion}, e.env)
	if err != nil {
		if said := bytes.TrimSpace(out); len(said) > 0 {
			err = fmt.Errorf("%w: %s", accesskey.ShownError(err), accesskey.ShownValue(string(said), false))
		}
		return fmt.Errorf("wall docker: docker version: %w", accesskey.ShownError(err))
	}
	version := string(bytes.TrimSpace(out))
	m := engineVersionShape.FindStringSubmatch(version)
	if m == nil {
		return errors.New("wall docker: nested Docker needs Docker Engine 28 or later; the engine gave no Docker Engine version")
	}
	if major, err := strconv.Atoi(m[1]); err != nil || major < nestFloor {
		return fmt.Errorf("wall docker: nested Docker needs Docker Engine 28 or later; the engine is %s", version)
	}
	return nil
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
	// subnets are the inside network's, where the relay listens.
	subnets []string
	// made holds the commands that remove what was created, in the order created.
	made [][]string
	temp string
	// env is the engine's selection every command of the run's runs with, nil for
	// Forager's own environment.
	env []string
	// created is true once the never-started container of the run's image exists, which
	// the image's files are read out of.
	created bool
	// relayed is true once the relay listens. used is true once the run's first use of
	// the enclosure ran, [dockerEnclosure.firstUse], and bundleMount is then the
	// bundle's --mount, empty for a run without an authority.
	relayed     bool
	used        bool
	bundleMount string
	// setupDir is the setup container's working directory and setupEnv the path of its
	// environment file, both empty until the setup container starts.
	setupDir, setupEnv string
	// placed is the place of the last transcript directory worked out, which
	// CheckTranscript and then Wrap read.
	placed *transcriptPlace
}

func (e *dockerEnclosure) inside() string  { return e.base + "-in" }
func (e *dockerEnclosure) outside() string { return e.base + "-out" }
func (e *dockerEnclosure) relay() string   { return e.base + "-relay" }
func (e *dockerEnclosure) agent() string   { return e.base + "-agent" }
func (e *dockerEnclosure) image() string   { return e.base + "-image" }
func (e *dockerEnclosure) setup() string   { return e.base + "-setup" }
func (e *dockerEnclosure) label() string   { return "dev.qory.run=" + e.req.RunID }

// docker runs one docker command; a failure carries what the command printed.
func (e *dockerEnclosure) docker(ctx context.Context, args ...string) ([]byte, error) {
	argv := append([]string{e.command()}, args...)
	out, err := e.sys.run(ctx, argv, e.env)
	if err != nil {
		return out, fmt.Errorf("wall docker: %s: %w: %s", accesskey.ShownValue(strings.Join(argv[:min(3, len(argv))], " "), false), accesskey.ShownError(err), accesskey.ShownValue(string(bytes.TrimSpace(out)), false))
	}
	return out, nil
}

func (e *dockerEnclosure) command() string { return e.d.command() }

// ProxyAddr is the gateway's address when this machine holds it, else loopback.
func (e *dockerEnclosure) ProxyAddr() string {
	if e.host == hostName {
		return link.Loopback
	}
	return net.JoinHostPort(e.host, "0")
}

// hardening is what both containers run with: not root, no capabilities, no way to
// gain any, and an init that reaps and passes signals on.
func (e *dockerEnclosure) hardening() []string {
	return []string{"--user", e.user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--init"}
}

// relayWait is how long the relay has to listen, the image's pull included, and how
// long the run's image has to be pulled when it is not the relay's.
const relayWait = 5 * time.Minute

// pullWait is how long the pull of an image a run names by its reference may take.
const pullWait = 10 * time.Minute

// pull fetches the image a run names by its reference with docker pull, under
// [pullWait], also when the engine holds it by that digest, so the engine fetches the
// layers it lacks: through the run's proxy when the session gives it an engine proxy,
// else over the machine's network with the engine's credentials. A pull is no check of
// the run's right to the image: on the classic image store the engine answers a pull of
// an image it holds from its cache of manifests. The session checks the manifest at the
// registry with the run's credentials before it calls Pull. pull refuses an image whose
// user is root, image_user_root: no user, root, a uid of 0 in any spelling, with or
// without a group, or a name the image's /etc/passwd maps to uid 0. A name the image
// cannot map, for want of /etc/passwd or of the name in it, is refused as well, since
// it cannot be checked. The agent runs as the wall's user whatever the image's, and that user is uid:gid in numbers, which Prepare requires
// for such an image, so neither the image's /etc/passwd nor its /etc/group chooses who
// the agent is; this keeps an image that expects root out of the run. An image its
// registry does not have is image_missing, [dockerEnclosure.fetch].
func (e *dockerEnclosure) pull(ctx context.Context) error {
	fetch, cancel := context.WithTimeout(ctx, pullWait)
	defer cancel()
	if err := e.fetch(fetch); err != nil {
		return err
	}
	config, err := e.imageConfig(ctx)
	if err != nil {
		return err
	}
	var user string
	if config != nil {
		user = config.User
	}
	name, _, _ := strings.Cut(strings.TrimSpace(user), ":")
	image := accesskey.ShownName(e.req.Image, false)
	root := func() error {
		return refusal.New(refusal.ImageUserRoot, []string{image}, "the image %s runs as root; a run's image runs as the wall's user", image)
	}
	switch {
	case name == "" || name == "root":
		return root()
	case uidShape.MatchString(name):
		if strings.Trim(name, "0") == "" {
			return root()
		}
		return nil
	}
	unchecked := func() error {
		return refusal.New(refusal.ImageUserRoot, []string{image}, "the image %s runs as the user %s, which no /etc/passwd of the image maps to a uid, so it cannot be checked for root; a run's image runs as the wall's user", image, accesskey.ShownName(name, false))
	}
	passwd, err := e.imageFile(ctx, "/etc/passwd")
	if err != nil {
		return unchecked()
	}
	uid, ok := passwdUID(passwd, name)
	switch {
	case !ok:
		return unchecked()
	case strings.Trim(uid, "0") == "":
		return root()
	}
	return nil
}

// fetch runs docker pull of the run's image. A pull whose output shows that the image's
// registry has no manifest of the reference, or no repository of its name, [imageMissing],
// is image_missing, with the reference as its name; when the engine pulls from the
// image's registry alone, any other failure, such as a denied pull, an unreachable
// registry or a timeout, is the pull's error. On the containerd image store of Docker
// Engine 29 (containerd 2.x), a 404 from a mirror is image_missing when the upstream
// cannot be reached or its authorization fails; a 403 or another error status from the
// upstream is a failure with no code. The classic image store, and containerd 1.7 in
// Docker 26 and 27, return the upstream's error.
func (e *dockerEnclosure) fetch(ctx context.Context) error {
	out, err := e.docker(ctx, "pull", e.req.Image)
	if err != nil && imageMissing(out) {
		image := accesskey.ShownName(e.req.Image, false)
		return refusal.New(refusal.ImageMissing, []string{image}, "the image %s is not in its registry", image)
	}
	return err
}

// What docker pull prints, Docker Engine 26 to 29, when the image's registry has no
// manifest of it. With the classic image store (moby's distribution/errors.go), the line
// contains the registry's error code in lower case: manifestUnknown for MANIFEST_UNKNOWN,
// nameUnknown for NAME_UNKNOWN. The line for DENIED, "pull access denied for <name>,
// repository does not exist or may require 'docker login': denied: …", and the line for
// UNAUTHORIZED match neither. The containerd image store's resolver (containerd 2.x's
// core/remotes/docker/resolver.go, and remotes/docker/resolver.go in containerd 1.7,
// which Docker 26 and 27 use) reads no error code: after a 404 to the request for the
// manifest, the line is notResolved, the reference twice and then "not found".
var (
	manifestUnknown = regexp.MustCompile(`manifest for \S+ not found: manifest unknown: `)
	nameUnknown     = regexp.MustCompile(`repository \S+ not found: name unknown: `)
	notResolved     = regexp.MustCompile(`(?m)failed to resolve reference "([^"\s]+)": (\S+): not found$`)
)

// imageMissing reports whether the output of docker pull shows that the image's registry
// has no manifest of the reference or no repository of its name.
func imageMissing(out []byte) bool {
	if manifestUnknown.Match(out) || nameUnknown.Match(out) {
		return true
	}
	for _, m := range notResolved.FindAllSubmatch(out, -1) {
		if bytes.Equal(m[1], m[2]) {
			return true
		}
	}
	return false
}

// Pull is [Puller.Pull] for a run's image by reference: it checks the request as
// Prepare does, then, with ca, writes ca as qory-run-<id>.crt, id the run's, in the
// directory of CertsDir for the registry host of req.Image and for each of hosts, runs
// the pull, docker pull also of an image the engine holds by that digest, and the check
// of its user, under [pullWait], and removes the certificates and the container it read
// the image's /etc/passwd from, in deferred calls that also run on a panic. A host that
// cannot be a directory name, such as a *. pattern, gets no certificate. The engine
// reads a host's directory at each pull, so the run's certificate is trusted for the
// pull alone.
func (d *Docker) Pull(ctx context.Context, req Request, ca []byte, hosts []string) (err error) {
	sys, user, err := d.checked(req)
	if err != nil || !req.Pull {
		return err
	}
	if len(ca) > 0 {
		remove, trustErr := Trust(d.CertsDir, req.RunID, ca, append([]string{registryHost(req.Image)}, hosts...))
		if trustErr != nil {
			return trustErr
		}
		defer func() { err = errors.Join(err, remove()) }()
	}
	e := &dockerEnclosure{d: d, sys: sys, req: req, user: user, base: "qory-" + req.RunID, env: d.selected()}
	defer func() { err = errors.Join(err, e.Close(context.WithoutCancel(ctx))) }()
	return e.pull(ctx)
}

// defaultCertsDir is where Docker Engine reads a registry's authorities from.
const defaultCertsDir = "/etc/docker/certs.d"

// certsHost is the shape of a registry host that a directory of CertsDir is named
// after: a host name or an IPv4 address in lower case, with an optional port.
var certsHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)

// Trust writes ca as qory-run-<runID>.crt in dir/<host>/ for each of hosts, once per
// host, making dir/<host> when it is missing, and returns what removes the files and
// every directory it made. Empty dir means /etc/docker/certs.d, where Docker Engine
// reads a registry's authorities from. A host name or an IPv4 address in lower case,
// with an optional port, gets a certificate; any other host, such as a *. pattern,
// gets none. A symbolic link at dir/<host> or at the file is refused. The writes and
// the removals go through an [os.Root] of dir, whose calls fail on a symbolic link out
// of dir, also one made after that check, and follow one that stays inside dir. A hard
// link at the file name is written through, and the file it links to is overwritten,
// also one outside dir, so dir must be writable only by the run's user. A failure to
// write removes what was written before it.
func Trust(dir, runID string, ca []byte, hosts []string) (func() error, error) {
	if dir == "" {
		dir = defaultCertsDir
	}
	// files and made are names in dir, as the os.Root of dir takes them.
	var files, made []string
	remove := func() error {
		if len(files) == 0 && len(made) == 0 {
			return nil
		}
		var errs []error
		root, err := os.OpenRoot(dir)
		if err != nil {
			for _, f := range files {
				errs = append(errs, unremoved(dir, f, err))
			}
			return errors.Join(errs...)
		}
		defer root.Close()
		for _, f := range files {
			if err := root.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, unremoved(dir, f, err))
			}
		}
		for _, m := range made {
			root.Remove(m)
		}
		return errors.Join(errs...)
	}
	var root *os.Root
	defer func() {
		if root != nil {
			root.Close()
		}
	}()
	seen := map[string]bool{}
	for _, host := range hosts {
		if seen[host] || !certsHost.MatchString(host) {
			continue
		}
		seen[host] = true
		if root == nil {
			r, err := os.OpenRoot(dir)
			if err != nil {
				return nil, errors.Join(unwritten(dir, host, err), remove())
			}
			root = r
		}
		info, err := root.Lstat(host)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := root.Mkdir(host, 0o755); err != nil {
				return nil, errors.Join(unwritten(dir, host, inDir(dir, err)), remove())
			}
			made = append(made, host)
		case err == nil && info.Mode()&fs.ModeSymlink != 0:
			return nil, errors.Join(linked("Replace the symbolic link "+accesskey.ShownValue(filepath.Join(dir, host), false)+" with a directory", host), remove())
		}
		f := filepath.Join(host, "qory-run-"+runID+".crt")
		if info, err := root.Lstat(f); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			return nil, errors.Join(linked("Remove the symbolic link "+accesskey.ShownValue(filepath.Join(dir, f), false), host), remove())
		}
		if trustPause != nil {
			trustPause(filepath.Join(dir, f))
		}
		// A write through a symbolic link out of dir fails in the os.Root, also one made
		// after the checks.
		if err := root.WriteFile(f, ca, 0o644); err != nil {
			return nil, errors.Join(unwritten(dir, host, inDir(dir, err)), remove())
		}
		files = append(files, f)
	}
	return remove, nil
}

// inDir is err of an os.Root of dir as the os functions give it: the path in dir
// joined to dir, so the error shows the whole path, and mkdirat, openat and removeat
// as mkdir, open and remove.
func inDir(dir string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		if !filepath.IsAbs(pe.Path) {
			pe.Path = filepath.Join(dir, pe.Path)
		}
		if op, ok := strings.CutSuffix(pe.Op, "at"); ok && (op == "mkdir" || op == "open" || op == "remove") {
			pe.Op = op
		}
	}
	return err
}

// unremoved is the error of the run's certificate f, a name in dir, that could not be
// removed.
func unremoved(dir, f string, err error) error {
	full := filepath.Join(dir, f)
	host := filepath.Base(filepath.Dir(full))
	return fmt.Errorf("Remove %s by hand: the run's certificate stays trusted for %s until it is removed (%s).", accesskey.ShownValue(full, false), accesskey.ShownValue(host, false), accesskey.ShownError(inDir(dir, err)))
}

// trustPause is what Trust calls with the certificate's path after its checks and
// before the write; nil for nothing. Tests set it.
var trustPause func(path string)

// linked is the error of a symbolic link where the run's certificate for host would be
// written, a directory of dir or the file in it, with fix first.
func linked(fix, host string) error {
	return fmt.Errorf("%s: the run's certificate for %s is not written through the symbolic link.", fix, accesskey.ShownValue(host, false))
}

// unwritten is the error of a certificate for host that could not be written in dir.
func unwritten(dir, host string, err error) error {
	return fmt.Errorf("Make %s writable for this user, as the machine's start unit does: the run's certificate for %s could not be written (%s).", accesskey.ShownValue(dir, false), accesskey.ShownValue(host, false), accesskey.ShownError(err))
}

// registryHost is the registry host of an image reference as the engine reads it,
// docker.io for a name whose first part has no dot or colon and is not localhost.
func registryHost(ref string) string {
	domain, _, _ := strings.Cut(fullReference(ref), "/")
	return domain
}

// RegistryManifest is where the registry of an image a run names by its reference,
// NAME@sha256:…, serves the image's manifest, as the engine reads the reference: host is
// the registry's API host, registry-1.docker.io for docker.io; repository is the path
// after the host, in library/ for a docker.io name of one part; digest is sha256:….
func RegistryManifest(ref string) (host, repository, digest string) {
	name, digest, _ := strings.Cut(fullReference(ref), "@")
	host, repository, _ = strings.Cut(name, "/")
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	return host, repository, digest
}

// held reports whether the engine holds the image a run names by its reference by that
// very reference: the image inspect of NAME@sha256:… answers, and NAME@sha256:… is among
// the image's repository digests. The same content under another name, or an image whose
// id is the digest, is not held by the reference. An engine that has no such image says
// so, and the image is not held. Any other failure of the inspect, such as an engine
// that cannot be reached, is the run's error, and is never taken for an image the
// engine lacks.
func (e *dockerEnclosure) held(ctx context.Context) (bool, error) {
	argv := []string{e.command(), "image", "inspect", "--format", "{{json .RepoDigests}}", e.req.Image}
	out, err := e.sys.output(ctx, argv, e.env)
	if err != nil {
		said := err.Error()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			said = string(bytes.TrimSpace(exit.Stderr))
		}
		if noSuchImage(said) {
			return false, nil
		}
		if exit != nil {
			return false, fmt.Errorf("wall docker: image inspect %s: %w: %s", accesskey.ShownName(e.req.Image, false), accesskey.ShownError(err), accesskey.ShownValue(said, false))
		}
		return false, fmt.Errorf("wall docker: image inspect %s: %w", accesskey.ShownName(e.req.Image, false), accesskey.ShownError(err))
	}
	var digests []string
	if err := json.Unmarshal(bytes.TrimSpace(out), &digests); err != nil {
		return false, fmt.Errorf("wall docker: the repository digests of %s: %w", accesskey.ShownName(e.req.Image, false), err)
	}
	want := fullReference(e.req.Image)
	return slices.ContainsFunc(digests, func(d string) bool { return fullReference(d) == want }), nil
}

// noSuchImage reports whether an engine's answer to an image inspect says it has no such
// image: Docker's and nerdctl's "No such image", Podman's "image not known".
func noSuchImage(said string) bool {
	said = strings.ToLower(said)
	return strings.Contains(said, "no such image") || strings.Contains(said, "image not known")
}

// noSuchContainer reports whether out, the output of a docker rm that failed, contains
// "no such container" in any case: the one failure that shows the container is gone.
// Output with "no such file or directory" or "not found", from a missing engine socket
// or a container runtime that fails, leaves the container's state unknown.
func noSuchContainer(out string) bool {
	return strings.Contains(strings.ToLower(out), "no such container")
}

// fullReference is a reference pinned by digest, NAME@sha256:…, with its registry and
// path in full, as the engine reads it: a NAME whose first part holds no dot or colon
// and is not localhost is on docker.io, and a docker.io NAME of one part is in library/.
// An engine lists a repository digest in either form.
func fullReference(ref string) string {
	name, digest, _ := strings.Cut(ref, "@")
	domain, rest, ok := strings.Cut(name, "/")
	if !ok || (!strings.ContainsAny(domain, ".:") && domain != "localhost") {
		domain, rest = "docker.io", name
	}
	if domain == "index.docker.io" {
		domain = "docker.io"
	}
	if domain == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	return domain + "/" + rest + "@" + digest
}

// imageConf is what the wall reads of an image's Config: its user and its
// environment.
type imageConf struct {
	User string
	Env  []string
}

// imageConfig is the Config of the run's image, nil when it has none. It is the whole
// Config, since an image that sets no user has no User in it, which a template of
// .Config.User fails on; no Config at all is no user either.
func (e *dockerEnclosure) imageConfig(ctx context.Context) (*imageConf, error) {
	argv := []string{e.command(), "image", "inspect", "--format", "{{json .Config}}", e.req.Image}
	out, err := e.sys.output(ctx, argv, e.env)
	if err != nil {
		return nil, fmt.Errorf("wall docker: image inspect: %w", accesskey.ShownError(err))
	}
	var config *imageConf
	if err := json.Unmarshal(bytes.TrimSpace(out), &config); err != nil {
		return nil, fmt.Errorf("wall docker: the image's user: %w", err)
	}
	return config, nil
}

// numericUser reports whether user is uid:gid in decimal digits, neither of them 0.
func numericUser(user string) bool {
	uid, gid, ok := strings.Cut(user, ":")
	return ok && uidShape.MatchString(uid) && uidShape.MatchString(gid) &&
		strings.Trim(uid, "0") != "" && strings.Trim(gid, "0") != ""
}

// uidShape is a uid written in decimal digits, leading zeros and all.
var uidShape = regexp.MustCompile(`^[0-9]+$`)

// passwdUID is the uid /etc/passwd gives the user name, as written, and whether it
// names the user with a uid of digits.
func passwdUID(passwd []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(strings.TrimSuffix(line, "\r"), ":")
		if len(f) >= 3 && f[0] == name && uidShape.MatchString(f[2]) {
			return f[2], true
		}
	}
	return "", false
}

// imageFile is a file of the run's image, read out of a container created from it and
// never started, on no network, by [copyOut]: a file over [fileLimit] is an error. The
// container is created once, and removed with the enclosure.
func (e *dockerEnclosure) imageFile(ctx context.Context, p string) ([]byte, error) {
	if err := e.createImage(ctx); err != nil {
		return nil, err
	}
	b, over, err := e.copyOut(ctx, e.image(), p)
	switch {
	case err != nil:
		return nil, err
	case over:
		return nil, fmt.Errorf("wall docker: %s of the image is over %d bytes", p, fileLimit)
	}
	return b, nil
}

// fileLimit is the most of a file the wall reads out of a container, and tarAllowance
// what docker cp may write around it, its tar headers and padding.
const (
	fileLimit    = 16 << 20
	tarAllowance = 64 << 10
)

// copyWait is how long a read of a file out of a container may take.
const copyWait = time.Minute

// copyOut reads the file at p out of the container with docker cp, under [copyWait],
// and returns the first [fileLimit] bytes of its content, and whether it is longer. It
// reads at most fileLimit and [tarAllowance] bytes of what docker cp writes, and stops
// the command there, so an image cannot make the wall hold more, whatever the file's
// size or how well it compresses.
func (e *dockerEnclosure) copyOut(ctx context.Context, container, p string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, copyWait)
	defer cancel()
	r, err := e.sys.stdout(ctx, []string{e.command(), "cp", "--follow-link", container + ":" + p, "-"}, e.env)
	if err != nil {
		return nil, false, err
	}
	stream, readErr := io.ReadAll(io.LimitReader(r, fileLimit+tarAllowance+1))
	closeErr := r.Close()
	over := len(stream) > fileLimit+tarAllowance
	if !over && readErr != nil {
		return nil, false, readErr
	}
	if !over && closeErr != nil {
		return nil, false, closeErr
	}
	b, size, err := firstFile(stream)
	if err != nil {
		return nil, false, err
	}
	return b, over || size > fileLimit, nil
}

// createImage creates the container of the run's image that is never started, once,
// under [relayWait], since it pulls an image the machine defines that the engine does
// not have: the image's files are read out of it, and the image is there before the
// agent's container starts. For an image by reference, and with NeverPull for any
// image, it runs with --pull=never, as the agent's container does.
func (e *dockerEnclosure) createImage(ctx context.Context) error {
	if e.created {
		return nil
	}
	pull, cancel := context.WithTimeout(ctx, relayWait)
	defer cancel()
	e.made = append(e.made, []string{"rm", "--force", "--volumes", e.image()})
	create := []string{"create", "--name", e.image(), "--label", e.label(), "--network", "none"}
	create = append(create, e.neverPull()...)
	create = append(create, "--entrypoint", HelperPath, e.req.Image)
	if out, err := e.docker(pull, create...); err != nil {
		if e.req.Pull {
			return err
		}
		return e.unpulled(e.req.Image, out, err)
	}
	e.created = true
	return nil
}

// neverPull is --pull=never for a container of the run's image: for an image by
// reference, which the engine pulls in the image step alone, and with NeverPull for an
// image the machine defines as well. Without either it is nothing, and the engine pulls
// an image the machine defines that it does not have.
func (e *dockerEnclosure) neverPull() []string {
	if e.req.Pull || e.req.NeverPull {
		return []string{"--pull=never"}
	}
	return nil
}

// unpulled is the error of a docker create or docker run of a container from image,
// one the machine defines, that failed with err after printing out. With NeverPull, an
// engine that has no such image fails the run with what to pull; any other failure is
// err as it is.
func (e *dockerEnclosure) unpulled(image string, out []byte, err error) error {
	if !e.req.NeverPull || !noSuchImage(string(out)) {
		return err
	}
	return fmt.Errorf("Pull the image on this machine before you set the engine proxy: the engine has no image %s, and under an engine proxy the wall pulls only in a run's image step.", accesskey.ShownName(image, false))
}

// relayImage is the image the relay starts from: the machine's default, or the run's
// when the request names none.
func (e *dockerEnclosure) relayImage() string {
	if e.req.RelayImage != "" {
		return e.req.RelayImage
	}
	return e.req.Image
}

// StartRelay starts the relay towards the proxy at l.Proxy, from the request's
// RelayImage, the machine's default, with l.ProxyToken as what it opens every connection
// with, and waits until it listens. The session calls it once the run's forwarder
// listens, as the run opens; Wrap and StartSetup call it when the relay has not started,
// and a relay that started is left as it is. Only l.Proxy and l.ProxyToken are read.
func (e *dockerEnclosure) StartRelay(ctx context.Context, l Launch) error {
	if e.relayed {
		return nil
	}
	_, port, err := net.SplitHostPort(l.Proxy)
	if err != nil {
		return fmt.Errorf("wall docker: the proxy's address: %w", accesskey.ShownError(err))
	}
	helper, err := mount(e.d.Helper, HelperPath, true)
	if err != nil {
		return err
	}
	relayEnv := []string{RelayInsideEnv + "=" + strings.Join(e.subnets, ",")}
	if l.ProxyToken != "" {
		relayEnv = append(relayEnv, RelayTokenEnv+"="+l.ProxyToken)
	}
	relayEnvFile, err := e.envFile("relay-env", relayEnv)
	if err != nil {
		return err
	}
	create := []string{"create", "--name", e.relay(), "--label", e.label(), "--network", e.outside()}
	if e.host == hostName {
		create = append(create, "--add-host", hostName+":host-gateway")
	}
	create = append(create, e.hardening()...)
	// The relay is on both networks, so it forwards no packet between them: what it
	// passes on is the connections it copies to the proxy, and nothing routed through it.
	create = append(create, "--sysctl", "net.ipv4.ip_forward=0", "--sysctl", "net.ipv6.conf.all.forwarding=0")
	if e.req.Docker {
		// Its interface on the inside network has IPv6, and takes no router
		// advertisement: its addresses and routes are the engine's alone.
		create = append(create, "--sysctl", "net.ipv6.conf.all.accept_ra=0", "--sysctl", "net.ipv6.conf.default.accept_ra=0")
	}
	// The relay's image is always one the machine defines: with NeverPull the engine
	// pulls none of it.
	if e.req.NeverPull {
		create = append(create, "--pull=never")
	}
	// The image's health check would run inside the relay, as its user and beside its
	// environment, with the relay's way out; the relay runs none.
	create = append(create, "--env-file", relayEnvFile, "--read-only", "--no-healthcheck", "--mount", helper, "--entrypoint", HelperPath, e.relayImage())
	create = append(create, e.d.RelayArgs...)
	create = append(create, fmt.Sprintf("%d=%s", relayPort, net.JoinHostPort(e.host, port)))
	pull, cancel := context.WithTimeout(ctx, relayWait)
	defer cancel()
	e.made = append(e.made, []string{"rm", "--force", "--volumes", e.relay()})
	if out, err := e.docker(pull, create...); err != nil {
		return e.unpulled(e.relayImage(), out, err)
	}
	if _, err := e.docker(ctx, "network", "connect", "--alias", relayAlias, e.inside(), e.relay()); err != nil {
		return err
	}
	if _, err := e.docker(ctx, "start", e.relay()); err != nil {
		return err
	}
	if err := e.relayListens(ctx); err != nil {
		return err
	}
	e.relayed = true
	return nil
}

// firstUse is what the first container of the run's image needs, once per enclosure:
// for an image by reference, the image held by its digest, which [Docker.Pull] fetched
// before; when the relay starts from another image, the container of the run's image
// that is never started, which the image's files are read out of; and with ca, the
// bundle the enclosure trusts. It returns the bundle's mount, empty without ca.
func (e *dockerEnclosure) firstUse(ctx context.Context, ca []byte) (string, error) {
	if e.used {
		return e.bundleMount, nil
	}
	// A run's image by reference was fetched by Pull, and its user checked: one the
	// engine does not hold by that digest starts no container, and nothing pulls it here.
	if e.req.Pull {
		held, err := e.held(ctx)
		if err == nil && !held {
			err = fmt.Errorf("wall docker: fetch %s with Pull before its first container starts: the engine does not hold it by its digest", accesskey.ShownName(e.req.Image, false))
		}
		if err != nil {
			return "", err
		}
	}
	// The run's image, when the relay's is another, is there before its first container
	// starts, and its files are read from a container made from it.
	if e.relayImage() != e.req.Image {
		if err := e.createImage(ctx); err != nil {
			return "", err
		}
	}
	if len(ca) > 0 {
		b, err := e.bundle(ctx, ca)
		if err != nil {
			return "", err
		}
		e.bundleMount = b
	}
	e.used = true
	return e.bundleMount, nil
}

// Wrap returns the docker run that starts the launch in the agent's container: on the
// internal network only, the launch's mounts at the paths they have on this machine or
// at their Targets, the workspace as the working directory inside one of them, the
// helper read-only, the socket's directory, and the launch's environment through a
// file, so no value is on a command line. It starts the relay first when it has not
// started, [dockerEnclosure.StartRelay], and runs the run's first use of the enclosure
// when no container of the run's image ran it. With a transcript directory it creates
// the agent's container, makes the bind's parents in it, [dockerEnclosure.copyDirs],
// and returns the docker start that attaches to it in place of the docker run. The
// session calls it once for each session.
func (e *dockerEnclosure) Wrap(ctx context.Context, l Launch) (Launch, error) {
	mounts, dir, err := e.mounts(l)
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
	env = append(env, link.ProxyEnv(fmt.Sprintf("http://%s:%d", relayAlias, relayPort))...)
	if l.Socket != "" {
		env = append(env, link.EnvRunSocket+"="+path.Join(hooksDir, filepath.Base(l.Socket)))
	}
	if len(l.CA) > 0 {
		for _, n := range e.d.SetsWithAuthority() {
			env = append(env, n+"="+BundlePath)
		}
	}
	envFile, err := e.envFile("env", env)
	if err != nil {
		return Launch{}, err
	}
	if err := e.StartRelay(ctx, l); err != nil {
		return Launch{}, err
	}
	bundle, err := e.firstUse(ctx, l.CA)
	if err != nil {
		return Launch{}, err
	}
	transcript, place, err := e.transcriptMount(ctx, l)
	if err != nil {
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
	// The image's health check would run inside the agent's container beside its
	// environment, and with a Docker of the agent's own as the enclosure's root; the
	// agent's container runs none.
	run = append(run, "--no-healthcheck")
	if !e.req.Docker {
		// For any image the agent's container starts with no IPv6 address but
		// loopback's: on the inside network, which has no IPv6 subnet, the engine leaves
		// its interface without IPv6, and IPv6 is off by default for an interface made
		// later. Loopback, there before, keeps ::1, which tools dial localhost by. With
		// nested Docker its interface has an address in the inside network's IPv6
		// subnet, and the enclosure's root sets the enclosure's own sysctls.
		run = append(run, "--sysctl", "net.ipv6.conf.default.disable_ipv6=1")
	}
	run = append(run, limits...)
	run = append(run, "--env-file", envFile, "--workdir", l.Dir, "--mount", helper)
	for _, m := range mounts {
		run = append(run, "--mount", m)
	}
	if bundle != "" {
		run = append(run, "--mount", bundle)
	}
	if transcript != "" {
		run = append(run, "--mount", transcript)
	}
	run = append(run, e.neverPull()...)
	if e.req.Docker {
		run = append(run, "--entrypoint", HelperPath, e.req.Image)
		run = append(run, e.d.NestArgs...)
		run = append(run, "--user", e.user, "--", l.Command)
	} else {
		run = append(run, "--entrypoint", l.Command, e.req.Image)
	}
	run = append(run, l.Args...)
	if rm := []string{"rm", "--force", "--volumes", e.agent()}; !slices.ContainsFunc(e.made, func(c []string) bool { return slices.Equal(c, rm) }) {
		e.made = append(e.made, rm)
	}
	if transcript != "" {
		// The agent's container is created first, so the transcript bind's parents are
		// made in it, owned by the agent's user, before the engine makes them owned by
		// root at the start; the launch then starts it.
		run[0] = "create"
		create, cancel := context.WithTimeout(ctx, relayWait)
		out, err := e.docker(create, run...)
		cancel()
		if err != nil {
			return Launch{}, e.unpulled(e.req.Image, out, err)
		}
		if err := e.copyDirs(ctx, place); err != nil {
			return Launch{}, err
		}
		run = []string{"start", "--attach", "--interactive", e.agent()}
	}
	// The docker CLI that starts the agent's container runs without the access key's
	// variables and the run key's, as every other command of the run's, and reaches
	// the engine recorded.
	cli := accesskey.WithoutVariables(os.Environ())
	if e.env != nil {
		cli = withSelection(cli, e.env)
	}
	return Launch{Command: e.command(), Args: run, Env: cli, Dir: dir}, nil
}

// Unwrap removes the agent's container that Wrap's launch started, within closeWait,
// as its session ends, so the next session's container can take its name. A docker rm
// that fails with [noSuchContainer]'s text is not an error: docker run --rm removes a
// container that exits. Every other failure is, and the container stays for Close to
// remove: an engine that cannot be reached leaves its state unknown, and under
// live-restore it still runs. Everything else the enclosure made stays until Close.
func (e *dockerEnclosure) Unwrap(ctx context.Context) error {
	return e.removeContainer(ctx, e.agent(), noSuchContainer)
}

// removeContainer removes one container of e.made with docker rm --force --volumes,
// within closeWait, and returns once the engine removed it: the engine kills what still
// runs in it. A failed command whose output gone accepts is not an error. On any other
// failure the entry stays in e.made, so Close tries again.
func (e *dockerEnclosure) removeContainer(ctx context.Context, name string, gone func(out string) bool) error {
	ctx, cancel := context.WithTimeout(ctx, closeWait)
	defer cancel()
	rm := []string{"rm", "--force", "--volumes", name}
	if err := e.remove(ctx, rm, gone); err != nil {
		return err
	}
	e.made = slices.DeleteFunc(e.made, func(c []string) bool { return slices.Equal(c, rm) })
	return nil
}

// StartSetup starts the setup container from the run's image with docker run --detach:
// on the internal network alone, where the agent reaches it by the name qory-setup,
// with the agent's flags and the launch's limits, the launch's mounts at their paths or
// their Targets, the workspace as its working directory, the helper and, with l.CA, the
// bundle read-only. Its environment, through a file, is the relay's proxy variables,
// with l.CA the variables that point a program at the bundle, and then l.Env. Its
// entrypoint is the helper with HoldArgs, [Hold], so it runs until
// [dockerEnclosure.RemoveSetup] or Close removes it. It starts the relay first when it
// has not started, [dockerEnclosure.StartRelay], and runs the run's first use of the
// enclosure when no container of the run's image ran it, as Wrap does. l.Command, l.Args,
// l.Interactive and l.Socket are not read: the setup container gets no hook socket.
func (e *dockerEnclosure) StartSetup(ctx context.Context, l Launch) error {
	if len(e.d.HoldArgs) == 0 {
		return errors.New("wall docker: setup needs the helper's arguments that keep the setup container running, HoldArgs")
	}
	if e.setupEnv != "" {
		return errors.New("wall docker: the setup container of the run started already")
	}
	l.Socket = ""
	mounts, _, err := e.mounts(l)
	if err != nil {
		return err
	}
	helper, err := mount(e.d.Helper, HelperPath, true)
	if err != nil {
		return err
	}
	limits, err := limits(l.Limits)
	if err != nil {
		return err
	}
	// Everything that can be refused is, before anything is started.
	env := link.ProxyEnv(fmt.Sprintf("http://%s:%d", relayAlias, relayPort))
	if len(l.CA) > 0 {
		for _, n := range e.d.SetsWithAuthority() {
			env = append(env, n+"="+BundlePath)
		}
	}
	envFile, err := e.envFile("setup-env", append(env, l.Env...))
	if err != nil {
		return err
	}
	if err := e.StartRelay(ctx, l); err != nil {
		return err
	}
	bundle, err := e.firstUse(ctx, l.CA)
	if err != nil {
		return err
	}
	run := []string{"run", "--detach", "--name", e.setup(), "--label", e.label(), "--network", e.inside(), "--network-alias", setupAlias}
	if e.req.Runtime != "" {
		run = append(run, "--runtime", e.req.Runtime)
	}
	// The setup container runs as the agent's container does without nested Docker:
	// not root, with no capability and none to gain, with no health check of the
	// image's, and with no IPv6 address but loopback's. It has no Docker daemon.
	run = append(run, e.hardening()...)
	run = append(run, "--no-healthcheck", "--sysctl", "net.ipv6.conf.default.disable_ipv6=1")
	run = append(run, limits...)
	run = append(run, "--env-file", envFile, "--workdir", l.Dir, "--mount", helper)
	for _, m := range mounts {
		run = append(run, "--mount", m)
	}
	if bundle != "" {
		run = append(run, "--mount", bundle)
	}
	run = append(run, e.neverPull()...)
	run = append(run, "--entrypoint", HelperPath, e.req.Image)
	run = append(run, e.d.HoldArgs...)
	pull, cancel := context.WithTimeout(ctx, relayWait)
	defer cancel()
	e.made = append(e.made, []string{"rm", "--force", "--volumes", e.setup()})
	if out, err := e.docker(pull, run...); err != nil {
		if e.req.Pull {
			return err
		}
		return e.unpulled(e.req.Image, out, err)
	}
	e.setupDir, e.setupEnv = l.Dir, envFile
	return nil
}

// ExecSetup runs one setup command, args, the program inside and its arguments, in the
// setup container with docker exec: as the wall's user, in the setup container's
// working directory, with its environment file and no input. The command's standard
// output and standard error go to stdout and stderr as they come. It returns the
// command's exit status, as docker exec exits with it. An exit status other than 0 from
// a setup container that stopped, the ctx's end, and a docker exec that did not run are
// errors.
func (e *dockerEnclosure) ExecSetup(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	if e.setupEnv == "" {
		return -1, errors.New("wall docker: start the setup container before its commands")
	}
	argv := append([]string{e.command(), "exec", "--user", e.user, "--workdir", e.setupDir, "--env-file", e.setupEnv, e.setup()}, args...)
	code, err := e.sys.stream(ctx, argv, e.env, stdout, stderr)
	switch {
	case ctx.Err() != nil:
		return -1, ctx.Err()
	case err != nil:
		return -1, fmt.Errorf("wall docker: docker exec: %w", accesskey.ShownError(err))
	case code != 0:
		// docker exec exits otherwise than 0 too when the setup container stopped: the
		// inspect of the container's state sets the two apart.
		if err := e.setupRuns(ctx); err != nil {
			return -1, err
		}
	}
	return code, nil
}

// setupRuns is nil while the setup container runs, and otherwise an error with what the
// container printed.
func (e *dockerEnclosure) setupRuns(ctx context.Context) error {
	state, err := e.docker(ctx, "inspect", "--format", "{{.State.Running}}", e.setup())
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(state)) == "true" {
		return nil
	}
	out, _ := e.docker(ctx, "logs", e.setup())
	return fmt.Errorf("wall docker: the setup container stopped: %s", accesskey.ShownValue(string(bytes.TrimSpace(out)), false))
}

// RemoveSetup removes the setup container within closeWait, with Close's docker rm
// --force --volumes, and returns once the engine removed it: every process in it has
// ended, and the name qory-setup no longer resolves on the internal network. A docker rm
// that fails with [noSuchContainer]'s text is not an error. Every other failure is, and
// the container stays for a later call or Close to remove. It touches the setup
// container alone, so it may follow an Unwrap, and a later Wrap may follow it.
func (e *dockerEnclosure) RemoveSetup(ctx context.Context) error {
	return e.removeContainer(ctx, e.setup(), noSuchContainer)
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
// socket's directory, writable, when the launch has a socket, the session's transcript
// directory, writable, when the launch has one, and, read-only, the private directory
// that contains the run's environment files and, with a CA, the bundle the enclosure
// binds, which it makes now.
func (e *dockerEnclosure) Binds(l Launch) ([]Bind, error) {
	out := []Bind{{Path: e.d.Helper, ReadOnly: true, Helper: true}}
	if l.Socket != "" {
		out = append(out, Bind{Path: filepath.Dir(l.Socket)})
	}
	if l.Transcript.Path != "" {
		out = append(out, Bind{Path: l.Transcript.Path})
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
		return accesskey.ShownError(err)
	}
	e.temp = dir
	return nil
}

// bundle writes the file the enclosure trusts: the image's own authorities, read out of
// the relay's container when it is the same image, and otherwise out of the container
// of the run's image that is never started, each of which exists by now, and the run's
// certificate after them. An image that keeps a bundle nowhere known gets the run's
// alone, which serves the hosts the proxy answers as and no other; that is the image's
// to mend. It returns the file's mount.
func (e *dockerEnclosure) bundle(ctx context.Context, ca []byte) (string, error) {
	from := e.relay()
	if e.relayImage() != e.req.Image {
		from = e.image()
	}
	// A bundle over [fileLimit] is read up to it, as before the read was bounded.
	var image []byte
	for _, p := range imageBundles {
		if b, _, err := e.copyOut(ctx, from, p); err == nil && bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
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
		return "", accesskey.ShownError(err)
	}
	return mount(file, BundlePath, true)
}

// firstFile is the content of the first file in a tar stream, what docker cp writes,
// at most [fileLimit] bytes of it, and the size its header gives. A stream cut short
// gives what it holds of the file.
func firstFile(stream []byte) ([]byte, int64, error) {
	r := tar.NewReader(bytes.NewReader(stream))
	for {
		h, err := r.Next()
		if err != nil {
			return nil, 0, err
		}
		if h.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(io.LimitReader(r, fileLimit))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				// A stream cut at the read's limit holds the start of the file.
				err = nil
			}
			return b, h.Size, err
		}
	}
}

// mounts are the launch's: what it lists and the socket's directory, and the
// workspace's directory on this machine. The workspace is the working directory
// inside; a mount whose path inside, its Path or its Target, holds it, by whole
// components, shows it, and a launch none of whose mounts does is refused: the adapter
// binds nothing of the caller's the launch does not list. A Target that is not
// absolute, or that is, holds or lies under the adapter's /qory, is refused.
func (e *dockerEnclosure) mounts(l Launch) ([]string, string, error) {
	if !filepath.IsAbs(l.Dir) {
		return nil, "", fmt.Errorf("wall docker: the workspace %s is not an absolute path", accesskey.ShownValue(l.Dir, true))
	}
	var binds []bind
	host := ""
	for _, m := range l.Mounts {
		if !filepath.IsAbs(m.Path) {
			return nil, "", fmt.Errorf("wall docker: the mount %s is not an absolute path", accesskey.ShownValue(m.Path, true))
		}
		if e.sys.socket(m.Path) {
			return nil, "", fmt.Errorf("wall docker: the mount %s is a socket or holds a container runtime's, which an enclosure never gets", accesskey.ShownValue(m.Path, true))
		}
		dst := m.Path
		if m.Target != "" {
			if !filepath.IsAbs(m.Target) {
				return nil, "", fmt.Errorf("wall docker: the mount %s is shown at %s, which is not an absolute path", accesskey.ShownValue(m.Path, true), accesskey.ShownValue(m.Target, true))
			}
			if under(qoryDir, m.Target) || under(m.Target, qoryDir) {
				return nil, "", fmt.Errorf("wall docker: the mount %s is shown at %s, which overlaps %s, the wall's", accesskey.ShownValue(m.Path, true), accesskey.ShownValue(m.Target, true), qoryDir)
			}
			dst = filepath.Clean(m.Target)
		}
		binds = append(binds, bind{m.Path, dst, m.ReadOnly})
		if rel, err := filepath.Rel(dst, l.Dir); host == "" && err == nil && under(dst, l.Dir) {
			host = filepath.Join(m.Path, rel)
		}
	}
	if host == "" {
		return nil, "", fmt.Errorf("wall docker: the workspace %s lies in none of the "+
			"launch's mounts", accesskey.ShownValue(l.Dir, true))
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
			return nil, "", err
		}
		out = append(out, m)
	}
	return out, host, nil
}

// transcriptMount is the --mount of the launch's transcript directory, empty for a
// launch with none: the directory, writable, at Under below the home of the agent's
// user inside, [dockerEnclosure.transcriptPlace]. A directory that is not absolute and
// clean, an Under that is not relative and clean or has a .. name, a directory that is,
// contains or lies inside one of the launch's mounts or the hook socket's directory, a
// place inside that is, contains or lies inside another mount's place inside or /qory, and
// a place the agent's container cannot bind for the agent ([Unbound]) are refused: no
// mount of the launch's shows the directory, and the bind hides no part of another one.
// It also returns the place, with the directories between the home and the bind's place
// that [dockerEnclosure.copyDirs] makes.
func (e *dockerEnclosure) transcriptMount(ctx context.Context, l Launch) (string, *transcriptPlace, error) {
	tr := l.Transcript
	if tr.Path == "" {
		return "", nil, nil
	}
	if !filepath.IsAbs(tr.Path) || filepath.Clean(tr.Path) != tr.Path {
		return "", nil, fmt.Errorf("wall docker: the transcript directory %s is not an absolute, clean path", accesskey.ShownValue(tr.Path, true))
	}
	var sources []string
	dsts := []string{qoryDir}
	for _, m := range l.Mounts {
		sources = append(sources, m.Path)
		if m.Target != "" {
			dsts = append(dsts, filepath.Clean(m.Target))
		} else {
			dsts = append(dsts, m.Path)
		}
	}
	if l.Socket != "" {
		sources = append(sources, filepath.Dir(l.Socket))
	}
	for _, p := range sources {
		if under(p, tr.Path) || under(tr.Path, p) {
			return "", nil, fmt.Errorf("wall docker: the transcript directory %s overlaps the mount %s; the session makes it outside every mount", accesskey.ShownValue(tr.Path, true), accesskey.ShownValue(p, true))
		}
	}
	place, err := e.transcriptPlace(ctx, l.Env, tr)
	if err != nil {
		return "", nil, err
	}
	if place.unbound != nil {
		return "", nil, fmt.Errorf("wall docker: %s: %s", place.unbound.Fix, place.unbound.Cause)
	}
	for _, d := range dsts {
		if under(d, place.dst) || under(place.dst, d) {
			return "", nil, fmt.Errorf("wall docker: set HOME to a directory where %s overlaps no mount: the transcript directory is bound there, and it overlaps %s", accesskey.ShownValue(place.dst, true), accesskey.ShownValue(d, true))
		}
	}
	m, err := mount(tr.Path, place.dst, false)
	if err != nil {
		return "", nil, err
	}
	return m, place, nil
}

// transcriptPlace is where the agent's container binds a session's transcript directory
// for one launch. dst is Under below the agent's home inside. mk are the directories
// between the home and dst, outermost first, that the image does not have, which
// [dockerEnclosure.copyDirs] writes owned by uid and gid, the agent's user and group
// inside. unbound, when set, is why the container binds no transcript directory. key is
// the directory, its Under and the launch's HOME, the inputs it is worked out from.
type transcriptPlace struct {
	key      string
	dst      string
	mk       []string
	uid, gid int
	unbound  *Unbound
}

// CheckTranscript returns why the agent's container binds no transcript directory t for
// a launch with the environment env, and nil when it binds it, as
// [dockerEnclosure.transcriptPlace] works it out. The session calls it before Wrap, so a
// launch that gets no bind starts without a resume.
func (e *dockerEnclosure) CheckTranscript(ctx context.Context, env []string, t Transcript) (*Unbound, error) {
	if t.Path == "" {
		return nil, nil
	}
	p, err := e.transcriptPlace(ctx, env, t)
	if err != nil {
		return nil, err
	}
	return p.unbound, nil
}

// transcriptPlace works out the place of the transcript directory t for a launch with
// the environment env, once for each directory, Under and HOME of env. The agent's
// user inside must be the session's uid, [dockerEnclosure.agentIDs], since the
// directory is mode 0700 and owned by that uid. The bind's place is Under below the
// agent's home, [dockerEnclosure.home]. Each directory from / down to that place, read
// out of the image, must be a directory and no symbolic link, since the engine follows
// a link inside the image and the bind could then land inside another mount; and each
// one above the place must let the agent's user and group search it. A directory the
// image does not have, and every one below it, is made: by the engine, owned by root and
// mode 0755, above the home, and by copyDirs below it.
func (e *dockerEnclosure) transcriptPlace(ctx context.Context, env []string, t Transcript) (*transcriptPlace, error) {
	key := t.Path + "\x00" + t.Under + "\x00" + lastHome(env)
	if e.placed != nil && e.placed.key == key {
		return e.placed, nil
	}
	if t.Under == "" || path.IsAbs(t.Under) || path.Clean(t.Under) != t.Under || slices.Contains(strings.Split(t.Under, "/"), "..") {
		return nil, fmt.Errorf("wall docker: the transcript's place below the home, %s, is not a relative, clean path", accesskey.ShownValue(t.Under, true))
	}
	p := &transcriptPlace{key: key}
	uid, gid, unbound, err := e.agentIDs(ctx)
	if err != nil {
		return nil, err
	}
	if unbound != nil {
		p.unbound, e.placed = unbound, p
		return p, nil
	}
	home, err := e.home(ctx, env)
	if err != nil {
		return nil, err
	}
	p.dst, p.uid, p.gid = path.Join(home, t.Under), uid, gid
	var names []string
	for q := p.dst; q != "/"; q = path.Dir(q) {
		names = append([]string{q}, names...)
	}
	missing := len(names)
	for i, q := range names {
		h, err := e.imageHeader(ctx, q)
		if err != nil {
			return nil, err
		}
		if h == nil {
			missing = i
			break
		}
		if why := unreachable(h, q, q == p.dst, uid, gid); why != nil {
			p.unbound, e.placed = why, p
			return p, nil
		}
	}
	for q := path.Dir(t.Under); q != "."; q = path.Dir(q) {
		if at := path.Join(home, q); slices.Index(names, at) >= missing {
			p.mk = append([]string{at}, p.mk...)
		}
	}
	e.placed = p
	return p, nil
}

// unreachable is why the directory q of the image, whose first tar header is h, keeps
// the transcript bind from the agent, uid and gid inside; nil when it does not. A
// symbolic link and a file that is no directory do, and so does a directory above the
// bind's place, last false, that the agent's user and group cannot search: the owner's
// bit counts for the owner, the group's for the group and the others' for the rest.
func unreachable(h *tar.Header, q string, last bool, uid, gid int) *Unbound {
	shown := accesskey.ShownValue(q, true)
	switch {
	case h.Typeflag == tar.TypeSymlink:
		return &Unbound{Fix: fmt.Sprintf("Make %s a directory in the image, not a symbolic link", shown),
			Cause: fmt.Sprintf("%s is a symbolic link in the image, which the engine follows, so the bind could land inside another mount", shown)}
	case h.Typeflag != tar.TypeDir:
		return &Unbound{Fix: fmt.Sprintf("Make %s a directory in the image", shown),
			Cause: fmt.Sprintf("%s is no directory in the image", shown)}
	case last:
		return nil
	}
	bit := int64(0o001)
	switch {
	case h.Uid == uid:
		bit = 0o100
	case h.Gid == gid:
		bit = 0o010
	}
	if h.Mode&bit != 0 {
		return nil
	}
	return &Unbound{Fix: fmt.Sprintf("Set HOME in the image to a directory that uid %d can reach, or let it search %s", uid, shown),
		Cause: fmt.Sprintf("%s has mode %04o and owner %d:%d in the image, so the agent, %d:%d, cannot reach the transcript directory below it", shown, h.Mode&0o7777, h.Uid, h.Gid, uid, gid)}
}

// agentIDs are the uid and gid the agent runs as inside, as the engine and [Nest] take
// them from the wall's user: its uid, and its group, by number or by name in
// the image's /etc/group, else the uid's group in the image's /etc/passwd, else 0.
// A wall's user that is a name, or a uid other than the session's, gets an Unbound: the
// session's transcript directory is mode 0700 and owned by the session's uid, so that
// agent could not write it.
func (e *dockerEnclosure) agentIDs(ctx context.Context) (int, int, *Unbound, error) {
	session, _ := e.sys.ids()
	u, g, hasGroup := strings.Cut(e.user, ":")
	if uid, err := strconv.Atoi(u); err != nil || uid != session {
		return 0, 0, &Unbound{Fix: fmt.Sprintf("Set the wall's user to uid %d, the session's, or leave it unset", session),
			Cause: fmt.Sprintf("the agent runs as %s, and the session's transcript directory is mode 0700 and owned by uid %d", accesskey.ShownName(e.user, true), session)}, nil
	}
	if hasGroup {
		if gid, err := strconv.Atoi(g); err == nil {
			return session, gid, nil, nil
		}
	}
	container, err := e.filesContainer(ctx)
	if err != nil {
		return 0, 0, nil, err
	}
	file, name, field := "/etc/passwd", u, 3
	if hasGroup {
		file, name, field = "/etc/group", g, 2
	}
	b, over, err := e.copyOut(ctx, container, file)
	if err != nil || over {
		return session, 0, nil, nil
	}
	return session, idField(b, name, hasGroup, field), nil, nil
}

// idField is the number in field of the line of passwd, an /etc/passwd or /etc/group,
// whose first field is name or, when byName is false, whose third field is name: a
// user's group or a group's id. It is 0 when no line matches.
func idField(passwd []byte, name string, byName bool, field int) int {
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(strings.TrimSuffix(line, "\r"), ":")
		if len(f) <= field || (byName && f[0] != name) || (!byName && f[2] != name) {
			continue
		}
		if n, err := strconv.Atoi(f[field]); err == nil {
			return n
		}
	}
	return 0
}

// imageHeader is the first tar header docker cp writes of the path p of the image, read
// out of [dockerEnclosure.filesContainer] under [copyWait] without --follow-link, so a
// symbolic link at p comes out as a header of type tar.TypeSymlink. It is nil when the image
// has nothing at p. The agent's container cannot be read instead: for a docker cp the
// engine makes the places of its binds, the transcript bind's parents among them.
func (e *dockerEnclosure) imageHeader(ctx context.Context, p string) (*tar.Header, error) {
	container, err := e.filesContainer(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, copyWait)
	defer cancel()
	argv := []string{e.command(), "cp", container + ":" + p, "-"}
	if r, err := e.sys.stdout(ctx, argv, e.env); err == nil {
		h, err := tar.NewReader(r).Next()
		r.Close()
		if err == nil {
			return h, nil
		}
	}
	// The path is missing, or the engine failed: the command's output shows which.
	out, err := e.sys.run(ctx, argv, e.env)
	switch {
	case err == nil:
		if h, err := tar.NewReader(bytes.NewReader(out)).Next(); err == nil {
			return h, nil
		}
	case noSuchPath(string(out)):
		return nil, nil
	}
	return nil, fmt.Errorf("wall docker: the check for %s in the image: %w: %s", accesskey.ShownValue(p, true), accesskey.ShownError(err), accesskey.ShownValue(string(bytes.TrimSpace(out)), false))
}

// noSuchPath reports whether out, the output of a docker cp out of a container that
// failed, shows that the path is missing: "could not find the file" in any case.
func noSuchPath(out string) bool {
	return strings.Contains(strings.ToLower(out), "could not find the file")
}

// copyDirs writes the directories p.mk into the agent's container, created and not
// started, as directories of mode 0700 owned by p.uid and p.gid, the agent's user and
// group inside, with docker cp of a tar on standard input. It passes no --archive, so
// the engine takes each owner from the tar's header: with --archive it takes the
// container's user, root with nested Docker, where the agent runs as the wall's user.
// Without the directories the engine makes them when it binds the transcript directory,
// owned by root, and the runtime makes nothing beside the bind, such as Claude Code's
// ~/.claude/session-env.
func (e *dockerEnclosure) copyDirs(ctx context.Context, p *transcriptPlace) error {
	if len(p.mk) == 0 {
		return nil
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	now := time.Now()
	for _, d := range p.mk {
		h := &tar.Header{Name: strings.TrimPrefix(d, "/") + "/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: p.uid, Gid: p.gid, ModTime: now}
		if err := w.WriteHeader(h); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, copyWait)
	defer cancel()
	argv := []string{e.command(), "cp", "-", e.agent() + ":/"}
	if out, err := e.sys.input(ctx, argv, e.env, b.Bytes()); err != nil {
		return fmt.Errorf("wall docker: the directory %s beside the transcript bind: %w: %s", accesskey.ShownValue(p.mk[0], true), accesskey.ShownError(err), accesskey.ShownValue(string(bytes.TrimSpace(out)), false))
	}
	return nil
}

// filesContainer is the container the image's files are read out of: the relay's, of
// the same image, once it started, or else the container of the run's image that is
// never started, which it creates when it does not exist yet.
func (e *dockerEnclosure) filesContainer(ctx context.Context) (string, error) {
	if e.relayImage() == e.req.Image && e.relayed {
		return e.relay(), nil
	}
	if err := e.createImage(ctx); err != nil {
		return "", err
	}
	return e.image(), nil
}

// home is the home of the agent's user inside, the HOME the agent's process has: the
// last HOME of env, the launch's environment, when it is not empty; else HOME of the
// image's environment; else the home in the image's /etc/passwd of the user the
// container starts as; else /. That user is the wall's user, or root with nested Docker,
// where the engine sets HOME for root and the helper keeps it when it starts the agent as
// the wall's user. A home that is not absolute is an error.
func (e *dockerEnclosure) home(ctx context.Context, env []string) (string, error) {
	checked := func(h, from string) (string, error) {
		if !path.IsAbs(h) {
			return "", fmt.Errorf("wall docker: the home inside, %s from %s, is not an absolute path", accesskey.ShownValue(h, true), from)
		}
		return path.Clean(h), nil
	}
	if h := lastHome(env); h != "" {
		return checked(h, "the launch's HOME")
	}
	config, err := e.imageConfig(ctx)
	if err != nil {
		return "", err
	}
	if config != nil {
		if h := lastHome(config.Env); h != "" {
			return checked(h, "the image's HOME")
		}
	}
	user, _, _ := strings.Cut(e.user, ":")
	if e.req.Docker {
		user = "0"
	}
	container, err := e.filesContainer(ctx)
	if err != nil {
		return "", err
	}
	passwd, over, err := e.copyOut(ctx, container, "/etc/passwd")
	if err != nil || over {
		return "/", nil
	}
	if h, ok := passwdHome(passwd, user); ok && h != "" {
		return checked(h, "the image's /etc/passwd")
	}
	return "/", nil
}

// lastHome is the value of the last HOME in env, empty when there is none.
func lastHome(env []string) string {
	h := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			h = v
		}
	}
	return h
}

// passwdHome is the home of the user in /etc/passwd, a name or a uid of digits, and
// whether it lists the user.
func passwdHome(passwd []byte, user string) (string, bool) {
	numeric := uidShape.MatchString(user)
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(strings.TrimSuffix(line, "\r"), ":")
		if len(f) < 6 {
			continue
		}
		if (numeric && f[2] == user) || (!numeric && f[0] == user) {
			return f[5], true
		}
	}
	return "", false
}

// under reports whether path is dir or lies below it, by whole components of the
// paths as written.
func under(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	up := ".." + string(filepath.Separator)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, up)
}

// limits are the agent's resource flags. The relay gets none: it is Forager's own.
func limits(l Limits) ([]string, error) {
	var out []string
	if l.CPUs != "" {
		if !cpusShape.MatchString(l.CPUs) {
			return nil, fmt.Errorf("wall docker: the cpus limit %s is not a decimal number", accesskey.ShownValue(l.CPUs, true))
		}
		out = append(out, "--cpus", l.CPUs)
	}
	for _, f := range []struct{ flag, name, value string }{{"--memory", "memory", l.Memory}, {"--shm-size", "shm size", l.ShmSize}} {
		if f.value == "" {
			continue
		}
		if !bytesShape.MatchString(f.value) {
			return nil, fmt.Errorf("wall docker: the %s %s is not a number of bytes with a unit of b, k, m or g", f.name, accesskey.ShownValue(f.value, true))
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
			return "", fmt.Errorf("wall docker: the path %s holds a comma or a quote and cannot be mounted", accesskey.ShownValue(p, true))
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
			return "", fmt.Errorf("wall docker: the environment entry %s is not NAME=value", accesskey.ShownName(name, true))
		}
		if strings.ContainsAny(kv, "\n\r") {
			name, _, _ := strings.Cut(kv, "=")
			return "", fmt.Errorf("wall docker: the value of %s holds a line break and cannot be passed", accesskey.ShownName(name, false))
		}
		b.WriteString(kv + "\n")
	}
	if err := e.makeTemp(); err != nil {
		return "", err
	}
	file := filepath.Join(e.temp, name)
	return file, accesskey.ShownError(os.WriteFile(file, []byte(b.String()), 0o600))
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
			return fmt.Errorf("wall docker: the relay exited: %s", accesskey.ShownValue(string(bytes.TrimSpace(out)), false))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wall docker: the relay did not listen: %s", accesskey.ShownValue(string(bytes.TrimSpace(out)), false))
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

// Close removes the containers and the networks, newest first, and the private
// directory with the environment files and the bundle. A docker rm that fails with
// [noSuchContainer]'s text is not an error, and neither is a network rm that fails with
// [goneAlready]'s text. Every other failure is: a docker rm that fails because the engine
// cannot be reached leaves the container's state unknown, and it may still run.
func (e *dockerEnclosure) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, closeWait)
	defer cancel()
	var errs []error
	for i := len(e.made) - 1; i >= 0; i-- {
		gone := goneAlready
		if e.made[i][0] == "rm" {
			gone = noSuchContainer
		}
		if err := e.remove(ctx, e.made[i], gone); err != nil {
			errs = append(errs, err)
		}
	}
	e.made = nil
	if e.temp != "" {
		errs = append(errs, accesskey.ShownError(os.RemoveAll(e.temp)))
		e.temp = ""
	}
	return errors.Join(errs...)
}

// remove runs one of the commands that remove what the enclosure made. A failed command
// whose output gone accepts is not an error.
func (e *dockerEnclosure) remove(ctx context.Context, argv []string, gone func(out string) bool) error {
	out, err := e.docker(ctx, argv...)
	if err != nil && !gone(string(out)) {
		return err
	}
	return nil
}

// goneAlready reports whether out, the output of a failed network rm, contains "no such"
// or "not found" in any case: a network that is gone already or was never made, but also
// a missing engine socket. Use [noSuchContainer] for a container: one that remains may
// still run.
func goneAlready(out string) bool {
	out = strings.ToLower(out)
	return strings.Contains(out, "no such") || strings.Contains(out, "not found")
}

// Reap removes the containers and the networks that carry the run's label: what a
// session that died left behind. The containers go first, since a network in use stays.
func (d *Docker) Reap(ctx context.Context, runID string) (int, error) {
	if !runIDShape.MatchString(runID) {
		return 0, fmt.Errorf("wall docker: the run id %s cannot name a container", accesskey.ShownName(runID, true))
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

func (hostSystem) stdout(ctx context.Context, argv, env []string) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := selectedCommand(ctx, argv, env)
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		cancel()
		return nil, accesskey.ShownError(err)
	}
	return &piped{r: out, cmd: cmd, cancel: cancel}, nil
}

func (hostSystem) input(ctx context.Context, argv, env []string, stdin []byte) ([]byte, error) {
	cmd := selectedCommand(ctx, argv, env)
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.CombinedOutput()
}

func (hostSystem) stream(ctx context.Context, argv, env []string, stdout, stderr io.Writer) (int, error) {
	cmd := selectedCommand(ctx, argv, env)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		return exit.ExitCode(), nil
	case err != nil:
		return -1, accesskey.ShownError(err)
	}
	return 0, nil
}

// piped is a command's standard output as it comes. Close kills the command when the
// output was not read to its end, and waits for it.
type piped struct {
	r      io.Reader
	cmd    *exec.Cmd
	cancel context.CancelFunc
	ended  bool
}

// Read reads the command's output, and notes its end.
func (p *piped) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if err == io.EOF {
		p.ended = true
	}
	return n, err
}

// Close kills the command when its output was not read to the end, and waits for it.
func (p *piped) Close() error {
	if !p.ended {
		p.cancel()
	}
	err := p.cmd.Wait()
	p.cancel()
	if !p.ended {
		// Stopped by the reader: what the command says of being killed is not news.
		return nil
	}
	return err
}

// selectedCommand is hostCommand, with the engine's selection in place of Forager's
// own when env is not nil.
func selectedCommand(ctx context.Context, argv, env []string) *exec.Cmd {
	if env == nil {
		return hostCommand(ctx, argv)
	}
	return engineCommand(ctx, argv, env)
}

// hostCommand is a command of the machine's the wall runs, the docker CLI say, with
// Forager's environment without the access key's variables and the run key's, which
// neither the CLI nor a credential helper it starts receives.
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
		return fmt.Errorf("not a Linux executable: %w", accesskey.ShownError(err))
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("dynamically linked; build it with CGO_ENABLED=0")
		}
	}
	return nil
}
