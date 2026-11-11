package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qoryai/forager/link"
	"golang.org/x/term"
)

// probePrefix starts the one line of standard output that holds the probe's report.
const probePrefix = "walltest-probe: "

// report is what the probe found inside the enclosure. An attempt that must fail
// reports its error; empty means it succeeded.
type report struct {
	OutsideAddress string            `json:"outside_address"`
	OutsideName    string            `json:"outside_name"`
	Metadata       string            `json:"metadata"`
	Allowed        int               `json:"allowed"`
	AllowedErr     string            `json:"allowed_err"`
	Denied         int               `json:"denied"`
	DeniedErr      string            `json:"denied_err"`
	OwnViaProxy    int               `json:"own_via_proxy"`
	MetaViaProxy   int               `json:"metadata_via_proxy"`
	HostByGateway  []string          `json:"host_by_gateway"`
	RecordWrite    string            `json:"record_write"`
	UID            int               `json:"uid"`
	GID            int               `json:"gid"`
	CapEff         string            `json:"cap_eff"`
	CapPrm         string            `json:"cap_prm"`
	CapBnd         string            `json:"cap_bnd"`
	CapInh         string            `json:"cap_inh"`
	CapAmb         string            `json:"cap_amb"`
	NoNewPrivs     string            `json:"no_new_privs"`
	Sockets        []string          `json:"sockets"`
	HostEnv        bool              `json:"host_env"`
	PassedEnv      bool              `json:"passed_env"`
	EnvNames       []string          `json:"env_names"`
	HostFile       bool              `json:"host_file"`
	SettingsWrite  string            `json:"settings_write"`
	Namespaces     map[string]string `json:"namespaces"`
	PathDenied     int               `json:"path_denied"`
	TLSDenied      int               `json:"tls_denied"`
	TLSDeniedErr   string            `json:"tls_denied_err"`
	TLSAllowed     int               `json:"tls_allowed"`
	TLSAllowedErr  string            `json:"tls_allowed_err"`
	Placeholder    string            `json:"placeholder"`
	TokenSeen      []string          `json:"token_seen"`
	Bundle         string            `json:"bundle"`
	BundleCerts    int               `json:"bundle_certs"`
	BundleKeys     int               `json:"bundle_keys"`
	Hook           string            `json:"hook"`
	Terminal       bool              `json:"terminal"`
	ToolAllowed    int               `json:"tool_allowed"`
	ToolAllowedErr string            `json:"tool_allowed_err"`
	ToolSaw        string            `json:"tool_saw"`
	ToolDenied     int               `json:"tool_denied"`
	Nested         *nested           `json:"nested,omitempty"`
	APIKeyStandIn  string            `json:"api_key_stand_in"`
	OAuthStandIn   string            `json:"oauth_stand_in"`
	APIKeyHost     int               `json:"api_key_host"`
	APIKeyHostErr  string            `json:"api_key_host_err"`
	OAuthHost      int               `json:"oauth_host"`
	OAuthHostErr   string            `json:"oauth_host_err"`
	OtherPlain     int               `json:"other_plain"`
	OtherPlainErr  string            `json:"other_plain_err"`
	OtherTunnel    int               `json:"other_tunnel"`
	OtherTunnelErr string            `json:"other_tunnel_err"`
	// KeySeen are where a runtime's key was seen: a variable, a process's environment,
	// an answer.
	KeySeen []string `json:"key_seen"`
	// Environs is how many of the processes' environments under /proc were read.
	Environs int `json:"environs"`
	// Prepared is what the run's setup command left in the workspace as the probe started,
	// and PreparedErr why there was nothing to read.
	Prepared    *preparedReport `json:"prepared,omitempty"`
	PreparedErr string          `json:"prepared_err"`
	// Workdir is the probe's working directory, and HostWorkspace whether the
	// workspace's path on the machine exists inside.
	Workdir       string `json:"workdir"`
	HostWorkspace bool   `json:"host_workspace"`
	// ImageDenied is what the probe sees of ANTHROPIC_BEDROCK_BASE_URL, a name the
	// runtime denies and the suite's image by reference sets in its ENV: unset, empty
	// or set.
	ImageDenied string `json:"image_denied"`
	// SetupService is what the service at PROBE_SETUP_SERVICE answered, asked with no
	// proxy, or why it did not answer; empty when the variable is not set.
	SetupService string `json:"setup_service"`
	// ReadOnly is what the probe found in a workspace bound read-only, when
	// PROBE_READ_ONLY is 1: the probe then tries nothing else.
	ReadOnly *readOnlyReport `json:"read_only,omitempty"`
	// RunAPI is what the probe found of the run API, when PROBE_RUN_API is 1: the probe
	// then tries nothing else.
	RunAPI *runAPIReport `json:"run_api,omitempty"`
	// Transcript is what the probe planted at its transcript's path, when
	// PROBE_TRANSCRIPT is set.
	Transcript *transcriptReport `json:"transcript,omitempty"`
	// SessionEnv is how the probe's mkdir of ~/.claude/session-env failed, beside the
	// transcript bind at ~/.claude/projects, as Claude Code makes it; empty when it did
	// not, and "no HOME" when HOME is empty.
	SessionEnv string `json:"session_env"`
	// Parent is what the probe sees of its parent, the helper's exec, which waits for
	// it and then measures the enclosure.
	Parent parentReport `json:"parent"`
	// CgroupV2 is whether /sys/fs/cgroup/memory.max exists inside: the helper's exec
	// then reads the enclosure's peak memory and CPU time.
	CgroupV2 bool `json:"cgroup_v2"`
	// TTY is what the terminal probe found; nil for the probe.
	TTY *terminalReport `json:"tty,omitempty"`
}

// parentReport is what the probe sees of its parent process: its arguments, the lines
// of its status and of the probe's that contain users, groups, capabilities and
// no_new_privs, the owner of its /proc fd directory, which is root while it is not
// dumpable, and each file descriptor with its target, or why the list could not be
// read; Err is why the rest could not be read.
type parentReport struct {
	Args   []string `json:"args"`
	Status []string `json:"status"`
	Self   []string `json:"self"`
	Owner  int      `json:"owner"`
	FDs    []string `json:"fds"`
	FDsErr string   `json:"fds_err"`
	Err    string   `json:"err"`
}

// privileges are the lines of a process's status that the parent's must match.
var privileges = []string{"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}

// statusLines returns the lines of /proc/<pid>/status that [privileges] lists.
func statusLines(pid string) ([]string, error) {
	b, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		name, _, _ := strings.Cut(line, ":")
		for _, p := range privileges {
			if name == p {
				out = append(out, strings.Join(strings.Fields(line), " "))
			}
		}
	}
	return out, nil
}

// probeParent reads the probe's parent process.
func probeParent() parentReport {
	var r parentReport
	pid := strconv.Itoa(os.Getppid())
	args, err := os.ReadFile("/proc/" + pid + "/cmdline")
	if err != nil {
		r.Err = err.Error()
		return r
	}
	r.Args = strings.Split(strings.TrimRight(string(args), "\x00"), "\x00")
	if r.Status, err = statusLines(pid); err != nil {
		r.Err = err.Error()
		return r
	}
	r.Self, _ = statusLines("self")
	r.Owner = -1
	if info, err := os.Stat("/proc/" + pid + "/fd"); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			r.Owner = int(st.Uid)
		}
	}
	entries, err := os.ReadDir("/proc/" + pid + "/fd")
	if err != nil {
		r.FDsErr = err.Error()
		return r
	}
	for _, e := range entries {
		target, _ := os.Readlink("/proc/" + pid + "/fd/" + e.Name())
		r.FDs = append(r.FDs, e.Name()+" "+target)
	}
	return r
}

// problem is what is wrong with the parent: not the helper's exec, other users, groups
// or privileges than the probe's, dumpable, so the probe can list its descriptors, or
// a file descriptor above 2 other than the Go runtime's poller, an eventpoll and an
// eventfd. Empty when nothing is.
func (r parentReport) problem() string {
	switch {
	case r.Err != "":
		return "the parent could not be read: " + r.Err
	case len(r.Args) < 2 || r.Args[1] != modeExec:
		return fmt.Sprintf("the parent is %q, not the helper's exec", r.Args)
	case len(r.Status) != len(privileges) || !slices.Equal(r.Status, r.Self):
		return fmt.Sprintf("the helper's exec waits with %q and the agent runs with %q", r.Status, r.Self)
	case r.Owner != 0 || r.FDsErr == "":
		return fmt.Sprintf("the helper's exec waits dumpable: its /proc fd directory belongs to uid %d, and the agent lists its descriptors %q (%s)", r.Owner, r.FDs, r.FDsErr)
	}
	for _, fd := range r.FDs {
		n, target, _ := strings.Cut(fd, " ")
		if n != "0" && n != "1" && n != "2" && target != "anon_inode:[eventpoll]" && target != "anon_inode:[eventfd]" {
			return fmt.Sprintf("the helper's exec waits with descriptor %s open on %s; all: %q", n, target, r.FDs)
		}
	}
	return ""
}

// The files of the case of a workspace bound read-only: the setup container writes
// setupFile, and the agent tries to write agentFile. A process in the setup container
// adds a line to writerFile every second until the container goes.
const (
	setupFile  = "setup.txt"
	agentFile  = "agent.txt"
	writerFile = "writer.txt"
)

// writerWait is how long the probe waits between its two reads of the size of the file
// at PROBE_WRITER_FILE: longer than two of the writer's intervals.
const writerWait = 2500 * time.Millisecond

// readOnlyReport is what the probe found in a workspace bound read-only: the text of
// setupFile or why it could not read it, the exit status and standard error of a shell
// that writes agentFile and, with a Docker inside, the exit status and output of a
// container the agent starts with the workspace bound that writes agentFile there, and
// of a privileged one that first tries to make the workspace writable: PrivRemount is
// the result of a bind-remount without the read-only flag, and PrivSetattr that of a
// mount_setattr that clears it, each "ok" or the error; empty when the call did not
// run. SetupAddrs and SetupLookupErr are what a lookup of the host of PROBE_SETUP_ADDR
// returned, and SetupDialErr why a connection to that address did not open, or empty
// when it opened. WriterBefore and WriterAfter are the sizes of the file at
// PROBE_WRITER_FILE, read writerWait apart, -1 for no such file.
type readOnlyReport struct {
	Setup       string `json:"setup"`
	SetupErr    string `json:"setup_err"`
	WriteExit   int    `json:"write_exit"`
	WriteStderr string `json:"write_stderr"`
	InnerExit   int    `json:"inner_exit"`
	InnerOutput string `json:"inner_output"`
	PrivExit    int    `json:"priv_exit"`
	PrivOutput  string `json:"priv_output"`
	PrivRemount string `json:"priv_remount"`
	PrivSetattr string `json:"priv_setattr"`

	SetupAddrs     []string `json:"setup_addrs"`
	SetupLookupErr string   `json:"setup_lookup_err"`
	SetupDialErr   string   `json:"setup_dial_err"`
	WriterBefore   int64    `json:"writer_before"`
	WriterAfter    int64    `json:"writer_after"`
}

// The prefixes of the lines with which a privileged container the agent started
// reports its calls that try to make the workspace writable.
const (
	remountPrefix = "walltest-remount: "
	setattrPrefix = "walltest-setattr: "
)

// callResult is how the probe reports a call: ok, or its error.
func callResult(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}

// fileSize is the size of the file at p, or -1 when it has none.
func fileSize(p string) int64 {
	info, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return info.Size()
}

// reach is a setup command: it exits 0 once the service at the URL it is given returns
// setupServiceLine, fetched with no proxy.
func reach(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "reach: give one URL")
		return 2
	}
	if got := direct(args[0]); got != setupServiceLine {
		fmt.Fprintln(os.Stderr, "reach:", got)
		return 1
	}
	return 0
}

// probeReadOnly reads setupFile and tries to write agentFile, with the image's shell and,
// when the enclosure has a Docker, from a container the agent starts. With
// PROBE_SETUP_ADDR it looks the address up and connects to it, and with
// PROBE_WRITER_FILE it reads that file's size twice.
func probeReadOnly() *readOnlyReport {
	var r readOnlyReport
	if b, err := os.ReadFile(setupFile); err != nil {
		r.SetupErr = err.Error()
	} else {
		r.Setup = string(b)
	}
	var stderr bytes.Buffer
	cmd := exec.Command("sh", "-c", "echo agent > "+agentFile)
	cmd.Stderr = &stderr
	r.WriteExit = exitCode(cmd.Run(), &stderr)
	r.WriteStderr = strings.TrimSpace(stderr.String())
	if os.Getenv("PROBE_DOCKER") == "1" {
		r.InnerExit, r.InnerOutput = innerWrite(false)
		r.PrivExit, r.PrivOutput = innerWrite(true)
		for _, line := range strings.Split(r.PrivOutput, "\n") {
			if rest, ok := strings.CutPrefix(line, remountPrefix); ok {
				r.PrivRemount = rest
			}
			if rest, ok := strings.CutPrefix(line, setattrPrefix); ok {
				r.PrivSetattr = rest
			}
		}
	}
	if addr := os.Getenv("PROBE_SETUP_ADDR"); addr != "" {
		host, _, _ := net.SplitHostPort(addr)
		addrs, err := net.LookupHost(host)
		r.SetupAddrs = addrs
		if err != nil {
			r.SetupLookupErr = err.Error()
		}
		r.SetupDialErr = dial(addr)
	}
	if f := os.Getenv("PROBE_WRITER_FILE"); f != "" {
		r.WriterBefore = fileSize(f)
		time.Sleep(writerWait)
		r.WriterAfter = fileSize(f)
	}
	return &r
}

// exitCode is the exit status of a command that ran with err, or -1 with err written to
// out when it did not run.
func exitCode(err error, out *bytes.Buffer) int {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	out.WriteString(err.Error())
	return -1
}

// writeFile is the probe in a container the agent started: it writes the file its
// argument names, and exits 1 with the error when the write fails. With --remount
// first, it tries to make the file's directory writable before the write, by a
// bind-remount and then by mount_setattr, and prints each call's result.
func writeFile(args []string) int {
	remount := len(args) == 2 && args[0] == "--remount"
	if remount {
		args = args[1:]
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "write-file: give one path, after --remount or alone")
		return 2
	}
	if remount {
		dir := filepath.Dir(args[0])
		fmt.Fprintln(os.Stderr, remountPrefix+callResult(remountWritable(dir)))
		fmt.Fprintln(os.Stderr, setattrPrefix+callResult(clearReadOnly(dir)))
	}
	if err := os.WriteFile(args[0], []byte("agent\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write-file:", err)
		return 1
	}
	return 0
}

// preparedFile is where in the workspace the run's setup command leaves its report.
const preparedFile = "prepared-was-here"

// preparedLine is the line the run's setup command writes on its standard output.
const preparedLine = "prepared the workspace"

// preparationWords are the words the run's setup command is given after its mode, one
// with a space and one with what a shell would expand.
var preparationWords = []string{"a word", "it's $HOME `id`"}

// preparedReport is what the run's setup command found: what the origin answered through
// the proxy, its network and mount namespaces, its user and the words it was given.
type preparedReport struct {
	Allowed    int      `json:"allowed"`
	AllowedErr string   `json:"allowed_err"`
	Net        string   `json:"net"`
	Mnt        string   `json:"mnt"`
	UID        int      `json:"uid"`
	Args       []string `json:"args"`
}

// prepare is the run's setup command: it reaches the origin through the proxy, leaves
// what it found in the workspace, for the probe to read as it starts, and writes
// preparedLine.
func prepare(args []string) int {
	r := preparedReport{Args: args, UID: os.Getuid()}
	r.Allowed, r.AllowedErr = get(os.Getenv("PROBE_ALLOWED"))
	r.Net, _ = os.Readlink("/proc/self/ns/net")
	r.Mnt, _ = os.Readlink("/proc/self/ns/mnt")
	b, _ := json.Marshal(r)
	if err := os.WriteFile(preparedFile, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "prepare: the workspace:", err)
		return 1
	}
	fmt.Println(preparedLine)
	return 0
}

// wait is how long an attempt that must fail is given to fail.
const wait = 3 * time.Second

// probe is the runtime of the suite's session: it tries what a wall forbids, uses what
// a wall provides, calls its hook the way a runtime does, prints its report and exits
// as told.
func probe(args []string) int {
	var r report
	if os.Getenv("PROBE_READ_ONLY") == "1" {
		r.ReadOnly = probeReadOnly()
		b, _ := json.Marshal(r)
		fmt.Println(probePrefix + string(b))
		return 0
	}
	if os.Getenv("PROBE_RUN_API") == "1" {
		r.RunAPI = probeRunAPI()
		b, _ := json.Marshal(r)
		fmt.Println(probePrefix + string(b))
		return 0
	}
	if kind := os.Getenv("PROBE_TRANSCRIPT"); kind != "" {
		var settings []string
		for i, a := range args {
			if a == "--settings" && i+1 < len(args) {
				settings = append(settings, args[i+1])
			}
		}
		r.Transcript = probeTranscript(kind, os.Getenv("PROBE_HOST_FILE"), settings)
		b, _ := json.Marshal(r)
		fmt.Println(probePrefix + string(b))
		return 0
	}
	// First, so what the setup command left is what it left before the probe started.
	if b, err := os.ReadFile(preparedFile); err != nil {
		r.PreparedErr = err.Error()
	} else if err := json.Unmarshal(b, &r.Prepared); err != nil {
		r.PreparedErr = err.Error()
	}
	r.OutsideAddress = dial("1.1.1.1:443")
	r.Metadata = dial("169.254.169.254:80")
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	if addrs, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err != nil {
		r.OutsideName = err.Error()
	} else if len(addrs) == 0 {
		r.OutsideName = "no addresses"
	}
	cancel()

	r.Allowed, r.AllowedErr = get(os.Getenv("PROBE_ALLOWED"))
	r.Denied, r.DeniedErr = get(os.Getenv("PROBE_DENIED"))
	r.OwnViaProxy, _ = get(os.Getenv("PROBE_OWN"))
	r.MetaViaProxy, _ = get("http://169.254.169.254/latest/meta-data/")
	// A host held to paths, asked for another; then the host a credential is for, which
	// the proxy answers as itself: a path outside the credential's is the proxy's own
	// 403, and a path inside it goes upstream, where there is nothing, with the
	// credential the record names. Both are verified against the bundle the wall gave.
	r.PathDenied, _ = get(os.Getenv("PROBE_ALLOWED") + "outside-the-paths")
	r.TLSDenied, r.TLSDeniedErr = get("https://" + credentialHost + "/outside-the-paths")
	r.TLSAllowed, r.TLSAllowedErr = get("https://" + credentialHost + credentialPath)
	// The tool's host, which exists nowhere: on its paths the tool answers with what the
	// proxy handed it, whatever the probe claimed under the proxy's prefix; off them the
	// proxy refuses, and the tool never hears of it.
	r.ToolAllowed, r.ToolSaw, r.ToolAllowedErr = fetch("https://"+toolHost+"/tool/inside", "Qory-Path-Rule", "/")
	r.ToolDenied, _ = get("https://" + toolHost + "/outside-the-tool")
	r.Placeholder = os.Getenv(placeholderVar)
	probeKeys(&r)
	for _, kv := range os.Environ() {
		if name, value, _ := strings.Cut(kv, "="); strings.Contains(value, tokenMark) {
			r.TokenSeen = append(r.TokenSeen, name)
		}
	}
	r.Bundle = os.Getenv("SSL_CERT_FILE")
	if b, err := os.ReadFile(r.Bundle); err == nil {
		r.BundleCerts = strings.Count(string(b), "BEGIN CERTIFICATE")
		r.BundleKeys = strings.Count(string(b), "PRIVATE KEY")
		if strings.Contains(string(b), tokenMark) {
			r.TokenSeen = append(r.TokenSeen, r.Bundle)
		}
	}
	// The first address of each network the probe is on is where an engine puts its
	// host, when it puts it anywhere.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip := n.IP.To4(); ip != nil && !ip.IsLoopback() {
				first := ip.Mask(n.Mask)
				first[3]++
				if addr := net.JoinHostPort(first.String(), os.Getenv("PROBE_HOST_PORT")); dial(addr) == "" {
					r.HostByGateway = append(r.HostByGateway, addr)
				}
			}
		}
	}

	r.UID, r.GID = os.Getuid(), os.Getgid()
	if f, err := os.Open("/proc/self/status"); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			name, value, _ := strings.Cut(s.Text(), ":")
			value = strings.TrimSpace(value)
			switch name {
			case "CapEff":
				r.CapEff = value
			case "CapPrm":
				r.CapPrm = value
			case "CapBnd":
				r.CapBnd = value
			case "CapInh":
				r.CapInh = value
			case "CapAmb":
				r.CapAmb = value
			case "NoNewPrivs":
				r.NoNewPrivs = value
			}
		}
		f.Close()
	}
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock", "/var/run/crio/crio.sock"} {
		if _, err := os.Stat(p); err == nil {
			r.Sockets = append(r.Sockets, p)
		}
	}
	r.HostEnv = os.Getenv(hostOnly) != ""
	if home := os.Getenv("HOME"); home == "" {
		r.SessionEnv = "no HOME"
	} else if err := os.Mkdir(filepath.Join(home, ".claude", "session-env"), 0o700); err != nil && !os.IsExist(err) {
		r.SessionEnv = err.Error()
	}
	r.PassedEnv = os.Getenv("PROBE_PASSED") == "yes"
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		r.EnvNames = append(r.EnvNames, name)
	}
	sort.Strings(r.EnvNames)
	if _, err := os.Stat(os.Getenv("PROBE_HOST_FILE")); err == nil {
		r.HostFile = true
	}
	r.Workdir, _ = os.Getwd()
	if u := os.Getenv("PROBE_SETUP_SERVICE"); u != "" {
		r.SetupService = direct(u)
	}
	switch v, ok := os.LookupEnv(imageDeniedVar); {
	case !ok:
		r.ImageDenied = "unset"
	case v == "":
		r.ImageDenied = "empty"
	default:
		r.ImageDenied = "set"
	}
	if _, err := os.Stat(os.Getenv("PROBE_HOST_WORKSPACE")); err == nil {
		r.HostWorkspace = true
	}
	r.Namespaces = map[string]string{}
	for _, ns := range []string{"net", "pid", "mnt", "ipc", "uts"} {
		r.Namespaces[ns], _ = os.Readlink("/proc/self/ns/" + ns)
	}
	if err := os.WriteFile("probe-was-here", []byte("inside"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "probe: the workspace:", err)
	}
	r.Terminal = term.IsTerminal(int(os.Stdout.Fd()))
	r.Parent = probeParent()
	if _, err := os.Stat("/sys/fs/cgroup/memory.max"); err == nil {
		r.CgroupV2 = true
	}

	for i, a := range args {
		if a == "--settings" && i+1 < len(args) {
			if f, err := os.OpenFile(args[i+1], os.O_WRONLY, 0); err != nil {
				r.SettingsWrite = err.Error()
			} else {
				f.Close()
			}
			if f, err := os.OpenFile(filepath.Join(filepath.Dir(args[i+1]), "events.jsonl"), os.O_WRONLY|os.O_APPEND, 0); err != nil {
				r.RecordWrite = err.Error()
			} else {
				f.Close()
			}
			r.Hook = hook(args[i+1])
		}
	}

	// Last, so what the containers it starts send through the proxy is recorded after
	// everything else.
	if os.Getenv("PROBE_DOCKER") == "1" {
		r.Nested = probeNested()
	}

	b, _ := json.Marshal(r)
	fmt.Println(probePrefix + string(b))
	code := 0
	fmt.Sscan(os.Getenv("PROBE_EXIT"), &code)
	return code
}

// probeKeys sends a runtime's two credentials' stand-ins as Claude Code does, the API
// key in x-api-key and the OAuth credential as a bearer, each to the recorder that is
// its host, then both to the recorder that is a host with no credential, plainly and
// through a tunnel; and looks for a key in every environment it can read.
func probeKeys(r *report) {
	r.APIKeyStandIn, r.OAuthStandIn = os.Getenv(apiKeyStandIn), os.Getenv(oauthStandIn)
	if host := os.Getenv("PROBE_API_KEY_HOST"); host != "" {
		bearer := "Bearer " + r.OAuthStandIn
		r.APIKeyHost, r.APIKeyHostErr = send(r, "https://"+net.JoinHostPort(host, recorderTLS)+modelPath, "x-api-key", r.APIKeyStandIn)
		r.OAuthHost, r.OAuthHostErr = send(r, "https://"+net.JoinHostPort(os.Getenv("PROBE_OAUTH_HOST"), recorderTLS)+modelPath, "authorization", bearer)
		other := os.Getenv("PROBE_OTHER_HOST")
		r.OtherPlain, r.OtherPlainErr = send(r, "http://"+net.JoinHostPort(other, recorderPlain)+modelPath, "x-api-key", r.APIKeyStandIn, "authorization", bearer)
		r.OtherTunnel, r.OtherTunnelErr = send(r, "https://"+net.JoinHostPort(other, recorderTLS)+modelPath, "x-api-key", r.APIKeyStandIn, "authorization", bearer)
	}
	for _, kv := range os.Environ() {
		if name, value, _ := strings.Cut(kv, "="); strings.Contains(value, keyMark) {
			r.KeySeen = append(r.KeySeen, name)
		}
	}
	environs, _ := filepath.Glob("/proc/[0-9]*/environ")
	for _, e := range environs {
		b, err := os.ReadFile(e)
		if err != nil {
			continue
		}
		r.Environs++
		if strings.Contains(string(b), keyMark) {
			r.KeySeen = append(r.KeySeen, e)
		}
	}
}

// send posts a body to u as postAnswer does; an answer that contains a key is noted in r.
func send(r *report, u string, header ...string) (int, string) {
	code, answer, err := postAnswer(u, header...)
	if strings.Contains(answer, keyMark) {
		r.KeySeen = append(r.KeySeen, "the answer of "+u)
	}
	return code, err
}

// postAnswer posts a body to u through the proxy of HTTP_PROXY, with the headers
// written in lower case, as Node writes them, and trusting the run's bundle and the
// suite's authority. It returns the status, the answer's headers and body as text, and
// the error of a request that failed.
func postAnswer(u string, header ...string) (int, string, string) {
	proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxyURL.Host == "" {
		return 0, "", "HTTP_PROXY is " + os.Getenv("HTTP_PROXY")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return 0, "", err.Error()
	}
	if der, err := base64.StdEncoding.DecodeString(os.Getenv(recordersCAVar)); err == nil {
		if cert, err := x509.ParseCertificate(der); err == nil {
			roots.AddCert(cert)
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", u, strings.NewReader(`{"model":"walltest","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		return 0, "", err.Error()
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header[header[i]] = []string{header[i+1]}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err.Error()
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, fmt.Sprint(resp.Header) + "\n" + string(b), ""
}

// dial reports the error of connecting, or nothing when the connection opened.
func dial(addr string) string {
	c, err := net.DialTimeout("tcp", addr, wait)
	if err != nil {
		return err.Error()
	}
	c.Close()
	return ""
}

// direct is the body of GET u with no proxy, or why there is none: the request is tried
// for 10 seconds, since a service a setup command started may still be starting.
func direct(u string) string {
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
	why := ""
	for range 20 {
		resp, err := client.Get(u)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(b)
		}
		why = err.Error()
		time.Sleep(500 * time.Millisecond)
	}
	return why
}

// get fetches u through the proxy the environment names, explicitly, because some of
// what the probe asks for is on loopback, which NO_PROXY exempts.
func get(u string) (int, string) {
	code, _, err := fetch(u)
	return code, err
}

// fetch is get with a header set, returning the body as well.
func fetch(u string, header ...string) (int, string, string) {
	proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxyURL.Host == "" {
		return 0, "", "HTTP_PROXY is " + os.Getenv("HTTP_PROXY")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, "", err.Error()
	}
	if len(header) == 2 {
		req.Header.Set(header[0], header[1])
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err.Error()
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b), ""
}

// serveTool is the suite's tool: it listens where the gateway sets and answers every
// request with the path rule and the id the proxy handed it.
func serveTool() int {
	ln, err := net.Listen("unix", os.Getenv(link.EnvToolListen))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "rule=%s id=%s", r.Header.Get(link.PathRuleHeader), r.Header.Get(link.RequestIDHeader))
	}))
	return 0
}

// hook calls the SessionEnd hooks the settings name, as the runtime would, and returns
// what they printed.
func hook(settings string) string {
	b, err := os.ReadFile(settings)
	if err != nil {
		return err.Error()
	}
	var s struct {
		Hooks map[string][]struct {
			Hooks []struct{ Command string } `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return err.Error()
	}
	var said strings.Builder
	for _, group := range s.Hooks["SessionEnd"] {
		for _, h := range group.Hooks {
			cmd := exec.Command("sh", "-c", h.Command)
			cmd.Stdin = strings.NewReader(`{"session_id":"probe","hook_event_name":"SessionEnd","reason":"other","cwd":"/"}`)
			out, err := cmd.CombinedOutput()
			said.Write(out)
			if err != nil {
				said.WriteString(err.Error())
			}
		}
	}
	return said.String()
}
