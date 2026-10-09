package e2e

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/qoryai/forager/wall"
)

// innerPrefix starts the one line of standard output that holds an inner container's
// report.
const innerPrefix = "walltest-inner: "

// decoyRan is the file, inside the enclosure, in which each program of [decoys] records
// that it ran, and as whom.
const decoyRan = "/tmp/walltest-decoys-ran"

// nested is what the probe found of the Docker of its own, when the enclosure has one.
type nested struct {
	// Ping is the status the daemon answered on its socket, as the agent's user.
	Ping    int    `json:"ping"`
	PingErr string `json:"ping_err"`
	// DaemonID is the inner daemon's ID, which is not the machine engine's.
	DaemonID string `json:"daemon_id"`
	// Listening are the TCP addresses of the enclosure that are not loopback and listen.
	Listening []string `json:"listening"`
	// Decoys are the programs of the run's PATH in the workspace that ran, each once as
	// the uid it ran as and its name.
	Decoys []string `json:"decoys"`
	// Image is the error of building an image from the probe, empty when it was built.
	Image string `json:"image"`
	// Containers are the reports of the containers the agent started, by kind.
	Containers map[string]inner `json:"containers"`
	// Command is the report of the container the agent started with the image's docker
	// command, as its user and with no proxy setting.
	Command inner `json:"command"`
	// Config is the agent's docker configuration, the directory above it and its file,
	// each with its mode and owner as the agent's user sees them, or the error it gets.
	Config []string `json:"config"`
}

// inner is what a container the agent started found. An attempt that must fail
// reports its error; empty means it succeeded.
type inner struct {
	Err            string `json:"err"`
	OutsideAddress string `json:"outside_address"`
	OutsideName    string `json:"outside_name"`
	Metadata       string `json:"metadata"`
	OriginDirect   string `json:"origin_direct"`
	ViaProxy       int    `json:"via_proxy"`
	ViaProxyErr    string `json:"via_proxy_err"`
	UID            int    `json:"uid"`
	// Proxy is the proxy the container found in its environment, when none was set for
	// it.
	Proxy string `json:"proxy,omitempty"`
	// Stderr is what the docker command printed on its standard error.
	Stderr string `json:"stderr,omitempty"`
}

// innerKinds are the containers the agent starts: plain, on the host's network, and
// privileged. Host and privileged are the enclosure's, not the machine's.
var innerKinds = []struct {
	name       string
	network    string
	privileged bool
}{{"plain", "", false}, {"host-network", "host", false}, {"privileged", "", true}}

// dockerClient speaks the Engine API on the inner daemon's socket.
func dockerClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", wall.NestSocket)
		},
	}}
}

// probeNested checks the Docker of the enclosure's own from the agent's side.
func probeNested() *nested {
	n := &nested{Containers: map[string]inner{}}
	// Last, so what the daemon ran for the containers the agent started counts too.
	defer func() { n.Decoys = decoysRan() }()
	c := dockerClient(30 * time.Second)
	resp, err := c.Get("http://docker/_ping")
	if err != nil {
		n.PingErr = err.Error()
		return n
	}
	resp.Body.Close()
	n.Ping = resp.StatusCode
	var info struct{ ID string }
	if err := getJSON(c, "http://docker/info", &info); err == nil {
		n.DaemonID = info.ID
	}
	n.Listening = listening()

	if err := importSelf(c); err != nil {
		n.Image = err.Error()
		return n
	}
	proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
	relay := ""
	if err == nil {
		if addrs, err := net.LookupHost(proxyURL.Hostname()); err == nil && len(addrs) > 0 {
			relay = "http://" + net.JoinHostPort(addrs[0], proxyURL.Port())
		}
	}
	for _, k := range innerKinds {
		n.Containers[k.name] = runInner(c, k.network, k.privileged, relay)
	}
	n.Config = configModes(os.Getenv("DOCKER_CONFIG"))
	n.Command = commandInner(os.Getenv("PROBE_ALLOWED"))
	return n
}

// commandInner starts a container of the probe the way the agent does, with the
// image's docker command, as the agent's user and in the enclosure's environment with
// nothing added: the proxy the container gets is the one the agent's DOCKER_CONFIG
// sets for the command, and the probe inside reads only the origin, from its argument.
func commandInner(origin string) inner {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return inner{Err: "the image contains no docker command: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, docker, "run", "--rm", probeImage, "/probe", modeInner, origin)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), innerPrefix); ok {
			var r inner
			if err := json.Unmarshal([]byte(rest), &r); err != nil {
				return inner{Err: err.Error()}
			}
			r.Stderr = strings.TrimSpace(stderr.String())
			return r
		}
	}
	return inner{Err: fmt.Sprintf("no report: %v: %s", err, bytes.TrimSpace(out)), Stderr: strings.TrimSpace(stderr.String())}
}

// configModes are the directory above the agent's docker configuration, the
// configuration's directory and its file, each with its mode and owner as the agent's
// user sees them, or the error that user gets.
func configModes(dir string) []string {
	if dir == "" {
		return []string{"DOCKER_CONFIG is not set"}
	}
	var out []string
	for _, p := range []string{filepath.Dir(dir), dir, filepath.Join(dir, "config.json")} {
		info, err := os.Stat(p)
		if err != nil {
			out = append(out, err.Error())
			continue
		}
		owner := ""
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			owner = fmt.Sprintf(" %d:%d", st.Uid, st.Gid)
		}
		out = append(out, fmt.Sprintf("%s %v%s", p, info.Mode(), owner))
	}
	return out
}

// decoysRan are the lines of [decoyRan], each once, in the order they were first
// written: none when no program wrote it, and the error when it is there but
// unreadable, so the check fails.
func decoysRan() []string {
	b, err := os.ReadFile(decoyRan)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{"unreadable: " + err.Error()}
	}
	var ran []string
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" && !seen[line] {
			seen[line] = true
			ran = append(ran, line)
		}
	}
	return ran
}

// getJSON decodes one answer of the daemon.
func getJSON(c *http.Client, u string, v any) error {
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %d %s", u, resp.StatusCode, bytes.TrimSpace(b))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// post sends one request to the daemon and returns its answer.
func post(c *http.Client, u string, body io.Reader, contentType string) ([]byte, error) {
	resp, err := c.Post(u, contentType, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return b, fmt.Errorf("%s: %d %s", u, resp.StatusCode, bytes.TrimSpace(b))
	}
	return b, nil
}

// probeImage is the image the probe builds of itself inside the enclosure.
const probeImage = "walltest-probe:inner"

// importSelf builds an image holding nothing but the probe, at /probe: the probe is
// static, so it needs no registry and no base image.
func importSelf(c *http.Client) error {
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "probe", Mode: 0o755, Size: int64(len(self)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	tw.Write(self)
	tw.Close()
	repo, tag, _ := strings.Cut(probeImage, ":")
	b, err := post(c, "http://docker/images/create?fromSrc=-&repo="+repo+"&tag="+tag, &buf, "application/x-tar")
	if err != nil {
		return err
	}
	if bytes.Contains(b, []byte(`"error"`)) {
		return fmt.Errorf("import: %s", bytes.TrimSpace(b))
	}
	return nil
}

// runInner starts one container of the probe in its inner mode and reads its report.
func runInner(c *http.Client, network string, privileged bool, relay string) inner {
	host := map[string]any{"Privileged": privileged}
	if network != "" {
		host["NetworkMode"] = network
	}
	body, _ := json.Marshal(map[string]any{
		"Image":      probeImage,
		"Cmd":        []string{"/probe", modeInner},
		"Env":        []string{"PROBE_ORIGIN=" + os.Getenv("PROBE_ALLOWED"), "PROBE_RELAY=" + relay},
		"HostConfig": host,
	})
	b, err := post(c, "http://docker/containers/create", bytes.NewReader(body), "application/json")
	if err != nil {
		return inner{Err: err.Error()}
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(b, &created); err != nil {
		return inner{Err: err.Error()}
	}
	defer func() {
		req, _ := http.NewRequest("DELETE", "http://docker/containers/"+created.ID+"?force=1", nil)
		if resp, err := c.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	if _, err := post(c, "http://docker/containers/"+created.ID+"/start", nil, "application/json"); err != nil {
		return inner{Err: err.Error()}
	}
	if _, err := post(c, "http://docker/containers/"+created.ID+"/wait", nil, "application/json"); err != nil {
		return inner{Err: err.Error()}
	}
	resp, err := c.Get("http://docker/containers/" + created.ID + "/logs?stdout=1&stderr=1")
	if err != nil {
		return inner{Err: err.Error()}
	}
	defer resp.Body.Close()
	out := demux(resp.Body)
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), innerPrefix); ok {
			var r inner
			if err := json.Unmarshal([]byte(rest), &r); err != nil {
				return inner{Err: err.Error()}
			}
			return r
		}
	}
	return inner{Err: "no report: " + out}
}

// demux is the output of a container without a terminal: frames of an 8-byte header,
// the stream and the length, then the bytes.
func demux(r io.Reader) string {
	var out strings.Builder
	br := bufio.NewReader(r)
	head := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, head); err != nil {
			return out.String()
		}
		n := binary.BigEndian.Uint32(head[4:])
		if _, err := io.CopyN(&out, br, int64(n)); err != nil {
			return out.String()
		}
	}
}

// listening are the TCP sockets of the probe's network namespace that listen on an
// address that is not loopback.
func listening() []string {
	var out []string
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			addr, port, _ := strings.Cut(fields[1], ":")
			ip := procIP(addr)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			p, _ := hex.DecodeString(port)
			if len(p) == 2 {
				out = append(out, net.JoinHostPort(ip.String(), fmt.Sprint(int(p[0])<<8|int(p[1]))))
			}
		}
	}
	return out
}

// procIP reads an address of /proc/net/tcp: 32-bit words in the host's byte order,
// which is little-endian on every machine the suite runs on.
func procIP(h string) net.IP {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b)
}

// innerProbe is the probe in a container the agent started: it tries what the wall
// forbids and reaches the origin through the relay. Started through the Engine API it
// reads the origin and the relay's address from PROBE_ORIGIN and PROBE_RELAY. Started
// by the docker command it reads the origin from its argument, and reaches the relay by
// the proxy variables the command set from the agent's configuration.
func innerProbe(args []string) int {
	r := inner{UID: os.Getuid()}
	r.OutsideAddress = dial("1.1.1.1:443")
	r.Metadata = dial("169.254.169.254:80")
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	if addrs, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err != nil {
		r.OutsideName = err.Error()
	} else if len(addrs) == 0 {
		r.OutsideName = "no addresses"
	}
	cancel()
	target := os.Getenv("PROBE_ORIGIN")
	var proxy func(*http.Request) (*url.URL, error)
	if len(args) > 0 {
		target = args[0]
		if r.Proxy = os.Getenv("HTTP_PROXY"); r.Proxy == "" {
			r.ViaProxyErr = "no HTTP_PROXY: the docker command set no proxy for the container"
		}
		proxy = http.ProxyFromEnvironment
	} else if relay, err := url.Parse(os.Getenv("PROBE_RELAY")); err != nil || relay.Host == "" {
		r.ViaProxyErr = "no relay address: " + os.Getenv("PROBE_RELAY")
	} else {
		proxy = http.ProxyURL(relay)
	}
	origin, err := url.Parse(target)
	if err == nil {
		r.OriginDirect = dial(origin.Host)
	}
	if r.ViaProxyErr == "" {
		client := &http.Client{Transport: &http.Transport{Proxy: proxy}, Timeout: 10 * time.Second}
		if resp, err := client.Get(target); err != nil {
			r.ViaProxyErr = err.Error()
		} else {
			resp.Body.Close()
			r.ViaProxy = resp.StatusCode
		}
	}
	b, _ := json.Marshal(r)
	fmt.Println(innerPrefix + string(b))
	return 0
}
