package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/qoryai/runner/link"
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
}

// wait is how long an attempt that must fail is given to fail.
const wait = 3 * time.Second

// probe is the runtime of the suite's session: it tries what a wall forbids, uses what
// a wall provides, calls its hook the way a runtime does, prints its report and exits
// as told.
func probe(args []string) int {
	var r report
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
	r.PassedEnv = os.Getenv("PROBE_PASSED") == "yes"
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		r.EnvNames = append(r.EnvNames, name)
	}
	sort.Strings(r.EnvNames)
	if _, err := os.Stat(os.Getenv("PROBE_HOST_FILE")); err == nil {
		r.HostFile = true
	}
	r.Namespaces = map[string]string{}
	for _, ns := range []string{"net", "pid", "mnt", "ipc", "uts"} {
		r.Namespaces[ns], _ = os.Readlink("/proc/self/ns/" + ns)
	}
	if err := os.WriteFile("probe-was-here", []byte("inside"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "probe: the workspace:", err)
	}
	r.Terminal = term.IsTerminal(int(os.Stdout.Fd()))

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

// send posts a body to u through the proxy of HTTP_PROXY, with the headers
// written in lower case, as Node writes them, and trusting the run's bundle and the
// suite's authority; an answer that contains a key is noted in r.
func send(r *report, u string, header ...string) (int, string) {
	proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxyURL.Host == "" {
		return 0, "HTTP_PROXY is " + os.Getenv("HTTP_PROXY")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return 0, err.Error()
	}
	if der, err := base64.StdEncoding.DecodeString(os.Getenv(recordersCAVar)); err == nil {
		if cert, err := x509.ParseCertificate(der); err == nil {
			roots.AddCert(cert)
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", u, strings.NewReader(`{"model":"walltest","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		return 0, err.Error()
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header[header[i]] = []string{header[i+1]}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(b), keyMark) || strings.Contains(fmt.Sprint(resp.Header), keyMark) {
		r.KeySeen = append(r.KeySeen, "the answer of "+u)
	}
	return resp.StatusCode, ""
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
