package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file pin the check of a run's image by reference at its registry,
// before the wall's pull: a HEAD of the manifest through the run's proxy, a token from
// the registry's realm when it asks for one, and what each answer makes of the run.

// registryHosts are the names the test registry's certificate is for: the registry of
// pinned and its token realm.
var registryHosts = []string{"registry.example", "auth.registry.example"}

// testRegistry is a TLS listener that serves what a registry serves at registryHosts,
// with handler, under an authority of the test's.
type testRegistry struct {
	*httptest.Server
	// ca is the authority of the server's certificate, as PEM.
	ca []byte
}

// startRegistry starts a test registry that answers with handler.
func startRegistry(handler http.Handler) *testRegistry {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "registry test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: registryHosts[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: registryHosts}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.StartTLS()
	return &testRegistry{Server: s, ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
}

// addr is the registry's listener, host:port.
func (r *testRegistry) addr() string { return r.Listener.Addr().String() }

// anyManifest answers the HEAD of every manifest 200, with the digest of its path.
func anyManifest(w http.ResponseWriter, r *http.Request) {
	if _, digest, ok := strings.Cut(r.URL.Path, "/manifests/"); ok && r.Method == http.MethodHead {
		w.Header().Set("Docker-Content-Digest", digest)
		return
	}
	http.NotFound(w, r)
}

// defaultRegistry is the registry every fake gateway's proxy tunnels a CONNECT to when
// the test sets no other, and whose authority the check trusts: it answers every
// manifest 200.
func defaultRegistry() func() {
	reg := startRegistry(http.HandlerFunc(anyManifest))
	session.SetManifestRoots(reg.ca)
	linktest.SetConnect(func(string) string { return reg.addr() })
	return reg.Close
}

// pinnedDigest is the digest of pinned.
var pinnedDigest = pinned[strings.Index(pinned, "@")+1:]

// registryToken is the fake token the test realm gives.
const registryToken = "fake-registry-token-0123456789"

// scripted is a registry and its token realm whose manifest answers follow a script.
type scripted struct {
	mu sync.Mutex
	// status is the manifest's answer to a HEAD without a token, and withToken its
	// answer to one with registryToken; digest is its Docker-Content-Digest, the path's
	// when empty; challenge, when set, is the WWW-Authenticate of a 401.
	status, withToken int
	digest, challenge string
	// realmStatus is the realm's answer, 200 with registryToken when 0.
	realmStatus int
	// hang has the manifest answer nothing until the request ends.
	hang bool
	// heads are the HEADs, each with its Authorization; realm the realm's queries, each
	// with its Authorization.
	heads, realm []string
}

func (s *scripted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/token" {
		s.realm = append(s.realm, r.URL.RawQuery+" "+r.Header.Get("Authorization"))
		if s.realmStatus != 0 {
			w.WriteHeader(s.realmStatus)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": registryToken})
		return
	}
	s.heads = append(s.heads, r.Method+" "+r.URL.Path+" "+r.Header.Get("Accept")+" "+r.Header.Get("Authorization"))
	if s.hang {
		s.mu.Unlock()
		<-r.Context().Done()
		s.mu.Lock()
		return
	}
	status := s.status
	if r.Header.Get("Authorization") == "Bearer "+registryToken {
		status = s.withToken
	}
	if status == http.StatusUnauthorized && s.challenge != "" {
		w.Header().Set("WWW-Authenticate", s.challenge)
	}
	if status == http.StatusOK {
		_, digest, _ := strings.Cut(r.URL.Path, "/manifests/")
		if s.digest != "" {
			digest = s.digest
		}
		w.Header().Set("Docker-Content-Digest", digest)
	}
	w.WriteHeader(status)
}

// bearer is the registry's Bearer challenge, with the realm of the test registry.
const bearer = `Bearer realm="https://auth.registry.example/token",service="registry.example",scope="repository:agents/app:pull"`

// held is a credential of the run on hosts: in the answer's credential_hosts when
// answered, and in its applied credentials when used, with paths when set.
type held struct {
	hosts, paths   []string
	answered, used bool
	// tool makes it a tool, forge, that serves hosts, in place of a credential.
	tool bool
}

// byReferenceHolding is byReference with the credentials creds in the run's answer.
func byReferenceHolding(g *linktest.Fake, creds []held) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["image"] = map[string]any{"ref": pinned, "reference": true}
		a["relay_image"] = "example.com/agent:1"
		applied := a["applied"].(map[string]any)
		applied["image"] = pinned
		var hosts, uses, tools []any
		for i, c := range creds {
			name := "registry-" + string(rune('a'+i))
			if c.tool {
				tools = append(tools, map[string]any{"name": "forge", "hosts": c.hosts})
				continue
			}
			if c.answered {
				hosts = append(hosts, map[string]any{"name": name, "hosts": c.hosts, "placeholders": []string{}, "auth": map[string]any{"scheme": "bearer"}})
			}
			if c.used {
				use := map[string]any{"name": name, "hosts": c.hosts, "scheme": "bearer"}
				if c.paths != nil {
					use["paths"] = c.paths
				}
				uses = append(uses, use)
			}
		}
		if hosts != nil {
			a["credential_hosts"] = hosts
		}
		if uses != nil {
			applied["credentials"] = uses
		}
		if tools != nil {
			applied["tools"] = tools
		}
		return linktest.Reply{Status: 200, Body: a}
	})
}

// TestTheImageIsCheckedAtItsRegistryBeforeThePull pins the check before the wall's pull,
// on one machine and behind a separate gateway: a HEAD of the manifest through the run's
// proxy, with the Accept of an index and a manifest; on a 401 with a Bearer challenge, a
// GET of the realm with the service and the scope of a pull, with no Authorization, and
// the HEAD again with the token; only a 200 pulls. A 401 after the token, a Basic
// challenge, a 403, a realm that answers 401 or 403, a realm over http on a host off
// loopback, a realm on a host with no ASCII form, a realm on another host than the
// registry's that a tool of the run serves, where a credential of the run applies on
// every path or on other paths, or that the answer lists a credential for with no use
// or a use with masked hosts, a digest the registry did not ask for and a host the
// run's proxy denies each fail the image step before the wall pulls, each error
// starting with what to fix; a 404 is image_missing. The token is in no error, no file
// of the run directory and no report.
func TestTheImageIsCheckedAtItsRegistryBeforeThePull(t *testing.T) {
	accept := "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, " +
		"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
	head := "HEAD /v2/agents/app/manifests/" + pinnedDigest + " " + accept + " "
	for _, c := range []struct {
		name  string
		reg   *scripted
		creds []held
		deny  string
		heads []string
		realm []string
		// want is the start of the error, empty for a pull; missing wants image_missing.
		want    string
		missing bool
	}{
		{name: "200", reg: &scripted{status: 200}, heads: []string{head}},
		{name: "a 401, the token, then 200", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			heads: []string{head, head + "Bearer " + registryToken}, realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "}},
		{name: "a realm on the registry's host, which a credential covers",
			reg:   &scripted{status: 401, withToken: 200, challenge: `Bearer realm="https://registry.example/token",service="registry.example"`},
			creds: []held{{hosts: []string{"registry.example"}, answered: true, used: true}},
			heads: []string{head, head + "Bearer " + registryToken}, realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "}},
		{name: "a realm a credential's paths cover", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"auth.registry.example"}, paths: []string{"/token"}, answered: true, used: true}},
			heads: []string{head, head + "Bearer " + registryToken}, realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "}},
		{name: "a realm no credential applies to", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"api.git.example"}, answered: true, used: true}},
			heads: []string{head, head + "Bearer " + registryToken}, realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "}},
		{name: "a realm a credential covers on every path", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"auth.registry.example"}, answered: true, used: true}}, heads: []string{head},
			want: "Set paths on the run's credentials for auth.registry.example, with one that covers /token: the token realm of the registry at registry.example is on that host, " +
				"and the check of the image " + pinned + " asks a realm on another host only where no run credential applies, or one whose paths cover the realm's path."},
		{name: "a realm a credential covers on other paths", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"auth.registry.example"}, paths: []string{"/repos/*"}, answered: true, used: true}}, heads: []string{head},
			want: "Set paths on the run's credentials for auth.registry.example, with one that covers /token: the token realm of the registry at registry.example is on that host, " +
				"and the check of the image " + pinned + " asks a realm on another host only where no run credential applies, or one whose paths cover the realm's path."},
		{name: "a realm a pattern's credential covers", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"*.registry.example"}, answered: true, used: true}}, heads: []string{head},
			want: "Set paths on the run's credentials for auth.registry.example, with one that covers /token: the token realm of the registry at registry.example is on that host, " +
				"and the check of the image " + pinned + " asks a realm on another host only where no run credential applies, or one whose paths cover the realm's path."},
		{name: "a realm a credential covers with no use listed", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"auth.registry.example"}, answered: true}}, heads: []string{head},
			want: "Check the credentials of the gateway's answer for auth.registry.example: it lists a credential for that host with no use, or a use whose hosts are masked, " +
				"so the check of the image " + pinned + " cannot tell what the run's proxy sets on a token request to that host."},
		{name: "a realm a credential with masked hosts may cover", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"(a value that contains a run key)"}, used: true}}, heads: []string{head},
			want: "Check the credentials of the gateway's answer for auth.registry.example: it lists a credential for that host with no use, or a use whose hosts are masked, " +
				"so the check of the image " + pinned + " cannot tell what the run's proxy sets on a token request to that host."},
		{name: "a realm a tool serves", reg: &scripted{status: 401, withToken: 200, challenge: bearer},
			creds: []held{{hosts: []string{"auth.registry.example"}, tool: true}}, heads: []string{head},
			want: "Use a registry with no token realm on auth.registry.example, which the run's tool forge serves: the run's proxy passes the token request to that tool, " +
				"and the check of the image " + pinned + " asks a realm on another host only where no tool of the run serves it."},
		{name: "a realm at the registry's host and its https port",
			reg:   &scripted{status: 401, withToken: 200, challenge: `Bearer realm="https://registry.example:443/token",service="registry.example"`},
			creds: []held{{hosts: []string{"registry.example"}, answered: true, used: true}},
			heads: []string{head, head + "Bearer " + registryToken}, realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "}},
		{name: "a realm on a host in fullwidth letters", reg: &scripted{status: 401, withToken: 200, challenge: `Bearer realm="https://ａｐｉ.forge.example/x"`},
			creds: []held{{hosts: []string{"api.forge.example"}, answered: true, used: true}}, heads: []string{head},
			want: "Check the registry at registry.example: its Bearer challenge to the check of the image " + pinned + " has the token realm host " + `"ａｐｉ.forge.example"` + ", which is not an ASCII host name or an IP address in canonical form."},
		{name: "a realm on a host with a letter that is not ASCII", reg: &scripted{status: 401, withToken: 200, challenge: `Bearer realm="https://bücher.example.com/x"`},
			creds: []held{{hosts: []string{"*.example.com"}, answered: true, used: true}}, heads: []string{head},
			want: "Check the registry at registry.example: its Bearer challenge to the check of the image " + pinned + " has the token realm host " + `"bücher.example.com"` + ", which is not an ASCII host name or an IP address in canonical form."},
		{name: "a realm on a host escaped with percent signs", reg: &scripted{status: 401, withToken: 200, challenge: `Bearer realm="https://%EF%BD%81pi.forge.example/x"`},
			creds: []held{{hosts: []string{"api.forge.example"}, answered: true, used: true}}, heads: []string{head},
			want: "Check the registry at registry.example: its Bearer challenge to the check of the image " + pinned + " has the token realm host " + `"ａpi.forge.example"` + ", which is not an ASCII host name or an IP address in canonical form."},
		{name: "a 401 after the token", reg: &scripted{status: 401, withToken: 401, challenge: bearer},
			heads: []string{head, head + "Bearer " + registryToken}, realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "},
			want: "Give the run a credential that may pull " + pinned + ": its registry answered 401 to the check of its manifest with the token from auth.registry.example."},
		{name: "a Basic challenge", reg: &scripted{status: 401, challenge: `Basic realm="registry"`}, heads: []string{head},
			want: "Give the run a credential for registry.example: its registry answered 401 to the check of the image " + pinned + " with no Bearer challenge."},
		{name: "a realm that answers 401", reg: &scripted{status: 401, challenge: bearer, realmStatus: 401}, heads: []string{head},
			realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "},
			want:  "Give the run a credential for auth.registry.example that may pull " + pinned + ": the token realm answered 401 to the check of the image."},
		{name: "403", reg: &scripted{status: 403}, heads: []string{head},
			want: "Give the run a credential that may pull " + pinned + ", or a path rule that covers /v2/agents/app/manifests/ on registry.example: the check of its manifest got 403 from its registry or from the run's proxy."},
		{name: "a realm that answers 403", reg: &scripted{status: 401, challenge: bearer, realmStatus: 403}, heads: []string{head},
			realm: []string{"scope=repository%3Aagents%2Fapp%3Apull&service=registry.example "},
			want: "Give the run a credential for auth.registry.example that may pull " + pinned + ", or a path rule that covers /token on auth.registry.example: " +
				"the token request got 403 from the realm or from the run's proxy."},
		{name: "a realm over http", reg: &scripted{status: 401, challenge: `Bearer realm="http://auth.registry.example/token",service="registry.example"`}, heads: []string{head},
			want: "Check the registry at registry.example: the realm of its Bearer challenge to the check of the image " + pinned + " is neither https nor http on loopback."},
		{name: "404", reg: &scripted{status: 404}, heads: []string{head}, missing: true},
		{name: "another digest", reg: &scripted{status: 200, digest: "sha256:" + strings.Repeat("c", 64)}, heads: []string{head},
			want: "Check the registry at registry.example: it answered the check of the image " + pinned + " with the digest sha256:" + strings.Repeat("c", 64) + "."},
		{name: "a registry the proxy denies", reg: &scripted{status: 200}, deny: "registry.example:443",
			want: "Allow registry.example in the node's policy, and in the server's policy for a run from a server.\n" +
				"The run's proxy denied the check of the image " + pinned + " at its registry (qory: egress to registry.example:443 denied by policy (mode enforce))."},
		{name: "a realm the proxy denies", reg: &scripted{status: 401, challenge: bearer}, deny: "auth.registry.example:443", heads: []string{head},
			want: "Allow auth.registry.example in the node's policy, and in the server's policy for a run from a server.\n" +
				"The run's proxy denied the check of the image " + pinned + " at its registry (qory: egress to auth.registry.example:443 denied by policy (mode enforce))."},
	} {
		for _, separate := range []bool{false, true} {
			name := c.name + ", one machine"
			if separate {
				name = c.name + ", separate gateway"
			}
			t.Run(name, func(t *testing.T) {
				c.reg.mu.Lock()
				c.reg.heads, c.reg.realm = nil, nil
				c.reg.mu.Unlock()
				reg := startRegistry(c.reg)
				defer reg.Close()
				defer session.SetManifestRoots(session.SetManifestRoots(reg.ca))
				sp, g := specGateway(t, "FAKE_EXIT=0")
				if separate {
					g = startRemote(t)
					g.SetInterval(30)
					sp.Gateway = session.RemoteGateway{RunKey: g.RunKey(t, event.NewRunID()), TLS: server.RemoteTLS{CAFile: g.CAFile()}}
				}
				g.OnConnect(func(hostport string) string {
					if hostport == c.deny {
						return ""
					}
					return reg.addr()
				})
				if c.creds != nil {
					byReferenceHolding(g, c.creds)
				} else {
					byReference(g)
				}
				w := &pullingWall{}
				sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
				reports := reportsOf(t, &sp)
				ctx := context.Background()
				r, err := session.Open(ctx, opened(sp))
				if err != nil {
					t.Fatal(err)
				}
				err = r.FetchImage(ctx)
				var ref *session.Refusal
				switch {
				case c.want == "" && !c.missing && err != nil:
					t.Errorf("the fetch: %v", err)
				case c.missing && (!errors.As(err, &ref) || ref.Code != refusals.ImageMissing || !slices.Equal(ref.Names, []string{pinned}) ||
					ref.Detail != "the image "+pinned+" is not in its registry: the registry answered 404 to the check of its manifest"):
					t.Errorf("the fetch: %v, want image_missing", err)
				case c.want != "" && (err == nil || err.Error() != c.want):
					t.Errorf("the fetch: %v\nwant %s", err, c.want)
				}
				if pulled := len(w.pulls) == 1; pulled != (c.want == "" && !c.missing) {
					t.Errorf("the wall pulled %+v", w.pulls)
				}
				c.reg.mu.Lock()
				heads, realm := c.reg.heads, c.reg.realm
				c.reg.mu.Unlock()
				if !slices.Equal(heads, c.heads) || !slices.Equal(realm, c.realm) {
					t.Errorf("the manifest's requests %q, want %q; the realm's %q, want %q", heads, c.heads, realm, c.realm)
				}
				if !slices.Contains(g.Connects(), "registry.example:443") {
					t.Errorf("the run's proxy got the CONNECTs %q", g.Connects())
				}
				closed, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded})
				if err != nil {
					t.Fatal(err)
				}
				state := "succeeded"
				if c.want != "" || c.missing {
					state = "failed"
				}
				var steps []string
				for _, l := range stepOrder(events(t, &session.Result{Dir: closed.Dir})) {
					if !strings.HasPrefix(l, "log ") {
						steps = append(steps, l)
					}
				}
				if want := []string{"step 1 image " + pinned, "step 1 " + state + " -1", "run exited"}; !slices.Equal(steps, want) {
					t.Errorf("the steps %q, want %q", steps, want)
				}
				noSecretIn(t, registryToken, r.Dir(), g, reports())
			})
		}
	}
}

// TestACheckThatTimesOutFailsTheStep pins a registry that does not answer the check: the
// image step fails after the check's time, with an error that says so, and the wall
// pulls nothing.
func TestACheckThatTimesOutFailsTheStep(t *testing.T) {
	reg := startRegistry(&scripted{hang: true})
	defer reg.Close()
	defer session.SetManifestRoots(session.SetManifestRoots(reg.ca))
	defer session.SetManifestWait(session.SetManifestWait(time.Second))
	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.OnConnect(func(string) string { return reg.addr() })
	byReference(g)
	w := &pullingWall{}
	sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	want := "Check that registry.example answers through the run's proxy within 1s: the check of the image " + pinned + " at its registry timed out."
	if err := r.FetchImage(ctx); err == nil || err.Error() != want || len(w.pulls) != 0 {
		t.Errorf("the fetch: %v, pulled %+v\nwant %s", err, w.pulls, want)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
}

// TestAFailedCheckStartsNoContainer pins the check in a join: a registry that answers 403
// ends the session failed, with no reason, before the wall pulls or wraps, so no
// container of the image starts.
func TestAFailedCheckStartsNoContainer(t *testing.T) {
	reg := startRegistry(&scripted{status: http.StatusForbidden})
	defer reg.Close()
	defer session.SetManifestRoots(session.SetManifestRoots(reg.ca))
	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.OnConnect(func(string) string { return reg.addr() })
	byReference(g)
	w := &targetWall{}
	sp.Wall, sp.Image, sp.ImagesAllow, sp.RunID = w, "example.com/agent:1", []string{"registry.example/"}, event.NewRunID()
	_, err := run(context.Background(), sp)
	if want := "Give the run a credential that may pull " + pinned + ", or a path rule that covers /v2/agents/app/manifests/ on registry.example: the check of its manifest got 403 from its registry or from the run's proxy."; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("the run: %v, want %s", err, want)
	}
	if len(w.pulls) != 0 || w.wrapped {
		t.Errorf("the wall pulled %+v, wrapped %v", w.pulls, w.wrapped)
	}
	startedThenExited(t, "the record", events(t, &session.Result{Dir: filepath.Join(sp.RunsDir, sp.RunID)}), "")
}

// TestTheManifestIsAtTheRegistrysAPIHost pins where the check finds a manifest: the
// registry's host, registry-1.docker.io for docker.io, and the repository in library/
// for a docker.io name of one part.
func TestTheManifestIsAtTheRegistrysAPIHost(t *testing.T) {
	const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for ref, want := range map[string]string{
		"registry.example/agents/app" + digest: "registry.example agents/app",
		"registry.example:5000/app" + digest:   "registry.example:5000 app",
		"app" + digest:                         "registry-1.docker.io library/app",
		"example/app" + digest:                 "registry-1.docker.io example/app",
		"docker.io/library/app" + digest:       "registry-1.docker.io library/app",
		"index.docker.io/example/app" + digest: "registry-1.docker.io example/app",
		"localhost:5000/agents/app" + digest:   "localhost:5000 agents/app",
		"ghcr.example/org/team/app" + digest:   "ghcr.example org/team/app",
	} {
		host, repository, d := wall.RegistryManifest(ref)
		if got := host + " " + repository; got != want || "@"+d != digest {
			t.Errorf("%s: %s %s, want %s", ref, got, d, want)
		}
	}
}
