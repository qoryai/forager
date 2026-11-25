package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// The ref the tests' push credential allows, and object ids of a push's commands.
const (
	pushRef = "refs/heads/qory/wi_01"
	zeroID  = "0000000000000000000000000000000000000000"
	oldID   = "1111111111111111111111111111111111111111"
	newID   = "2222222222222222222222222222222222222222"
	longID  = "3333333333333333333333333333333333333333333333333333333333333333"
	caps    = "\x00report-status side-band-64k agent=git/2.47.0"
	pack    = "PACK\x00\x00\x00\x02\x00\x00\x00\x00 the pack's bytes"
)

// command is one ref command as git sends it, the first with its capabilities.
func command(old, new, ref string, first bool) string {
	line := old + " " + new + " " + ref
	if first {
		line += caps
	}
	return pkt(line)
}

// guardedOrigin is a git host that a credential with PushRef is for, and one whose
// credential has none, behind a terminating proxy; it records each body it reads.
type guardedOrigin struct {
	client *http.Client
	dec    *decisions
	mu     sync.Mutex
	bodies []string
}

func (o *guardedOrigin) received() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.bodies...)
}

func newGuardedOrigin(t *testing.T) *guardedOrigin {
	t.Helper()
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	o := &guardedOrigin{dec: &decisions{}}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		o.mu.Lock()
		o.bodies = append(o.bodies, string(b))
		o.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		io.WriteString(w, inside(lines("unpack ok", "ok "+pushRef)))
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	p, err := Listen("", policy.Observe, nil, nil, o.dec.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.dial = (&dials{secure: origin.Listener.Addr().String(), plain: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	token := func() string { return "a-forge-token" }
	p.Terminate(ca, []Credential{
		{Name: "forge", Hosts: []string{"git.example"}, Scheme: "bearer", Token: token, Paths: []string{"/example-org/app.git/*"}, PushRef: pushRef},
		{Name: "read", Hosts: []string{"read.example"}, Scheme: "bearer", Token: token},
	}, nil, nil)
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
	t.Cleanup(tr.CloseIdleConnections)
	o.client = &http.Client{Transport: tr, Timeout: 20 * time.Second}
	return o
}

// push sends body to target as git sends a push, with header's members set over git's,
// and returns the status and the answer.
func (o *guardedOrigin) push(t *testing.T, target string, body io.Reader, header map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const guardedPush = "https://git.example/example-org/app.git/git-receive-pack"

// TestTheBranchGuardPassesAPushOfItsRef pins the pushes the guard lets through, the
// body unchanged: an update, a create and a delete of PushRef, with shallow lines and
// sha256 ids, git's probe of a flush alone, and the body sent in pieces.
func TestTheBranchGuardPassesAPushOfItsRef(t *testing.T) {
	for name, body := range map[string]string{
		"an update":                     command(oldID, newID, pushRef, true) + flush + pack,
		"a create":                      command(zeroID, newID, pushRef, true) + flush + pack,
		"a delete":                      command(oldID, zeroID, pushRef, true) + flush,
		"after a shallow line":          pkt("shallow "+oldID) + command(oldID, newID, pushRef, true) + flush + pack,
		"with sha256 object ids":        command(longID, longID, pushRef, true) + flush + pack,
		"git's probe":                   flush,
		"with a line break":             pkt(oldID+" "+newID+" "+pushRef+caps+"\n") + flush + pack,
		"with every capability allowed": pkt(oldID+" "+newID+" "+pushRef+"\x00report-status report-status-v2 side-band side-band-64k quiet atomic ofs-delta delete-refs agent=JGit/7.1 object-format=sha1 session-id=abc") + flush + pack,
	} {
		t.Run(name, func(t *testing.T) {
			o := newGuardedOrigin(t)
			status, answer := o.push(t, guardedPush, strings.NewReader(body), nil)
			if status != http.StatusOK || !strings.Contains(answer, "ok "+pushRef) {
				t.Fatalf("got %d %q; want the host's 200", status, answer)
			}
			if got := o.received(); len(got) != 1 || got[0] != body {
				t.Errorf("the host read %q; want the body unchanged", got)
			}
		})
	}
	t.Run("in pieces", func(t *testing.T) {
		o := newGuardedOrigin(t)
		body := pkt("shallow "+oldID) + command(oldID, newID, pushRef, true) + flush + pack
		pr, pw := io.Pipe()
		go func() {
			for i := 0; i < len(body); i += 7 {
				pw.Write([]byte(body[i:min(i+7, len(body))]))
				time.Sleep(time.Millisecond)
			}
			pw.Close()
		}()
		status, _ := o.push(t, guardedPush, pr, nil)
		if got := o.received(); status != http.StatusOK || len(got) != 1 || got[0] != body {
			t.Errorf("got %d, the host read %q; want 200 and the body unchanged", status, got)
		}
	})
}

// TestTheBranchGuardRefusesAnyOtherPush pins the guard's 403s, each before anything
// reaches the host, recorded denied with wall:push-ref: a push to another branch, a
// created or a deleted other ref, PushRef beside another, a credential with no
// PushRef, a path no credential covers, a signed push, push options and any other
// capability outside the list, capabilities with a control character, ref commands in
// side-band or of another form, a body that goes on after the flush with anything but
// a pack, git's probe followed by more bytes, a content coding, and a request that
// names receive-pack in another form.
func TestTheBranchGuardRefusesAnyOtherPush(t *testing.T) {
	type c struct {
		target string
		body   string
		header map[string]string
		text   string
	}
	only := func(ref string) string {
		return "qory: push only " + pushRef + ".\nThe push of " + ref + " to git.example/example-org/app.git/git-receive-pack was not sent"
	}
	unread := "qory: send the push's ref commands as git does"
	capability := "qory: push with git over HTTPS, without --push-option.\nThe push to git.example/example-org/app.git/git-receive-pack has the capability "
	capabilities := "qory: push with git over HTTPS, without --push-option.\nThe push to git.example/example-org/app.git/git-receive-pack has the capabilities "
	goesOn := "qory: push with git over HTTPS, with nothing but a pack after the ref commands.\nThe push to git.example/example-org/app.git/git-receive-pack has other data after them, so it was not sent.\n"
	for name, c := range map[string]c{
		"another branch":              {guardedPush, command(oldID, newID, "refs/heads/main", true) + flush + pack, nil, only(`"refs/heads/main"`)},
		"a created ref":               {guardedPush, command(zeroID, newID, "refs/heads/other", true) + flush + pack, nil, only(`"refs/heads/other"`)},
		"a deleted ref":               {guardedPush, command(oldID, zeroID, "refs/heads/main", true) + flush, nil, only(`"refs/heads/main"`)},
		"a tag":                       {guardedPush, command(zeroID, newID, "refs/tags/v1", true) + flush + pack, nil, only(`"refs/tags/v1"`)},
		"its ref, then another":       {guardedPush, command(oldID, newID, pushRef, true) + command(oldID, newID, "refs/heads/main", false) + flush + pack, nil, only(`"refs/heads/main"`)},
		"no push_ref":                 {"https://read.example/example-org/app.git/git-receive-pack", command(oldID, newID, pushRef, true) + flush + pack, nil, "qory: push through qory's push step, with a credential that allows a push.\nThe run's credential for read.example allows no push, so the push was not sent.\n"},
		"a path no credential covers": {"https://git.example/other-org/app.git/git-receive-pack", command(oldID, newID, pushRef, true) + flush + pack, nil, "qory: push through qory's push step, with a credential that allows a push.\nThe run's credential for git.example allows no push, so the push was not sent.\n"},
		"push options":                {guardedPush, pkt(zeroID+" "+newID+" "+pushRef+"\x00report-status push-options") + flush + pkt("merge_request.create") + pkt("merge_request.target=main") + flush + pack, nil, capability + `"push-options", so it was not sent`},
		"another capability":          {guardedPush, pkt(oldID+" "+newID+" "+pushRef+"\x00report-status x-unknown=1") + flush + pack, nil, capability + `"x-unknown=1", so it was not sent`},
		"push options after a tab":    {guardedPush, pkt(zeroID+" "+newID+" "+pushRef+"\x00agent=x\tpush-options") + flush + pkt("merge_request.create") + flush + pack, nil, capabilities + `"agent=x\tpush-options", which have a control character`},
		"a control character":         {guardedPush, pkt(oldID+" "+newID+" "+pushRef+"\x00report-status\vquiet") + flush + pack, nil, capabilities + `"report-status\vquiet"`},
		"push-cert as a capability":   {guardedPush, pkt(oldID+" "+newID+" "+pushRef+"\x00report-status push-cert=1700000000-abc") + flush + pack, nil, capability + `"push-cert=1700000000-abc", so it was not sent`},
		"lines after the flush":       {guardedPush, command(oldID, newID, pushRef, true) + flush + pkt("merge_request.create") + flush + pack, nil, goesOn},
		"git's probe, then more":      {guardedPush, flush + command(zeroID, newID, "refs/heads/main", true) + flush + pack, nil, goesOn},
		"a delete, then bytes":        {guardedPush, command(oldID, zeroID, pushRef, true) + flush + "x", nil, goesOn},
		"a signed push":               {guardedPush, pkt("push-cert"+caps+"\n") + pkt("certificate version 0.1\n") + pkt(oldID+" "+newID+" "+pushRef+"\n") + pkt("push-cert-end\n") + flush, nil, "qory: push without --signed"},
		"commands in side-band":       {guardedPush, band(bandReport, oldID+" "+newID+" "+pushRef+caps) + flush + pack, nil, unread},
		"commands split in band 1":    {guardedPush, band(bandReport, command(oldID, newID, pushRef, true)[:20]) + band(bandReport, command(oldID, newID, pushRef, true)[20:]) + flush, nil, unread},
		"a short object id":           {guardedPush, command("1111", newID, pushRef, true) + flush + pack, nil, unread},
		"an empty line":               {guardedPush, "0004" + flush, nil, unread},
		"no flush":                    {guardedPush, command(oldID, newID, pushRef, true), nil, "qory: send the push's ref commands within 64 KiB"},
		"gzip":                        {guardedPush, command(oldID, newID, pushRef, true) + flush, map[string]string{"Content-Encoding": "gzip"}, "qory: push with git over HTTPS"},
		"another content type":        {guardedPush, command(oldID, newID, pushRef, true) + flush, map[string]string{"Content-Type": "application/octet-stream"}, "qory: push with git over HTTPS"},
		"a trailing slash":            {guardedPush + "/", command(oldID, newID, pushRef, true) + flush, nil, "qory: push with git over HTTPS"},
		"upper case":                  {"https://git.example/example-org/app.git/GIT-RECEIVE-PACK", command(oldID, newID, pushRef, true) + flush, nil, "qory: push with git over HTTPS"},
	} {
		t.Run(name, func(t *testing.T) {
			o := newGuardedOrigin(t)
			status, answer := o.push(t, c.target, strings.NewReader(c.body), c.header)
			if status != http.StatusForbidden || !strings.HasPrefix(answer, c.text) {
				t.Errorf("got %d %q; want 403 %q", status, answer, c.text)
			}
			if got := o.received(); len(got) != 0 {
				t.Errorf("the host read %q; want nothing", got)
			}
			last := o.dec.at(-1)
			if last.Allowed || last.PathRule != PushRefRule || last.Outcome != Refused {
				t.Errorf("the decision %+v; want denied, refused, %s", last, PushRefRule)
			}
		})
	}
}

// TestTheBranchGuardRefusesASlowSection pins the wait: ref commands that have not
// ended within PushCommandsWait are refused.
func TestTheBranchGuardRefusesASlowSection(t *testing.T) {
	was := PushCommandsWait
	PushCommandsWait = 200 * time.Millisecond
	t.Cleanup(func() { PushCommandsWait = was })
	o := newGuardedOrigin(t)
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte(command(oldID, newID, pushRef, true)))
		time.Sleep(2 * time.Second)
		pw.CloseWithError(errors.New("the test ends the body"))
	}()
	status, answer := o.push(t, guardedPush, pr, nil)
	if status != http.StatusForbidden || !strings.HasPrefix(answer, "qory: send the push's ref commands within 64 KiB and 200ms") {
		t.Errorf("got %d %q; want the 403 of a slow section", status, answer)
	}
	if got := o.received(); len(got) != 0 {
		t.Errorf("the host read %q; want nothing", got)
	}
}

// TestTheBranchGuardReadsCommandsInAnyPieces pins readCommands on bodies that arrive
// whole, a byte a read and three bytes a read: the bytes it returns are every byte it
// read, and its decision is the same, for the commands and for what follows their
// flush.
func TestTheBranchGuardReadsCommandsInAnyPieces(t *testing.T) {
	good := pkt("shallow "+oldID) + command(oldID, newID, pushRef, true) + flush + pack
	bad := command(oldID, newID, pushRef, true) + command(oldID, newID, "refs/heads/main", false) + flush + pack
	big := strings.Repeat(pkt("shallow "+oldID), MaxPushCommands/40) + flush
	for name, split := range splits {
		read, err := readCommands(split(strings.NewReader(good)), pushRef)
		if err != nil || !strings.HasPrefix(good, string(read)) || !strings.Contains(string(read), flush) {
			t.Errorf("%s: a good push read %q, %v; want its commands and flush", name, read, err)
		}
		var refused *pushRefusal
		if _, err := readCommands(split(strings.NewReader(bad)), pushRef); !errors.As(err, &refused) || !strings.Contains(refused.text, `"refs/heads/main"`) {
			t.Errorf("%s: another ref gave %v; want its refusal", name, err)
		}
		if _, err := readCommands(split(strings.NewReader(big)), pushRef); err == nil || errors.As(err, &refused) {
			t.Errorf("%s: a section over %d bytes gave %v; want the cap's error", name, MaxPushCommands, err)
		}
		if read, err := readCommands(split(strings.NewReader(flush)), pushRef); err != nil || string(read) != flush {
			t.Errorf("%s: git's probe read %q, %v; want the flush", name, read, err)
		}
		for _, more := range []string{flush + "x", command(oldID, newID, pushRef, true) + flush + "PAC", command(oldID, newID, pushRef, true) + flush + "0004"} {
			if _, err := readCommands(split(strings.NewReader(more)), pushRef); !errors.As(err, &refused) || !strings.Contains(refused.text, "has other data after them") {
				t.Errorf("%s: %q gave %v; want the refusal of what follows the flush", name, more, err)
			}
		}
	}
}
