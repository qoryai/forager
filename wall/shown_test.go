package wall

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
)

// The phrases a message prints in place of a value or a name with qak_ or qrk_ in it.
var (
	valueWithSecret = accesskey.ShownValue("qak_", false)
	valueWithRunKey = accesskey.ShownValue("qrk_", false)
	nameWithSecret  = accesskey.ShownName("qak_", false)
	nameWithRunKey  = accesskey.ShownName("qrk_", false)
)

// noPrefix fails the test when msg contains qak_ or qrk_, in any case.
func noPrefix(t *testing.T, what, msg string) {
	t.Helper()
	if accesskey.ContainsSecret(msg) {
		t.Errorf("%s prints qak_ or qrk_: %s", what, msg)
	}
}

// saying is a machine whose every docker command fails and prints out.
type saying struct {
	*recorder
	out string
}

func (s saying) run(_ context.Context, argv, _ []string) ([]byte, error) {
	s.lines = append(s.lines, words(argv))
	return []byte(s.out), errors.New("exit status 1")
}

// quoting is a machine whose image inspect fails with err, or, when helper is true,
// whose check of the helper does.
type quoting struct {
	*recorder
	err    error
	helper bool
}

func (q quoting) output(ctx context.Context, argv, env []string) ([]byte, error) {
	if q.helper {
		return q.recorder.output(ctx, argv, env)
	}
	return nil, q.err
}

func (q quoting) checkHelper(string) error {
	if q.helper {
		return q.err
	}
	return nil
}

// TestAQuotedValueWithASecretPrefixIsAPhrase pins that a message that quotes a value or
// a name the wall refused prints a phrase in its place when it contains qak_ or qrk_ in
// any case, and quotes a value without either as before.
func TestAQuotedValueWithASecretPrefixIsAPhrase(t *testing.T) {
	ctx := context.Background()
	prepare := func(req Request) error {
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: &recorder{t: t, uid: 1000}}
		_, err := d.Prepare(ctx, req)
		return err
	}
	e := &dockerEnclosure{sys: &recorder{t: t}}
	none := func(string, string) (int, int, bool) { return 0, 0, false }
	resolve := func(string) ([]string, error) { return nil, nil }
	for _, c := range []struct {
		name          string
		call          func(string) error
		secret, clean string
		want          string
	}{
		{"run id", func(v string) error { return prepare(Request{RunID: v, Image: "i"}) },
			"-QAK_x", "-x", `wall docker: the run id "-x" cannot name a container`},
		{"image", func(v string) error { return prepare(Request{RunID: runID, Image: v}) },
			"-qak_x", "-x", `wall docker: "-x" is not an image reference`},
		{"relay image", func(v string) error { return prepare(Request{RunID: runID, Image: "i", RelayImage: v}) },
			"-qrk_y", "-x", `wall docker: "-x" is not an image reference`},
		{"runtime", func(v string) error { return prepare(Request{RunID: runID, Image: "i", Runtime: v}) },
			"-QRK_y", "-x", `wall docker: "-x" is not a container runtime's name`},
		{"user", func(v string) error {
			d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: v, sys: &recorder{t: t, uid: 1000}}
			_, err := d.Prepare(ctx, Request{RunID: runID, Image: "i"})
			return err
		}, "-qak_x", "-x", `wall docker: the user "-x" is not uid[:gid] or a name`},
		{"user by name", func(v string) error {
			d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: v, sys: &recorder{t: t, uid: 1000}}
			_, err := d.Prepare(ctx, Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true})
			return err
		}, "qrk_y", "app", `wall docker: an image a run names by its reference needs the wall's user as uid:gid in numbers, neither of them 0, not "app", which the image's /etc/passwd or /etc/group would resolve`},
		{"reaped run id", func(v string) error { _, err := (&Docker{sys: &recorder{t: t}}).Reap(ctx, v); return err },
			"-qak_x", "-x", `wall docker: the run id "-x" cannot name a container`},
		{"cpus", func(v string) error { _, err := limits(Limits{CPUs: v}); return err },
			"qak_x", "x1", `wall docker: the cpus limit "x1" is not a decimal number`},
		{"memory", func(v string) error { _, err := limits(Limits{Memory: v}); return err },
			"QRK_y", "1t", `wall docker: the memory "1t" is not a number of bytes with a unit of b, k, m or g`},
		{"mounted path", func(v string) error { _, err := mount(v, "/dst", false); return err },
			"/a,qak_x", "/a,b", `wall docker: the path "/a,b" holds a comma or a quote and cannot be mounted`},
		{"workspace", func(v string) error { _, _, err := e.mounts(Launch{Dir: v}); return err },
			"qrk_y", "work", `wall docker: the workspace "work" is not an absolute path`},
		{"mount", func(v string) error {
			_, _, err := e.mounts(Launch{Dir: "/work", Mounts: []Mount{{Path: v}}})
			return err
		}, "qak_x", "work", `wall docker: the mount "work" is not an absolute path`},
		{"mount target", func(v string) error {
			_, _, err := e.mounts(Launch{Dir: "/work", Mounts: []Mount{{Path: "/work", Target: v}}})
			return err
		}, "qak_x", "work", `wall docker: the mount "/work" is shown at "work", which is not an absolute path`},
		{"environment entry", func(v string) error { _, err := e.envFile("env", []string{v}); return err },
			"qak_x", "#A", `wall docker: the environment entry "#A" is not NAME=value`},
		{"engine's wall", func(v string) error {
			_, err := runContainersExist(ctx, &recorder{t: t}, Engine{Wall: v}, runID)
			return err
		}, "qak_x", "other", `wall: the "other" wall's engine cannot be asked`},
		{"engine's variable", func(v string) error {
			_, err := runContainersExist(ctx, &recorder{t: t}, Engine{Wall: "docker", Command: "docker", Env: []string{v + "=1"}}, runID)
			return err
		}, "QAK_x", "PATH", `wall docker: PATH does not select an engine`},
		{"forward", func(v string) error { _, _, err := parseForward(v); return err },
			"qak_x", "x", `relay: forward "x" is not port=host:port`},
		{"subnet", func(v string) error { _, _, err := insideAddrs(v, nil); return err },
			"QRK_y", "x", `relay: "x" in QORY_RELAY_INSIDE is not a subnet`},
		{"user map", userNamespaced, "0 qak_x", "0 1", `nest: the user map "0 1" cannot be read`},
		{"image's user", func(v string) error { _, _, err := nestIDs(v, none); return err },
			"qak_x", "app", `nest: the image has no user "app"`},
		{"image's group", func(v string) error { _, _, err := nestIDs("1000:"+v, none); return err },
			"qrk_y", "app", `nest: the image has no group "app"`},
		{"proxy", func(v string) error {
			_, err := nestProxies(func(k string) string { return map[string]string{"HTTPS_PROXY": v}[k] }, resolve)
			return err
		}, "qak_x", "::", `nest: the proxy "::" is not a URL`},
	} {
		err := c.call(c.secret)
		if err == nil {
			t.Errorf("%s: %q was taken", c.name, c.secret)
			continue
		}
		noPrefix(t, c.name, err.Error())
		if !strings.Contains(err.Error(), "(a name that contains") && !strings.Contains(err.Error(), "(a value that contains") {
			t.Errorf("%s: no phrase in %s", c.name, err)
		}
		if err := c.call(c.clean); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
	}
}

// TestARefusalOfAnImageWithASecretPrefixListsAPhrase pins that an image_user_root
// refusal lists and describes an image or a user whose name contains qak_ or qrk_ by a
// phrase, and a name without either as before.
func TestARefusalOfAnImageWithASecretPrefixListsAPhrase(t *testing.T) {
	const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const tail = "; a run's image runs as the wall's user"
	for _, c := range []struct {
		image, user string
		names       []string
		detail      string
	}{
		{"registry.example/qak_x/app" + digest, `"0"`, []string{nameWithSecret},
			"the image " + nameWithSecret + " runs as root" + tail},
		{"registry.example/QRK_y/app" + digest, `"0"`, []string{nameWithRunKey},
			"the image " + nameWithRunKey + " runs as root" + tail},
		{byReference, `"0"`, []string{byReference}, "the image " + byReference + " runs as root" + tail},
		{byReference, `"qrk_y"`, []string{byReference}, "the image " + byReference + " runs as the user " +
			nameWithRunKey + ", which no /etc/passwd of the image maps to a uid, so it cannot be checked for root" + tail},
		{byReference, `"nobody"`, []string{byReference}, "the image " + byReference + " runs as the user " +
			"nobody, which no /etc/passwd of the image maps to a uid, so it cannot be checked for root" + tail},
	} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: c.user}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
		_, err := d.Prepare(context.Background(), Request{RunID: runID, Image: c.image, RelayImage: "example.com/agent:1", Pull: true})
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.ImageUserRoot {
			t.Errorf("image %s, user %s: %v, want image_user_root", c.image, c.user, err)
			continue
		}
		if !slices.Equal(r.Names, c.names) || r.Detail != c.detail {
			t.Errorf("image %s, user %s: names %q, detail %q\nwant %q, %q", c.image, c.user, r.Names, r.Detail, c.names, c.detail)
		}
		noPrefix(t, "the refusal", err.Error())
	}
}

// TestAnErrorThatQuotesASecretIsAPhrase pins that an error of the machine's whose text
// contains qak_ or qrk_, such as an os error that quotes a path, reaches the wall's
// message as a phrase and is still wrapped, and that one without either reaches it as
// before.
func TestAnErrorThatQuotesASecretIsAPhrase(t *testing.T) {
	ctx := context.Background()
	quoted := errors.New("open /home/dev/qak_x/config.json: permission denied")
	clean := errors.New("open /home/dev/config.json: permission denied")

	inspect := func(err error) error {
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: quoting{&recorder{t: t, uid: 1000}, err, false}}
		_, got := d.Prepare(ctx, Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true})
		return got
	}
	if got, want := inspect(quoted), "wall docker: image inspect "+byReference+": "+valueWithSecret; got == nil || got.Error() != want || !errors.Is(got, quoted) {
		t.Errorf("image inspect: %v, want %s, wrapping the error", got, want)
	}
	if got, want := inspect(clean), "wall docker: image inspect "+byReference+": "+clean.Error(); got == nil || got.Error() != want {
		t.Errorf("image inspect: %v, want %s", got, want)
	}

	helper := func(path string, err error) error {
		d := &Docker{Helper: path, RelayArgs: []string{"relay"}, sys: quoting{&recorder{t: t, uid: 1000}, err, true}}
		_, got := d.Prepare(ctx, Request{RunID: runID, Image: "i"})
		return got
	}
	if got, want := helper("/opt/QRK_y/helper", quoted), "wall docker: helper "+valueWithRunKey+": "+valueWithSecret; got == nil || got.Error() != want || !errors.Is(got, quoted) {
		t.Errorf("helper: %v, want %s, wrapping the error", got, want)
	}
	if got, want := helper("/h", clean), "wall docker: helper /h: "+clean.Error(); got == nil || got.Error() != want {
		t.Errorf("helper: %v, want %s", got, want)
	}

	proxy := func(host string, err error) error {
		env := func(k string) string { return map[string]string{"HTTPS_PROXY": "http://" + host + ":3128"}[k] }
		_, got := nestProxies(env, func(string) ([]string, error) { return nil, err })
		return got
	}
	if got, want := proxy("qak_x.example", errors.New("lookup qak_x.example: no such host")),
		"nest: the proxy's name "+valueWithSecret+" does not resolve: "+valueWithSecret; got == nil || got.Error() != want {
		t.Errorf("proxy: %v, want %s", got, want)
	}
	if got, want := proxy("elsewhere", errors.New("lookup elsewhere: no such host")),
		"nest: the proxy's name elsewhere does not resolve: lookup elsewhere: no such host"; got == nil || got.Error() != want {
		t.Errorf("proxy: %v, want %s", got, want)
	}
	if got, want := proxy("elsewhere", nil), "nest: the proxy's name elsewhere does not resolve: <nil>"; got == nil || got.Error() != want {
		t.Errorf("proxy: %v, want %s", got, want)
	}
}

// TestProgramOutputWithASecretIsAPhrase pins that what a docker command printed, and the
// command itself, reach the wall's message as a phrase when they contain qak_ or qrk_,
// and as before when they contain neither.
func TestProgramOutputWithASecretIsAPhrase(t *testing.T) {
	ctx := context.Background()
	prepare := func(command, out string, nested bool) error {
		d := &Docker{Command: command, Helper: "/h", RelayArgs: []string{"relay"}, NestArgs: []string{"nest"},
			sys: saying{&recorder{t: t, uid: 1000}, out}}
		req := Request{RunID: runID, Image: "i"}
		if nested {
			req.Docker, req.Runtime = true, "sysbox-runc"
		}
		_, err := d.Prepare(ctx, req)
		return err
	}
	for _, c := range []struct {
		name, command, out string
		nested             bool
		want               string
	}{
		{"output", "", "Error: no network qak_x", false,
			"wall docker: docker network create: exit status 1: " + valueWithSecret},
		{"command", "/opt/QAK_x/docker", "Error: told to fail", false,
			"wall docker: " + valueWithSecret + ": exit status 1: Error: told to fail"},
		{"clean", "", "Error: told to fail", false,
			"wall docker: docker network create: exit status 1: Error: told to fail"},
		{"version output", "", "Error: QRK_y unknown", true,
			"wall docker: docker version: exit status 1: " + valueWithRunKey},
		{"clean version output", "", "Error: told to fail", true,
			"wall docker: docker version: exit status 1: Error: told to fail"},
	} {
		err := prepare(c.command, c.out, c.nested)
		if err == nil {
			t.Errorf("%s: a wall was prepared", c.name)
			continue
		}
		noPrefix(t, c.name, err.Error())
		if first, _, _ := strings.Cut(err.Error(), "\n"); first != c.want {
			t.Errorf("%s: %s, want %s", c.name, first, c.want)
		}
	}

	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, stderr: "Error: qrk_y denied"}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	_, err := d.Prepare(ctx, Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true})
	if err == nil || !strings.HasSuffix(err.Error(), ": "+valueWithRunKey) {
		t.Errorf("image inspect's error output: %v", err)
	} else {
		noPrefix(t, "image inspect's error output", err.Error())
	}

	e := Engine{Wall: "docker", Command: "/opt/engine/docker", Pinned: true, ID: "4c1f0a2e-engine"}
	for id, want := range map[string]string{
		"qak_x-engine": "wall docker: /opt/engine/docker reaches the engine " + valueWithSecret + `, not "4c1f0a2e-engine", the one the run was in`,
		"other-engine": `wall docker: /opt/engine/docker reaches the engine "other-engine", not "4c1f0a2e-engine", the one the run was in`,
	} {
		_, err := runContainersExist(ctx, &recorder{t: t, engineID: id}, e, runID)
		if err == nil || err.Error() != want {
			t.Errorf("engine id %s: %v, want %s", id, err, want)
		}
	}
}

// TestTheMachinesCommandsPrintAPhraseForASecretInTheProgram pins the errors of the
// machine's engine and stdout commands for a program that cannot start: a program path
// that contains qak_ or qrk_ is the phrase, and the error still wraps the exec error.
func TestTheMachinesCommandsPrintAPhraseForASecretInTheProgram(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name string
		call func(argv []string) error
	}{
		{"engine", func(argv []string) error {
			_, err := hostSystem{}.engine(context.Background(), argv, []string{"DOCKER_HOST=unix:///nowhere"})
			return err
		}},
		{"stdout", func(argv []string) error {
			r, err := hostSystem{}.stdout(context.Background(), argv, nil)
			if err == nil {
				r.Close()
			}
			return err
		}},
	} {
		for _, program := range []string{dir + "/qak_FAKE/docker", dir + "/QRK_FAKE/docker"} {
			err := c.call([]string{program, "version"})
			if err == nil {
				t.Fatalf("%s %s: no error", c.name, program)
			}
			noPrefix(t, c.name, err.Error())
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s %s: %v does not wrap fs.ErrNotExist", c.name, program, err)
			}
		}
	}
}
