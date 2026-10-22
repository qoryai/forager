package wall

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
)

// byReference is an image a run names by its reference pinned by digest.
const byReference = "registry.example/agents/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// at is the index of the first line that starts with the prefix, -1 when none does.
func at(lines []string, prefix string) int {
	return slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, prefix) })
}

// TestDockerFetchesAnImageByReferenceFirst pins the fetch of an image a run names by its
// reference: Pull checks the engine's store, runs docker pull of an image the engine
// does not hold, then checks its user; Prepare finds the image by its digest, pulls
// nothing, and then makes the first network; the relay from the request's RelayImage,
// the machine's default; a container of the image, never started and on no network,
// created before the agent's, and removed with the rest.
func TestDockerFetchesAnImageByReferenceFirst(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	req := Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}
	if err := d.Pull(context.Background(), req, nil, nil); err != nil {
		t.Fatal(err)
	}
	e, err := d.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := e.Wrap(context.Background(), launch())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := "docker image inspect --format '{{json .RepoDigests}}' " + byReference
	held, pull, inspect, found, network := at(rec.lines, check), at(rec.lines, "docker pull "+byReference), at(rec.lines, "docker image inspect --format '{{json .Config}}' "+byReference), at(rec.lines[3:], check), at(rec.lines, "docker network create")
	if held != 0 || pull != 1 || inspect != 2 || found != 0 || network != 4 || strings.Count(strings.Join(rec.lines, "\n"), "docker pull ") != 1 {
		t.Errorf("the check at %d, the pull at %d, the user's inspect at %d, Prepare's check at %d after them, the first network at %d:\n%s", held, pull, inspect, found, network, strings.Join(rec.lines, "\n"))
	}
	relay := at(rec.lines, "docker create --name qory-"+runID+"-relay ")
	if relay < 0 || !strings.Contains(rec.lines[relay], " --entrypoint /qory/qory example.com/agent:1 relay ") {
		t.Errorf("the relay does not start from the machine's default:\n%s", strings.Join(rec.lines, "\n"))
	}
	image := at(rec.lines, "docker create --name qory-"+runID+"-image --label dev.qory.run="+runID+" --network none --pull=never --entrypoint /qory/qory "+byReference)
	if image < relay {
		t.Errorf("the image's container is not created after the relay:\n%s", strings.Join(rec.lines, "\n"))
	}
	if at(rec.lines, "docker rm --force --volumes qory-"+runID+"-image") < 0 {
		t.Errorf("the image's container is left:\n%s", strings.Join(rec.lines, "\n"))
	}
	if entry := slices.Index(wrapped.Args, "--entrypoint"); entry < 0 || wrapped.Args[entry+2] != byReference {
		t.Errorf("the agent does not start from the image by reference: %s", words(wrapped.Args))
	}
	if never := slices.Index(wrapped.Args, "--pull=never"); never < 0 || never > slices.Index(wrapped.Args, "--entrypoint") {
		t.Errorf("the agent's container may pull the image by reference: %s", words(wrapped.Args))
	}
}

// TestDockerPullsAMachinesImageAsBefore pins the containers of an image the machine
// defines: neither the container the wall reads the image's files from nor the agent's
// runs with --pull=never, so the engine pulls an image of the machine's that it does
// not have when it creates them.
func TestDockerPullsAMachinesImageAsBefore(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	req := Request{RunID: runID, Image: "example.com/agent:1", RelayImage: "example.com/relay:1"}
	e, err := d.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := e.Wrap(context.Background(), launch())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	image := at(rec.lines, "docker create --name qory-"+runID+"-image ")
	if image < 0 || strings.Contains(rec.lines[image], "--pull") || slices.Contains(wrapped.Args, "--pull=never") {
		t.Errorf("a machine's image with --pull:\n%s\n%s", strings.Join(rec.lines, "\n"), words(wrapped.Args))
	}
}

// TestDockerRefusesAnImageWhoseUserIsRoot pins the user check of an image by reference:
// no user, unset or empty, root, a uid of 0 in any spelling, with or without a group,
// and a name the image's /etc/passwd maps to uid 0 are image_user_root, and so is a
// name it cannot map; any other user passes. Pull makes no network and leaves no
// container either way.
func TestDockerRefusesAnImageWhoseUserIsRoot(t *testing.T) {
	const passwd = "root:x:0:0:root:/root:/bin/sh\ntoor:x:00:0::/:/bin/sh\napp:x:1000:1000::/srv/app:/bin/sh\n"
	for _, c := range []struct {
		user   string
		passwd bool
		root   bool
	}{
		{"none", true, true},
		{"null", true, true},
		{`""`, true, true},
		{`"0"`, true, true},
		{`"00"`, true, true},
		{`"0:1000"`, true, true},
		{`"root"`, true, true},
		{`"root:app"`, true, true},
		{`"toor"`, true, true},
		{`"app"`, false, true},
		{`"nobody"`, true, true},
		{`"1000"`, false, false},
		{`"1000:0"`, false, false},
		{`"app"`, true, false},
		{`"app:app"`, true, false},
	} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: c.user}
		if c.passwd {
			rec.files = map[string]string{"/etc/passwd": passwd}
		}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
		err := d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, nil, nil)
		var r *accesskey.Refusal
		switch {
		case !c.root && err != nil:
			t.Errorf("user %s (passwd %v): %v", c.user, c.passwd, err)
		case at(rec.lines, "docker create") >= 0 && at(rec.lines, "docker rm --force --volumes qory-"+runID+"-image") < 0:
			t.Errorf("user %s: the image's container is left:\n%s", c.user, strings.Join(rec.lines, "\n"))
		case !c.root:
		case !errors.As(err, &r) || r.Code != refusal.ImageUserRoot || !slices.Equal(r.Names, []string{byReference}):
			t.Errorf("user %s (passwd %v): %v, want image_user_root", c.user, c.passwd, err)
		case at(rec.lines, "docker network") >= 0:
			t.Errorf("user %s: a network was made before the refusal:\n%s", c.user, strings.Join(rec.lines, "\n"))
		}
	}
}

// TestDockerLeavesNothingWhenTheFetchFails pins that an image by reference that cannot
// be fetched is an error of Pull, that the wall made nothing for it, and that Prepare
// then refuses the image, which the engine does not hold, before it makes anything.
func TestDockerLeavesNothingWhenTheFetchFails(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, fail: "docker pull"}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	req := Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}
	if err := d.Pull(context.Background(), req, nil, nil); err == nil {
		t.Fatal("an image that cannot be fetched was pulled")
	}
	if len(rec.lines) != 2 || at(rec.lines, "docker image inspect --format '{{json .RepoDigests}}' "+byReference) != 0 {
		t.Errorf("commands beside the check and the pull:\n%s", strings.Join(rec.lines, "\n"))
	}
	want := "wall docker: fetch " + byReference + " with Pull before Prepare: the engine does not hold it by its digest"
	if _, err := d.Prepare(context.Background(), req); err == nil || err.Error() != want {
		t.Errorf("Prepare of an image the engine does not hold: %v, want %s", err, want)
	}
	if len(rec.lines) != 3 || at(rec.lines, "docker pull") != 1 {
		t.Errorf("Prepare ran more than the check:\n%s", strings.Join(rec.lines, "\n"))
	}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, Pull: true, Docker: true, Runtime: "sysbox-runc"}); err == nil {
		t.Error("an image by reference was given nested Docker")
	}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "--privileged"}); err == nil {
		t.Error("a flag was taken as the relay's image")
	}
}

// TestDockerPullsNoImageItHoldsByTheDigest pins that the engine is asked first whether it
// holds the image by the reference: one it lists among the image's repository digests,
// in either the short form or in full, is not pulled, and its user is still checked; the
// same content under another name, another digest of the name, and an image with no
// repository digest are pulled; and an engine whose inspect fails other than with no such
// image is the run's error, with no pull and nothing made.
func TestDockerPullsNoImageItHoldsByTheDigest(t *testing.T) {
	const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, c := range []struct {
		image string
		held  []string
		pull  bool
	}{
		{byReference, []string{byReference}, false},
		{byReference, []string{"registry.example/agents/other" + digest, byReference}, false},
		{"docker.io/library/app" + digest, []string{"app" + digest}, false},
		{"app" + digest, []string{"docker.io/library/app" + digest}, false},
		{"example/app" + digest, []string{"index.docker.io/example/app" + digest}, false},
		{byReference, []string{"registry.example/agents/other" + digest}, true},
		{byReference, []string{"registry.example:5000/agents/app" + digest}, true},
		{byReference, []string{"registry.example/agents/app@sha256:" + strings.Repeat("f", 64)}, true},
		{"library/app" + digest, []string{"example/app" + digest}, true},
		{byReference, []string{}, true},
		{byReference, nil, true},
	} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`, held: c.held}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
		if err := d.Pull(context.Background(), Request{RunID: runID, Image: c.image, RelayImage: "example.com/agent:1", Pull: true}, nil, nil); err != nil {
			t.Errorf("%s held as %v: %v", c.image, c.held, err)
			continue
		}
		check, pull, user := at(rec.lines, "docker image inspect --format '{{json .RepoDigests}}' "+c.image), at(rec.lines, "docker pull "+c.image), at(rec.lines, "docker image inspect --format '{{json .Config}}' "+c.image)
		if check != 0 || (pull >= 0) != c.pull || user < 0 {
			t.Errorf("%s held as %v: the check at %d, the pull at %d (want one: %v), the user's inspect at %d:\n%s", c.image, c.held, check, pull, c.pull, user, strings.Join(rec.lines, "\n"))
		}
	}

	// An image the engine holds whose user is root is refused all the same.
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"root"`, held: []string{byReference}}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	err := d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, nil, nil)
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != refusal.ImageUserRoot {
		t.Errorf("a held image whose user is root: %v, want image_user_root", err)
	}
	if at(rec.lines, "docker pull") >= 0 || at(rec.lines, "docker network") >= 0 {
		t.Errorf("a held image whose user is root was pulled, or a network made:\n%s", strings.Join(rec.lines, "\n"))
	}

	// An image the engine holds with no Config, as a containerd store holds an index with
	// the content of none of its platforms, is pulled, and its user read again after the pull: a user
	// that is not root passes, root is refused.
	for _, c := range []struct {
		after string
		root  bool
	}{{`"1000:1000"`, false}, {`"root"`, true}, {"null", true}} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: "null", pulledUser: c.after, held: []string{byReference}}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
		err := d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, nil, nil)
		var r *accesskey.Refusal
		switch {
		case !c.root && err != nil:
			t.Errorf("held with no Config, %s after the pull: %v", c.after, err)
		case !c.root:
		case !errors.As(err, &r) || r.Code != refusal.ImageUserRoot:
			t.Errorf("held with no Config, %s after the pull: %v, want image_user_root", c.after, err)
		}
		inspect := "docker image inspect --format '{{json .Config}}' " + byReference
		first, pull := at(rec.lines, inspect), at(rec.lines, "docker pull "+byReference)
		if first < 0 || pull < first || at(rec.lines[pull:], inspect) < 0 {
			t.Errorf("held with no Config, %s after the pull: the user's inspect at %d, the pull at %d, no inspect after it:\n%s", c.after, first, pull, strings.Join(rec.lines, "\n"))
		}
	}

	// The engine's answer on standard error decides: no such image is an image to pull,
	// any other answer is the run's error, with what the engine said, and no pull.
	for _, c := range []struct {
		stderr string
		pull   bool
	}{
		{"Error response from daemon: No such image: " + byReference, true},
		{"Error: " + byReference + ": image not known", true},
		{"permission denied while trying to connect to the Docker daemon socket", false},
	} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`, stderr: c.stderr}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
		err := d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, nil, nil)
		pulled := at(rec.lines, "docker pull "+byReference) >= 0
		switch {
		case c.pull && err != nil:
			t.Errorf("%q: %v", c.stderr, err)
		case c.pull:
		case err == nil:
			t.Errorf("%q: pulled", c.stderr)
		case !strings.Contains(err.Error(), c.stderr) || !strings.Contains(err.Error(), "image inspect "+byReference):
			t.Errorf("%q: %v, want what the engine said", c.stderr, err)
		}
		if pulled != c.pull {
			t.Errorf("%q: pulled %v, want %v:\n%s", c.stderr, pulled, c.pull, strings.Join(rec.lines, "\n"))
		}
	}

	// An engine that does not answer the check is the run's error, not an image to pull.
	rec = &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`, down: true}
	d = &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	err = d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Cannot connect to the Docker daemon") {
		t.Errorf("an engine that does not answer: %v", err)
	}
	if len(rec.lines) != 1 {
		t.Errorf("commands beside the check of an engine that does not answer:\n%s", strings.Join(rec.lines, "\n"))
	}
}

// TestDockerReadsTheBundleOutOfTheRunsImage pins that the authorities the enclosure
// trusts are the run's image's, read out of a container of it, when the relay starts
// from another image.
func TestDockerReadsTheBundleOutOfTheRunsImage(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000,
		files: map[string]string{"/etc/ssl/certs/ca-certificates.crt": "-----BEGIN CERTIFICATE-----\nIMAGE\n-----END CERTIFICATE-----\n"}}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:2", RelayImage: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	l := launch()
	l.CA = []byte("-----BEGIN CERTIFICATE-----\nRUN\n-----END CERTIFICATE-----\n")
	if _, err := e.Wrap(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	cp := at(rec.lines, "docker cp --follow-link qory-"+runID+"-image:/etc/ssl/certs/ca-certificates.crt -")
	if cp < 0 || at(rec.lines, "docker cp --follow-link qory-"+runID+"-relay:") >= 0 {
		t.Errorf("the bundle is not read out of the run's image:\n%s", strings.Join(rec.lines, "\n"))
	}
}

// TestDockerShowsAMountAtItsTarget pins a mount shown at another path inside: bound at
// its Target, the working directory under it, the docker command started in the
// workspace's directory on this machine; and a Target that is not absolute, or that is,
// holds or lies under /qory, refused.
func TestDockerShowsAMountAtItsTarget(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "i"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	l := launch()
	l.Dir, l.Mounts = "/workspace/src", []Mount{{Path: "/work", Target: "/workspace"}, {Path: "/work/.qory/runs/" + runID, ReadOnly: true}}
	wrapped, err := e.Wrap(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	line := words(wrapped.Args)
	if !strings.Contains(line, "--workdir /workspace/src") || !strings.Contains(line, "--mount type=bind,src=/work,dst=/workspace ") || wrapped.Dir != "/work/src" {
		t.Errorf("the dir %q, the command %s", wrapped.Dir, line)
	}
	for _, target := range []string{"workspace", "/qory", "/qory/workspace", "/"} {
		l := launch()
		l.Dir, l.Mounts = "/workspace", []Mount{{Path: "/work", Target: target}}
		if target != "workspace" {
			l.Dir = target
		}
		if _, err := e.Wrap(context.Background(), l); err == nil {
			t.Errorf("a mount shown at %q was bound", target)
		}
	}
}

// TestDockerNeedsANumericUserForAnImageByReference pins that the wall's user of a run
// in an image by reference is uid:gid in numbers, neither 0, since the engine would
// look a name, or a uid's groups, up in the image's /etc/passwd and /etc/group: a name,
// a uid alone and a gid of 0 are refused before any command, by Pull and by Prepare,
// uid:gid passes, and a run in the machine's image takes them all.
func TestDockerNeedsANumericUserForAnImageByReference(t *testing.T) {
	for _, c := range []struct {
		user string
		ok   bool
	}{
		{"agent", false},
		{"1000", false},
		{"1000:0", false},
		{"1000:000", false},
		{"agent:1000", false},
		{"1000:1000", true},
	} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`, held: []string{byReference}}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: c.user, sys: rec}
		req := Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}
		if err := d.Pull(context.Background(), req, nil, nil); (err == nil) != c.ok || (!c.ok && len(rec.lines) != 0) {
			t.Errorf("%s: Pull: %v, after:\n%s", c.user, err, strings.Join(rec.lines, "\n"))
		}
		rec.lines = nil
		e, err := d.Prepare(context.Background(), req)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", c.user, err)
		case c.ok:
			e.Close(context.Background())
		case err == nil || !strings.Contains(err.Error(), "uid:gid"):
			t.Errorf("%s: %v, want the wall's user as uid:gid", c.user, err)
		case len(rec.lines) != 0:
			t.Errorf("%s: commands before the refusal:\n%s", c.user, strings.Join(rec.lines, "\n"))
		}
		if c.ok {
			continue
		}
		rec = &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
		d = &Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: c.user, sys: rec}
		e, err = d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
		if err != nil {
			t.Errorf("%s in the machine's image: %v", c.user, err)
			continue
		}
		e.Close(context.Background())
	}
}

// TestDockerNeedsTheMachinesImageForTheRelay pins that a run in an image by reference
// without RelayImage is refused before any command, by Prepare and by Pull: its relay
// would otherwise start from the run's image.
func TestDockerNeedsTheMachinesImageForTheRelay(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, Pull: true}); err == nil || !strings.Contains(err.Error(), "RelayImage") {
		t.Errorf("an image by reference without RelayImage: %v", err)
	}
	if err := d.Pull(context.Background(), Request{RunID: runID, Image: byReference, Pull: true}, nil, nil); err == nil || !strings.Contains(err.Error(), "RelayImage") {
		t.Errorf("the pull of an image by reference without RelayImage: %v", err)
	}
	if len(rec.lines) != 0 {
		t.Errorf("commands before the refusal:\n%s", strings.Join(rec.lines, "\n"))
	}
}

// TestDockerStopsReadingAFileOverTheLimit pins the reads out of a container of the
// run's image: an /etc/passwd whose docker cp writes without end is read no further
// than the limit and its tar headers, the command stopped, and the user it would map
// refused as one that cannot be checked; and a bundle that does is read no further
// either, and the run goes on without it.
func TestDockerStopsReadingAFileOverTheLimit(t *testing.T) {
	const most = fileLimit + tarAllowance + 1
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"app"`, endless: "/etc/passwd"}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	err := d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, nil, nil)
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != refusal.ImageUserRoot {
		t.Errorf("an endless /etc/passwd: %v, want image_user_root", err)
	}
	if !rec.stopped || rec.streamed > most+64<<10 {
		t.Errorf("the read went on: %d bytes, stopped %v", rec.streamed, rec.stopped)
	}

	rec = &recorder{t: t, gateway: "172.30.0.1", uid: 1000, endless: "/etc/ssl/certs/ca-certificates.crt"}
	d = &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:2", RelayImage: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	l := launch()
	l.CA = []byte("-----BEGIN CERTIFICATE-----\nRUN\n-----END CERTIFICATE-----\n")
	if _, err := e.Wrap(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if !rec.stopped || rec.streamed > most+64<<10 {
		t.Errorf("the bundle's read went on: %d bytes, stopped %v", rec.streamed, rec.stopped)
	}
}

// certsOf are the files under dir, by their path from it, with their content.
func certsOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && p != dir {
			rel, _ := filepath.Rel(dir, p)
			b, _ := os.ReadFile(p)
			out[rel] = string(b)
		}
		return nil
	})
	return out
}

// TestDockerTrustsTheRunsCertificateForThePullAlone pins the run's certificate in
// CertsDir: during the pull, qory-run-<id>.crt with the certificate in the directory of
// the image's registry host and of each other host once, none for a *. pattern or a
// host that cannot be a directory's name; after the pull, also when it fails or its
// context ends, no file of the run's and no directory Pull made, while a directory
// that was there stays with its files; without a certificate, no file at all.
func TestDockerTrustsTheRunsCertificateForThePullAlone(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nRUN\n-----END CERTIFICATE-----\n"
	file := "qory-run-" + runID + ".crt"
	hosts := []string{"auth.registry.example", "*.registry.example", "registry.example", "auth.registry.example", "../escape", "[::1]:5000", "Registry.Example"}
	for _, c := range []struct {
		name   string
		fail   string
		cancel bool
		ca     string
	}{{name: "a pull"}, {name: "a pull that fails", fail: "docker pull"}, {name: "a pull whose context ends", fail: "docker pull", cancel: true}, {name: "no certificate"}} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "registry.example"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "registry.example", "ca.crt"), []byte("the machine's"), 0o644); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var during map[string]string
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`, fail: c.fail}
			rec.onPull = func() {
				during = certsOf(t, dir)
				if c.cancel {
					cancel()
				}
			}
			d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, CertsDir: dir, sys: rec}
			var given []byte
			if c.name != "no certificate" {
				given = []byte(ca)
			}
			err := d.Pull(ctx, Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, given, hosts)
			if (err != nil) != (c.fail != "") {
				t.Errorf("the pull: %v", err)
			}
			want := map[string]string{"registry.example": "", "registry.example/ca.crt": "the machine's"}
			if given != nil {
				want["registry.example/"+file] = ca
				want["auth.registry.example"] = ""
				want["auth.registry.example/"+file] = ca
			}
			if !maps.Equal(during, want) {
				t.Errorf("during the pull, CertsDir has %q, want %q", during, want)
			}
			after := map[string]string{"registry.example": "", "registry.example/ca.crt": "the machine's"}
			if got := certsOf(t, dir); !maps.Equal(got, after) {
				t.Errorf("after the pull, CertsDir has %q, want %q", got, after)
			}
		})
	}
}

// TestDockerRemovesTheCertificatesBeforeAFailedWrite pins a write of the run's
// certificate that fails for the second host: Pull returns the error of that host, and
// the first host's file and the directory Pull made for it are gone, with no pull.
func TestDockerRemovesTheCertificatesBeforeAFailedWrite(t *testing.T) {
	ca := []byte("-----BEGIN CERTIFICATE-----\nRUN\n-----END CERTIFICATE-----\n")
	dir := t.TempDir()
	// A file where the second host's directory would be: the write into it fails.
	if err := os.WriteFile(filepath.Join(dir, "auth.registry.example"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, CertsDir: dir, sys: rec}
	err := d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, ca, []string{"auth.registry.example"})
	want := "Make " + dir + " writable for this user, as the machine's start unit does: the run's certificate for auth.registry.example could not be written ("
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("the second host's write: %v, want an error that starts with %s", err, want)
	}
	if got, after := certsOf(t, dir), map[string]string{"auth.registry.example": "not a directory"}; !maps.Equal(got, after) {
		t.Errorf("after the failed write, CertsDir has %q, want %q", got, after)
	}
	if len(rec.lines) != 0 {
		t.Errorf("commands after the failed write:\n%s", strings.Join(rec.lines, "\n"))
	}
}

// TestDockerCleansUpAPullThatPanics pins a pull that panics while it reads the image's
// /etc/passwd, as a caller that recovers meets it: the run's certificate is removed,
// and so is the container the wall read the file from.
func TestDockerCleansUpAPullThatPanics(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"app"`}
	rec.onCopy = func() { panic("docker cp") }
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, CertsDir: dir, sys: rec}
	recovered := func() (v any) {
		defer func() { v = recover() }()
		d.Pull(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}, []byte("CA"), nil)
		return nil
	}()
	if recovered != "docker cp" {
		t.Errorf("the caller recovered %v", recovered)
	}
	if got := certsOf(t, dir); len(got) != 0 {
		t.Errorf("after the panic, CertsDir has %q", got)
	}
	created, removed := at(rec.lines, "docker create --name qory-"+runID+"-image "), at(rec.lines, "docker rm --force --volumes qory-"+runID+"-image")
	if created < 0 || removed < created {
		t.Errorf("the image's container after the panic:\n%s", strings.Join(rec.lines, "\n"))
	}
}

// TestDockerSaysHowToFixACertificateItCannotWriteOrRemove pins the errors of the run's
// certificate: a CertsDir this user cannot write is an error before any pull, with the
// fix first and no file left; a certificate that cannot be removed after the pull is
// an error whose fix is to remove it by hand.
func TestDockerSaysHowToFixACertificateItCannotWriteOrRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory of mode 0500")
	}
	ca := []byte("-----BEGIN CERTIFICATE-----\nRUN\n-----END CERTIFICATE-----\n")
	req := Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, CertsDir: dir, sys: rec}
	err := d.Pull(context.Background(), req, ca, nil)
	want := "Make " + dir + " writable for this user, as the machine's start unit does: the run's certificate for registry.example could not be written (mkdir " + filepath.Join(dir, "registry.example") + ": permission denied)."
	if err == nil || err.Error() != want {
		t.Errorf("an unwritable CertsDir: %v, want %s", err, want)
	}
	if len(rec.lines) != 0 {
		t.Errorf("commands after the failed write:\n%s", strings.Join(rec.lines, "\n"))
	}

	dir = t.TempDir()
	host := filepath.Join(dir, "registry.example")
	rec = &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	rec.onPull = func() { os.Chmod(host, 0o500) }
	defer os.Chmod(host, 0o755)
	d = &Docker{Helper: "/h", RelayArgs: []string{"relay"}, CertsDir: dir, sys: rec}
	err = d.Pull(context.Background(), req, ca, nil)
	f := filepath.Join(host, "qory-run-"+runID+".crt")
	want = "Remove " + f + " by hand: the run's certificate stays trusted for registry.example until it is removed (remove " + f + ": permission denied)."
	if err == nil || err.Error() != want {
		t.Errorf("a certificate that cannot be removed: %v, want %s", err, want)
	}
}
