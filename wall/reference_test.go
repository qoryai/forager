package wall

import (
	"context"
	"errors"
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
// reference: docker pull, then its user, before any network is made; the relay from
// the request's RelayImage, the machine's default; a container of the image, never
// started and on no network, created before the agent's, and removed with the rest;
// and the fetch reported.
func TestDockerFetchesAnImageByReferenceFirst(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true})
	if err != nil {
		t.Fatal(err)
	}
	if took, ok := e.(Fetcher).ImageFetch(); !ok || took < 0 {
		t.Errorf("the fetch reported %v, %v", took, ok)
	}
	wrapped, err := e.Wrap(context.Background(), launch())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	pull, inspect, network := at(rec.lines, "docker pull "+byReference), at(rec.lines, "docker image inspect --format '{{json .Config}}' "+byReference), at(rec.lines, "docker network create")
	if pull != 0 || inspect != 1 || network != 2 {
		t.Errorf("the pull at %d, the user's inspect at %d, the first network at %d:\n%s", pull, inspect, network, strings.Join(rec.lines, "\n"))
	}
	relay := at(rec.lines, "docker create --name qory-"+runID+"-relay ")
	if relay < 0 || !strings.Contains(rec.lines[relay], " --entrypoint /qory/qory example.com/agent:1 relay ") {
		t.Errorf("the relay does not start from the machine's default:\n%s", strings.Join(rec.lines, "\n"))
	}
	image := at(rec.lines, "docker create --name qory-"+runID+"-image --label dev.qory.run="+runID+" --network none --entrypoint /qory/qory "+byReference)
	if image < relay {
		t.Errorf("the image's container is not created after the relay:\n%s", strings.Join(rec.lines, "\n"))
	}
	if at(rec.lines, "docker rm --force --volumes qory-"+runID+"-image") < 0 {
		t.Errorf("the image's container is left:\n%s", strings.Join(rec.lines, "\n"))
	}
	if entry := slices.Index(wrapped.Args, "--entrypoint"); entry < 0 || wrapped.Args[entry+2] != byReference {
		t.Errorf("the agent does not start from the image by reference: %s", words(wrapped.Args))
	}
}

// TestDockerRefusesAnImageWhoseUserIsRoot pins the user check of an image by reference:
// no user, unset or empty, root, a uid of 0 in any spelling, with or without a group,
// and a name the image's /etc/passwd maps to uid 0 are image_user_root, and so is a name
// it cannot map; any other user passes. A refusal makes no network and leaves nothing.
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
		e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true})
		var r *accesskey.Refusal
		switch {
		case !c.root && err != nil:
			t.Errorf("user %s (passwd %v): %v", c.user, c.passwd, err)
		case !c.root:
			e.Close(context.Background())
		case !errors.As(err, &r) || r.Code != refusal.ImageUserRoot || !slices.Equal(r.Names, []string{byReference}):
			t.Errorf("user %s (passwd %v): %v, want image_user_root", c.user, c.passwd, err)
		case at(rec.lines, "docker network") >= 0:
			t.Errorf("user %s: a network was made before the refusal:\n%s", c.user, strings.Join(rec.lines, "\n"))
		case at(rec.lines, "docker create") >= 0 && at(rec.lines, "docker rm --force --volumes qory-"+runID+"-image") < 0:
			t.Errorf("user %s: the image's container is left:\n%s", c.user, strings.Join(rec.lines, "\n"))
		}
	}
}

// TestDockerLeavesNothingWhenTheFetchFails pins that an image by reference that cannot
// be fetched is no enclosure, and that the wall made nothing for it.
func TestDockerLeavesNothingWhenTheFetchFails(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, fail: "docker pull"}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true}); err == nil {
		t.Fatal("an image that cannot be fetched was prepared")
	}
	if len(rec.lines) != 1 {
		t.Errorf("commands beside the pull:\n%s", strings.Join(rec.lines, "\n"))
	}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, Pull: true, Docker: true, Runtime: "sysbox-runc"}); err == nil {
		t.Error("an image by reference was given nested Docker")
	}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "--privileged"}); err == nil {
		t.Error("a flag was taken as the relay's image")
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
// a uid alone and a gid of 0 are refused before any command, uid:gid passes, and a run
// in the machine's image takes them all as before.
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
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, User: c.user, sys: rec}
		e, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true})
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
// without RelayImage is refused before any command: its relay would otherwise start
// from the run's image.
func TestDockerNeedsTheMachinesImageForTheRelay(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000, user: `"1000:1000"`}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	if _, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, Pull: true}); err == nil || !strings.Contains(err.Error(), "RelayImage") {
		t.Errorf("an image by reference without RelayImage: %v", err)
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
	_, err := d.Prepare(context.Background(), Request{RunID: runID, Image: byReference, RelayImage: "example.com/agent:1", Pull: true})
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
