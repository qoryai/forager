package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// The files a separate gateway writes in a run's record directory beside the stream's,
// each mode 0600, so that a gateway that starts again on the same directory can reopen
// the run: the run request ([keptRequest]), the policy members given ([givenFile]),
// the join decisions ([joinsFile]), the mark of a model key past its limit or out of
// use after a 401, with the stop's reason ([limitMark]), and the keys out of use after
// a 401 ([unauthorizedFile]); the run's CA is [proxy.CACertFile] and
// [proxy.CAKeyFile]. The local link writes none of them. The stream's Discard and
// Reclaim remove them by these names.
const (
	requestFile      = "request.json"
	givenFile        = "given.jsonl"
	joinsFile        = "joins.jsonl"
	limitMark        = "model-key-limit"
	unauthorizedFile = "model-keys-unauthorized.json"
	// unauthorizedTemp is where [writeUnauthorized] writes the file before it renames
	// it, so a crash leaves the file before the write or the file after it, whole.
	unauthorizedTemp = unauthorizedFile + ".tmp"
)

// The CA key sweep (the user's "545 (a)", 2026-11-13): a gateway removes the files kept
// to reopen a run, the CA files and the run request among them, of a run record it does
// not hold whose events.jsonl has not changed for more than caSweepAge, at Start and
// every caSweepEvery. A live run's session sends a heartbeat at least every
// server.MaxInterval, 300 s, so its record changes at least 3 times within caSweepAge;
// a record that does not is of a run that no session reopens, and its key goes from the
// disk. A record with a final event is never reopened, so its key goes too.
const (
	caSweepEvery = 10 * time.Minute
	caSweepAge   = 15 * time.Minute
)

// keptRequest is request.json: what [run.Decide] reads of the run request, so a
// gateway that starts again decides the run as its open did. Its image references have
// no user information ([withoutUserInfo]): a registry's credentials stay off the disk.
type keptRequest struct {
	Version   int                   `json:"version"`
	Wall      bool                  `json:"wall"`
	Narrowing *server.LinkNarrowing `json:"narrowing,omitempty"`
	Images    *server.LinkImages    `json:"images,omitempty"`
}

// digestSuffix is a reference's trailing digest of an algorithm the OCI image
// specification registers: @sha256: or @blake3: and 64 lower-case hexadecimal digits,
// or @sha512: and 128. The OCI grammar of any algorithm would also match a tag after
// user information, such as @base:latest, and keep the user information whole.
var digestSuffix = regexp.MustCompile(`@(?:sha256:[0-9a-f]{64}|blake3:[0-9a-f]{64}|sha512:[0-9a-f]{128})$`)

// withoutUserInfo is the image reference ref without the user information it may start
// with, which may contain a registry's credentials: its trailing digest is set aside,
// everything up to and with the last @ of the rest is left out, a scheme in front of
// the user information too, and the digest is put back. A password may contain / and @,
// and a user may be an email address. A reference with no @ before its digest is
// returned as it is, and so is a result of withoutUserInfo.
func withoutUserInfo(ref string) string {
	rest, digest := ref, ""
	if loc := digestSuffix.FindStringIndex(ref); loc != nil {
		rest, digest = ref[:loc[0]], ref[loc[0]:]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	return rest + digest
}

// imagesWithoutUserInfo is a copy of the session's images with each reference, the
// default's when it is one and each definition's, without its user information
// ([withoutUserInfo]); nil for nil. The allowed prefixes, which contain no user
// information ([policy.CheckImagePrefix]), stay as they are.
func imagesWithoutUserInfo(li *server.LinkImages) *server.LinkImages {
	if li == nil {
		return nil
	}
	out := &server.LinkImages{Default: withoutUserInfo(li.Default), Allow: slices.Clone(li.Allow)}
	for _, d := range li.Definitions {
		d.Ref = withoutUserInfo(d.Ref)
		out.Definitions = append(out.Definitions, d)
	}
	return out
}

// keptNotRemoved is the report of the run runID whose kept files [stream.RemoveKept]
// did not remove from its record dir, the fix first.
func keptNotRemoved(runID, dir string, err error) string {
	names := stream.KeptFiles()
	list := strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	return fmt.Sprintf("run %s: remove %s from %s by hand: removing them failed: %v", accesskey.ShownValue(runID, false), list, accesskey.ShownValue(dir, false), accesskey.ShownError(err))
}

// narrowingOf is the session's narrowing of the run request as [run.Config] takes it,
// nil for none.
func narrowingOf(n *server.LinkNarrowing) *run.Narrowing {
	if n == nil {
		return nil
	}
	return &run.Narrowing{Allow: n.Egress.Allow, Deny: n.Egress.Deny}
}

// writeRequest writes request.json of the run request req to dir, each image reference
// without its user information.
func writeRequest(dir string, req *server.LinkRunRequest) error {
	b, err := json.Marshal(keptRequest{Version: 1, Wall: req.Wall, Narrowing: req.Narrowing, Images: imagesWithoutUserInfo(req.Images)})
	if err != nil {
		return err
	}
	return writeKept(dir, requestFile, append(b, '\n'))
}

// readRequest reads request.json from dir. The run is decided again with Wall,
// narrowingOf(Narrowing) and images(Images).
func readRequest(dir string) (keptRequest, error) {
	var k keptRequest
	b, err := os.ReadFile(filepath.Join(dir, requestFile))
	if err != nil {
		return k, accesskey.ShownError(err)
	}
	if err := json.Unmarshal(b, &k); err != nil || k.Version != 1 {
		return k, fmt.Errorf("%s is not a run request the gateway wrote", accesskey.ShownValue(filepath.Join(dir, requestFile), false))
	}
	return k, nil
}

// keptJoin is one line of joins.jsonl: one join decision, written before the gateway
// writes its answer, with names alone. Session is the join's number; Accepted is true for a
// 200, false for a 403; Passes are the request's passes; Model is the model key the
// answer starts the session with, empty for none; NoKey is the request's model_key
// false; and ModelCredential is the request's model_credential, empty for none, which
// the replay of a join compares.
type keptJoin struct {
	Session         int      `json:"session"`
	Accepted        bool     `json:"accepted"`
	Passes          []string `json:"passes"`
	Model           string   `json:"model"`
	NoKey           bool     `json:"no_key"`
	ModelCredential string   `json:"model_credential,omitempty"`
}

// kept is the join's line of joins.jsonl.
func (j *join) kept() keptJoin {
	passes := j.passes
	if passes == nil {
		passes = []string{}
	}
	return keptJoin{Session: j.session, Accepted: j.accepted, Passes: passes, Model: j.model, NoKey: j.noKey, ModelCredential: j.credential}
}

// join is the join of the line, with neither its session.started nor its
// session.exited numbered: the record's events set those.
func (k keptJoin) join() *join {
	return &join{session: k.Session, accepted: k.Accepted, passes: slices.Clone(k.Passes), model: k.Model, noKey: k.NoKey, credential: k.ModelCredential}
}

// readJoins reads joins.jsonl from dir, in order; no file is no join. A line that does
// not decode, a write the gateway did not finish and so never answered, is skipped and
// counted in torn.
func readJoins(dir string) (joins []keptJoin, torn int, err error) {
	err = readKeptLines(filepath.Join(dir, joinsFile), func(line []byte) bool {
		var k keptJoin
		if json.Unmarshal(line, &k) != nil || k.Session < 1 {
			return false
		}
		joins = append(joins, k)
		return true
	}, &torn)
	return joins, torn, err
}

// readGiven reads given.jsonl from dir: the members of dev.qory.run.policy_applied the
// gateway gave the run, in order, each as [appliedOf] makes it; no file is none. A line
// that does not decode is skipped and counted in torn.
func readGiven(dir string) (given []map[string]any, torn int, err error) {
	err = readKeptLines(filepath.Join(dir, givenFile), func(line []byte) bool {
		var a map[string]any
		if json.Unmarshal(line, &a) != nil || a == nil {
			return false
		}
		given = append(given, a)
		return true
	}, &torn)
	return given, torn, err
}

// limitMarked reports whether dir has the mark of a model key past its limit or out of
// use after a 401: the proxy passed a limit refusal or a 401 to the session, and no
// join or end of a session cleared it since. reason is the stop's reason the mark
// contains ([markStop]), empty when it has none: no answer to a batch had the stop
// before the gateway stopped, or its write did not end.
func limitMarked(dir string) (reason string, marked bool, err error) {
	path := filepath.Join(dir, limitMark)
	_, err = os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", false, nil
	case err != nil:
		return "", false, accesskey.ShownError(err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", false, accesskey.ShownError(err)
	}
	defer f.Close()
	// A reason is 22 bytes at most; a longer file is no reason the gateway wrote.
	b, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return "", false, accesskey.ShownError(err)
	}
	if r := string(bytes.TrimSuffix(b, []byte("\n"))); modelkey.StopReason(r) {
		reason = r
	}
	return reason, true, nil
}

// markStop writes reason, the stop's reason of the gateway's answers to the session
// ([modelkey.Group.Stop]), into dir's [limitMark], made with mode 0600 when the mark
// is missing.
func markStop(dir, reason string) error {
	return writeKept(dir, limitMark, []byte(reason+"\n"))
}

// keptUnauthorized is model-keys-unauthorized.json: the keys of the run's key group
// out of use after a 401 of the model provider ([modelkey.Group.Unauthorized]).
type keptUnauthorized struct {
	Version int       `json:"version"`
	Keys    []keptKey `json:"keys"`
}

// keptKey is one key of [keptUnauthorized]: its name, when the 401 arrived, and Out,
// true once the key left the group for the run; false while its renewal is pending.
type keptKey struct {
	Credential string    `json:"credential"`
	At         time.Time `json:"at"`
	Out        bool      `json:"out"`
}

// writeUnauthorized writes keys to dir's [unauthorizedFile] whole ([replaceKept]), or
// removes the file when keys is empty: every key a renewal brought back.
func writeUnauthorized(dir string, keys []modelkey.Unauthorized) error {
	if len(keys) == 0 {
		err := os.Remove(filepath.Join(dir, unauthorizedFile))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return accesskey.ShownError(err)
		}
		return syncDir(dir)
	}
	k := keptUnauthorized{Version: 1, Keys: make([]keptKey, 0, len(keys))}
	for _, u := range keys {
		k.Keys = append(k.Keys, keptKey{Credential: u.Credential, At: u.At, Out: u.Out})
	}
	b, err := json.Marshal(k)
	if err != nil {
		return err
	}
	return replaceKept(dir, unauthorizedFile, unauthorizedTemp, append(b, '\n'))
}

// replaceKept puts b in dir's file name whole: it writes b to temp, made with mode 0600
// after a temp left by a crash is removed, syncs it, renames it to name and syncs dir.
// A write that fails removes temp and leaves name as it was.
func replaceKept(dir, name, temp string, b []byte) error {
	tmp := filepath.Join(dir, temp)
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return accesskey.ShownError(err)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	_, werr := f.Write(b)
	err = errors.Join(werr, f.Sync(), f.Close())
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		if rerr := os.Remove(tmp); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, rerr)
		}
		return accesskey.ShownError(err)
	}
	return syncDir(dir)
}

// readUnauthorized reads dir's [unauthorizedFile]: no file is no key.
func readUnauthorized(dir string) ([]modelkey.Unauthorized, error) {
	path := filepath.Join(dir, unauthorizedFile)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	var k keptUnauthorized
	if err := json.Unmarshal(b, &k); err != nil || k.Version != 1 {
		return nil, fmt.Errorf("remove %s, or start another run: it is not a list of model keys the gateway wrote", accesskey.ShownValue(path, false))
	}
	out := make([]modelkey.Unauthorized, 0, len(k.Keys))
	for _, key := range k.Keys {
		out = append(out, modelkey.Unauthorized{Credential: key.Credential, At: key.At, Out: key.Out})
	}
	return out, nil
}

// readKeptLines calls take with each line of file that is not blank, without its newline;
// a line for which take returns false is counted in torn. No file is no line.
func readKeptLines(file string, take func([]byte) bool, torn *int) error {
	f, err := os.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return accesskey.ShownError(err)
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		line, err := br.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 && !take(line) {
			*torn++
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return accesskey.ShownError(err)
		}
	}
}

// writeKept writes b to dir's file name, made or emptied, mode 0600, synced, then
// syncs dir. When the write or the sync fails, it removes the file, so no part of b
// stays on the disk.
func writeKept(dir, name string, b []byte) error {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	_, werr := f.Write(b)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, rerr)
		}
		return accesskey.ShownError(err)
	}
	return syncDir(dir)
}

// appendKept adds v's JSON as one line to dir's file name, made with mode 0600 when it
// does not exist, and syncs it; dir is synced when the file was made. A file whose last
// line has no newline, a write the gateway did not finish, gets one first, so v starts
// a line, as [stream.Stream.Reopen] mends events.jsonl. When the append fails, the file
// is cut back to its size before it.
func appendKept(dir, name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	_, err = os.Lstat(path)
	made := errors.Is(err, fs.ErrNotExist)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return accesskey.ShownError(err)
	}
	size := info.Size()
	line := append(b, '\n')
	if size > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, size-1); err != nil {
			f.Close()
			return accesskey.ShownError(err)
		}
		if last[0] != '\n' {
			line = append([]byte{'\n'}, line...)
		}
	}
	_, werr := f.Write(line)
	if err := errors.Join(werr, f.Sync()); err != nil {
		// What the failed write left goes, so the next line does not follow a part of
		// this one.
		err = errors.Join(err, f.Truncate(size), f.Close())
		return accesskey.ShownError(err)
	}
	if err := f.Close(); err != nil {
		return accesskey.ShownError(err)
	}
	if made {
		return syncDir(dir)
	}
	return nil
}

// markLimit makes dir's empty [limitMark], mode 0600, when passed is true and removes
// it when it is false, then syncs the file and dir.
func markLimit(dir string, passed bool) error {
	path := filepath.Join(dir, limitMark)
	if !passed {
		if err := os.Remove(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return accesskey.ShownError(err)
		}
		return syncDir(dir)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return accesskey.ShownError(err)
	}
	return syncDir(dir)
}

// syncDir syncs the directory, so the entries made or removed in it last.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return accesskey.ShownError(err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return accesskey.ShownError(err)
	}
	return nil
}

// sweepCA starts the CA key sweep of a separate gateway's records: one pass now, then
// one every caSweepEvery until [Gateway.stopSweep]. The records are those under
// [Gateway.sweptDir].
func (g *Gateway) sweepCA() {
	if g.sweptDir() == "" {
		return
	}
	every, age := g.sweepTimes()
	tick, stopTick := g.sweepTick(every)
	stop, done := make(chan struct{}), make(chan struct{})
	g.sweepStop, g.sweepDone = stop, done
	report := g.report
	routine.Go(report, func() {
		defer close(done)
		defer stopTick()
		for {
			routine.Do(report, func() { g.sweep(time.Now(), age) })
			select {
			case <-stop:
				return
			case <-tick:
			}
		}
	})
}

// sweepTimes are how often the CA key sweep runs and how long a record it sweeps has
// not changed: caSweepEvery and caSweepAge, or the Config's when a test sets them.
func (g *Gateway) sweepTimes() (every, age time.Duration) {
	every, age = caSweepEvery, caSweepAge
	if g.cfg.caSweepEvery != 0 {
		every = g.cfg.caSweepEvery
	}
	if g.cfg.caSweepAge != 0 {
		age = g.cfg.caSweepAge
	}
	return every, age
}

// sweepTick is the CA key sweep's ticker of interval every: its channel and what stops
// it.
func (g *Gateway) sweepTick(every time.Duration) (<-chan time.Time, func()) {
	if g.cfg.sweepTicker != nil {
		return g.cfg.sweepTicker(every)
	}
	t := time.NewTicker(every)
	return t.C, t.Stop
}

// sweptDir is the directory whose entries are the run record directories the sweep
// reads: Dir/runs, or with RunDir the directory RunDir makes each record in, when
// RunDir makes it as <directory>/<run id>; empty for none.
func (g *Gateway) sweptDir() string {
	if g.cfg.RunDir == nil {
		if g.cfg.Dir == "" {
			return ""
		}
		return filepath.Join(g.cfg.Dir, "runs")
	}
	const none = "00000000-0000-0000-0000-000000000000"
	if dir := g.cfg.RunDir(none); filepath.Base(dir) == none {
		return filepath.Dir(dir)
	}
	return ""
}

// stopSweep stops the CA key sweep and waits for a pass in flight.
func (g *Gateway) stopSweep() {
	if g.sweepStop == nil {
		return
	}
	close(g.sweepStop)
	<-g.sweepDone
	g.sweepStop = nil
}

// sweep removes the files kept to reopen a run ([stream.RemoveKept]) from each
// record under [Gateway.sweptDir] that meets all of these: it is the record directory
// of its name's run, the gateway does not hold its run, and its events.jsonl has not
// changed for more than age as of now. A record without events.jsonl counts the time
// of those files in place of it.
//
// The sweep and a reopen do not race: with g.mu held, the sweep checks that the run is
// neither in g.runs nor in g.reopening and adds it to g.sweeping, and a reopen checks
// that the run is not in g.sweeping and adds itself to g.reopening. The sweep removes
// the files with g.mu free, then takes the run from g.sweeping. A request that comes
// meanwhile gets a 503, and the next one a 410, as for any record past its age.
func (g *Gateway) sweep(now time.Time, age time.Duration) {
	root := g.sweptDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			g.report(fmt.Sprintf("the CA key sweep could not list %s: %v", accesskey.ShownValue(root, false), accesskey.ShownError(err)))
		}
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id, dir := e.Name(), filepath.Join(root, e.Name())
		if g.stream.Dir(id) != dir {
			continue
		}
		kept, err := newestOf(dir, proxy.CAKeyFile, proxy.CACertFile, requestFile)
		if err != nil || kept.IsZero() {
			continue
		}
		changed, err := newestOf(dir, sink.EventsFile)
		if err != nil {
			continue
		}
		if changed.IsZero() {
			changed = kept
		}
		if now.Sub(changed) <= age {
			continue
		}
		g.mu.Lock()
		held := g.runs[id] != nil || g.reopening[id] != nil
		if !held {
			g.sweeping[id] = true
		}
		g.mu.Unlock()
		if held {
			continue
		}
		err = stream.RemoveKept(dir)
		g.mu.Lock()
		delete(g.sweeping, id)
		g.mu.Unlock()
		if err != nil {
			g.report(keptNotRemoved(id, dir, err))
			continue
		}
		g.report(fmt.Sprintf("run %s: removed the files kept to reopen it: its record has not changed for %s", accesskey.ShownValue(id, false), age))
	}
}

// newestOf is the most recent modification time of the files of dir named in names,
// zero when none exists.
func newestOf(dir string, names ...string) (time.Time, error) {
	var newest time.Time
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return time.Time{}, err
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, nil
}

// reopenCall is one reopen of a suspended run in flight: every request of the run waits
// for done, then finds the run in lr, nil when the reopen failed, and final true when
// it failed for good.
type reopenCall struct {
	done  chan struct{}
	lr    *linkRun
	final bool
}
