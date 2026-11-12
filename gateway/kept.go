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
	"slices"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// The files a separate gateway writes in a run's record directory beside the stream's,
// each mode 0600, so that a gateway that starts again on the same directory can reopen
// the run: the run request ([keptRequest]), the policy members given ([givenFile]),
// the join decisions ([joinsFile]) and the mark of a model key past its limit
// ([limitMark]); the run's CA is [proxy.CACertFile] and [proxy.CAKeyFile]. The local
// link writes none of them. The stream's Discard and Reclaim remove them by these names.
const (
	requestFile = "request.json"
	givenFile   = "given.jsonl"
	joinsFile   = "joins.jsonl"
	limitMark   = "model-key-limit"
)

// The CA key sweep (the user's "545 (a)", 2026-11-13): a gateway removes the CA files
// of a run record it does not hold whose events.jsonl has not changed for more than
// caSweepAge, at Start and every caSweepEvery. A live run's
// session sends a heartbeat at least every server.MaxInterval, 300 s, so its record
// changes at least 3 times within caSweepAge; a record that does not is of a run that
// no session reopens, and its key goes from the disk. A record with a final event is
// never reopened, so its key goes too.
const (
	caSweepEvery = 10 * time.Minute
	caSweepAge   = 15 * time.Minute
)

// keptRequest is request.json: what [run.Decide] reads of the run request, so a
// gateway that starts again decides the run as its open did. Images may contain a
// registry's credentials in a reference's user information, as the run request does.
type keptRequest struct {
	Version   int                   `json:"version"`
	Wall      bool                  `json:"wall"`
	Narrowing *server.LinkNarrowing `json:"narrowing,omitempty"`
	Images    *server.LinkImages    `json:"images,omitempty"`
}

// narrowingOf is the session's narrowing of the run request as [run.Config] takes it,
// nil for none.
func narrowingOf(n *server.LinkNarrowing) *run.Narrowing {
	if n == nil {
		return nil
	}
	return &run.Narrowing{Allow: n.Egress.Allow, Deny: n.Egress.Deny}
}

// writeRequest writes request.json of the run request req to dir.
func writeRequest(dir string, req *server.LinkRunRequest) error {
	b, err := json.Marshal(keptRequest{Version: 1, Wall: req.Wall, Narrowing: req.Narrowing, Images: req.Images})
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
// answers it, with names alone. Session is the join's number; Accepted is true for a
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

// limitMarked reports whether dir has the mark of a model key past its limit: the
// proxy passed a limit refusal to the session, and no join or end of a session cleared
// it since.
func limitMarked(dir string) (bool, error) {
	_, err := os.Lstat(filepath.Join(dir, limitMark))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, accesskey.ShownError(err)
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
// syncs dir.
func writeKept(dir, name string, b []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	_, werr := f.Write(b)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		return accesskey.ShownError(err)
	}
	return syncDir(dir)
}

// appendKept adds v's JSON as one line to dir's file name, made with mode 0600 when it
// does not exist, and syncs it; dir is synced when the file was made.
func appendKept(dir, name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	_, err = os.Lstat(path)
	made := errors.Is(err, fs.ErrNotExist)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	_, werr := f.Write(append(b, '\n'))
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
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

// sweepCA starts the CA key sweep of a separate gateway's records under Dir/runs: one
// pass now, then one every caSweepEvery until [Gateway.stopSweep].
func (g *Gateway) sweepCA() {
	if g.cfg.Dir == "" || g.cfg.RunDir != nil {
		// The records are not under Dir/runs.
		return
	}
	every, age := caSweepEvery, caSweepAge
	if g.cfg.caSweepEvery != 0 {
		every = g.cfg.caSweepEvery
	}
	if g.cfg.caSweepAge != 0 {
		age = g.cfg.caSweepAge
	}
	stop, done := make(chan struct{}), make(chan struct{})
	g.sweepStop, g.sweepDone = stop, done
	report := g.report
	routine.Go(report, func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			routine.Do(report, func() { g.sweep(time.Now(), age) })
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	})
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

// sweep removes [proxy.CACertFile] and [proxy.CAKeyFile] from each record under
// Dir/runs that meets both: the gateway does not hold its run, and its events.jsonl has
// not changed for more than age as of now. A record without events.jsonl counts its CA
// files' time in place of it.
//
// The sweep and a reopen do not race: the sweep checks that the run is neither in
// g.runs nor in g.reopening and removes the files with g.mu held, and a reopen adds
// itself to g.reopening with g.mu held before it reads them. Either the sweep removes
// the files first, and the reopen finds none and fails for good, as for a record past
// its age, or the sweep leaves the record alone. g.mu is held for two removals and a
// sync of the directory, for a record unchanged for caSweepAge alone.
func (g *Gateway) sweep(now time.Time, age time.Duration) {
	root := filepath.Join(g.cfg.Dir, "runs")
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
		ca, err := newestOf(dir, proxy.CAKeyFile, proxy.CACertFile)
		if err != nil || ca.IsZero() {
			continue
		}
		changed, err := newestOf(dir, sink.EventsFile)
		if err != nil {
			continue
		}
		if changed.IsZero() {
			changed = ca
		}
		if now.Sub(changed) <= age {
			continue
		}
		g.mu.Lock()
		held := g.runs[id] != nil || g.reopening[id] != nil
		if !held {
			err = proxy.RemoveCA(dir)
		}
		g.mu.Unlock()
		if held {
			continue
		}
		if err != nil {
			g.report(fmt.Sprintf("run %s: removing its CA files: %v", accesskey.ShownValue(id, false), err))
			continue
		}
		g.report(fmt.Sprintf("run %s: removed its CA files: its record has not changed for %s", accesskey.ShownValue(id, false), age))
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
