package session

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/runtimes"
)

// TranscriptChunk is the most bytes of the masked transcript one
// dev.qory.session.transcript contains: 32 KiB before the base64 encoding.
const TranscriptChunk = 32 << 10

// userHome is the home of the user the session runs as; a test sets another.
var userHome = os.UserHomeDir

// transcriptPoll is how often the session reads what the runtime appended to its
// transcript while the runtime runs.
var transcriptPoll = time.Second

// transcript sends the file in which a runtime with resume writes its session, as
// dev.qory.session.transcript events: whole lines as the runtime appends them, each
// masked whole, cut into chunks of at most [TranscriptChunk] bytes. Each read is of the
// bytes appended since the last one; the bytes after the last newline wait for the
// rest of their line. A line over [maxTranscriptLine] bytes, and a file over
// [maxTranscript] bytes, stop the transcript with one line. home is the
// directory on this machine that stands for ~, the runtime's home. The file's path comes
// from the first hook input that contains resume.PathFrom, and until then from
// resume.Path with the runtime's session id and the slug of its working directory. The
// session reads no path outside resume.Prefix, with a .. segment, or through a
// symbolic link.
//
// Behind a wall, root is the session's transcript directory, which the wall binds at
// resume.Prefix inside, and home is empty: the file's path is <slug>/<session id>.jsonl
// below root alone, whatever a hook input contains, the session id a UUID in lower case
// ([walledSessionID]), and the file is read as [readBeneath] reads it. A session id of
// another shape, or a file the session does not read, writes one line, and nothing more
// is sent. Its methods may be called from any goroutine.
type transcript struct {
	resume runtimes.Resume
	home   string
	root   string
	// slug is the runtime's working directory with every character other than an
	// ASCII letter or digit replaced by -.
	slug string
	// mask replaces the run's secrets and a hidden harness's text in one line.
	mask func(string) string
	// send writes one dev.qory.session.transcript's data, without session; line writes
	// one dev.qory.run.log line of the session on stderr.
	send func(data map[string]any)
	line func(string)

	mu sync.Mutex
	// sessionID is the runtime's session id; rel is the file's path relative to home,
	// fromHook true once a hook input set it.
	sessionID string
	rel       string
	fromHook  bool
	// restored is true for the session that restored a paused run's transcript: rel is
	// the restored file's, whatever a hook input or the working directory shows, and
	// warned is true once a hook input had the path of another file.
	restored bool
	warned   bool
	// read is the bytes of the file read so far; partial is the part of them after the
	// last newline, not sent yet, at most [maxTranscriptLine] bytes; sent is the masked bytes sent: the next chunk's offset.
	// seen is true once a read found the file. ended is true once the file became
	// shorter than read, or once finish ran: nothing more is sent.
	read    int64
	partial []byte
	sent    int64
	seen    bool
	ended   bool
}

// maxTranscriptLine is the longest line of a transcript the session sends, 8 MiB: the
// most it keeps in memory of a line whose newline the runtime has not written yet.
const maxTranscriptLine = 8 << 20

// newTranscript returns the transcript of a runtime with resume rs whose home on this
// machine is home and whose working directory is cwd.
func newTranscript(rs runtimes.Resume, home, cwd string, mask func(string) string, send func(map[string]any), line func(string)) *transcript {
	return &transcript{resume: rs, home: home, slug: cwdSlug(cwd), mask: mask, send: send, line: line}
}

// newWalledTranscript returns the transcript of a walled runtime with resume rs whose
// transcript directory on this machine is root and whose working directory inside is
// cwd.
func newWalledTranscript(rs runtimes.Resume, root, cwd string, mask func(string) string, send func(map[string]any), line func(string)) *transcript {
	return &transcript{resume: rs, root: root, slug: cwdSlug(cwd), mask: mask, send: send, line: line}
}

// resumeArgsKept is the error of a session whose wall binds no transcript directory and
// whose launch does not end with the resume arguments the session added: fix, then
// cause, then the guard, which only a defect in Forager reaches.
func resumeArgsKept(fix, cause string) string {
	return fix + ", then continue the paused run again: " + cause + ". The session cannot take the resume arguments off the launch, because the launch ends with other arguments, which only a defect in Forager causes"
}

// noResume is the line of a transcript that a continuation cannot resume from: fix, the
// change that lets it, then what follows, then cause.
func noResume(fix, cause string) string {
	return fix + ". A continuation of this run starts the runtime without a resume: " + cause
}

// restore fixes the file to the restored transcript rel, resume.path relative to the
// home, and the session id to id: the resumed runtime appends to that file, under the
// paused run's slug, so the session sends the whole file from offset 0, the restored
// lines first. A path the session does not read leaves the transcript with no path.
func (t *transcript) restore(id, rel string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(id) > maxSessionID || (t.root != "" && !walledSessionID.MatchString(id)) {
		return
	}
	t.sessionID, t.restored, t.fromHook = id, true, true
	t.setPath(rel)
}

// sameRestored checks p, the path of resume.PathFrom of a hook input, against the
// restored file: a file of another name writes one line, once, and the session goes on
// reading the restored one. Only the name, <session id>.jsonl, is compared: Claude Code
// 2.1.316 resumed in another working directory sends the path under that directory's
// slug and appends to the restored file all the same. Call it with mu locked.
func (t *transcript) sameRestored(p string) {
	if path.Base(p) == path.Base(t.rel) || t.warned || t.rel == "" {
		return
	}
	t.warned = true
	t.line(fmt.Sprintf("Check that the runtime resumes from ~/%s. The session reads the restored transcript there, and %s of the hook input is %q", t.rel, t.resume.PathFrom, accesskey.ShownValue(p[:min(len(p), 256)], false)))
}

// walledID takes id as the session id of a walled runtime, once: a UUID in lower case
// sets the path, <slug>/<id>.jsonl below the transcript directory; another id writes
// one line, and nothing is sent. Call it with mu locked.
func (t *transcript) walledID(id string) {
	if t.sessionID != "" || t.ended {
		return
	}
	if !walledSessionID.MatchString(id) {
		t.ended = true
		// The agent chooses the id: the line has at most its first 64 bytes, quoted, so
		// no newline in it starts another line.
		t.line(noResume("Use a runtime whose session ids are UUIDs in lower case", fmt.Sprintf("the runtime's session id %q is not a UUID in lower case, so the session reads no transcript", accesskey.ShownName(id[:min(len(id), 64)], false))))
		return
	}
	t.sessionID = id
	t.setPath(strings.TrimPrefix(t.resume.Prefix, "~/") + t.slug + "/" + id + ".jsonl")
}

// cwdSlug is dir with every character other than an ASCII letter or digit replaced by
// -: /workspace becomes -workspace.
func cwdSlug(dir string) string {
	b := []byte(dir)
	for i, c := range b {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			b[i] = '-'
		}
	}
	return string(b)
}

// record reads a record of the runtime: a hook input's resume.PathFrom, which sets the
// file's path, and its session_id; and dev.qory.runtime.started's session_id, which
// sets the path from resume.Path while no hook input set it.
func (t *transcript) record(rec runtimes.Record) {
	if rec.Source != runtimes.SourceHooks {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := rec.Record[t.resume.PathFrom].(string); ok && t.restored {
		t.sameRestored(p)
		return
	}
	if t.root != "" {
		if id, ok := rec.Record["session_id"].(string); ok {
			t.walledID(id)
		}
		return
	}
	if id, ok := rec.Record["session_id"].(string); ok && t.sessionID == "" && len(id) <= maxSessionID {
		t.sessionID = id
	}
	p, ok := rec.Record[t.resume.PathFrom].(string)
	if !ok || t.fromHook {
		return
	}
	t.fromHook = true
	rel, ok := strings.CutPrefix(p, strings.TrimSuffix(t.home, "/")+"/")
	if !ok {
		rel = ""
	}
	if !t.setPath(rel) {
		t.line(noResume("Keep the runtime's transcript below "+t.resume.Prefix, fmt.Sprintf("the session reads no transcript outside %s, and %s of the hook input is %s", t.resume.Prefix, t.resume.PathFrom, p)))
	}
}

// started reads the runtime's session id from its dev.qory.runtime.started.
func (t *transcript) started(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.root != "" {
		t.walledID(sessionID)
		return
	}
	if t.sessionID == "" && len(sessionID) <= maxSessionID {
		t.sessionID = sessionID
	}
	if t.rel == "" && !t.fromHook && t.sessionID != "" {
		p := strings.NewReplacer("{session_id}", t.sessionID, "{cwd_slug}", t.slug).Replace(t.resume.Path)
		if !t.setPath(strings.TrimPrefix(p, "~/")) {
			t.line(noResume("Keep the runtime's transcript below "+t.resume.Prefix, fmt.Sprintf("the session reads no transcript outside %s, and the transcript's path is %s", t.resume.Prefix, p)))
		}
	}
}

// setPath sets the file's path relative to home, and reports whether rel is one the
// session reads: under the prefix, with no empty, . or .. segment. Otherwise the file
// has no path. A path that changes starts the file's chunks at offset 0 again.
func (t *transcript) setPath(rel string) bool {
	prefix := strings.TrimPrefix(t.resume.Prefix, "~/")
	ok := strings.HasPrefix(rel, prefix) && len(rel) > len(prefix) && !dotted(rel) && len(rel) <= maxTranscriptPath
	if !ok {
		rel = ""
	}
	if rel != t.rel {
		t.rel, t.read, t.sent, t.partial = rel, 0, 0, nil
	}
	return ok
}

// maxSessionID is the longest session id dev.qory.session.transcript's session_id
// contains.
const maxSessionID = 128

// maxTranscriptPath is the longest path relative to the home that
// dev.qory.session.transcript's path, ~/ and this path, can contain.
const maxTranscriptPath = 1024 - len("~/")

// dotted reports whether p has an empty, . or .. segment.
func dotted(p string) bool {
	for s := range strings.SplitSeq(p, "/") {
		if s == "" || s == "." || s == ".." {
			return true
		}
	}
	return false
}

// run reads the file every [transcriptPoll] until stop is closed.
func (t *transcript) run(stop <-chan struct{}) {
	tick := time.NewTicker(transcriptPoll)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			t.poll(false)
		}
	}
}

// finish reads the file once more to its end, and sends nothing after it. Behind a
// wall, a file no read found writes one line: no transcript was sent.
func (t *transcript) finish() {
	t.poll(true)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.root != "" && !t.ended && !t.seen && t.rel != "" {
		t.line(noResume("Check that the runtime writes its transcript at ~/"+t.rel, "the file does not exist, so the session sent no transcript"))
	}
	t.ended = true
}

// poll reads what the runtime appended since the last read, and sends the whole lines
// of it, with what an earlier read held of the first; with final, the rest of the file
// too.
func (t *transcript) poll(final bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended || t.rel == "" || t.sessionID == "" {
		return
	}
	var b []byte
	var size int64
	var err error
	if t.root != "" {
		b, size, err = readBeneath(t.root, strings.TrimPrefix(t.rel, strings.TrimPrefix(t.resume.Prefix, "~/")), t.read)
	} else {
		b, size, err = readUnlinked(t.home, t.rel, t.read)
	}
	var refused *beneathRefused
	if errors.As(err, &refused) {
		t.ended = true
		t.line(noResume(refused.fix, fmt.Sprintf("the session reads no transcript at ~/%s: %s", t.rel, refused.why)))
		return
	}
	if err != nil {
		return
	}
	t.seen = true
	if size < t.read {
		t.ended = true
		t.line(noResume("Let the runtime only append to its transcript", fmt.Sprintf("the transcript ~/%s became shorter than the %d bytes read", t.rel, t.read)))
		return
	}
	if len(b) == 0 && !final {
		return
	}
	t.read += int64(len(b))
	data := b
	if len(t.partial) > 0 {
		data = append(t.partial, b...)
	}
	t.partial = nil
	if !final {
		end := bytes.LastIndexByte(data, '\n') + 1
		data, t.partial = data[:end], bytes.Clone(data[end:])
	}
	var masked []byte
	long := len(t.partial) > maxTranscriptLine
	for l := range bytes.SplitAfterSeq(data, []byte("\n")) {
		if len(l) > maxTranscriptLine {
			long = true
			break
		}
		masked = append(masked, t.mask(string(l))...)
	}
	for len(masked) > 0 {
		n := min(len(masked), TranscriptChunk)
		t.send(map[string]any{"session_id": t.sessionID, "path": "~/" + t.rel, "offset": t.sent, "bytes": base64.StdEncoding.EncodeToString(masked[:n])})
		t.sent += int64(n)
		masked = masked[n:]
	}
	if long {
		t.ended, t.partial = true, nil
		t.line(noResume(fmt.Sprintf("Keep each line of the transcript at most %d bytes (8 MiB)", maxTranscriptLine), fmt.Sprintf("a line of the transcript ~/%s is longer, so the session sends no more of it", t.rel)))
	}
}

// errLinked is the error of a path to the transcript through a symbolic link or to no
// regular file.
var errLinked = errors.New("the transcript's path is a symbolic link or no regular file")

// readUnlinked reads the file at rel under home from offset on, and returns its bytes
// and the file's size. It opens the file through an os.Root of home, so no name leads
// out of it, and fails on a path any of whose names is a symbolic link, or that is no
// regular file. A file over [maxTranscript] bytes is [errTooLarge], as behind a wall.
func readUnlinked(home, rel string, offset int64) ([]byte, int64, error) {
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()
	at := ""
	for s := range strings.SplitSeq(rel, "/") {
		at = path.Join(at, s)
		fi, err := root.Lstat(at)
		if err != nil {
			return nil, 0, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, 0, errLinked
		}
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, errLinked
	}
	if fi.Size() > maxTranscript {
		return nil, 0, errTooLarge
	}
	if fi.Size() < offset {
		return nil, fi.Size(), nil
	}
	b, err := io.ReadAll(io.NewSectionReader(f, offset, fi.Size()-offset))
	return b, fi.Size(), err
}

// sessionTranscript is the transcript of session n's runtime rt, nil for a runtime
// without resume. A run with no wall reads it under the runtime's home, HOME of env,
// the launch's environment, or the home of the user the session runs as when env has
// none, and the runtime's working directory dir. Behind a wall, root is the session's
// transcript directory, which the wall binds at resume.prefix inside, and dir the
// working directory inside; the session reads the transcript below root. A walled
// session with no transcript directory, root empty, sends none. For the session that
// restored a paused run's transcript, restore, it reads the restored file
// ([transcript.restore]).
func (r *Run) sessionTranscript(rt runtimes.Runtime, n int, walled bool, root string, env []string, dir string, masker *mask.Masker, hidden *mask.Harness, restore *restored) *transcript {
	tr := r.newSessionTranscript(rt, n, walled, root, env, dir, masker, hidden)
	if tr != nil && restore != nil {
		tr.restore(restore.sessionID, restore.rel)
	}
	return tr
}

// newSessionTranscript is the transcript of [Run.sessionTranscript] before a restore.
func (r *Run) newSessionTranscript(rt runtimes.Runtime, n int, walled bool, root string, env []string, dir string, masker *mask.Masker, hidden *mask.Harness) *transcript {
	resumes, ok := rt.(runtimes.Resumes)
	if !ok {
		return nil
	}
	rs, ok := resumes.Resume()
	if !ok {
		return nil
	}
	line := func(l string) { r.writeLog("stderr", n, 0, []byte(l+"\n")) }
	mask := func(l string) string { return hidden.Replace(masker.Replace(l)) }
	send := func(data map[string]any) {
		data["session"] = n
		r.write(event.SessionTranscript, data)
	}
	if walled {
		if root == "" {
			return nil
		}
		return newWalledTranscript(rs, root, dir, mask, send, line)
	}
	home := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			home = v
		}
	}
	if home == "" {
		home, _ = userHome()
	}
	if home == "" {
		line(noResume("Set HOME for the runtime", "the runtime has no home, so the session finds no transcript"))
		return nil
	}
	return newTranscript(rs, home, dir, mask, send, line)
}
