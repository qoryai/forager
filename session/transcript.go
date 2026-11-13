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
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

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
// transcript while the runtime runs, unless the join's spec sets another interval.
const transcriptPoll = time.Second

// transcript sends the file in which a runtime with resume writes its session, as
// dev.qory.session.transcript events: whole lines as the runtime appends them, each
// masked whole, cut into chunks of at most [TranscriptChunk] bytes. Each read is of the
// bytes appended since the last one; the bytes after the last newline wait for the
// rest of their line. A line over [maxTranscriptLine] bytes, and a file over
// [maxTranscript] bytes, stop the transcript with one line. home is the
// directory on this machine that stands for ~, the runtime's home. The file's path comes
// from the first hook input that contains resume.PathFrom, when the descriptor sets
// one, and until then from resume.Path with the runtime's session id and the slug of
// its working directory. A resume.Path with a * is a pattern: each read searches for
// the file until one matches ([findMatches]), and more than one writes one line and
// sends nothing. The session reads no path outside resume.Prefix, with a .. segment, or
// through a symbolic link.
//
// Behind a wall, root is the session's transcript directory, which the wall binds at
// resume.Prefix inside, and home is empty: the file's path is resume.Path below root
// alone, whatever a hook input contains, the session id a UUID in lower case
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
	// fromHook true once a hook input set it. pattern is the path of a resume.path with
	// a *, which each read searches for until one file matches, while rel is empty;
	// nil otherwise.
	sessionID string
	rel       string
	fromHook  bool
	pattern   *pathPattern
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
// whose launch does not have the resume arguments the session added where it added
// them: fix, then cause, then the guard, which only a defect in Forager reaches.
func resumeArgsKept(fix, cause string) string {
	return fix + ", then continue the paused run again: " + cause + ". The session cannot take the resume arguments off the launch, because the launch has other arguments where they were added, which only a defect in Forager causes"
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
// sets the path, resume.path with id and the slug, below the transcript directory, or
// its pattern when resume.path has a *; another id writes one line, and nothing is
// sent. Call it with mu locked.
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
	below := strings.TrimPrefix(t.resume.Path, t.resume.Prefix)
	if strings.Contains(below, "*") {
		t.pattern = newPathPattern(below, id, t.slug, false)
		return
	}
	t.setPath(strings.TrimPrefix(t.resume.Prefix, "~/") + strings.NewReplacer("{session_id}", id, "{cwd_slug}", t.slug).Replace(below))
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
	from := t.resume.PathFrom
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := rec.Record[from].(string); ok && from != "" && t.restored {
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
	p, ok := rec.Record[from].(string)
	if !ok || from == "" || t.fromHook {
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
	if t.rel == "" && t.pattern == nil && !t.fromHook && t.sessionID != "" {
		if strings.Contains(t.resume.Path, "*") {
			t.pattern = newPathPattern(strings.TrimPrefix(t.resume.Path, t.resume.Prefix), t.sessionID, t.slug, false)
			return
		}
		p := strings.NewReplacer("{session_id}", t.sessionID, "{cwd_slug}", t.slug).Replace(t.resume.Path)
		if !t.setPath(strings.TrimPrefix(p, "~/")) {
			t.line(noResume("Keep the runtime's transcript below "+t.resume.Prefix, fmt.Sprintf("the session reads no transcript outside %s, and the transcript's path is %s", t.resume.Prefix, p)))
		}
	}
}

// setPath sets the file's path relative to home, and reports whether rel is one the
// session reads: under the prefix, with no empty, . or .. segment. Otherwise the file
// has no path. A path that changes starts the file's chunks at offset 0 again. Either
// way the search of a pattern ends.
func (t *transcript) setPath(rel string) bool {
	t.pattern = nil
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

// start reads the file every interval in a goroutine until end runs. end returns once
// that goroutine has returned, so no read of the file follows it; a second call of end
// does nothing.
func (t *transcript) start(interval time.Duration) (end func()) {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t.run(stop, interval)
	}()
	return sync.OnceFunc(func() {
		close(stop)
		<-done
	})
}

// run reads the file every interval until stop is closed.
func (t *transcript) run(stop <-chan struct{}, interval time.Duration) {
	tick := time.NewTicker(interval)
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
	switch {
	case t.root == "" || t.ended || t.seen:
	case t.rel != "":
		t.line(noResume("Check that the runtime writes its transcript at ~/"+t.rel, "the file does not exist, so the session sent no transcript"))
	case t.pattern != nil:
		t.line(noResume("Check that the runtime writes its transcript at "+t.resume.Prefix+t.pattern.shown, "no file matches, so the session sent no transcript"))
	}
	t.ended = true
}

// poll reads what the runtime appended since the last read, and sends the whole lines
// of it, with what an earlier read held of the first; with final, the rest of the file
// too.
func (t *transcript) poll(final bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended || t.sessionID == "" {
		return
	}
	if t.rel == "" && t.pattern != nil {
		t.find()
	}
	if t.ended || t.rel == "" {
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

// find searches for the file of the pattern, the part of resume.path below
// resume.prefix: behind a wall below the transcript directory, without one below
// resume.prefix under the home. One file that matches sets the path, and more than one
// writes one line and ends the transcript. A search that fails, or finds none, is tried
// again at the next read. Call it with mu locked.
func (t *transcript) find() {
	prefix := strings.TrimPrefix(t.resume.Prefix, "~/")
	base, start := t.home, prefix
	if t.root != "" {
		base, start = t.root, ""
	}
	found, err := findMatches(base, start, t.pattern)
	switch {
	case err != nil, len(found) == 0:
		return
	case len(found) > 1:
		t.ended = true
		t.line(noResume("Keep one transcript of the runtime's session at "+t.resume.Prefix+t.pattern.shown, "more than one file matches it, so the session reads none of them"))
		return
	}
	rel := prefix + found[0]
	if !t.setPath(rel) {
		t.line(noResume("Keep the runtime's transcript below "+t.resume.Prefix, fmt.Sprintf("the session reads no transcript outside %s, and the transcript's path is ~/%s", t.resume.Prefix, rel)))
	}
}

// errLinked is the error of a path to the transcript through a symbolic link or to no
// regular file.
var errLinked = errors.New("the transcript's path is a symbolic link or no regular file")

// readUnlinked reads the file at rel under home from offset on, and returns its bytes
// and the file's size. It opens the file through an os.Root of home, so no name leads
// out of it, and fails on a path any of whose names is a symbolic link, or that is no
// regular file, checked before the open and again on the open file. It opens the file
// without blocking, so a FIFO put at rel between the check and the open ends the read
// at once with [errLinked] instead of waiting for a writer. A file over [maxTranscript]
// bytes is [errTooLarge], as behind a wall.
func readUnlinked(home, rel string, offset int64) ([]byte, int64, error) {
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()
	at := ""
	var fi fs.FileInfo
	for s := range strings.SplitSeq(rel, "/") {
		at = path.Join(at, s)
		if fi, err = root.Lstat(at); err != nil {
			return nil, 0, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, 0, errLinked
		}
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, errLinked
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil {
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

// pathPattern is the part of a resume.path below resume.prefix with {session_id} and
// {cwd_slug} replaced: one expression for each name, in which a * of resume.path
// matches any characters other than / inside that name. A name it matches is never .
// or ...
type pathPattern struct {
	// names has one expression for each name, nil for one that matches nothing.
	names []*regexp.Regexp
	// shown is the path with each value replaced, a * left as it is, for a line.
	shown string
}

// slugPattern is the expression of {cwd_slug} that matches any slug, the shape of
// [cwdSlug]'s result.
const slugPattern = `[A-Za-z0-9-]{1,255}`

// newPathPattern is the pattern of tmpl, the part of a resume.path below
// resume.prefix, with {session_id} replaced by id and {cwd_slug} by slug. With
// anySlug, {cwd_slug} matches any slug instead. A replaced value is literal, a * in it
// included; a value with a / in it matches no name. A name whose expression does not
// compile, which only text that is no UTF-8 causes, matches nothing.
func newPathPattern(tmpl, id, slug string, anySlug bool) *pathPattern {
	p := &pathPattern{shown: strings.NewReplacer("{session_id}", id, "{cwd_slug}", slug).Replace(tmpl)}
	for name := range strings.SplitSeq(tmpl, "/") {
		var b strings.Builder
		b.WriteString("^")
		for name != "" {
			switch {
			case strings.HasPrefix(name, "*"):
				b.WriteString("[^/]*")
				name = name[1:]
			case strings.HasPrefix(name, "{session_id}"):
				b.WriteString(regexp.QuoteMeta(id))
				name = name[len("{session_id}"):]
			case strings.HasPrefix(name, "{cwd_slug}"):
				if anySlug {
					b.WriteString(slugPattern)
				} else {
					b.WriteString(regexp.QuoteMeta(slug))
				}
				name = name[len("{cwd_slug}"):]
			default:
				b.WriteString(regexp.QuoteMeta(name[:1]))
				name = name[1:]
			}
		}
		b.WriteString("$")
		// A failed compile returns nil, which matches nothing.
		re, _ := regexp.Compile(b.String())
		p.names = append(p.names, re)
	}
	return p
}

// matchName reports whether name, one name of a path, matches the i-th name of p.
func (p *pathPattern) matchName(i int, name string) bool {
	return name != "." && name != ".." && name != "" && p.names[i] != nil && p.names[i].MatchString(name)
}

// matches reports whether rel, a path of names separated by /, matches p name by name.
func (p *pathPattern) matches(rel string) bool {
	names := strings.Split(rel, "/")
	if len(names) != len(p.names) {
		return false
	}
	for i, n := range names {
		if !p.matchName(i, n) {
			return false
		}
	}
	return true
}

// findBatch is how many entries of a directory [findMatches] reads at a time: it
// bounds the memory of one read, not the entries read.
const findBatch = 256

// findMatches returns the paths below start, relative to start, whose names match p,
// at most two, in the order the directories list them. start is a path below base,
// empty for base itself, none of whose names is a symbolic link. It reads through an
// os.Root of base, so no name leads out of it. It follows a name of a directory only
// when the entry is a directory, never a symbolic link; the last name matches an entry
// of any type, which the read of the file then checks. A directory that does not exist
// matches nothing.
func findMatches(base, start string, p *pathPattern) ([]string, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	at := ""
	for s := range strings.SplitSeq(start, "/") {
		if s == "" {
			continue
		}
		at = path.Join(at, s)
		fi, err := root.Lstat(at)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			return nil, errLinked
		}
	}
	var found []string
	err = findBelow(root, dirOrDot(at), "", p, 0, &found)
	return found, err
}

// dirOrDot is dir, or . for an empty dir.
func dirOrDot(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}

// findBelow adds to found the paths below dir, relative to the start of the search
// with rel the path of dir, whose names from the i-th on match p, until found has two.
func findBelow(root *os.Root, dir, rel string, p *pathPattern, i int, found *[]string) error {
	f, err := root.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	last := i == len(p.names)-1
	for {
		entries, err := f.ReadDir(findBatch)
		for _, e := range entries {
			if !p.matchName(i, e.Name()) {
				continue
			}
			at := path.Join(rel, e.Name())
			if last {
				*found = append(*found, at)
			} else if e.Type().IsDir() {
				if err := findBelow(root, path.Join(dir, e.Name()), at, p, i+1, found); err != nil {
					return err
				}
			}
			if len(*found) > 1 {
				return nil
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
