package session

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/runfile"
	"github.com/qoryai/forager/session/runtimes"
)

// ResumeTranscript and ResumeScript are the files in a session's directory with which
// a session with no wall resumes the runtime session of a paused run: the paused run's transcript,
// as the gateway's link returns it, and the script that writes it under the runtime's
// home and starts the runtime with the descriptor's resume.args.
const (
	ResumeTranscript = "resume.jsonl"
	ResumeScript     = "resume.sh"
)

// maxResumeTranscript is the largest transcript the session reads, [server.MaxTranscript].
var maxResumeTranscript = server.MaxTranscript

// resumeWait is how long the session waits for the transcript.
const resumeWait = 10 * time.Minute

// resumeLaunch is the launch of a session that resumes the runtime session of the paused
// run of the run answer's resume, and an empty line; or launch as it is, and the line
// the session writes on stderr once its dev.qory.session.started is written, when the
// resume fails. Only the run's first session whose runtime has resume tries. It reads
// the transcript over the gateway's link, [server.Link.Transcript], which on the local
// link is GET /v1/run-configuration/<run_id>/transcript, and writes the bytes and
// [ResumeScript] in
// the session's directory, and starts launch through the script, which writes the
// bytes at resume.path under the runtime's home and adds the descriptor's resume.args,
// {session_id} replaced by resume.session_id, right after the first argument equal to
// the descriptor's resume.after, or at the end ([resumeAt]). inside is a path on this
// machine as the runtime reads it. A failure of the script's write starts the runtime
// without the arguments, after the same line from the script.
//
// Behind a wall, root is where the session reads the transcript: its transcript
// directory, which the wall binds at resume.prefix inside, or the writable mount whose
// place holds an absolute resume.prefix. The session writes the bytes there itself, at
// the run configuration's resume.path below resume.prefix, before the agent's container
// starts ([writeBeneath]), and inserts resume.args in launch the same way, with no
// script. A resume.session_id that is not a UUID in lower case is a failed resume, and
// so is a walled session with no transcript directory, root's dir empty, with root's
// unbound as the fix and the cause when it has one. With a wall or without one, a
// resume.path that does not match the descriptor's resume.path with resume.session_id,
// {cwd_slug} any slug, is a failed resume. A resume.prefix that starts with ~/ is
// below the runtime's home, and an absolute one is that path.
//
// rs is the runtime's resume, nil for none, with resume.home_var resolved ([resumeOf]).
// For a descriptor with home_var, resume.path is the paused run's absolute path, below
// that run's value of the variable: the session restores the file at the same names
// below this session's resolved resume.prefix ([sessionResume.moved]), and a
// resume.path that has no such names is a failed resume. A home_var with no usable
// value, rs.unset, is a failed resume, with its fix and cause.
//
// A restore also returns the [restored] transcript: the session reads the transcript
// the resumed runtime appends to at resume.path, under the paused run's slug, and the
// session takes the arguments off again when the enclosure binds no transcript
// directory ([wall.TranscriptChecker]).
func (r *Run) resumeLaunch(ctx context.Context, rs *sessionResume, sessionDir string, walled bool, root transcriptRoot, inside func(string) string, launch runtimes.Launch) (runtimes.Launch, string, *restored) {
	if r.answer.Resume == nil || r.resumeTried || rs == nil {
		return launch, "", nil
	}
	// want is a copy: a resume.path below another run's home_var moves below this
	// session's, and the run answer stays as the gateway sent it.
	want := *r.answer.Resume
	failed := func(fix, cause string) (runtimes.Launch, string, *restored) {
		return launch, resumeFailed(want.RunID, fix, cause), nil
	}
	r.resumeTried = true
	if u := rs.unset; u != nil {
		return failed(u.Fix, u.Cause)
	}
	checkPath := "Check resume.path in the run configuration"
	moved, ok := rs.moved(want.Path)
	if !ok {
		return failed(checkPath, fmt.Sprintf("its path %s lies outside %s, with an absolute path in place of ${%s}", want.Path, rs.prefix, rs.HomeVar))
	}
	want.Path = moved
	rel, ok := strings.CutPrefix(want.Path, leadOf(rs.Prefix))
	if !ok || !strings.HasPrefix(want.Path, rs.Prefix) || len(want.Path) == len(rs.Prefix) || dotted(rel) {
		return failed(checkPath, fmt.Sprintf("its path %s lies outside %s", want.Path, rs.Prefix))
	}
	// The session id goes into the runtime's arguments: one that starts with - would be
	// read as an option. Behind a wall it must also be a UUID, below.
	if strings.HasPrefix(want.SessionID, "-") {
		return failed("Check resume.session_id in the run configuration", fmt.Sprintf("its session id %s starts with -, so the runtime would read it as an option", accesskey.ShownName(want.SessionID, false)))
	}
	args := make([]string, len(rs.Args))
	for i, a := range rs.Args {
		args[i] = strings.ReplaceAll(a, "{session_id}", want.SessionID)
	}
	at := resumeAt(launch.Args, rs.After)
	below := strings.TrimPrefix(want.Path, rs.Prefix)
	if walled {
		if root.dir == "" {
			if u := root.unbound; u != nil {
				return failed(u.Fix, u.Cause)
			}
			return failed("Use a runtime whose resume.prefix is a directory below the runtime's home, or an absolute one", "the session has no transcript directory behind the wall")
		}
		if !walledSessionID.MatchString(want.SessionID) {
			return failed("Check resume.session_id in the run configuration", fmt.Sprintf("its session id %s is not a UUID in lower case", accesskey.ShownName(want.SessionID, false)))
		}
	}
	if pattern := newPathPattern(strings.TrimPrefix(rs.Path, rs.Prefix), want.SessionID, "", true); !pattern.matches(below) {
		return failed(checkPath, fmt.Sprintf("its path %s does not match %s%s, with {cwd_slug} a slug", r.answer.Resume.Path, rs.prefix, pattern.shown))
	}
	if walled {
		b, err := r.fetchTranscript(ctx)
		if err != nil {
			return failed(fetchFix(want.RunID), err.Error())
		}
		if err := writeBeneath(root.dir, path.Join(root.under, below), b); err != nil {
			return failed("Check the session's transcript directory "+pathShown(root.dir), fmt.Sprintf("the write to %s failed: %s", want.Path, accesskey.ShownError(err).Error()))
		}
		launch.Args = slices.Concat(launch.Args[:at], args, launch.Args[at:])
		return launch, "", &restored{sessionID: want.SessionID, rel: rel, args: args, after: len(launch.Args) - at - len(args)}
	}
	b, err := r.fetchTranscript(ctx)
	if err != nil {
		return failed(fetchFix(want.RunID), err.Error())
	}
	transcript := filepath.Join(sessionDir, ResumeTranscript)
	if err := runfile.Replace(transcript, b, 0o644); err != nil {
		return failed("Check the session's directory "+pathShown(sessionDir), accesskey.ShownError(err).Error())
	}
	script := filepath.Join(sessionDir, ResumeScript)
	// The script keeps the command and the arguments up to the one equal to
	// resume.after before the resume arguments: 1 + at words of its arguments.
	head := 0
	if at < len(launch.Args) {
		head = 1 + at
	}
	text := resumeScriptAt(want.RunID, inside(transcript), want.Path, args, head)
	if err := runfile.Replace(script, []byte(text), 0o644); err != nil {
		return failed("Check the session's directory "+pathShown(sessionDir), accesskey.ShownError(err).Error())
	}
	launch.Args = append([]string{script, launch.Command}, launch.Args...)
	launch.Command = "/bin/sh"
	return launch, "", &restored{sessionID: want.SessionID, rel: rel}
}

// restored is the transcript a session restored: sessionID is resume.session_id; rel
// is resume.path relative to the runtime's home, such as
// .claude/projects/<slug of the paused run>/<session id>.jsonl, or to / for an absolute
// one, the file the resumed runtime appends to; args are the arguments a walled session added to the launch, and
// after the count of the launch's arguments that follow them, 0 when args are last.
type restored struct {
	sessionID string
	rel       string
	args      []string
	after     int
}

// resumeAt is where the resume arguments go in args, a launch's arguments: right after
// the first one equal to after, or at the end when after is empty or no argument
// equals it.
func resumeAt(args []string, after string) int {
	if after != "" {
		if i := slices.Index(args, after); i >= 0 {
			return i + 1
		}
	}
	return len(args)
}

// fetchFix is the fix of a resume whose read of the transcript of run runID failed.
func fetchFix(runID string) string {
	return "Check that the control plane has the transcript of run " + runID
}

// resumeFailed is the line of a resume that failed: fix, the change that lets it
// resume, then that the transcript of run runID could not be restored, for cause.
func resumeFailed(runID, fix, cause string) string {
	return fmt.Sprintf("%s. The runtime starts without a resume: the transcript of run %s could not be restored: %s", fix, runID, cause)
}

// resumeScript is the text of [ResumeScript]: it copies transcript, a path as the
// runtime reads it, to dst, the run configuration's resume.path: below $HOME, the
// runtime's home, for one that starts with ~/, else the absolute path. Then it starts
// its arguments, the runtime's command and arguments, with args added at the end; when
// the copy fails, it writes the line of a failed resume on stderr and starts them
// without args.
func resumeScript(runID, transcript, dst string, args []string) string {
	return resumeScriptAt(runID, transcript, dst, args, 0)
}

// resumeScriptAt is [resumeScript] with args inserted after the first head words of
// its arguments, the command among them; at the end when head is 0.
func resumeScriptAt(runID, transcript, dst string, args []string, head int) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quote(a)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Forager wrote this script to resume the runtime session of run %s. It writes\n", runID)
	rel, inHome := strings.CutPrefix(dst, "~/")
	fix := "Check that HOME inside is writable"
	if inHome {
		b.WriteString("# the transcript under the runtime's home, then starts the runtime with the resume\n")
		b.WriteString("# arguments, or without them when the write fails.\n")
		fmt.Fprintf(&b, "dst=\"$HOME\"/%s\n", quote(rel))
		fmt.Fprintf(&b, "if [ -n \"$HOME\" ] && mkdir -p \"${dst%%/*}\" && cp %s \"$dst\"; then\n", quote(transcript))
	} else {
		fix = "Check that " + path.Dir(dst) + " is writable"
		b.WriteString("# the transcript at its path, then starts the runtime with the resume arguments,\n")
		b.WriteString("# or without them when the write fails.\n")
		fmt.Fprintf(&b, "dst=%s\n", quote(dst))
		fmt.Fprintf(&b, "if mkdir -p \"${dst%%/*}\" && cp %s \"$dst\"; then\n", quote(transcript))
	}
	if head == 0 {
		fmt.Fprintf(&b, "\texec \"$@\" %s\n", strings.Join(quoted, " "))
	} else {
		// Each word moves from the front to the end in turn, the resume arguments
		// before the word that follows the first head words.
		fmt.Fprintf(&b, "\tk=%d\n", head)
		b.WriteString("\tfor a do\n\t\tshift\n")
		fmt.Fprintf(&b, "\t\tif [ \"$k\" -eq 0 ]; then set -- \"$@\" %s; fi\n", strings.Join(quoted, " "))
		b.WriteString("\t\tset -- \"$@\" \"$a\"\n\t\tk=$((k - 1))\n\tdone\n")
		b.WriteString("\texec \"$@\"\n")
	}
	b.WriteString("fi\n")
	fmt.Fprintf(&b, "echo %s >&2\n", quote(resumeFailed(runID, fix, "the copy to "+dst+" failed")))
	b.WriteString("exec \"$@\"\n")
	return b.String()
}

// fetchTranscript reads the transcript of the paused run over the gateway's link. An
// answer other than 200, an empty transcript or one over [maxResumeTranscript] is an
// error, whose text starts with what happened.
func (r *Run) fetchTranscript(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, resumeWait)
	defer cancel()
	b, err := r.link.Transcript(ctx, r.disc.Run.URL, r.id, maxResumeTranscript)
	var ref *accesskey.Refusal
	var se *server.StatusError
	switch {
	case errors.As(err, &ref):
		return nil, fmt.Errorf("the gateway returned %d %s to the transcript request", ref.Status, accesskey.ShownValue(ref.Code, false))
	case errors.As(err, &se):
		return nil, fmt.Errorf("the gateway returned %d to the transcript request", se.Status)
	case err != nil:
		return nil, accesskey.ShownError(err)
	case len(b) == 0:
		return nil, errors.New("the gateway returned an empty transcript")
	}
	return b, nil
}
