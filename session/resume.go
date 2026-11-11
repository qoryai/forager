package session

import (
	"context"
	"errors"
	"fmt"
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
// {session_id} replaced by resume.session_id. inside is a path on this machine as the
// runtime sees it. A failure of the script's write starts the runtime without the
// arguments, after the same line from the script.
//
// Behind a wall, root is the session's transcript directory, which the wall binds at
// resume.prefix inside: the session writes the bytes there itself, at resume.path's
// <slug>/<session id>.jsonl below resume.prefix, before the agent's container starts
// ([writeBeneath]), and adds resume.args to launch, with no script; it also returns the
// arguments it added, which the session takes off again when the enclosure binds no
// transcript directory ([wall.TranscriptChecker]). A resume.session_id that is not a UUID
// in lower case, or a resume.path below resume.prefix of another shape, is a failed
// resume. A walled session with no transcript directory, root empty, does not resume.
func (r *Run) resumeLaunch(ctx context.Context, rt runtimes.Runtime, sessionDir string, walled bool, root string, inside func(string) string, launch runtimes.Launch) (runtimes.Launch, string, []string) {
	want := r.answer.Resume
	if want == nil || r.resumeTried {
		return launch, "", nil
	}
	failed := func(fix, cause string) (runtimes.Launch, string, []string) {
		return launch, resumeFailed(want.RunID, fix, cause), nil
	}
	resumes, ok := rt.(runtimes.Resumes)
	if !ok {
		return launch, "", nil
	}
	rs, ok := resumes.Resume()
	if !ok {
		return launch, "", nil
	}
	r.resumeTried = true
	checkPath := "Check resume.path in the run configuration"
	rel, ok := strings.CutPrefix(want.Path, "~/")
	if !ok || !strings.HasPrefix(want.Path, rs.Prefix) || len(want.Path) == len(rs.Prefix) || dotted(rel) {
		return failed(checkPath, fmt.Sprintf("its path %s lies outside %s", want.Path, rs.Prefix))
	}
	args := make([]string, len(rs.Args))
	for i, a := range rs.Args {
		args[i] = strings.ReplaceAll(a, "{session_id}", want.SessionID)
	}
	if walled {
		if root == "" {
			return failed("Use a runtime whose resume.path is resume.prefix followed by {cwd_slug}/{session_id}.jsonl", "the session has no transcript directory behind the wall")
		}
		below := strings.TrimPrefix(want.Path, rs.Prefix)
		if !walledSessionID.MatchString(want.SessionID) {
			return failed("Check resume.session_id in the run configuration", fmt.Sprintf("its session id %s is not a UUID in lower case", accesskey.ShownName(want.SessionID, false)))
		}
		if _, name, err := splitTranscript(below); err != nil || name != want.SessionID+".jsonl" {
			return failed(checkPath, fmt.Sprintf("its path %s is not %s<slug>/%s.jsonl", want.Path, rs.Prefix, want.SessionID))
		}
		b, err := r.fetchTranscript(ctx)
		if err != nil {
			return failed(fetchFix(want.RunID), err.Error())
		}
		if err := writeBeneath(root, below, b); err != nil {
			return failed("Check the session's transcript directory "+pathShown(root), fmt.Sprintf("the write to %s failed: %s", want.Path, accesskey.ShownError(err).Error()))
		}
		launch.Args = append(slices.Clone(launch.Args), args...)
		return launch, "", args
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
	text := resumeScript(want.RunID, inside(transcript), rel, args)
	if err := runfile.Replace(script, []byte(text), 0o644); err != nil {
		return failed("Check the session's directory "+pathShown(sessionDir), accesskey.ShownError(err).Error())
	}
	launch.Args = append([]string{script, launch.Command}, launch.Args...)
	launch.Command = "/bin/sh"
	return launch, "", nil
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
// runtime sees it, to rel under $HOME, the runtime's home, then starts its arguments, the
// runtime's command and arguments, with args added; when the copy fails, it writes the
// line of a failed resume on stderr and starts them without args.
func resumeScript(runID, transcript, rel string, args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quote(a)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Forager wrote this script to resume the runtime session of run %s. It writes\n", runID)
	b.WriteString("# the transcript under the runtime's home, then starts the runtime with the resume\n")
	b.WriteString("# arguments, or without them when the write fails.\n")
	fmt.Fprintf(&b, "dst=\"$HOME\"/%s\n", quote(rel))
	fmt.Fprintf(&b, "if [ -n \"$HOME\" ] && mkdir -p \"${dst%%/*}\" && cp %s \"$dst\"; then\n", quote(transcript))
	fmt.Fprintf(&b, "\texec \"$@\" %s\n", strings.Join(quoted, " "))
	b.WriteString("fi\n")
	fmt.Fprintf(&b, "echo %s >&2\n", quote(resumeFailed(runID, "Check that HOME inside is writable", "the copy to ~/"+rel+" failed")))
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
