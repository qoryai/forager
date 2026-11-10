package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/runfile"
	"github.com/qoryai/forager/session/runtimes"
)

// ResumeTranscript and ResumeScript are the files in a session's directory with which
// the session resumes the runtime session of a paused run: the paused run's transcript,
// as GET /resume/transcript of the run API returns it, and the script that writes it
// under the runtime's home and starts the runtime with the descriptor's resume.args.
const (
	ResumeTranscript = "resume.jsonl"
	ResumeScript     = "resume.sh"
)

// maxResumeTranscript is the largest transcript GET /resume/transcript returns, 64 MiB.
var maxResumeTranscript int64 = 64 << 20

// resumeWait is how long the session waits for GET /resume/transcript, the route's
// time for the request.
const resumeWait = 10 * time.Minute

// resumeLaunch is the launch of a session that resumes the runtime session of the paused
// run of the run answer's resume, and an empty line; or launch as it is, and the line
// the session writes on stderr once its dev.qory.session.started is written, when the
// resume fails. Only the run's first session whose runtime has resume tries. It reads
// GET /resume/transcript through [Run.RunAPI], writes the bytes and [ResumeScript] in
// the session's directory, and starts launch through the script, which writes the
// bytes at resume.path under the runtime's home and adds the descriptor's resume.args,
// {session_id} replaced by resume.session_id. inside is a path on this machine as the
// runtime sees it. A failure of the script's write starts the runtime without the
// arguments, after the same line from the script.
func (r *Run) resumeLaunch(ctx context.Context, rt runtimes.Runtime, sessionDir string, inside func(string) string, launch runtimes.Launch) (runtimes.Launch, string) {
	want := r.answer.Resume
	if want == nil || r.resumeTried {
		return launch, ""
	}
	failed := func(cause string) (runtimes.Launch, string) {
		return launch, resumeFailed(want.RunID, cause)
	}
	resumes, ok := rt.(runtimes.Resumes)
	if !ok {
		return launch, ""
	}
	rs, ok := resumes.Resume()
	if !ok {
		return launch, ""
	}
	r.resumeTried = true
	rel, ok := strings.CutPrefix(want.Path, "~/")
	if !ok || !strings.HasPrefix(want.Path, rs.Prefix) || len(want.Path) == len(rs.Prefix) || dotted(rel) {
		return failed(fmt.Sprintf("its path %s lies outside %s", want.Path, rs.Prefix))
	}
	client, base, err := r.RunAPI()
	if err != nil {
		return failed(err.Error())
	}
	b, err := fetchTranscript(ctx, client, base)
	if err != nil {
		return failed(err.Error())
	}
	transcript := filepath.Join(sessionDir, ResumeTranscript)
	if err := runfile.Replace(transcript, b, 0o644); err != nil {
		return failed(accesskey.ShownError(err).Error())
	}
	args := make([]string, len(rs.Args))
	for i, a := range rs.Args {
		args[i] = strings.ReplaceAll(a, "{session_id}", want.SessionID)
	}
	script := filepath.Join(sessionDir, ResumeScript)
	text := resumeScript(want.RunID, inside(transcript), rel, args)
	if err := runfile.Replace(script, []byte(text), 0o644); err != nil {
		return failed(accesskey.ShownError(err).Error())
	}
	launch.Args = append([]string{script, launch.Command}, launch.Args...)
	launch.Command = "/bin/sh"
	return launch, ""
}

// resumeFailed is the line of a resume that failed: the transcript of run runID could
// not be restored, for cause.
func resumeFailed(runID, cause string) string {
	return fmt.Sprintf("The runtime starts without a resume: the transcript of run %s could not be restored: %s", runID, cause)
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
	fmt.Fprintf(&b, "echo %s >&2\n", quote(resumeFailed(runID, "the copy to ~/"+rel+" failed")))
	b.WriteString("exec \"$@\"\n")
	return b.String()
}

// fetchTranscript reads GET /resume/transcript of the run API at base with client. Its
// bytes count only when the read ends cleanly: the gateway verifies the signed digest
// at the end of the stream, and ends the stream of bytes that do not match with no last
// chunk. An answer other than 200, an empty transcript or one over
// [maxResumeTranscript] is an error, whose text starts with what happened.
func fetchTranscript(ctx context.Context, client *http.Client, base string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, resumeWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/resume/transcript", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		// The client's error names the request by its URL, which resolves nowhere.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("GET /resume/transcript failed: %w", accesskey.ShownError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var refusal struct {
			Error string `json:"error"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, server.MaxRefusal))
		code := ""
		if json.Unmarshal(body, &refusal) == nil && refusal.Error != "" {
			code = " " + refusal.Error
		}
		return nil, fmt.Errorf("GET /resume/transcript returned %d%s", resp.StatusCode, accesskey.ShownValue(code, false))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResumeTranscript+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("the read of GET /resume/transcript ended before the transcript's end, so its digest is not verified: %w", accesskey.ShownError(err))
	case int64(len(b)) > maxResumeTranscript:
		return nil, fmt.Errorf("GET /resume/transcript returned more than %d bytes", maxResumeTranscript)
	case len(b) == 0:
		return nil, errors.New("GET /resume/transcript returned an empty transcript")
	}
	return b, nil
}
