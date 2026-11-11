package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/runtimes"
)

// transcriptsDir is the directory in the run directory that contains the transcript
// directory of each walled session whose runtime has resume, transcripts/<n>/, which
// the wall binds writable at the runtime's resume.prefix inside.
const transcriptsDir = "transcripts"

// makeTranscriptDir makes the transcript directory of walled session n, transcripts/<n>
// in the run directory runDir, mode 0700 and owned by the user the session runs as, and
// returns it with its place below the home inside, resume.prefix without ~/ and its
// last /. A runtime without resume, or whose resume.path is not
// <prefix>{cwd_slug}/{session_id}.jsonl, gets none: both are empty. The directory
// must lie in the run directory and outside workspace and every one of binds, the places
// the enclosure binds, as [checkTranscriptDir] checks; otherwise the join fails.
func makeTranscriptDir(rt runtimes.Runtime, runDir string, n int, workspace string, binds []bindSource) (string, string, error) {
	resumes, ok := rt.(runtimes.Resumes)
	if !ok {
		return "", "", nil
	}
	rs, ok := resumes.Resume()
	if !ok || rs.Path != rs.Prefix+"{cwd_slug}/{session_id}.jsonl" {
		return "", "", nil
	}
	under := strings.TrimSuffix(strings.TrimPrefix(rs.Prefix, "~/"), "/")
	if under == "" || path.Clean(under) != under || path.IsAbs(under) || dotted(under) {
		return "", "", nil
	}
	parent := filepath.Join(runDir, transcriptsDir)
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", "", accesskey.ShownError(err)
	}
	if fi, err := os.Lstat(parent); err != nil || !fi.IsDir() {
		return "", "", fmt.Errorf("the transcript directories %s are no directory of the run's", pathShown(parent))
	}
	dir := filepath.Join(parent, strconv.Itoa(n))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", "", accesskey.ShownError(err)
	}
	if err := checkTranscriptDir(dir, runDir, workspace, binds); err != nil {
		return "", "", err
	}
	return dir, under, nil
}

// checkTranscriptDir checks the transcript directory dir, resolved: it lies inside the
// run directory runDir, so in no other run's, and it is not, contains no and lies inside
// no workspace or bind of binds, the run directory's entry among them left out.
func checkTranscriptDir(dir, runDir, workspace string, binds []bindSource) error {
	at, err := split(dir, 0)
	if err != nil {
		return fmt.Errorf("cannot resolve the transcript directory %s: %w", pathShown(dir), err)
	}
	run, err := split(runDir, 0)
	if err != nil {
		return fmt.Errorf("cannot resolve the run directory %s: %w", pathShown(runDir), err)
	}
	if ok, same := holds(run, at); !ok || same {
		return fmt.Errorf("the transcript directory %s lies outside the run directory %s", pathShown(dir), pathShown(runDir))
	}
	places := []string{workspace}
	for _, b := range binds {
		if b.Kind != kindRun {
			places = append(places, b.Path)
		}
	}
	for _, p := range places {
		how, err := overlap(p, dir)
		if err != nil {
			return err
		}
		if how != "" {
			return fmt.Errorf("the transcript directory %s overlaps %s, which the enclosure binds; the session makes it outside every place the enclosure binds", pathShown(dir), pathShown(p))
		}
	}
	return nil
}
