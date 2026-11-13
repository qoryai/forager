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
	"github.com/qoryai/forager/wall"
)

// transcriptsDir is the directory in the run directory that contains the transcript
// directory of each walled session whose runtime has resume, transcripts/<n>/, which
// the wall binds writable at the runtime's resume.prefix inside.
const transcriptsDir = "transcripts"

// transcriptRoot is where a walled session reads the transcript of its runtime, and
// writes a restored one: below dir, a directory on this machine, at the names under,
// then resume.path below resume.prefix. The zero value is none.
type transcriptRoot struct {
	// dir is the session's transcript directory, transcripts/<n> in the run directory,
	// or the path on this machine of the writable mount whose place inside holds an
	// absolute resume.prefix.
	dir string
	// under is the names from dir down to resume.prefix: empty for the transcript
	// directory, and the place of resume.prefix below the mount's place inside for a
	// mount.
	under string
	// bind is where the wall binds dir inside, [wall.Transcript.Under]: resume.prefix
	// without ~/ and its last /, relative to the home, or an absolute resume.prefix
	// without its last /. Empty when the wall binds no transcript directory, as for a
	// mount, which the enclosure shows already.
	bind string
	// unbound, when set, is why the session reads no transcript and the runtime starts
	// without a resume: an absolute resume.prefix inside a read-only mount.
	unbound *wall.Unbound
}

// wallTranscript is the transcript directory the wall binds, the zero value for none.
func (t transcriptRoot) wallTranscript() wall.Transcript {
	if t.bind == "" {
		return wall.Transcript{}
	}
	return wall.Transcript{Path: t.dir, Under: t.bind}
}

// makeTranscriptDir is where walled session n reads the transcript of its runtime rt,
// with the binds the enclosure shows, mounts, each at its place inside. A runtime
// without resume, whose resume.prefix is the home itself, or whose resume.path has an
// empty, . or .. name below resume.prefix, gets none.
//
// An absolute resume.prefix inside the place of a writable mount, the innermost one, is
// read there: dir is the mount's path on this machine, and the wall binds nothing. One
// inside a read-only mount gets unbound, and the runtime cannot write it. A mount whose
// place lies inside an absolute resume.prefix fails the join. Otherwise the session
// makes its transcript directory, transcripts/<n> in the run directory runDir, mode 0700
// and owned by the user the session runs as, which the wall binds at resume.prefix,
// below the home or absolute. The directory must lie in the run directory and outside
// workspace and every one of binds, the places the enclosure binds, as
// [checkTranscriptDir] checks; otherwise the join fails.
func makeTranscriptDir(rt runtimes.Runtime, runDir string, n int, workspace string, binds []bindSource, mounts []wall.Mount) (transcriptRoot, error) {
	resumes, ok := rt.(runtimes.Resumes)
	if !ok {
		return transcriptRoot{}, nil
	}
	rs, ok := resumes.Resume()
	below, isBelow := strings.CutPrefix(rs.Path, rs.Prefix)
	if !ok || !isBelow || below == "" || dotted(below) {
		return transcriptRoot{}, nil
	}
	var bind string
	if place, ok := strings.CutPrefix(rs.Prefix, "/"); ok {
		place = strings.TrimSuffix(place, "/")
		if place == "" || dotted(place) {
			return transcriptRoot{}, nil
		}
		place = "/" + place
		at, err := inMount(rs.Prefix, place, mounts)
		if err != nil {
			return transcriptRoot{}, err
		}
		if at != nil {
			return *at, nil
		}
		bind = place
	} else {
		bind = strings.TrimSuffix(strings.TrimPrefix(rs.Prefix, "~/"), "/")
		if bind == "" || path.Clean(bind) != bind || path.IsAbs(bind) || dotted(bind) {
			return transcriptRoot{}, nil
		}
	}
	parent := filepath.Join(runDir, transcriptsDir)
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return transcriptRoot{}, accesskey.ShownError(err)
	}
	if fi, err := os.Lstat(parent); err != nil || !fi.IsDir() {
		return transcriptRoot{}, fmt.Errorf("the transcript directories %s are no directory of the run's", pathShown(parent))
	}
	dir := filepath.Join(parent, strconv.Itoa(n))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return transcriptRoot{}, accesskey.ShownError(err)
	}
	if err := checkTranscriptDir(dir, runDir, workspace, binds); err != nil {
		return transcriptRoot{}, err
	}
	return transcriptRoot{dir: dir, bind: bind}, nil
}

// inMount is where the session reads the transcript of a runtime whose resume.prefix
// is the absolute place, clean, with no last /, when one of mounts is shown at it or
// around it: below the path on this machine of the innermost one that holds it, when it
// is writable, and unbound when it is read-only. It is nil when none holds it, and an
// error when a mount's place lies inside it: the wall would bind the transcript
// directory over that mount.
func inMount(prefix, place string, mounts []wall.Mount) (*transcriptRoot, error) {
	var holder *wall.Mount
	for i, m := range mounts {
		at := placeInside(m)
		switch {
		case at != place && under(place, at):
			return nil, fmt.Errorf("Show the mount %s outside resume.prefix %s, or at a place that contains it: "+
				"the session reads the runtime's transcript below resume.prefix, and the mount is shown at %s, "+
				"inside it", pathShown(m.Path), pathShown(prefix), pathShown(at))
		case under(at, place) && (holder == nil || len(parts(at)) > len(parts(placeInside(*holder)))):
			holder = &mounts[i]
		}
	}
	if holder == nil {
		return nil, nil
	}
	at := placeInside(*holder)
	if holder.ReadOnly {
		return &transcriptRoot{unbound: &wall.Unbound{
			Fix: "Show resume.prefix in a writable mount, or use a descriptor whose resume.prefix lies outside read-only mounts",
			Cause: fmt.Sprintf("resume.prefix %s lies inside the mount %s, shown at %s, read-only, so the runtime "+
				"cannot write its transcript there", pathShown(prefix), pathShown(holder.Path), pathShown(at)),
		}}, nil
	}
	rel, err := filepath.Rel(at, place)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		rel = ""
	}
	return &transcriptRoot{dir: holder.Path, under: rel}, nil
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
