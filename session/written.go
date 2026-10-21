package session

import (
	"fmt"
	"path/filepath"
	"slices"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/hostfile"
	"github.com/qoryai/forager/session/runtimes"
)

// writtenPlaces are the places a walled run could have written, as SessionSpec.Written lists
// them, the writable binds of the other walled runs in the registry and, behind a wall,
// the run's writable binds: the places of the plan the enclosure binds writable, the
// workspace among them, and the wall's writable binds.
func writtenPlaces(spec runSpec, runID string, plan mountPlan, own []bindSource) ([]string, error) {
	others, err := othersWritable(runID)
	if err != nil {
		return nil, err
	}
	places := slices.Concat(spec.Written, others)
	if spec.Wall == nil {
		return places, nil
	}
	for _, b := range slices.Concat(plan.sources, own) {
		if b.Writable {
			places = append(places, b.Path)
		}
	}
	return places, nil
}

// readable is what [runtimes.Attach.Readable] asks of a file before the runtime reads
// it from this machine: where its path resolves through every link when no place holds
// it, and why not otherwise. The places are worked out once, on the first call, so a
// run that reads no file reads nothing for them. A path with a ".." name is refused
// first: the system applies ".." after the link before it, so the path made clean,
// which the check judges, would name another file than the one opened; without one the
// clean path is the path the runtime opens. A place holds a path when the path,
// absolute and clean or resolved through every link, is the place or lies inside it,
// the place taken as given and resolved, by whole names and regardless of case, as
// [Overlap] compares them, and when a name on the way to the path is looked up inside
// it: a link there leads where a walled run points it. A path or a place that cannot
// be resolved is refused, so a file is never taken for one it may not be.
func readable(places func() ([]string, error)) func(string) (string, error) {
	once := sync.OnceValues(places)
	return func(path string) (string, error) {
		if hostfile.DotDot(path) {
			return "", hostfile.ErrDotDot
		}
		at, err := split(path, 0)
		if err != nil {
			return "", fmt.Errorf("cannot resolve it: %w", accesskey.ShownError(err))
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("cannot resolve it: %w", accesskey.ShownError(err))
		}
		looks, err := lookups(path)
		if err != nil {
			return "", fmt.Errorf("cannot resolve it: %w", accesskey.ShownError(err))
		}
		all, err := once()
		if err != nil {
			return "", err
		}
		forms := [][]string{parts(abs), parts(at.String())}
		for _, p := range all {
			in, err := split(p, 0)
			if err != nil {
				return "", fmt.Errorf("cannot resolve the place %s: %w", pathShown(p), accesskey.ShownError(err))
			}
			given, err := filepath.Abs(p)
			if err != nil {
				return "", fmt.Errorf("cannot resolve the place %s: %w", pathShown(p), accesskey.ShownError(err))
			}
			ok, _ := holds(in, at)
			for _, place := range [][]string{parts(given), parts(in.String())} {
				for _, names := range forms {
					ok = ok || namesWithin(place, names)
				}
			}
			if ok {
				return "", &runtimes.WrittenError{How: "lies in", Place: pathShown(p)}
			}
			if _, through := lookedUpIn(in, looks); through {
				return "", &runtimes.WrittenError{How: "is reached through", Place: pathShown(p)}
			}
		}
		return at.String(), nil
	}
}

// readableDir is what [runtimes.Attach.ReadableDir] asks of a directory before the
// runtime passes it to the program: what [readable] asks, and then that no place lies
// inside it. A directory holds a place when the place, absolute and clean or resolved
// through every link, is the directory or lies inside it, the directory taken as given
// and resolved, by whole names and regardless of case. A place that cannot be resolved
// is refused.
func readableDir(places func() ([]string, error)) func(string) (string, error) {
	once := sync.OnceValues(places)
	file := readable(once)
	return func(path string) (string, error) {
		resolved, err := file(path)
		if err != nil {
			return "", err
		}
		at, err := split(path, 0)
		if err != nil {
			return "", fmt.Errorf("cannot resolve it: %w", accesskey.ShownError(err))
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("cannot resolve it: %w", accesskey.ShownError(err))
		}
		all, err := once()
		if err != nil {
			return "", err
		}
		forms := [][]string{parts(abs), parts(at.String())}
		for _, p := range all {
			in, err := split(p, 0)
			if err != nil {
				return "", fmt.Errorf("cannot resolve the place %s: %w", pathShown(p), accesskey.ShownError(err))
			}
			given, err := filepath.Abs(p)
			if err != nil {
				return "", fmt.Errorf("cannot resolve the place %s: %w", pathShown(p), accesskey.ShownError(err))
			}
			ok, _ := holds(at, in)
			for _, place := range [][]string{parts(given), parts(in.String())} {
				for _, names := range forms {
					ok = ok || namesWithin(names, place)
				}
			}
			if ok {
				return "", &runtimes.WrittenError{How: "contains", Place: pathShown(p)}
			}
		}
		return resolved, nil
	}
}

// namesWithin reports whether the names of a path begin with the names of a place, each
// as [sameName] compares them.
func namesWithin(place, names []string) bool {
	if len(place) > len(names) {
		return false
	}
	for i, n := range place {
		if !sameName(n, names[i]) {
			return false
		}
	}
	return true
}
