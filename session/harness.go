package session

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/mask"
)

// The limits of the files a session reads from a hidden harness's home: at most
// HarnessMaxFiles regular files, each of at most HarnessMaxFileSize bytes, and at most
// HarnessMaxSize bytes in all. A file over a limit is not read, and its text is not
// masked: each is a report line.
const (
	HarnessMaxFiles    = 10000
	HarnessMaxFileSize = 1 << 20
	HarnessMaxSize     = 16 << 20
)

// readHarness is the masker of the harness files under home, read once, as the session
// starts: every regular file, by its path relative to home, apart from a file that
// contains a zero byte, which is binary. A link is not followed, so no file outside
// home is read; a file a link inside home points to is read at its path when it lies
// in home. A file over a limit, or that cannot be read, is left out, and report gets a
// line for it. An error means home itself cannot be read.
func readHarness(home string, report func(string)) (*mask.Harness, error) {
	root, err := filepath.EvalSymlinks(home)
	if err == nil {
		var info os.FileInfo
		if info, err = os.Stat(root); err == nil && !info.IsDir() {
			err = fmt.Errorf("%s is not a directory", accesskey.ShownValue(home, true))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("give the session a harness home it can read: the run masks the harness's text, and reading the home failed: %w", accesskey.ShownError(err))
	}
	var files []mask.HarnessFile
	seen, total := 0, 0
	skip := func(rel, why string) {
		report(fmt.Sprintf("the text of the harness file %s is not masked: %s", accesskey.ShownValue(rel, false), why))
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if err != nil {
			if p == root {
				return err
			}
			skip(rel, "reading it failed: "+accesskey.ShownError(err).Error())
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if seen++; seen > HarnessMaxFiles {
			skip(rel, fmt.Sprintf("the home has more than %d files, and the files after this one are not read either", HarnessMaxFiles))
			return filepath.SkipAll
		}
		text, why := readHarnessFile(p)
		switch {
		case why != "":
			skip(rel, why)
		case text == nil:
		case total+len(text) > HarnessMaxSize:
			skip(rel, fmt.Sprintf("the files before it have %d bytes, and this file would bring them over %d", total, HarnessMaxSize))
		default:
			total += len(text)
			files = append(files, mask.HarnessFile{Path: rel, Text: text})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("give the session a harness home it can read: the run masks the harness's text, and reading the home failed: %w", accesskey.ShownError(err))
	}
	return mask.ForHarness(files), nil
}

// readHarnessFile is the text of the file at p, opened without following a link, or
// nil for a file that is not regular once opened, or that contains a zero byte; why is
// why it is not read, empty when it is.
func readHarnessFile(p string) (text []byte, why string) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "reading it failed: " + accesskey.ShownError(err).Error()
	}
	defer f.Close()
	info, err := f.Stat()
	switch {
	case err != nil:
		return nil, "reading it failed: " + accesskey.ShownError(err).Error()
	case !info.Mode().IsRegular():
		return nil, ""
	case info.Size() > HarnessMaxFileSize:
		return nil, fmt.Sprintf("it has more than %d bytes", HarnessMaxFileSize)
	}
	text, err = io.ReadAll(io.LimitReader(f, HarnessMaxFileSize+1))
	switch {
	case err != nil:
		return nil, "reading it failed: " + accesskey.ShownError(err).Error()
	case len(text) > HarnessMaxFileSize:
		return nil, fmt.Sprintf("it has more than %d bytes", HarnessMaxFileSize)
	case bytes.IndexByte(text, 0) >= 0:
		return nil, ""
	}
	return text, ""
}
