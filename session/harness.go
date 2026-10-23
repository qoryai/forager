package session

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/mask"
)

// The limits of the files a session reads from a hidden harness's home: at most
// HarnessMaxFiles regular files, each of at most HarnessMaxFileSize bytes, and at most
// HarnessMaxSize bytes in all. A home over a limit fails the join, with the path of
// the file that is over it.
const (
	HarnessMaxFiles    = 10000
	HarnessMaxFileSize = 1 << 20
	HarnessMaxSize     = 16 << 20
)

// harnessLinkText is the error, and the report line, of a link in a hidden harness's
// home, rel its path relative to the home.
func harnessLinkText(rel string) string {
	return "Replace the link " + accesskey.ShownValue(rel, false) + " in the harness home with a copy; the mask reads only files there."
}

// readHarness is the masker of the harness files under home, read once, as the session
// starts, through an os.Root of home, so no name leads out of it: every regular file,
// by its path relative to home. A link anywhere under home is an error, and report
// gets a line with the same text: a link to a file or a directory, inside the home or
// out of it, or to nothing. A file that contains a zero byte is binary: it is skipped,
// and report gets a line for it. An error means as well that the home, one of its
// directories or one of its files cannot be read, that a file changed between the walk
// and its read, or that the home is over a limit; its text starts with the fix.
func readHarness(home string, report func(string)) (*mask.Harness, error) {
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, fmt.Errorf("give the session a harness home it can read: the run masks the harness's text, and reading the home failed: %w", accesskey.ShownError(err))
	}
	defer root.Close()
	var files []mask.HarnessFile
	count, total := 0, 0
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		shown := accesskey.ShownValue(rel, false)
		switch {
		case err != nil && rel == ".":
			return fmt.Errorf("give the session a harness home it can read: the run masks the harness's text, and reading the home failed: %w", accesskey.ShownError(err))
		case err != nil:
			return fmt.Errorf("make each directory of the harness home readable: reading %s failed: %w", shown, accesskey.ShownError(err))
		case d.Type()&fs.ModeSymlink != 0:
			text := harnessLinkText(rel)
			report(text)
			return errors.New(text)
		case !d.Type().IsRegular():
			return nil
		}
		if count++; count > HarnessMaxFiles {
			return fmt.Errorf("make the harness home at most %d files: %s is file %d", HarnessMaxFiles, shown, count)
		}
		text, err := readHarnessFile(root, rel, report)
		switch {
		case err != nil:
			return err
		case bytes.IndexByte(text, 0) >= 0:
			report(fmt.Sprintf("the text of the harness file %s is not masked: it contains a zero byte", shown))
		case total+len(text) > HarnessMaxSize:
			return fmt.Errorf("make the harness files at most %d bytes in all: with %s they have %d", HarnessMaxSize, shown, total+len(text))
		default:
			total += len(text)
			files = append(files, mask.HarnessFile{Path: rel, Text: text})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mask.ForHarness(files), nil
}

// readHarnessFile is the text of the regular file rel of root, opened without waiting
// on a file that is not regular. The error of a file that cannot be read, that has
// more than HarnessMaxFileSize bytes, whose name is a link once it is open, or that is
// no longer the regular file the name leads to, starts with the fix; for a link,
// report gets a line with the same text.
func readHarnessFile(root *os.Root, rel string, report func(string)) ([]byte, error) {
	shown := accesskey.ShownValue(rel, false)
	unreadable := func(err error) error {
		return fmt.Errorf("make each harness file readable: reading %s failed: %w", shown, accesskey.ShownError(err))
	}
	link := func() error {
		text := harnessLinkText(rel)
		report(text)
		return errors.New(text)
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if named, lerr := root.Lstat(rel); lerr == nil && named.Mode()&fs.ModeSymlink != 0 {
			return nil, link()
		}
		return nil, unreadable(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, unreadable(err)
	}
	// An os.Root follows a link that stays in it: the name must still be the regular
	// file that is open.
	named, err := root.Lstat(rel)
	switch {
	case err != nil:
		return nil, unreadable(err)
	case named.Mode()&fs.ModeSymlink != 0:
		return nil, link()
	case !info.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(info, named):
		return nil, fmt.Errorf("keep the harness home unchanged while the session starts: %s changed while it was read", shown)
	case info.Size() > HarnessMaxFileSize:
		return nil, fmt.Errorf("make each harness file at most %d bytes: %s has %d", HarnessMaxFileSize, shown, info.Size())
	}
	text, err := io.ReadAll(io.LimitReader(f, HarnessMaxFileSize+1))
	switch {
	case err != nil:
		return nil, unreadable(err)
	case len(text) > HarnessMaxFileSize:
		return nil, fmt.Errorf("make each harness file at most %d bytes: %s has more", HarnessMaxFileSize, shown)
	}
	return text, nil
}
