// Package program finds where a program Forager starts lives on this machine: the
// directories a mount must leave out, so the agent cannot change what runs outside the
// wall.
package program

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// Dirs are the directories of the program a command names, found as exec finds it: a
// name with a separator is a path, relative to the working directory; a bare name is
// looked up in PATH. When the program's file is a symbolic link, the directory of the
// file it leads to is one more, since the program that runs is there. A bare name PATH
// does not hold has none: nothing on this machine runs under it.
func Dirs(command string) []string {
	if command == "" {
		return nil
	}
	path := command
	if !strings.ContainsRune(command, filepath.Separator) {
		found, err := exec.LookPath(command)
		if err != nil {
			return nil
		}
		path = found
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	dirs := []string{filepath.Dir(abs)}
	if target, err := filepath.EvalSymlinks(abs); err == nil {
		if d := filepath.Dir(target); d != dirs[0] {
			dirs = append(dirs, d)
		}
	}
	return dirs
}
