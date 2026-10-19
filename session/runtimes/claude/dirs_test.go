package claude_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// readableDir is the fake's ReadableDir: what its Readable refuses, and a directory
// that holds the written place.
func (f *fakeWritten) readableDir(p string) (string, error) {
	resolved, err := f.readable(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(f.written)
	if err != nil {
		real = f.written
	}
	for _, dir := range []string{p, resolved} {
		for _, place := range []string{f.written, real} {
			if strings.HasPrefix(place, strings.TrimSuffix(dir, "/")+"/") {
				return "", &runtimes.WrittenError{How: "contains", Place: f.written}
			}
		}
	}
	return resolved, nil
}

// walledDirs prepares a walled launch of args with the fake's Readable and ReadableDir,
// and inside as the Attach's Inside.
func walledDirs(t *testing.T, f *fakeWritten, inside func(string) string, args []string) (runtimes.Launch, error) {
	t.Helper()
	return claude.Settings([]string{"Stop"}, runtimes.Attach{
		Launch: runtimes.Launch{Command: "claude", Args: args}, RunDir: t.TempDir(), Forwarder: []string{"q"},
		Walled: true, Readable: f.readable, ReadableDir: f.readableDir, Inside: inside,
	})
}

// plugin makes a plugin directory under dir with a manifest, a skill and an agent.
func plugin(t *testing.T, dir string) string {
	t.Helper()
	writeFile(t, filepath.Join(dir, ".claude-plugin", "plugin.json"), `{"name":"p"}`)
	writeFile(t, filepath.Join(dir, "skills", "s", "SKILL.md"), "# s")
	writeFile(t, filepath.Join(dir, "agents", "a.md"), "# a")
	return dir
}

// TestAWalledLaunchsPluginDirIsChecked pins the check of a --plugin-dir or
// --plugin-dir-no-mcp value: the directory may not lie in or contain a place a walled
// run can write, no link under it may lead into one, no file under it may have more
// than one name, it may have at most 10,000 entries, and a .zip is checked as a file.
// A plugin that passes is passed as it is.
func TestAWalledLaunchsPluginDirIsChecked(t *testing.T) {
	for _, flag := range []string{"--plugin-dir", "--plugin-dir-no-mcp"} {
		t.Run(flag, func(t *testing.T) {
			fix := "Move the plugin to a directory no walled run writes."
			for name, c := range map[string]struct {
				make func(t *testing.T, home, work string) string
				want func(home, work string) string
			}{
				"a plugin that passes": {
					make: func(t *testing.T, home, work string) string { return plugin(t, filepath.Join(home, "p")) },
				},
				"a directory that contains the place": {
					make: func(t *testing.T, home, work string) string { return home },
					want: func(home, work string) string {
						return "This launch passes " + flag + " " + home + ", and that directory contains " + work +
							", which a walled run can write, so the run does not start. " + fix
					},
				},
				"a directory in the place": {
					make: func(t *testing.T, _, work string) string { return plugin(t, filepath.Join(work, "p")) },
					want: func(_, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(work, "p") + ", and that directory lies in " + work +
							", which a walled run can write, so the run does not start. " + fix
					},
				},
				"a link into the place": {
					make: func(t *testing.T, home, work string) string {
						p := plugin(t, filepath.Join(home, "p"))
						writeFile(t, filepath.Join(work, "x", "SKILL.md"), "# x")
						symlink(t, filepath.Join(work, "x"), filepath.Join(p, "skills", "x"))
						return p
					},
					want: func(home, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(home, "p") + ", and its link " +
							filepath.Join(home, "p", "skills", "x") + " leads into " + work + ", which a walled run can write, " +
							"so the run does not start. Replace the link with a copy, or move what it leads to out of " + work + "."
					},
				},
				"a link to a directory that holds a link into the place": {
					make: func(t *testing.T, home, work string) string {
						p := plugin(t, filepath.Join(home, "p"))
						module := filepath.Join(home, "cache", "skill")
						writeFile(t, filepath.Join(work, "SKILL.md"), "# x")
						if err := os.MkdirAll(module, 0o755); err != nil {
							t.Fatal(err)
						}
						symlink(t, filepath.Join(work, "SKILL.md"), filepath.Join(module, "SKILL.md"))
						symlink(t, module, filepath.Join(p, "skills", "y"))
						return p
					},
					want: func(home, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(home, "p") + ", and its link " +
							filepath.Join(home, "p", "skills", "y", "SKILL.md") + " leads into " + work + ", which a walled run can write, " +
							"so the run does not start. Replace the link with a copy, or move what it leads to out of " + work + "."
					},
				},
				"a link to a directory outside the place": {
					make: func(t *testing.T, home, work string) string {
						p := plugin(t, filepath.Join(home, "p"))
						writeFile(t, filepath.Join(home, "cache", "skill", "SKILL.md"), "# y")
						symlink(t, filepath.Join(home, "cache", "skill"), filepath.Join(p, "skills", "y"))
						symlink(t, p, filepath.Join(p, "skills", "loop"))
						return p
					},
				},
				"a file with a second name": {
					make: func(t *testing.T, home, work string) string {
						p := plugin(t, filepath.Join(home, "p"))
						if err := os.Link(filepath.Join(p, "agents", "a.md"), filepath.Join(home, "a.md")); err != nil {
							t.Fatal(err)
						}
						return p
					},
					want: func(home, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(home, "p") + ", and " +
							filepath.Join(home, "p", "agents", "a.md") + " has more than one hard link, so a walled run could change it " +
							"under another name, and the run does not start. Replace the file with a copy that has one name."
					},
				},
				"a link to a file with a second name": {
					make: func(t *testing.T, home, work string) string {
						p := plugin(t, filepath.Join(home, "p"))
						cmd := writeFile(t, filepath.Join(home, "cache", "c.md"), "# c")
						if err := os.Link(cmd, filepath.Join(home, "c2.md")); err != nil {
							t.Fatal(err)
						}
						symlink(t, cmd, filepath.Join(p, "c.md"))
						return p
					},
					want: func(home, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(home, "p") + ", and " +
							filepath.Join(home, "p", "c.md") + " has more than one hard link, so a walled run could change it " +
							"under another name, and the run does not start. Replace the file with a copy that has one name."
					},
				},
				"10,000 entries": {
					make: func(t *testing.T, home, work string) string { return entries(t, filepath.Join(home, "p"), 10_000) },
				},
				"10,001 entries": {
					make: func(t *testing.T, home, work string) string { return entries(t, filepath.Join(home, "p"), 10_001) },
					want: func(home, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(home, "p") + ", which has more than 10,000 entries, " +
							"the most Forager checks, so the run does not start. Pass a smaller plugin directory."
					},
				},
				"a .zip": {
					make: func(t *testing.T, home, work string) string { return writeFile(t, filepath.Join(home, "p.zip"), "PK") },
				},
				"a .zip in the place": {
					make: func(t *testing.T, _, work string) string { return writeFile(t, filepath.Join(work, "p.zip"), "PK") },
					want: func(_, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(work, "p.zip") + ", and that file lies in " + work +
							", which a walled run can write, so the run does not start. " + fix
					},
				},
				"a .zip that is a link": {
					make: func(t *testing.T, home, work string) string {
						zip := writeFile(t, filepath.Join(home, "p.zip"), "PK")
						symlink(t, zip, filepath.Join(home, "link.zip"))
						return filepath.Join(home, "link.zip")
					},
					want: func(home, work string) string {
						return "This launch passes " + flag + " " + filepath.Join(home, "link.zip") + ", and that file is a link, so the run does not start."
					},
				},
			} {
				t.Run(name, func(t *testing.T) {
					// The written place lies in home, which the plugin directory is
					// made in.
					home := t.TempDir()
					work := mkdir(t, filepath.Join(home, "work"))
					f := &fakeWritten{written: work}
					value := c.make(t, home, work)
					args := []string{"-p", "hi", flag, value}
					got, err := walledDirs(t, f, nil, args)
					if c.want == nil {
						if err != nil || !slices.Equal(got.Args[:len(args)], args) {
							t.Fatalf("launch %q, %v", got.Args, err)
						}
						return
					}
					if want := c.want(home, work); err == nil || err.Error() != want {
						t.Errorf("got %v, want %q", err, want)
					}
				})
			}
		})
	}
}

// entries makes a directory under which there are n entries: files, ten to a
// directory, the directories counted.
func entries(t *testing.T, dir string, n int) string {
	t.Helper()
	made := 0
	for d := 0; made < n; d++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%04d", d))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		made++
		for i := 0; i < 9 && made < n; i++ {
			if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			made++
		}
	}
	return dir
}

// TestAWalledLaunchsPluginLinkIntoTheWorkspaceInsideIsRefused pins that, for a run
// whose workspace is at /workspace inside, a link under a plugin directory that leads
// to /workspace, directly, through another link or after a name that does not exist
// here, is refused, though no such path is a place of this machine's; and that a link
// that cannot be followed is refused with the reason.
func TestAWalledLaunchsPluginLinkIntoTheWorkspaceInsideIsRefused(t *testing.T) {
	inside := func(s string) string { return s }
	for name, c := range map[string]struct {
		to  func(home string) string
		hop string
	}{
		"a link to /workspace":            {to: func(string) string { return "/workspace" }},
		"a link below /workspace":         {to: func(string) string { return "/workspace/skills/x" }},
		"a link past a name that is none": {to: func(string) string { return "/absent/../workspace/x" }},
		"a link through another link": {
			to:  func(home string) string { return filepath.Join(home, "hop") },
			hop: "/workspace/y",
		},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			p := plugin(t, filepath.Join(home, "p"))
			if c.hop != "" {
				// hop lies outside the plugin directory, so the scan meets it only
				// through x.
				symlink(t, c.hop, filepath.Join(home, "hop"))
			}
			symlink(t, c.to(home), filepath.Join(p, "skills", "x"))
			_, err := walledDirs(t, &fakeWritten{written: t.TempDir()}, inside, []string{"--plugin-dir", p})
			want := "This launch passes --plugin-dir " + p + ", and its link " + filepath.Join(p, "skills", "x") +
				" leads into /workspace, which a walled run can write, so the run does not start. " +
				"Replace the link with a copy, or move what it leads to out of /workspace."
			if err == nil || err.Error() != want {
				t.Errorf("got %v, want %q", err, want)
			}
		})
	}
	t.Run("a link loop", func(t *testing.T) {
		home := t.TempDir()
		p := plugin(t, filepath.Join(home, "p"))
		symlink(t, filepath.Join(home, "b"), filepath.Join(home, "a"))
		symlink(t, filepath.Join(home, "a"), filepath.Join(home, "b"))
		symlink(t, filepath.Join(home, "a"), filepath.Join(p, "skills", "x"))
		_, err := walledDirs(t, &fakeWritten{written: t.TempDir()}, inside, []string{"--plugin-dir", p})
		want := "--plugin-dir " + p + ": " + filepath.Join(p, "skills", "x") + ": too many links"
		if err == nil || err.Error() != want {
			t.Errorf("got %v, want %q", err, want)
		}
	})
	t.Run("a value that is a link loop", func(t *testing.T) {
		home := t.TempDir()
		symlink(t, filepath.Join(home, "b"), filepath.Join(home, "a"))
		symlink(t, filepath.Join(home, "a"), filepath.Join(home, "b"))
		value := filepath.Join(home, "a")
		_, err := walledDirs(t, &fakeWritten{written: t.TempDir()}, inside, []string{"--plugin-dir", value})
		if want := "--plugin-dir " + value + ": too many links"; err == nil || err.Error() != want {
			t.Errorf("got %v, want %q", err, want)
		}
	})
	t.Run("without Inside", func(t *testing.T) {
		home := t.TempDir()
		p := plugin(t, filepath.Join(home, "p"))
		symlink(t, "/workspace/skills/x", filepath.Join(p, "skills", "x"))
		if _, err := walledDirs(t, &fakeWritten{written: t.TempDir()}, nil, []string{"--plugin-dir", p}); err != nil {
			t.Errorf("refused: %v", err)
		}
	})
}

// TestAWalledLaunchsValueInTheWorkspaceInsideIsRefused pins that, for a run whose
// workspace is at /workspace inside, a value of --plugin-dir, --plugin-dir-no-mcp or
// --add-dir whose path reaches /workspace, as written or through a link of this
// machine's, is refused before Forager checks the path here: the enclosure reads it
// from the workspace. A .zip is a file in the text.
func TestAWalledLaunchsValueInTheWorkspaceInsideIsRefused(t *testing.T) {
	inside := func(s string) string { return s }
	home := t.TempDir()
	symlink(t, "/workspace/plug", filepath.Join(home, "plug"))
	symlink(t, "/workspace/p.zip", filepath.Join(home, "w.zip"))
	plugins := "Move the plugin to a directory no walled run writes."
	for _, flag := range []string{"--plugin-dir", "--plugin-dir-no-mcp", "--add-dir"} {
		for value, what := range map[string]string{
			"/workspace/plug":            "directory",
			"/workspace":                 "directory",
			filepath.Join(home, "plug"):  "directory",
			"/workspace/p.zip":           "file",
			filepath.Join(home, "w.zip"): "file",
		} {
			t.Run(flag+" "+value, func(t *testing.T) {
				fix := plugins
				if flag == "--add-dir" {
					fix = "Remove --add-dir " + value + ", or add a directory no walled run writes."
				}
				want := "This launch passes " + flag + " " + value + ", and that " + what + " lies in /workspace, " +
					"which a walled run can write, so the run does not start. " + fix
				_, err := walledDirs(t, &fakeWritten{written: t.TempDir()}, inside, []string{flag, value})
				if err == nil || err.Error() != want {
					t.Errorf("got %v, want %q", err, want)
				}
			})
		}
	}
	t.Run("a .zip outside /workspace", func(t *testing.T) {
		zip := writeFile(t, filepath.Join(home, "p.zip"), "PK")
		if _, err := walledDirs(t, &fakeWritten{written: t.TempDir()}, inside, []string{"--plugin-dir", zip}); err != nil {
			t.Errorf("refused: %v", err)
		}
	})
}

// TestAWalledLaunchsPluginLinkTextSaysWhereItLeads pins the text of a link that leads
// to a directory that contains a place a walled run can write, and of one whose path
// goes through such a place.
func TestAWalledLaunchsPluginLinkTextSaysWhereItLeads(t *testing.T) {
	home := t.TempDir()
	p := plugin(t, filepath.Join(home, "p"))
	other := mkdir(t, filepath.Join(home, "other"))
	work := mkdir(t, filepath.Join(other, "work"))
	symlink(t, other, filepath.Join(p, "skills", "x"))
	_, err := walledDirs(t, &fakeWritten{written: work}, nil, []string{"--plugin-dir", p})
	target, _ := filepath.EvalSymlinks(other)
	want := "This launch passes --plugin-dir " + p + ", and its link " + filepath.Join(p, "skills", "x") + " leads to " + target +
		", and " + target + " contains " + work + ", which a walled run can write, so the run does not start. " +
		"Replace the link with a copy, or link to a directory that contains no place a walled run writes."
	if err == nil || err.Error() != want {
		t.Errorf("contains: got %v, want %q", err, want)
	}

	q := plugin(t, filepath.Join(home, "q"))
	symlink(t, filepath.Join(home, "elsewhere"), filepath.Join(q, "skills", "y"))
	through := func(path string) (string, error) {
		if strings.HasSuffix(path, "/skills/y") {
			return "", &runtimes.WrittenError{How: "is reached through", Place: "/work"}
		}
		return filepath.EvalSymlinks(path)
	}
	_, err = claude.Settings([]string{"Stop"}, runtimes.Attach{
		Launch: runtimes.Launch{Args: []string{"--plugin-dir", q}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
		Walled: true, Readable: through, ReadableDir: through,
	})
	want = "This launch passes --plugin-dir " + q + ", and its link " + filepath.Join(q, "skills", "y") + " leads through /work, " +
		"which a walled run can write, so the run does not start. Replace the link with a copy, or point it at a path that " +
		"does not go through /work."
	if err == nil || err.Error() != want {
		t.Errorf("reached through: got %v, want %q", err, want)
	}
}

// TestAWalledLaunchsPluginDirectoriesAreReadOnce pins that a directory of the plugin
// reached again through a link is not read and counted again: a plugin whose entries
// are within 10,000 only when each directory is read once passes.
func TestAWalledLaunchsPluginDirectoriesAreReadOnce(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p")
	entries(t, filepath.Join(p, "big"), 9_000)
	symlink(t, filepath.Join(p, "big"), filepath.Join(p, "alias"))
	symlink(t, filepath.Join(p, "big", "d0001"), filepath.Join(p, "big", "d0000", "sub"))
	if _, err := walledDirs(t, &fakeWritten{written: t.TempDir()}, nil, []string{"--plugin-dir", p}); err != nil {
		t.Errorf("refused: %v", err)
	}
}

// TestAWalledLaunchsAddDirIsChecked pins the check of an --add-dir value: the
// directory as --plugin-dir's is checked, with the entries read only under .claude and
// at CLAUDE.md, in every form the flag takes.
func TestAWalledLaunchsAddDirIsChecked(t *testing.T) {
	work := t.TempDir()
	linked := func(t *testing.T, ref, at string) string {
		writeFile(t, filepath.Join(work, "settings.json"), "{}")
		if err := os.MkdirAll(filepath.Dir(filepath.Join(ref, at)), 0o755); err != nil {
			t.Fatal(err)
		}
		symlink(t, filepath.Join(work, "settings.json"), filepath.Join(ref, at))
		return ref
	}
	linkText := func(ref, at string) string {
		return "This launch passes --add-dir " + ref + ", and its link " + filepath.Join(ref, at) + " leads into " + work +
			", which a walled run can write, so the run does not start. Replace the link with a copy, or move what it leads to out of " + work + "."
	}
	for name, c := range map[string]struct {
		make func(t *testing.T, ref string) string
		want func(ref string) string
	}{
		"a directory that passes": {make: func(t *testing.T, ref string) string {
			writeFile(t, filepath.Join(ref, ".claude", "settings.json"), "{}")
			return ref
		}},
		"a .claude/settings.json link into the place": {
			make: func(t *testing.T, ref string) string { return linked(t, ref, ".claude/settings.json") },
			want: func(ref string) string { return linkText(ref, ".claude/settings.json") },
		},
		"a .claude link into the place": {
			make: func(t *testing.T, ref string) string {
				symlink(t, work, filepath.Join(ref, ".claude"))
				return ref
			},
			want: func(ref string) string { return linkText(ref, ".claude") },
		},
		"a CLAUDE.md link into the place": {
			make: func(t *testing.T, ref string) string { return linked(t, ref, "CLAUDE.md") },
			want: func(ref string) string { return linkText(ref, "CLAUDE.md") },
		},
		"a .claude link back to the directory": {
			make: func(t *testing.T, ref string) string {
				symlink(t, ref, filepath.Join(ref, ".claude"))
				return linked(t, ref, "settings.json")
			},
			want: func(ref string) string { return linkText(ref, ".claude/settings.json") },
		},
		"a link under .claude back to the directory": {
			make: func(t *testing.T, ref string) string {
				mkdir(t, filepath.Join(ref, ".claude"))
				symlink(t, ref, filepath.Join(ref, ".claude", "skills"))
				return linked(t, ref, "evil/SKILL.md")
			},
			want: func(ref string) string { return linkText(ref, ".claude/skills/evil/SKILL.md") },
		},
		"a link into the place outside .claude": {
			make: func(t *testing.T, ref string) string { return linked(t, ref, "src/settings.json") },
		},
		"a directory in the place": {
			make: func(t *testing.T, _ string) string { return mkdir(t, filepath.Join(work, "ref")) },
			want: func(string) string {
				return "This launch passes --add-dir " + filepath.Join(work, "ref") + ", and that directory lies in " + work +
					", which a walled run can write, so the run does not start. Remove --add-dir " + filepath.Join(work, "ref") +
					", or add a directory no walled run writes."
			},
		},
	} {
		for _, form := range []string{"space", "=", "several", "twice"} {
			t.Run(name+", "+form, func(t *testing.T) {
				ref := c.make(t, t.TempDir())
				other := t.TempDir()
				args := map[string][]string{
					"space":   {"--add-dir", ref},
					"=":       {"--add-dir=" + ref},
					"several": {"--add-dir", other, ref, "-p", "hi"},
					"twice":   {"--add-dir", other, "--add-dir", ref},
				}[form]
				got, err := walledDirs(t, &fakeWritten{written: work}, nil, args)
				if c.want == nil {
					if err != nil || !slices.Equal(got.Args[:len(args)], args) {
						t.Fatalf("launch %q, %v", got.Args, err)
					}
					return
				}
				if want := c.want(ref); err == nil || err.Error() != want {
					t.Errorf("got %v, want %q", err, want)
				}
			})
		}
	}
	for value, want := range map[string]string{
		"~/ref": "This launch passes --add-dir ~/ref, and inside the wall ~ is the home of the wall's user, " +
			"which Forager cannot check, so the run does not start. Pass an absolute path.",
		"ref": "This launch passes --add-dir ref, a relative path that Claude Code reads from the workspace, " +
			"which a walled run can write, so the run does not start. Pass an absolute path outside the workspace.",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := walledDirs(t, &fakeWritten{written: work}, nil, []string{"--add-dir", value}); err == nil || err.Error() != want {
				t.Errorf("got %v, want %q", err, want)
			}
		})
	}
}

// mkdir makes the directory and returns it.
func mkdir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// symlink makes a symbolic link at at to to.
func symlink(t *testing.T, to, at string) {
	t.Helper()
	if err := os.Symlink(to, at); err != nil {
		t.Fatal(err)
	}
}
