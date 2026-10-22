package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/internal/chunk"
)

// skillText is the text of an example harness file, skills/implement/SKILL.md, and
// skillPut its replacement.
const (
	skillText = `# Implement

1. Read the work item and list each thing to build.
2. Write a test for each item on the list.
3. Change the code until every test passes.
4. Run the checks the workspace defines.
`
	skillPut = "[harness text: skills/implement/SKILL.md]"
)

// writeHome writes files, by their paths relative to the home, into a temporary
// directory, and returns the directory.
func writeHome(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	for p, text := range files {
		f := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// readHome is readHarness of home, and its report lines.
func readHome(t *testing.T, home string) (*mask.Harness, []string) {
	t.Helper()
	var lines []string
	h, err := readHarness(home, func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatal(err)
	}
	return h, lines
}

// TestTheHarnessFilesAreReadOnce pins what readHarness reads: each regular file by
// its path relative to the home, the files as they were when it read them, and no file
// through a link, inside the home or out of it. A file with a zero byte is not read,
// which is a report line.
func TestTheHarnessFilesAreReadOnce(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.md")
	outsideText := "Outside line one of the notes.\nOutside line two of the notes.\nOutside line three of the notes.\n"
	os.WriteFile(outside, []byte(outsideText), 0o644)
	binary := "Binary line one of the file.\nBinary line two of the file.\nBinary line three of the file.\n\x00"
	home := writeHome(t, map[string]string{"skills/implement/SKILL.md": skillText, "bin/tool": binary})
	for link, target := range map[string]string{
		"skills/outside.md": outside,
		"linked":            filepath.Dir(outside),
		"skills/alias.md":   filepath.Join(home, "skills/implement/SKILL.md"),
		"aliased":           filepath.Join(home, "skills"),
	} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Fatal(err)
		}
	}
	h, lines := readHome(t, home)
	if want := []string{"the text of the harness file bin/tool is not masked: it contains a zero byte"}; fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Errorf("the report lines %q, want %q", lines, want)
	}
	// A change in the home after the read changes nothing.
	os.WriteFile(filepath.Join(home, "skills/implement/SKILL.md"), []byte("Changed line one.\nChanged line two.\nChanged line three.\n"), 0o644)
	for in, want := range map[string]string{
		skillText: skillPut + "\n",
		"Changed line one.\nChanged line two.\nChanged line three.\n": "Changed line one.\nChanged line two.\nChanged line three.\n",
		outsideText:            outsideText,
		binary[:len(binary)-1]: binary[:len(binary)-1],
	} {
		if got := h.Replace(in); got != want {
			t.Errorf("%.40q: %q, want %q", in, got, want)
		}
	}
}

// readHomeError is the error of readHarness of home, which must fail.
func readHomeError(t *testing.T, home string) string {
	t.Helper()
	h, err := readHarness(home, func(string) {})
	if err == nil {
		t.Fatalf("readHarness read %v, want an error", h)
	}
	return err.Error()
}

// TestAHarnessFileOverTheLimitFailsTheRead pins a file of more than
// HarnessMaxFileSize bytes: the error starts with the fix and contains the file's path
// and size.
func TestAHarnessFileOverTheLimitFailsTheRead(t *testing.T) {
	big := strings.Repeat("Big line of a file over the limit.\n", HarnessMaxFileSize/35+1)
	home := writeHome(t, map[string]string{"skills/implement/SKILL.md": skillText, "data/big.md": big})
	if got, want := readHomeError(t, home), fmt.Sprintf("make each harness file at most 1048576 bytes: data/big.md has %d", len(big)); got != want {
		t.Errorf("the error %q, want %q", got, want)
	}
}

// TestAHarnessOverTheLimitOfAllFilesFailsTheRead pins 17 files of HarnessMaxFileSize
// bytes: the first 16 are HarnessMaxSize bytes, which is in the limit, and the 17th
// fails the read.
func TestAHarnessOverTheLimitOfAllFilesFailsTheRead(t *testing.T) {
	home := t.TempDir()
	text := []byte(strings.Repeat("A line of a file at the limit of size.\n", HarnessMaxFileSize/39+1)[:HarnessMaxFileSize])
	for i := range HarnessMaxSize/HarnessMaxFileSize + 1 {
		if err := os.WriteFile(filepath.Join(home, fmt.Sprintf("f%02d.md", i)), text, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := readHomeError(t, home), "make the harness files at most 16777216 bytes in all: with f16.md they have 17825792"; got != want {
		t.Errorf("the error %q, want %q", got, want)
	}
	os.Remove(filepath.Join(home, "f16.md"))
	readHome(t, home)
}

// TestAHarnessOverTheLimitOfFilesFailsTheRead pins a home with one file more than
// HarnessMaxFiles: the file after the limit fails the read.
func TestAHarnessOverTheLimitOfFilesFailsTheRead(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 10001 files")
	}
	home := t.TempDir()
	for i := range HarnessMaxFiles + 1 {
		if err := os.WriteFile(filepath.Join(home, fmt.Sprintf("f%05d.md", i)), []byte(fmt.Sprintf("line %d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := readHomeError(t, home), "make the harness home at most 10000 files: f10000.md is file 10001"; got != want {
		t.Errorf("the error %q, want %q", got, want)
	}
}

// TestAHarnessFileThatCannotBeReadFailsTheRead pins a file and a directory that the
// session's user cannot read: each fails the read, with its path.
func TestAHarnessFileThatCannotBeReadFailsTheRead(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads every file")
	}
	home := writeHome(t, map[string]string{"skills/implement/SKILL.md": skillText, "skills/locked/notes.md": "notes\n"})
	file := filepath.Join(home, "skills/implement/SKILL.md")
	os.Chmod(file, 0)
	if got, want := readHomeError(t, home), "make each harness file readable: reading skills/implement/SKILL.md failed: "; !strings.HasPrefix(got, want) {
		t.Errorf("the error %q, want it to start with %q", got, want)
	}
	os.Chmod(file, 0o644)
	dir := filepath.Join(home, "skills/locked")
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if got, want := readHomeError(t, home), "make each directory of the harness home readable: reading skills/locked failed: "; !strings.HasPrefix(got, want) {
		t.Errorf("the error %q, want it to start with %q", got, want)
	}
}

// TestTheLogWriterMasksTheHarnessAtEverySplit writes a stream with a proxy URL and the
// skill's text, as cat prints it and inside a JSON line, in two writes, split at every
// place: on pipes; on a terminal, whose lines end in CRLF, with a pause longer than the
// gap between the writes; and on a terminal cut between them, as a resize cuts it. The
// password is masked first, then the skill's text: no chunk contains either, and the
// chunks joined are the stream with qory-proxy-password and the replacement in their
// places.
func TestTheLogWriterMasksTheHarnessAtEverySplit(t *testing.T) {
	h := mask.ForHarness([]mask.HarnessFile{{Path: "skills/implement/SKILL.md", Text: []byte(skillText)}})
	escaped, _ := json.Marshal(skillText)
	lf := "HTTP_PROXY=http://qory:" + fakeProxyPassword + "@127.0.0.1:1\n" + skillText + `{"content":` + string(escaped) + "}\nend\n"
	lfWant := "HTTP_PROXY=http://qory:" + mask.ProxyPassword + "@127.0.0.1:1\n" + skillPut + "\n" + `{"content":"` + skillPut + `\n"}` + "\nend\n"
	for _, way := range []string{"pipes", "terminal", "resize"} {
		input, want := lf, lfWant
		if way != "pipes" {
			input, want = strings.ReplaceAll(lf, "\n", "\r\n"), strings.ReplaceAll(lfWant, "\n", "\r\n")
		}
		for i := 0; i <= len(input); i += 7 {
			t.Run(fmt.Sprintf("%s %d", way, i), func(t *testing.T) {
				t.Parallel()
				c := &chunks{}
				p := &process{logs: func(string) func([]byte) { return c.emit }, masker: mask.Proxy(proxyUser, fakeProxyPassword), harness: h}
				l := p.logWriter("stream", way != "pipes")
				l.Write([]byte(input[:i]))
				switch way {
				case "terminal":
					time.Sleep(chunk.Gap + 30*time.Millisecond)
				case "resize":
					l.cut()
				}
				l.Write([]byte(input[i:]))
				l.Flush()
				c.mu.Lock()
				defer c.mu.Unlock()
				for _, g := range c.got {
					if strings.Contains(g, fakeProxyPassword) || strings.Contains(g, "Change the code") {
						t.Errorf("a chunk contains the password or the skill: %q", g)
					}
				}
				if got := strings.Join(c.got, ""); got != want {
					t.Errorf("the chunks %q, want %q", c.got, want)
				}
			})
		}
	}
}

// TestThePasswordIsMaskedBeforeTheHarness pins a harness file that contains the
// forwarder's password: the password is masked first, so the file's text is no longer
// in the record's string nor in the stream, and they show the file's other two lines
// with qory-proxy-password in the place of the password.
func TestThePasswordIsMaskedBeforeTheHarness(t *testing.T) {
	text := "Proxy line one of the setup.\nHTTP_PROXY=http://qory:" + fakeProxyPassword + "@127.0.0.1:1\nProxy line three of the setup.\n"
	want := strings.ReplaceAll(text, fakeProxyPassword, mask.ProxyPassword)
	h := mask.ForHarness([]mask.HarnessFile{{Path: "setup/proxy.md", Text: []byte(text)}})
	m := mask.Proxy(proxyUser, fakeProxyPassword)
	if got := (texts{secrets: m, harness: h}).replace(text); got != want {
		t.Errorf("the record's string %q, want %q", got, want)
	}
	c := &chunks{}
	p := &process{logs: func(string) func([]byte) { return c.emit }, masker: m, harness: h}
	l := p.logWriter("stream", false)
	l.Write([]byte(text))
	l.Flush()
	if got := strings.Join(c.got, ""); got != want {
		t.Errorf("the stream %q, want %q", got, want)
	}
}

// TestARecordIsMaskedOfTheHarness pins a hook record of a tool's input and result as
// the session decodes it: the skill's text in the input's and the result's strings,
// at any depth, is the replacement, the forwarder's password in them is
// qory-proxy-password, and every other value stays.
func TestARecordIsMaskedOfTheHarness(t *testing.T) {
	h := mask.ForHarness([]mask.HarnessFile{{Path: "skills/implement/SKILL.md", Text: []byte(skillText)}})
	var data map[string]any
	record := map[string]any{
		"tool":     "Bash",
		"input":    map[string]any{"command": "cat \"$QORY_HARNESS_HOME/skills/implement/SKILL.md\"", "description": "Read the skill"},
		"response": map[string]any{"stdout": skillText, "stderr": "HTTP_PROXY=http://qory:" + fakeProxyPassword + "@127.0.0.1:1", "interrupted": false},
		"messages": []any{map[string]any{"text": "From the skill:\n" + skillText}},
	}
	b, _ := json.Marshal(record)
	json.Unmarshal(b, &data)
	got := maskedRecord(texts{secrets: mask.Proxy(proxyUser, fakeProxyPassword), harness: h}, data)
	want := map[string]any{
		"tool":     "Bash",
		"input":    map[string]any{"command": "cat \"$QORY_HARNESS_HOME/skills/implement/SKILL.md\"", "description": "Read the skill"},
		"response": map[string]any{"stdout": skillPut + "\n", "stderr": "HTTP_PROXY=http://qory:" + mask.ProxyPassword + "@127.0.0.1:1", "interrupted": false},
		"messages": []any{map[string]any{"text": "From the skill:\n" + skillPut + "\n"}},
	}
	if g, w := fmt.Sprint(got), fmt.Sprint(want); g != w {
		t.Errorf("the masked record %s, want %s", g, w)
	}
	if !bytes.Contains([]byte(data["response"].(map[string]any)["stdout"].(string)), []byte("Change the code")) {
		t.Error("the record's map was changed")
	}
	if maskedRecord(texts{}, data)["response"].(map[string]any)["stdout"] != skillText {
		t.Error("no masker changed the record")
	}
}
