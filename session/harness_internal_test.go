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

// TestTheHarnessFilesAreReadOnceWithinTheLimits pins what readHarness reads: each
// regular file by its path relative to the home, the files as they were when it read
// them, no file through a link, no binary file, and no file over the limit of size,
// which is a report line.
func TestTheHarnessFilesAreReadOnceWithinTheLimits(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.md")
	outsideText := "Outside line one of the notes.\nOutside line two of the notes.\nOutside line three of the notes.\n"
	os.WriteFile(outside, []byte(outsideText), 0o644)
	binary := "Binary line one of the file.\nBinary line two of the file.\nBinary line three of the file.\n\x00"
	big := strings.Repeat("Big line of a file over the limit.\n", HarnessMaxFileSize/35+1)
	home := writeHome(t, map[string]string{"skills/implement/SKILL.md": skillText, "bin/tool": binary, "data/big.md": big})
	if err := os.Symlink(outside, filepath.Join(home, "skills", "outside.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(home, "linked")); err != nil {
		t.Fatal(err)
	}
	h, lines := readHome(t, home)
	if want := []string{fmt.Sprintf("the text of the harness file data/big.md is not masked: it has more than %d bytes", HarnessMaxFileSize)}; fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Errorf("the report lines %q, want %q", lines, want)
	}
	// A change in the home after the read changes nothing.
	os.WriteFile(filepath.Join(home, "skills/implement/SKILL.md"), []byte("Changed line one.\nChanged line two.\nChanged line three.\n"), 0o644)
	for in, want := range map[string]string{
		skillText: skillPut + "\n",
		"Changed line one.\nChanged line two.\nChanged line three.\n": "Changed line one.\nChanged line two.\nChanged line three.\n",
		outsideText:            outsideText,
		binary[:len(binary)-1]: binary[:len(binary)-1],
		big[:35*4]:             big[:35*4],
	} {
		if got := h.Replace(in); got != want {
			t.Errorf("%.40q: %q, want %q", in, got, want)
		}
	}
}

// TestTheHarnessFilesAreReadUpToTheLimitOfFiles pins a home with one file more than
// HarnessMaxFiles: the files after the limit are not read, which is one report line.
func TestTheHarnessFilesAreReadUpToTheLimitOfFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 10001 files")
	}
	home := t.TempDir()
	for i := range HarnessMaxFiles + 1 {
		if err := os.WriteFile(filepath.Join(home, fmt.Sprintf("f%05d.md", i)), []byte(fmt.Sprintf("line %d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, lines := readHome(t, home)
	if want := fmt.Sprintf("the text of the harness file f%05d.md is not masked: the home has more than %d files, and the files after this one are not read either", HarnessMaxFiles, HarnessMaxFiles); len(lines) != 1 || lines[0] != want {
		t.Errorf("the report lines %q, want %q", lines, want)
	}
}

// TestTheLogWriterMasksTheHarnessAtEverySplit writes a stream with a proxy URL and the
// skill's text, as cat prints it and inside a JSON line, in two writes, split at every
// place: on pipes, on a terminal with a pause longer than the gap between the writes,
// and on a terminal cut between them, as a resize cuts it. The password is masked
// first, then the skill's text: no chunk contains either, and the chunks joined are
// the stream with qory-proxy-password and the replacement in their places.
func TestTheLogWriterMasksTheHarnessAtEverySplit(t *testing.T) {
	h := mask.ForHarness([]mask.HarnessFile{{Path: "skills/implement/SKILL.md", Text: []byte(skillText)}})
	escaped, _ := json.Marshal(skillText)
	input := "HTTP_PROXY=http://qory:" + fakeProxyPassword + "@127.0.0.1:1\n" + skillText + `{"content":` + string(escaped) + "}\nend\n"
	want := "HTTP_PROXY=http://qory:" + mask.ProxyPassword + "@127.0.0.1:1\n" + skillPut + "\n" + `{"content":"` + skillPut + `\n"}` + "\nend\n"
	for _, way := range []string{"pipes", "terminal", "resize"} {
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
