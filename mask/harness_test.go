package mask_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/qoryai/forager/mask"
)

// skill is the text of an example harness file, skills/implement/SKILL.md.
const skill = `---
name: implement
description: Build the change the work item describes.
---

# Implement

1. Read the work item and list each thing to build.
2. Write a test for each item on the list.
3. Change the code until every test passes.
4. Run the checks the workspace defines.
5. Write what changed in the change log.
`

// review is the text of a second example file, skills/review/SKILL.md.
const review = `# Review

- Read the diff from its first line to its last.
- Run each test the change adds, and the suite.
- List each defect with its file and line.
`

// harness is the masker of the two example files.
func harness() *mask.Harness {
	return mask.ForHarness([]mask.HarnessFile{
		{Path: "skills/implement/SKILL.md", Text: []byte(skill)},
		{Path: "skills/review/SKILL.md", Text: []byte(review)},
	})
}

const (
	implementPut = "[harness text: skills/implement/SKILL.md]"
	reviewPut    = "[harness text: skills/review/SKILL.md]"
)

// TestThreeLinesAreMaskedAndTwoAreNot pins the rule of lines: three consecutive lines
// of a file are replaced with one text, whatever their indentation and their trailing
// whitespace, and two are left as they are.
func TestThreeLinesAreMaskedAndTwoAreNot(t *testing.T) {
	h := harness()
	three := "before\n  2. Write a test for each item on the list.  \n3. Change the code until every test passes.\n\t4. Run the checks the workspace defines.\nafter\n"
	if got, want := h.Replace(three), "before\n  "+implementPut+"\nafter\n"; got != want {
		t.Errorf("three lines: %q, want %q", got, want)
	}
	two := "before\n2. Write a test for each item on the list.\n3. Change the code until every test passes.\nafter\n"
	if got := h.Replace(two); got != two {
		t.Errorf("two lines: %q", got)
	}
	// A blank line between the file's lines is skipped.
	gap := "1. Read the work item and list each thing to build.\n\n2. Write a test for each item on the list.\n   \n3. Change the code until every test passes.\n"
	if got := h.Replace(gap); got != implementPut+"\n" {
		t.Errorf("three lines apart by blank lines: %q", got)
	}
	// Three lines that are each a line of the file, but not consecutive in it.
	apart := "1. Read the work item and list each thing to build.\n3. Change the code until every test passes.\n5. Write what changed in the change log.\n"
	if got := h.Replace(apart); got != apart {
		t.Errorf("three lines not consecutive in the file: %q", got)
	}
}

// long is a file of one paragraph of 400 characters on one line.
var long = strings.Repeat("Each step of the plan names its input and its output. ", 8)[:400]

// accentedLong is a line of 406 characters with accents, which ends in a space.
var accentedLong = strings.Repeat("Étape: écrire le résultat de chaque test, puis le relire. ", 7)

// TestTwoHundredCharactersAreMaskedAndNot199 pins the rule of characters: 200
// consecutive characters of a file, inside one line, are replaced, and 199 are not.
// Characters are counted, not bytes.
func TestTwoHundredCharactersAreMaskedAndNot199(t *testing.T) {
	accented := strings.Repeat("é", 150) + strings.Repeat("a", 150)
	h := mask.ForHarness([]mask.HarnessFile{{Path: "notes/plan.md", Text: []byte(long)}, {Path: "notes/accents.md", Text: []byte(accented)}})
	put := "[harness text: notes/plan.md]"
	for _, c := range []struct {
		from, n int
		masked  bool
	}{{0, 200, true}, {0, 199, false}, {100, 200, true}, {201, 199, false}, {150, 250, true}} {
		piece := long[c.from : c.from+c.n]
		in := "<" + piece + ">"
		want := in
		if c.masked {
			// The space a match ends in stays.
			want = "<" + put + piece[len(strings.TrimRight(piece, " ")):] + ">"
		}
		if got := h.Replace(in); got != want {
			t.Errorf("%d characters from %d: %q, want %q", c.n, c.from, got, want)
		}
	}
	// 200 characters of 2 bytes and 1 byte, and 199 of them.
	runes := []rune(accented)
	if got, want := h.Replace("<"+string(runes[50:250])+">"), "<[harness text: notes/accents.md]>"; got != want {
		t.Errorf("200 characters: %q, want %q", got, want)
	}
	if in := "<" + string(runes[50:249]) + ">"; h.Replace(in) != in {
		t.Errorf("199 characters of %d bytes are masked", len(string(runes[50:249])))
	}
}

// TestTextInJSONIsMasked pins the text inside JSON: a tool's input and output as a
// stream of JSON lines has them, with the file's line breaks and quotes escaped, and a
// file read with line numbers. The JSON stays valid, and its other members stay.
func TestTextInJSONIsMasked(t *testing.T) {
	h := harness()
	input, _ := json.Marshal(map[string]any{"type": "tool_use", "name": "Write", "input": map[string]any{"file_path": "/workspace/notes.md", "content": skill}})
	var numbered strings.Builder
	for i, l := range strings.Split(strings.TrimSuffix(review, "\n"), "\n") {
		fmt.Fprintf(&numbered, "%6d\t%s\n", i+1, l)
	}
	output, _ := json.Marshal(map[string]any{"type": "tool_result", "tool_use_id": "toolu_1", "content": numbered.String()})
	for _, c := range []struct {
		in   []byte
		key  string
		want string
	}{
		{input, "content", implementPut},
		{output, "content", reviewPut},
	} {
		got := h.Replace(string(c.in))
		var m map[string]any
		if err := json.Unmarshal([]byte(got), &m); err != nil {
			t.Fatalf("%s: not JSON once masked: %v", got, err)
		}
		v := m[c.key]
		if in, ok := m["input"].(map[string]any); ok {
			v = in[c.key]
			if in["file_path"] != "/workspace/notes.md" {
				t.Errorf("file_path %v", in["file_path"])
			}
		}
		if s, _ := v.(string); strings.TrimSpace(s) != c.want {
			t.Errorf("%s: %q, want %q", c.key, s, c.want)
		}
	}
	// A string of an event's data, decoded: the text as it is.
	if got := h.Replace("cat printed:\n" + review); got != "cat printed:\n"+reviewPut+"\n" {
		t.Errorf("a decoded string: %q", got)
	}
	// Each e as the escape \u0065, and each é as \u00e9.
	escaped := strings.ReplaceAll(strings.ReplaceAll(accentedLong, "e", `\u0065`), "é", `\u00e9`)
	h2 := mask.ForHarness([]mask.HarnessFile{{Path: "notes/plan.md", Text: []byte(accentedLong)}})
	if !strings.Contains(escaped, `\u0065`) || !strings.Contains(escaped, `\u00e9`) {
		t.Fatalf("the escaped text has no escape: %.80q", escaped)
	}
	if got := h2.Replace(`{"text":"` + escaped + `"}`); got != `{"text":"[harness text: notes/plan.md] "}` {
		t.Errorf("the text with escapes of e and é: %q", got)
	}
}

// TestTwoFilesAreMaskedEachWithItsPath pins the text of two files next to each other:
// each is replaced with its file's path, and two pieces of one file with only
// whitespace between them are one.
func TestTwoFilesAreMaskedEachWithItsPath(t *testing.T) {
	h := harness()
	in := skill + review + "end\n"
	if got, want := h.Replace(in), implementPut+"\n"+reviewPut+"\nend\n"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
	lines := strings.Split(skill, "\n")
	pieces := strings.Join(lines[0:3], "\n") + "\n\n\n" + strings.Join(lines[7:10], "\n") + "\n"
	if got := h.Replace(pieces); got != implementPut+"\n" {
		t.Errorf("two pieces of one file apart by blank lines: %q", got)
	}
	mixed := strings.Join(lines[0:3], "\n") + "\nnot the harness\n" + strings.Join(lines[7:10], "\n") + "\n"
	if got, want := h.Replace(mixed), implementPut+"\nnot the harness\n"+implementPut+"\n"; got != want {
		t.Errorf("two pieces apart by a line: %q, want %q", got, want)
	}
}

// TestThePathInAReplacementIsCleaned pins a path with quotes, a terminal's code and a
// bidirectional mark: the replacement contains the path without the escape character
// and the mark, and with the quotes escaped, in a string and inside a JSON string, with
// its escapes decoded or not.
func TestThePathInAReplacementIsCleaned(t *testing.T) {
	h := mask.ForHarness([]mask.HarnessFile{{Path: "notes/\"plan\"\x1b[2J\u202e.md", Text: []byte(long)}})
	if got, want := h.Replace(long), `[harness text: notes/\"plan\"[2J.md] `; got != want {
		t.Errorf("the replacement %q, want %q", got, want)
	}
	in, _ := json.Marshal(map[string]string{"text": long})
	if got, want := h.Replace(string(in)), `{"text":"[harness text: notes/\"plan\"[2J.md] "}`; got != want {
		t.Errorf("the replacement in JSON %q, want %q", got, want)
	}
	in, _ = json.Marshal(map[string]string{"text": long + "\n"})
	var out map[string]string
	if err := json.Unmarshal([]byte(h.Replace(string(in))), &out); err != nil || out["text"] != `[harness text: notes/\"plan\"[2J.md] `+"\n" {
		t.Errorf("the replacement in JSON with escapes decoded %q, %v", out["text"], err)
	}
}

// TestWhitespaceAtTheEndsOfAMatchStays pins a file whose text starts with spaces and a
// tab: the whitespace before the first other character of a match stays in front of
// the replacement, and the whitespace after its last.
func TestWhitespaceAtTheEndsOfAMatchStays(t *testing.T) {
	h := mask.ForHarness([]mask.HarnessFile{{Path: "notes/plan.md", Text: []byte("  \t" + long + "\n")}})
	if got, want := h.Replace("plan:  \t"+long+"\nend\n"), "plan:  \t[harness text: notes/plan.md] \nend\n"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

// TestTheWriterMasksTextSplitAcrossWrites writes a stream that contains a file's text
// in two writes, split at every place: the stream is masked as one string is, and the
// writer keeps back at most the last 199 characters, and the last lines that are lines
// of the files.
func TestTheWriterMasksTextSplitAcrossWrites(t *testing.T) {
	h := harness()
	body := "start of the output\n" + skill + "middle\n" + `{"content":"` + strings.ReplaceAll(review, "\n", `\n`) + `"}` + "\nend of the output\n"
	want := h.Replace(body)
	if !strings.Contains(want, implementPut) || !strings.Contains(want, reviewPut) {
		t.Fatalf("Replace: %q", want)
	}
	for i := 0; i <= len(body); i++ {
		var out bytes.Buffer
		w := h.Writer(&out)
		w.Write([]byte(body[:i]))
		w.Write([]byte(body[i:]))
		w.Flush()
		if out.String() != want {
			t.Errorf("split at %d: %q", i, out.String())
		}
	}
	// Byte by byte.
	var out bytes.Buffer
	w := h.Writer(&out)
	for i := range len(body) {
		w.Write([]byte{body[i]})
	}
	w.Flush()
	if out.String() != want {
		t.Errorf("byte by byte: %q", out.String())
	}
	// Text that is no file's is written once 199 more characters follow it.
	out.Reset()
	w = h.Writer(&out)
	other := strings.Repeat("x", 300)
	w.Write([]byte(other))
	if out.Len() != 101 {
		t.Errorf("%d bytes written of 300, want 101", out.Len())
	}
	w.Flush()
	if out.String() != other {
		t.Errorf("after Flush: %q", out.String())
	}
	var none *mask.Harness
	out.Reset()
	none.Writer(&out).Write([]byte(skill))
	if out.String() != skill || none.Replace(skill) != skill {
		t.Error("a nil Harness masked something")
	}
}

// TestALongTextIsOneReplacement writes a file's text 30 times its size in writes of
// 4 KiB: the stream is one replacement.
func TestALongTextIsOneReplacement(t *testing.T) {
	text := harnessText(rand.New(rand.NewPCG(1, 2)), 128<<10)
	h := mask.ForHarness([]mask.HarnessFile{{Path: "big.md", Text: text}})
	var out bytes.Buffer
	w := h.Writer(&out)
	for b := text; len(b) > 0; {
		n := min(len(b), 4096)
		w.Write(b[:n])
		b = b[n:]
	}
	w.Flush()
	if out.String() != "[harness text: big.md]" {
		t.Errorf("%.200q", out.String())
	}
}

// words are the words the benchmark's text is made of.
var words = strings.Fields("the plan step test check build change file line work item list read write run each list " +
	"output input value field record event stream chunk source target place order count error result")

// harnessText is n bytes of lines of words.
func harnessText(r *rand.Rand, n int) []byte {
	var b bytes.Buffer
	for b.Len() < n {
		for i := range 4 + r.IntN(10) {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(words[r.IntN(len(words))])
		}
		b.WriteByte('\n')
	}
	return b.Bytes()[:n]
}

// BenchmarkReplace masks 1 MiB of text, a tenth of it a file's text in pieces of 2
// KiB, against a harness of 2 MiB in 64 files.
func BenchmarkReplace(b *testing.B) {
	h, text := benchmarkHarness()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		h.Replace(text)
	}
}

// BenchmarkWriter writes the text of BenchmarkReplace in writes of 4 KiB.
func BenchmarkWriter(b *testing.B) {
	h, text := benchmarkHarness()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		w := h.Writer(discard{})
		for t := text; len(t) > 0; {
			n := min(len(t), 4096)
			w.Write([]byte(t[:n]))
			t = t[n:]
		}
		w.Flush()
	}
}

// BenchmarkForHarness indexes a harness of 2 MiB in 64 files.
func BenchmarkForHarness(b *testing.B) {
	files := benchmarkFiles()
	for b.Loop() {
		mask.ForHarness(files)
	}
}

// discard is a writer that writes nowhere.
type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }

// benchmarkFiles is a harness of 2 MiB in 64 files of 32 KiB.
func benchmarkFiles() []mask.HarnessFile {
	r := rand.New(rand.NewPCG(3, 4))
	var files []mask.HarnessFile
	for i := range 64 {
		files = append(files, mask.HarnessFile{Path: fmt.Sprintf("skills/s%02d/SKILL.md", i), Text: harnessText(r, 32<<10)})
	}
	return files
}

// benchmarkHarness is the masker of benchmarkFiles and 1 MiB of text.
func benchmarkHarness() (*mask.Harness, string) {
	files := benchmarkFiles()
	r := rand.New(rand.NewPCG(5, 6))
	var text bytes.Buffer
	for text.Len() < 1<<20 {
		if r.IntN(10) == 0 {
			f := files[r.IntN(len(files))].Text
			at := r.IntN(len(f) - 2048)
			text.Write(f[at : at+2048])
			continue
		}
		text.Write(harnessText(r, 2048))
	}
	return mask.ForHarness(files), text.String()[:1<<20]
}
