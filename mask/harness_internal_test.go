package mask

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// words is n bytes of text in which no 32 bytes repeat: words of a letter and a
// number.
func words(letter string, n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "%s%06d ", letter, i)
	}
	return b.String()[:n]
}

// writeInPieces writes s to hw in writes of size bytes and returns the most bytes hw
// kept after a write, and the bytes the writes scanned: for each write, the bytes hw
// kept before it and the write.
func writeInPieces(t *testing.T, hw *HarnessWriter, s string, size int) (most, scanned int) {
	t.Helper()
	for i := 0; i < len(s); i += size {
		b := []byte(s[i:min(i+size, len(s))])
		scanned += len(hw.buf) + len(b)
		if _, err := hw.Write(b); err != nil {
			t.Fatal(err)
		}
		most = max(most, len(hw.buf))
	}
	return most, scanned
}

// keptMost is the most bytes the writer keeps after a write of size bytes: the end
// of the match written last, keepMost bytes after it, the write, and a line number
// before them.
func keptMost(size int) int { return contextMost + keepMost + size + utf8Max + 12 }

const utf8Max = 4

// TestALineOverTheCapMasksTheLinesBeforeIt pins three lines of a file, the second
// longer than keepMost, written in 64-byte writes. The first line has trailing
// whitespace that the file does not have, so only the rule of lines matches it. Once
// the second line passes the cap, the writer writes the first line masked with the
// second: the output contains no line of the file, and the writer keeps at most
// keptMost bytes.
func TestALineOverTheCapMasksTheLinesBeforeIt(t *testing.T) {
	first, second, third := "Step one of the plan.", words("b", 70<<10), "Step three of the plan."
	h := ForHarness([]HarnessFile{{Path: "notes/plan.md", Text: []byte(first + "\n" + second + "\n" + third + "\n")}})
	var out bytes.Buffer
	hw := h.Writer(&out)
	in := "before\n" + first + "  \t\n" + second + "\n" + third + "\nafter\n"
	if most, _ := writeInPieces(t, hw, in, 64); most > keptMost(64) {
		t.Errorf("the writer kept %d bytes, more than %d", most, keptMost(64))
	}
	hw.Flush()
	if want := "before\n[harness text: notes/plan.md]\nafter\n"; out.String() != want {
		t.Errorf("%.200q, want %q", out.String(), want)
	}
}

// TestBlankLinesOverTheCapMaskTheLinesBeforeThem pins two lines of a file, then 90 KiB
// of blank lines, which a run of lines skips, then the file's third line, written in
// 64-byte writes, with a file whose longest line is longer than each blank line.
// Once the blank lines pass the cap, the writer writes the two lines masked: no line
// of the file is in the output.
func TestBlankLinesOverTheCapMaskTheLinesBeforeThem(t *testing.T) {
	lines := []string{"Line one of the notes.", "Line two of the notes.", "Line three of the notes."}
	h := ForHarness([]HarnessFile{{Path: "notes/long.md", Text: []byte(strings.Join(lines, "\n") + "\n" + words("c", 4<<10) + "\n")}})
	var out bytes.Buffer
	hw := h.Writer(&out)
	in := lines[0] + "  \n" + lines[1] + "  \n" + strings.Repeat(strings.Repeat(" ", 1500)+"\n", 60) + lines[2] + "  \nend\n"
	if most, _ := writeInPieces(t, hw, in, 64); most > keptMost(64) {
		t.Errorf("the writer kept %d bytes, more than %d", most, keptMost(64))
	}
	hw.Flush()
	for _, l := range lines {
		if strings.Contains(out.String(), l) {
			t.Errorf("the output contains %q", l)
		}
	}
	if !strings.HasSuffix(out.String(), "[harness text: notes/long.md]  \nend\n") {
		t.Errorf("the output ends %q", out.String()[max(0, out.Len()-80):])
	}
}

// TestARepeatedLineOverTheCapIsMasked pins a line of a file, then a line of 70 KiB of
// = with spaces in front, which no piece of the index contains, written in 64-byte
// writes. Once the line of = passes the cap, the writer masks the line before it and
// the line of = itself.
func TestARepeatedLineOverTheCapIsMasked(t *testing.T) {
	rule := strings.Repeat("=", 70<<10)
	h := ForHarness([]HarnessFile{{Path: "notes/rule.md", Text: []byte("Line one of the rule.\n" + rule + "\nLine three of the rule.\n")}})
	var out bytes.Buffer
	hw := h.Writer(&out)
	writeInPieces(t, hw, "Line one of the rule.  \n  "+rule[:68<<10], 64)
	if strings.Contains(out.String(), "Line one") || strings.Contains(out.String(), "==") {
		t.Errorf("the output %.200q", out.String())
	}
}

// TestTheWriterIsLinearInALongLine writes 128 KiB, 256 KiB and 384 KiB of a 1 MiB
// line of a file of three lines, a line that is not finished, in 64-byte writes. The writer keeps at
// most keptMost bytes after each write, so each write scans at most that many and the
// write, and the second 128 KiB scan as many bytes as the third, give or take 10%.
// A writer that kept the whole line would scan 5/3 as many for the third.
func TestTheWriterIsLinearInALongLine(t *testing.T) {
	line := words("a", 1<<20)
	h := ForHarness([]HarnessFile{{Path: "notes/long.md", Text: []byte("Notes.\n" + line + "\nEnd of the notes.\n")}})
	scan := func(n int) int {
		var out bytes.Buffer
		hw := h.Writer(&out)
		start := time.Now()
		most, scanned := writeInPieces(t, hw, line[:n], 64)
		t.Logf("%d bytes: %v, %d bytes scanned, at most %d kept", n, time.Since(start), scanned, most)
		if most > keptMost(64) {
			t.Errorf("for %d bytes the writer kept %d bytes, more than %d", n, most, keptMost(64))
		}
		hw.Flush()
		if out.String() != "[harness text: notes/long.md] " {
			t.Errorf("for %d bytes the output %.100q", n, out.String())
		}
		return scanned
	}
	one, two, three := scan(128<<10), scan(256<<10), scan(384<<10)
	if second, third := two-one, three-two; float64(third) > 1.1*float64(second) {
		t.Errorf("the third 128 KiB scanned %d bytes, more than 1.1 times the %d of the second", third, second)
	}
}

// writes records each write it is given.
type writes struct{ got [][]byte }

func (w *writes) Write(b []byte) (int, error) {
	w.got = append(w.got, bytes.Clone(b))
	return len(b), nil
}

// TestTheCutIsAtTheStartOfACharacter pins a line of 100 KiB of €, 3 bytes each, that
// is no text of the file, written in 64-byte writes, with a file whose longest line
// is longer: the writer keeps the line back up to the cap, and each write it makes
// ends at the end of a character, and all of them are the line.
func TestTheCutIsAtTheStartOfACharacter(t *testing.T) {
	h := ForHarness([]HarnessFile{{Path: "notes/long.md", Text: []byte("Notes.\n" + words("d", 200<<10) + "\nEnd of the notes.\n")}})
	w := &writes{}
	hw := h.Writer(w)
	line := strings.Repeat("€", 100<<10/3)
	writeInPieces(t, hw, line, 64)
	if len(w.got) == 0 {
		t.Fatal("the writer wrote nothing before the end of the line")
	}
	hw.Flush()
	for i, b := range w.got {
		if !utf8.Valid(b) {
			t.Errorf("write %d of %d is not whole characters: it ends %q", i, len(w.got), b[max(0, len(b)-4):])
		}
	}
	if got := string(bytes.Join(w.got, nil)); got != line {
		t.Errorf("the writes are %d bytes, want the %d of the line", len(got), len(line))
	}
}

// writtenAs is s written to a writer of h in writes of size bytes, and flushed.
func writtenAs(t *testing.T, h *Harness, s string, size int) string {
	t.Helper()
	var out bytes.Buffer
	hw := h.Writer(&out)
	writeInPieces(t, hw, s, size)
	if err := hw.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// TestARunOfLinesAcrossBlankLinesIsMasked pins two lines of a file and its third line
// with blank lines between the second and the third, in writes of 1 byte, 64 bytes and
// 4 KiB: the output is the output of Replace. The blank lines are 70 empty lines, more
// than the 64 the writer keeps back, and 60 blank lines of 1500 bytes, each after a
// line number and a tab, as a file read with line numbers shows them, over the cap,
// with lines one and two numbered too.
func TestARunOfLinesAcrossBlankLinesIsMasked(t *testing.T) {
	lines := []string{"Line one of the notes.", "Line two of the notes.", "Line three of the notes."}
	short := ForHarness([]HarnessFile{{Path: "notes/short.md", Text: []byte(strings.Join(lines, "\n") + "\n")}})
	long := ForHarness([]HarnessFile{{Path: "notes/long.md", Text: []byte(strings.Join(lines, "\n") + "\n" + words("c", 4<<10) + "\n")}})
	numbered := "     1\t" + lines[0] + "\n     2\t" + lines[1] + "\n"
	for n := 3; n < 63; n++ {
		numbered += fmt.Sprintf("%6d\t%s\n", n, strings.Repeat(" ", 1500))
	}
	numbered += "    63\t" + lines[2] + "\nend\n"
	for _, c := range []struct {
		name string
		h    *Harness
		in   string
	}{
		{"70 empty lines", short, lines[0] + "\n" + lines[1] + "\n" + strings.Repeat("\n", 70) + lines[2] + "\nend\n"},
		{"numbered blank lines over the cap", long, numbered},
	} {
		want := c.h.Replace(c.in)
		for _, l := range lines {
			if strings.Contains(want, l) {
				t.Fatalf("%s: Replace shows %q", c.name, l)
			}
		}
		for _, size := range []int{1, 64, 4 << 10} {
			if got := writtenAs(t, c.h, c.in, size); got != want {
				t.Errorf("%s in writes of %d bytes: %.200q, want %.200q", c.name, size, got, want)
			}
		}
	}
}

// TestARunOfLinesAcrossLongBlankLinesIsMasked pins two lines of a file and its third
// line with 200 KiB of blank lines between the second and the third, plain and after
// line numbers after a tab or an arrow, in writes of 61, 64, 67 bytes and 4 KiB. The
// writer writes the blank lines
// before the third line arrives, so it remembers the two lines of the file before
// them: the output contains no line of the file, and Replace of the output changes
// nothing.
func TestARunOfLinesAcrossLongBlankLinesIsMasked(t *testing.T) {
	lines := []string{"Line one of the notes.", "Line two of the notes.", "Line three of the notes."}
	h := ForHarness([]HarnessFile{{Path: "notes/long.md", Text: []byte(strings.Join(lines, "\n") + "\n" + words("c", 4<<10) + "\n")}})
	numbered := "     1\t" + lines[0] + "\n     2\t" + lines[1] + "\n"
	for n := 3; n < 103; n++ {
		numbered += fmt.Sprintf("%6d\t%s\n", n, strings.Repeat(" ", 2000))
	}
	numbered += "   103\t" + lines[2] + "\nend\n"
	plain := lines[0] + "\n" + lines[1] + "\n" + strings.Repeat(strings.Repeat(" ", 2000)+"\n", 100) + lines[2] + "\nend\n"
	arrows := strings.ReplaceAll(numbered, "\t", "→")
	for name, in := range map[string]string{"plain": plain, "numbered": numbered, "numbered with arrows": arrows} {
		for _, size := range []int{61, 64, 67, 4 << 10} {
			got := writtenAs(t, h, in, size)
			for _, l := range lines {
				if strings.Contains(got, l) {
					t.Errorf("%s in writes of %d bytes: the output contains %q", name, size, l)
				}
			}
			if h.Replace(got) != got {
				t.Errorf("%s in writes of %d bytes: Replace of the output changes it", name, size)
			}
		}
	}
}

// TestALineBetweenEndsTheRemembering pins two lines of a file, then a line of other
// text, then the file's third line: the third line is shown, as Replace shows it,
// when the other line lies between the second line and 200 KiB of blank lines, and
// when it is a line of other text and 100 KiB of spaces right before the third line.
func TestALineBetweenEndsTheRemembering(t *testing.T) {
	lines := []string{"Line one of the notes.", "Line two of the notes.", "Line three of the notes."}
	h := ForHarness([]HarnessFile{{Path: "notes/long.md", Text: []byte(strings.Join(lines, "\n") + "\n" + words("c", 4<<10) + "\n")}})
	for name, in := range map[string]string{
		"before the blank lines": lines[0] + "\n" + lines[1] + "\nOther text.\n" + strings.Repeat(strings.Repeat(" ", 2000)+"\n", 100) + lines[2] + "\nend\n",
		"a long line":            lines[0] + "\n" + lines[1] + "\nOther text." + strings.Repeat(" ", 100<<10) + "\n" + lines[2] + "\nend\n",
	} {
		if !strings.Contains(h.Replace(in), lines[2]) {
			t.Fatalf("%s: Replace masks the third line", name)
		}
		for _, size := range []int{64, 4 << 10} {
			if got := writtenAs(t, h, in, size); !strings.Contains(got, lines[2]) {
				t.Errorf("%s in writes of %d bytes: the third line is masked: %.120q", name, size, got[max(0, len(got)-120):])
			}
		}
	}
}

// TestCarryKeepsTheLinesOfTheFilesBeforeTheBuffer pins carry, which the writer calls
// for the bytes it drops: it remembers the last two lines of the files with blank
// lines alone after them; forgets them after another line, after a blank line longer
// than every line of the files, which ends a run of lines, or when the bytes dropped
// end in other text, the start of the buffer's first line included; and moves the
// start of the buffer back to the start of a line number that the dropped bytes end
// in.
func TestCarryKeepsTheLinesOfTheFilesBeforeTheBuffer(t *testing.T) {
	lines := []string{"Line one of the notes.", "Line two of the notes.", "Line three of the notes."}
	h := ForHarness([]HarnessFile{{Path: "notes/n.md", Text: []byte(strings.Join(lines, "\n") + "\n")}})
	two := lines[0] + "\n" + lines[1] + "\n   \n"
	all := func(b string) int { return len(b) }
	for _, c := range []struct {
		name string
		m    lineMemory
		b    string
		keep func(string) int
		n    int
		head lineHead
		back int
	}{
		{"two lines and a blank line", lineMemory{}, two, all, 2, headBlank, 0},
		{"another line after them", lineMemory{}, two + "Other text.\n", all, 0, headBlank, 0},
		{"a blank line longer than every line of the files", lineMemory{}, two + strings.Repeat(" ", 200) + "\n", all, 0, headBlank, 0},
		{"other text at the cut", lineMemory{}, two + "Other", all, 0, headText, 0},
		{"a number at the cut", lineMemory{}, two + "    12", all, 2, headBlank, 2},
		{"a number and part of an arrow at the cut", lineMemory{}, two + "    12\xe2\x86", all, 2, headBlank, 4},
		{"a number and a tab at the cut", lineMemory{}, two + "    12\t  ", all, 2, headNumbered, 0},
		{"the rest of a line of other text", lineMemory{n: 2, head: headText}, "      \n   \n", all, 0, headBlank, 0},
	} {
		m, keep := h.carry(c.m, []byte(c.b), c.keep(c.b))
		if m.n != c.n || m.head != c.head || keep != len(c.b)-c.back {
			t.Errorf("%s: %d lines, head %d, keep %d; want %d, %d, %d", c.name, m.n, m.head, keep, c.n, c.head, len(c.b)-c.back)
		}
	}
}
