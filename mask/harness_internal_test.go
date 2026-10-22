package mask

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
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
// of the match written last, keepMost bytes after it, and the write.
func keptMost(size int) int { return contextMost + keepMost + size + utf8Max }

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
