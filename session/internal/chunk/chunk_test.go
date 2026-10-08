package chunk_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/runner/session/internal/chunk"
)

// TestChunksCutAtLinesAndAtSize pins the rule: a newline ends a chunk and keeps its
// newline, a long line is cut at Size, and a partial line waits for Flush.
func TestChunksCutAtLinesAndAtSize(t *testing.T) {
	var got []string
	w := chunk.New(func(b []byte) { got = append(got, string(b)) })
	long := strings.Repeat("x", chunk.Size+10)
	w.Write([]byte("one\ntwo\nthr"))
	w.Write([]byte("ee\n" + long + "\ntail"))
	if len(got) != 5 {
		t.Fatalf("%d chunks: %q", len(got), got)
	}
	want := []string{"one\n", "two\n", "three\n", long[:chunk.Size], long[chunk.Size:] + "\n"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d = %q, want %q", i, got[i], want[i])
		}
	}
	w.Flush()
	if len(got) != 6 || got[5] != "tail" {
		t.Errorf("after flush: %q", got[len(got)-1])
	}
	w.Flush()
	if len(got) != 6 {
		t.Error("a second flush emitted something")
	}
	if strings.Join(got, "") != "one\ntwo\nthree\n"+long+"\ntail" {
		t.Error("the chunks do not concatenate to the input")
	}
}

// chunks collects what a terminal writer emits, from whichever goroutine.
type chunks struct {
	mu  sync.Mutex
	got []string
}

func (c *chunks) emit(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, string(b))
}

func (c *chunks) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.got...)
}

// wait gives the gap timer time to fire: several gaps, so a slow machine is not a
// failure.
func wait(gap time.Duration) { time.Sleep(6 * gap) }

// TestTerminalCutsAtTheGapAndNotAtLines pins the terminal rule: a line break cuts
// nothing, a redraw written in several pieces inside the gap is one chunk, and the
// chunk goes out once the stream has been quiet for the gap.
func TestTerminalCutsAtTheGapAndNotAtLines(t *testing.T) {
	const gap = 20 * time.Millisecond
	var c chunks
	w := chunk.NewTerminal(c.emit, gap)
	w.Write([]byte("\x1b[2J\x1b[H> hel"))
	w.Write([]byte("lo\r\n"))
	w.Write([]byte("\x1b[1A\x1b[2K> hello w\r\n"))
	if got := c.all(); len(got) != 0 {
		t.Fatalf("emitted inside the gap: %q", got)
	}
	wait(gap)
	got := c.all()
	if len(got) != 1 || got[0] != "\x1b[2J\x1b[H> hello\r\n\x1b[1A\x1b[2K> hello w\r\n" {
		t.Fatalf("after the gap: %q", got)
	}
	w.Write([]byte("\x1b[1A\x1b[2K> hello wo\r\n"))
	wait(gap)
	if got := c.all(); len(got) != 2 || got[1] != "\x1b[1A\x1b[2K> hello wo\r\n" {
		t.Fatalf("second redraw: %q", got)
	}
	w.Flush()
	if got := c.all(); len(got) != 2 {
		t.Errorf("a flush with nothing held emitted something: %q", got)
	}
}

// TestTerminalCutsAtSizeWhileTheStreamNeverPauses pins the bound: a stream that keeps
// writing is cut at Size, never later, and what is held at the end goes out on Flush.
func TestTerminalCutsAtSizeWhileTheStreamNeverPauses(t *testing.T) {
	var c chunks
	w := chunk.NewTerminal(c.emit, time.Hour)
	piece := strings.Repeat("y", 1000)
	for i := 0; i < 10; i++ {
		w.Write([]byte(piece))
	}
	got := c.all()
	if len(got) != 2 || len(got[0]) != chunk.Size || len(got[1]) != chunk.Size {
		t.Fatalf("%d chunks of %v bytes", len(got), lengths(got))
	}
	w.Flush()
	got = c.all()
	if len(got) != 3 || len(got[2]) != 10000-2*chunk.Size {
		t.Fatalf("after flush: %v bytes", lengths(got))
	}
	if strings.Join(got, "") != strings.Repeat(piece, 10) {
		t.Error("the chunks do not concatenate to the input")
	}
}

// TestTerminalNeverCutsInsideACharacter pins the character rule at both cuts: at Size
// the character that would straddle the cut starts the next chunk, and at the gap the
// bytes of a character whose rest has not arrived wait for it, and are not lost when the
// stream ends first.
func TestTerminalNeverCutsInsideACharacter(t *testing.T) {
	const gap = 20 * time.Millisecond
	var c chunks
	w := chunk.NewTerminal(c.emit, gap)
	// 4095 ASCII bytes, then a three-byte character: a cut at 4096 would split it.
	head := strings.Repeat("a", chunk.Size-1)
	w.Write([]byte(head + "€" + "b"))
	got := c.all()
	if len(got) != 1 || got[0] != head {
		t.Fatalf("at Size: %d chunks, first of %d bytes", len(got), len(got[0]))
	}
	wait(gap)
	if got := c.all(); len(got) != 2 || got[1] != "€b" {
		t.Fatalf("after the gap: %q", got[1:])
	}
	// The first two bytes of a three-byte character, then a pause, then the rest.
	euro := []byte("€")
	w.Write(append([]byte("x"), euro[:2]...))
	wait(gap)
	if got := c.all(); len(got) != 3 || got[2] != "x" {
		t.Fatalf("an incomplete character was emitted: %q", got[2:])
	}
	w.Write(euro[2:])
	wait(gap)
	if got := c.all(); len(got) != 4 || got[3] != "€" {
		t.Fatalf("the completed character: %q", got[3:])
	}
	// An incomplete character at the end of the stream is not lost.
	w.Write(euro[:1])
	wait(gap)
	w.Flush()
	if got := c.all(); len(got) != 5 || got[4] != string(euro[:1]) {
		t.Fatalf("after flush: %q", got[4:])
	}
	// Bytes that are not UTF-8 are cut like any other, not held.
	w.Write([]byte{0xff, 0xfe})
	wait(gap)
	if got := c.all(); len(got) != 6 || got[5] != "\xff\xfe" {
		t.Fatalf("bytes that are not UTF-8: %q", got[5:])
	}
}

func lengths(s []string) []int {
	out := make([]int, len(s))
	for i, v := range s {
		out[i] = len(v)
	}
	return out
}

// TestTerminalTakesAWriteOfExactlySize pins the edge a pseudo-terminal's reads hit: a
// write that brings what is held to exactly Size bytes is one chunk, not a panic.
func TestTerminalTakesAWriteOfExactlySize(t *testing.T) {
	var got []string
	w := chunk.NewTerminal(func(b []byte) { got = append(got, string(b)) }, time.Hour)
	for i := 0; i < 4; i++ {
		w.Write([]byte(strings.Repeat("x", chunk.Size/4)))
	}
	w.Flush()
	if len(got) != 1 || len(got[0]) != chunk.Size {
		t.Fatalf("%d chunks, first of %d bytes", len(got), len(got[0]))
	}
}
