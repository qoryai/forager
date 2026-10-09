// Package chunk cuts a stream of bytes into the log chunks of the contract. A pipe is
// cut into lines: one line or Size bytes, whichever comes first. A terminal stream is
// cut at Size bytes or at a quiet gap after the last write, never inside a multibyte
// character, and a line break cuts nothing: a full-screen program redraws on every
// keypress, and cut at line breaks its record is thousands of chunks of a few bytes.
package chunk

import (
	"sync"
	"time"
	"unicode/utf8"
)

// Size is the longest chunk, in bytes. A line longer than it is cut at it.
const Size = 4096

// Gap is how long a terminal stream stays quiet after a write before what is held is a
// chunk: long enough that one redraw, written in several system calls, stays one chunk,
// and short enough that what the user sees is soon in the record.
const Gap = 50 * time.Millisecond

// Writer is an io.Writer for a pipe that hands complete chunks to emit as they form: at
// every newline, inclusive, and at Size bytes. What remains is held until the next write
// or [Writer.Flush]. It is safe for concurrent writes; chunks are emitted in write order.
type Writer struct {
	emit func([]byte)
	mu   sync.Mutex
	buf  []byte
}

// New returns a writer that hands each chunk to emit. The slice passed to emit is the
// callee's; the writer does not reuse it.
func New(emit func([]byte)) *Writer {
	return &Writer{emit: emit}
}

// Write cuts p, with what was held, into chunks. It never fails.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		n := -1
		for i, b := range w.buf {
			if b == '\n' || i+1 == Size {
				n = i + 1
				break
			}
		}
		if n < 0 {
			return len(p), nil
		}
		chunk := make([]byte, n)
		copy(chunk, w.buf[:n])
		w.buf = w.buf[n:]
		w.emit(chunk)
	}
}

// Flush emits what is held, if anything, as a final chunk.
func (w *Writer) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) == 0 {
		return
	}
	chunk := w.buf
	w.buf = nil
	w.emit(chunk)
}

// Terminal is an io.Writer for a pseudo-terminal's output that hands chunks to emit at
// Size bytes, and once no write has come for the gap. A chunk is never cut inside a
// multibyte character: at Size the character that would straddle the cut starts the
// next chunk, and at the gap the bytes of a character whose rest has not arrived wait
// for it. A stream that never pauses is cut at Size; what is held when the stream ends
// goes out on [Terminal.Flush]. It is safe for concurrent writes; chunks are emitted in
// write order, the gap's from the timer's goroutine.
type Terminal struct {
	emit  func([]byte)
	gap   time.Duration
	mu    sync.Mutex
	buf   []byte
	last  time.Time
	timer *time.Timer
}

// NewTerminal returns a terminal writer that hands each chunk to emit, cutting after
// gap of quiet; zero means [Gap]. The slice passed to emit is the callee's.
func NewTerminal(emit func([]byte), gap time.Duration) *Terminal {
	if gap <= 0 {
		gap = Gap
	}
	return &Terminal{emit: emit, gap: gap}
}

// Write holds p after what was held, emits every full Size of it, and arms the gap for
// the rest. It never fails.
func (t *Terminal) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	t.last = time.Now()
	for len(t.buf) >= Size {
		t.cut(boundary(t.buf, Size))
	}
	if len(t.buf) > 0 {
		t.arm(t.gap)
	}
	return len(p), nil
}

// arm has quiet run after d. The timer is one and reused: a write inside the gap moves
// it, so a stream that never pauses never fires it and is cut at Size instead.
func (t *Terminal) arm(d time.Duration) {
	if t.timer == nil {
		t.timer = time.AfterFunc(d, t.quiet)
		return
	}
	t.timer.Reset(d)
}

// quiet emits what is held once the gap has passed since the last write. A timer that
// fires early, because a write moved it while it was firing, is armed again for the
// remainder.
func (t *Terminal) quiet() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.buf) == 0 {
		return
	}
	if since := time.Since(t.last); since < t.gap {
		t.arm(t.gap - since)
		return
	}
	if n := whole(t.buf); n > 0 {
		t.cut(n)
	}
}

// cut emits the first n held bytes as a chunk.
func (t *Terminal) cut(n int) {
	chunk := make([]byte, n)
	copy(chunk, t.buf[:n])
	t.buf = t.buf[n:]
	t.emit(chunk)
}

// Flush emits what is held, if anything, as a final chunk, an incomplete character
// included: the stream is over and its rest is not coming.
func (t *Terminal) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timer.Stop()
	}
	if len(t.buf) == 0 {
		return
	}
	t.cut(len(t.buf))
}

// boundary is where to cut buf for a chunk of at most n bytes, n at most len(buf): at
// n, or before the multibyte character that would straddle n, and at n after all when
// the bytes around it are not UTF-8.
func boundary(buf []byte, n int) int {
	// Nothing follows n: no character can straddle it.
	if n >= len(buf) {
		return n
	}
	for i := n; i > n-utf8.UTFMax && i > 0; i-- {
		if utf8.RuneStart(buf[i]) {
			return i
		}
	}
	return n
}

// whole is the length of the longest prefix of buf that ends on a character boundary:
// the lead byte of a multibyte character, and the continuation bytes after it, whose
// rest has not arrived are left out. Bytes that are not UTF-8 count as whole.
func whole(buf []byte) int {
	for back := 1; back < utf8.UTFMax && back <= len(buf); back++ {
		i := len(buf) - back
		if buf[i] < utf8.RuneSelf {
			return len(buf)
		}
		if !utf8.RuneStart(buf[i]) {
			continue
		}
		if !utf8.FullRune(buf[i:]) {
			return i
		}
		return len(buf)
	}
	return len(buf)
}
