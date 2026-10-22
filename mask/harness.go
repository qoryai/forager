package mask

import (
	"bytes"
	"hash/maphash"
	"io"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// The rule of a harness masker: text counts as a harness file's once it matches at
// least HarnessLines consecutive lines of the file, or at least HarnessChars
// consecutive characters of it.
const (
	// HarnessLines is the fewest consecutive lines of a harness file that count as its
	// text. A line matches when it is the same as the file's line once the whitespace
	// at its start and its end is left out. Lines that are empty once that whitespace
	// is left out are skipped on both sides.
	HarnessLines = 3
	// HarnessChars is the fewest consecutive characters of a harness file that count
	// as its text, line breaks included.
	HarnessChars = 200
)

// gram is the length in bytes of the pieces of a file the masker looks up, and step
// the distance between the pieces it indexes: every span of HarnessChars bytes of a
// file contains one indexed piece whole.
const (
	gram = 32
	step = HarnessChars - gram + 1
)

// most is the most places one key of the index lists: a line triple or a piece that
// many files share is looked for in the first files alone.
const most = 8

// filterShift is how far a piece's hash is shifted right to give its bit in the filter
// in front of the index of pieces, and filterBits the filter's size in bits.
const (
	filterShift = 64 - 20
	filterBits  = 1 << 20
)

// HarnessFile is one file of a harness home: Path, its path relative to the home with
// slashes, such as skills/implement/SKILL.md, and Text, its bytes.
type HarnessFile struct {
	Path string
	Text []byte
}

// Harness masks the text of the files of a harness home: [Harness.Replace] in a
// string, and the writer of [Harness.Writer] in a stream. Each piece of text that
// counts as a file's, by the rule of HarnessLines and HarnessChars, is replaced with
// [harness text: <path>], and pieces of one file next to each other, or apart by
// whitespace alone, are replaced with one such text. <path> is the file's Path without
// its control characters, such as the escape character of a terminal's codes, and
// without bidirectional marks, and with " and \ escaped as in a JSON string, so a
// replacement never ends a JSON string. Text is
// matched as it is, and also with its JSON escapes decoded, such as \n, \" and \u00e9,
// so the text inside a JSON string in a stream is found too; a line that starts with a
// line number and a tab or an arrow, as a file read with line numbers shows it,
// matches without the number. Carriage returns before line breaks are left out of the
// match. A run of a pattern of up to four bytes, such as a line of = or of spaces,
// counts toward a match of characters next to other text of the file, and is no match
// by itself; whitespace at either end of a match stays. The cost of Replace is
// linear in the text. A nil Harness replaces nothing. A Harness is safe for concurrent
// use.
type Harness struct {
	files []harnessFile
	seed  maphash.Seed
	// triples lists, for the hash of each HarnessLines consecutive lines of a file that
	// are not blank, the files that contain them; nil when no file has that many lines.
	triples map[uint64][]int32
	// lines maps the hash of each line of the files that is not blank to the first
	// file that has it, and longest is the length of the longest one.
	lines   map[uint64]int32
	longest int
	// periodic lists the lines of the files longer than keepMost/2 bytes that repeat a
	// pattern of up to period bytes, which no piece of the index contains.
	periodic []periodicLine
	// pieces lists, for the rolling hash of each indexed piece, its places; nil when
	// no file has HarnessChars bytes. filter has a bit set for each of those hashes.
	pieces map[uint64][]place
	filter []uint64
	// base is the rolling hash's base, and top base to the power gram-1.
	base, top uint64
}

// harnessFile is a file of the harness, with its text's carriage returns before line
// breaks left out, and its replacement text as it is and JSON-escaped.
type harnessFile struct {
	text      []byte
	put, json []byte
}

// periodicLine is a line of file that repeats pattern, of length bytes with its
// whitespace left out.
type periodicLine struct {
	file    int32
	pattern string
	length  int
}

// place is a piece's file and its offset in the file.
type place struct{ file, at int32 }

// ForHarness returns the masker of files, which keeps the files' Text slices; the
// caller does not change them. With no file it returns nil.
func ForHarness(files []HarnessFile) *Harness {
	if len(files) == 0 {
		return nil
	}
	h := &Harness{seed: maphash.MakeSeed(), base: rand.Uint64() | 1, lines: map[uint64]int32{}, triples: map[uint64][]int32{}, pieces: map[uint64][]place{}}
	h.top = 1
	for range gram - 1 {
		h.top *= h.base
	}
	for i, f := range files {
		put := []byte("[harness text: " + string(jsonEscaped([]byte(cleanPath(f.Path)), false, false)) + "]")
		text := f.Text
		if bytes.Contains(text, []byte("\r\n")) {
			text = bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n"))
		}
		h.files = append(h.files, harnessFile{text: text, put: put, json: jsonEscaped(put, false, false)})
		h.indexLines(int32(i), text)
		h.indexPieces(int32(i), text)
	}
	if len(h.triples) == 0 {
		h.triples = nil
	}
	if len(h.pieces) == 0 {
		h.pieces = nil
	} else {
		h.filter = make([]uint64, filterBits/64)
		for k := range h.pieces {
			b := k >> filterShift
			h.filter[b/64] |= 1 << (b % 64)
		}
	}
	return h
}

// cleanPath is p as a replacement contains it: valid UTF-8 without control characters
// and bidirectional marks, so a terminal that shows a replacement moves no cursor,
// changes no colour and reverses no text for the path.
func cleanPath(p string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(p, ""))
}

// indexLines adds the lines of file f, its text, to the set of lines and the index of
// triples.
func (h *Harness) indexLines(f int32, text []byte) {
	var hashes []uint64
	for line := range bytes.SplitSeq(text, []byte("\n")) {
		t := bytes.TrimSpace(line)
		if len(t) == 0 {
			continue
		}
		k := maphash.Bytes(h.seed, t)
		if _, in := h.lines[k]; !in {
			h.lines[k] = f
		}
		h.longest = max(h.longest, len(t))
		if len(t) > keepMost/2 {
			if p := periodOf(t); p > 0 {
				h.periodic = append(h.periodic, periodicLine{file: f, pattern: string(t[:p]), length: len(t)})
			}
		}
		hashes = append(hashes, k)
	}
	for j := 0; j+HarnessLines <= len(hashes); j++ {
		k := h.triple(hashes[j], hashes[j+1], hashes[j+2])
		if l := h.triples[k]; len(l) < most && (len(l) == 0 || l[len(l)-1] != f) {
			h.triples[k] = append(l, f)
		}
	}
}

// indexPieces adds the pieces of file f, its text, at every step-th offset. A piece
// that repeats a pattern of up to period bytes is left out, and the pieces at the ends
// of the run of that pattern it lies in are added in its place: the piece that starts
// one byte before the run, and the piece that ends one byte after it. Every span of
// HarnessChars bytes of the file that is not all one such run then contains an
// indexed piece whole.
func (h *Harness) indexPieces(f int32, text []byte) {
	if len(text) < HarnessChars {
		return
	}
	add := func(at int) {
		if at < 0 || at+gram > len(text) {
			return
		}
		k := h.roll(text[at : at+gram])
		if l := h.pieces[k]; len(l) < most && !slices.Contains(l, place{file: f, at: int32(at)}) {
			h.pieces[k] = append(l, place{file: f, at: int32(at)})
		}
	}
	runEnd := -1
	for at := 0; at+gram <= len(text); at += step {
		p := periodOf(text[at : at+gram])
		if p == 0 {
			add(at)
			continue
		}
		if at+gram <= runEnd {
			continue
		}
		start, end := at, at+gram
		for start > 0 && text[start-1] == text[start-1+p] {
			start--
		}
		for end < len(text) && text[end] == text[end-p] {
			end++
		}
		add(start - 1)
		add(end - gram + 1)
		runEnd = end
	}
}

// triple is the hash of three line hashes in their order.
func (h *Harness) triple(a, b, c uint64) uint64 {
	return maphash.Comparable(h.seed, [3]uint64{a, b, c})
}

// roll is the rolling hash of b, gram bytes.
func (h *Harness) roll(b []byte) uint64 {
	var k uint64
	for _, c := range b {
		k = k*h.base + uint64(c)
	}
	return k
}

// span is a piece of text that counts as file's, from start to end, and whether it
// lies in a JSON string, where its replacement is JSON-escaped.
type span struct {
	start, end int
	file       int32
	json       bool
}

// view is the text the masker matches, made from raw bytes: the bytes as they are, or
// with their JSON escapes decoded, with the carriage returns before line breaks left
// out either way. from and to are, for each byte of text, where the raw bytes it was
// made from start and end; nil when text is the raw bytes.
type view struct {
	text     []byte
	from, to []int32
	json     bool
}

// rawStart is where the raw bytes of text from i on start.
func (v *view) rawStart(i int, raw int) int {
	switch {
	case v.from == nil:
		return i
	case i >= len(v.text):
		return raw
	}
	return int(v.from[i])
}

// rawEnd is where the raw bytes of text before i end.
func (v *view) rawEnd(i int) int {
	switch {
	case v.to == nil:
		return i
	case i == 0:
		return 0
	}
	return int(v.to[i-1])
}

// plainView is b as the masker matches it as it is.
func plainView(b []byte) view {
	if !bytes.Contains(b, []byte("\r\n")) {
		return view{text: b}
	}
	v := view{text: make([]byte, 0, len(b)), from: make([]int32, 0, len(b)), to: make([]int32, 0, len(b))}
	for i, c := range b {
		v.add(c, i, i+1)
	}
	return v
}

// add appends c, made from raw[from:to], to v, and leaves out a carriage return
// before c when c is a line break: the line break then starts where the carriage
// return did.
func (v *view) add(c byte, from, to int) {
	if c == '\n' && len(v.text) > 0 && v.text[len(v.text)-1] == '\r' {
		v.text[len(v.text)-1] = '\n'
		v.to[len(v.to)-1] = int32(to)
		return
	}
	v.text = append(v.text, c)
	v.from = append(v.from, int32(from))
	v.to = append(v.to, int32(to))
}

// jsonView is b with its JSON escapes decoded, and each quote that no backslash escapes
// as a zero byte, which ends a line and matches no file's byte: such a quote starts or
// ends a JSON string. An escape that is not whole is left as it is.
func jsonView(b []byte) view {
	v := view{text: make([]byte, 0, len(b)), from: make([]int32, 0, len(b)), to: make([]int32, 0, len(b)), json: true}
	var r [utf8.UTFMax]byte
	for i := 0; i < len(b); {
		c := b[i]
		if c == '"' {
			v.add(0, i, i+1)
			i++
			continue
		}
		if c != '\\' || i+1 == len(b) {
			v.add(c, i, i+1)
			i++
			continue
		}
		var d byte
		switch b[i+1] {
		case 'n':
			d = '\n'
		case 't':
			d = '\t'
		case 'r':
			d = '\r'
		case 'b':
			d = '\b'
		case 'f':
			d = '\f'
		case '/', '\\', '"':
			d = b[i+1]
		case 'u':
			code, n := unicodeEscape(b[i:])
			if n == 0 {
				v.add(c, i, i+1)
				i++
				continue
			}
			for _, e := range r[:utf8.EncodeRune(r[:], code)] {
				v.add(e, i, i+n)
			}
			i += n
			continue
		default:
			v.add(c, i, i+1)
			i++
			continue
		}
		v.add(d, i, i+2)
		i += 2
	}
	return v
}

// unicodeEscape is the character of the \uXXXX escape b starts with, a pair of
// surrogates included, and the escape's length; 0 when b starts with none.
func unicodeEscape(b []byte) (rune, int) {
	hex := func(b []byte) (rune, bool) {
		if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
			return 0, false
		}
		var r rune
		for _, c := range b[2:6] {
			switch {
			case '0' <= c && c <= '9':
				r = r<<4 | rune(c-'0')
			case 'a' <= c && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case 'A' <= c && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	r, ok := hex(b)
	if !ok {
		return 0, 0
	}
	if 0xD800 <= r && r < 0xDC00 {
		if lo, ok := hex(b[6:]); ok && 0xDC00 <= lo && lo < 0xE000 {
			return (r-0xD800)<<10 | (lo - 0xDC00) + 0x10000, 12
		}
	}
	if 0xD800 <= r && r < 0xE000 {
		return utf8.RuneError, 6
	}
	return r, 6
}

// lineBreak reports whether c ends a line of a view.
func lineBreak(c byte) bool { return c == '\n' || c == 0 }

// textLine is a line of a view that is not blank: where it starts and ends with its
// whitespace left out, the hash it is matched by, and, for a line that starts with a
// line number, the hash of the line with the number, alt.
type textLine struct {
	start, end int
	key, alt   uint64
	numbered   bool
}

// numberedLine is the part of line after a line number at its start, which follows
// whitespace and ends in a tab or an arrow, and whether line has one.
func numberedLine(line []byte) ([]byte, bool) {
	t := bytes.TrimLeftFunc(line, unicode.IsSpace)
	d := 0
	for d < len(t) && d < 10 && '0' <= t[d] && t[d] <= '9' {
		d++
	}
	switch {
	case d == 0:
		return line, false
	case d < len(t) && t[d] == '\t':
		return t[d+1:], true
	case bytes.HasPrefix(t[d:], []byte("→")):
		return t[d+len("→"):], true
	}
	return line, false
}

// lineOf is line, which starts at offset in its view, as the masker matches it; false
// for a blank line.
func (h *Harness) lineOf(line []byte, offset int) (textLine, bool) {
	content, numbered := numberedLine(line)
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return textLine{}, false
	}
	whole := bytes.TrimLeftFunc(line, unicode.IsSpace)
	start := offset + len(line) - len(whole)
	whole = bytes.TrimRightFunc(whole, unicode.IsSpace)
	l := textLine{start: start, end: start + len(whole), key: maphash.Bytes(h.seed, content), numbered: numbered}
	if numbered {
		l.alt = maphash.Bytes(h.seed, whole)
	}
	return l, true
}

// lineSpans appends the spans of HarnessLines or more consecutive lines of v that are
// lines of one file, those of one file next to each other merged. prior is the lines
// of the files before v with blank lines alone after them, which count as lines at the
// start of v: a run that starts in them starts at 0.
func (h *Harness) lineSpans(v *view, spans []span, prior []textLine) []span {
	if h.triples == nil {
		return spans
	}
	var lines []textLine
	for _, l := range prior {
		l.start, l.end = 0, 0
		lines = append(lines, l)
	}
	t := v.text
	for s := 0; s < len(t); {
		e := s
		for e < len(t) && !lineBreak(t[e]) {
			e++
		}
		if e-s <= h.longest+64 {
			if l, ok := h.lineOf(t[s:e], s); ok {
				lines = append(lines, l)
			}
		} else {
			// A line longer than every line of the files, with room for its whitespace
			// and a number, matches none: it ends a run of lines.
			lines = append(lines, textLine{start: s, end: e, key: 0})
		}
		s = e + 1
	}
	var files []int32
	first, last := -1, -1
	closeRun := func() {
		if first >= 0 {
			spans = append(spans, span{start: lines[first].start, end: lines[last].end, file: files[0], json: v.json})
		}
		first, last = -1, -1
	}
	for w := 0; w+HarnessLines <= len(lines); w++ {
		a, b, c := lines[w], lines[w+1], lines[w+2]
		found := h.triples[h.triple(a.key, b.key, c.key)]
		if found == nil && (a.numbered || b.numbered || c.numbered) {
			found = h.triples[h.triple(a.altKey(), b.altKey(), c.altKey())]
		}
		if found == nil {
			continue
		}
		if first >= 0 && w <= last+1 {
			if both := shared(files, found); len(both) > 0 {
				files, last = both, w+HarnessLines-1
				continue
			}
			start := max(w, last+1)
			closeRun()
			first, last, files = start, w+HarnessLines-1, slices.Clone(found)
			continue
		}
		closeRun()
		first, last, files = w, w+HarnessLines-1, slices.Clone(found)
	}
	closeRun()
	return spans
}

// altKey is the hash l is matched by with its line number.
func (l textLine) altKey() uint64 {
	if l.numbered {
		return l.alt
	}
	return l.key
}

// shared is the files of a that b lists too, in a's order.
func shared(a, b []int32) []int32 {
	var out []int32
	for _, f := range a {
		if slices.Contains(b, f) {
			out = append(out, f)
		}
	}
	return out
}

// charSpans appends the spans of HarnessChars or more consecutive characters of v that
// are characters of one file. Each piece of v whose hash is a piece's of the index is
// compared with the file at that place, and the match is extended both ways; a match
// along a diagonal, the difference between the offsets in v and in the file, is
// extended once. A piece that repeats a pattern of up to period bytes is not looked
// up, as it is not indexed.
func (h *Harness) charSpans(v *view, spans []span) []span {
	t := v.text
	if h.pieces == nil || len(t) < HarnessChars {
		return spans
	}
	var seen map[[2]int64]int
	// covered is the end of the spans found so far.
	covered := 0
	i, k := 0, h.roll(t[:gram])
	for {
		if b := k >> filterShift; h.filter[b/64]&(1<<(b%64)) != 0 && periodOf(t[i:i+gram]) == 0 {
			for _, p := range h.pieces[k] {
				text := h.files[p.file].text
				at := int(p.at)
				diagonal := [2]int64{int64(p.file), int64(at - i)}
				if seen[diagonal] >= i+gram || !bytes.Equal(t[i:i+gram], text[at:at+gram]) {
					continue
				}
				end, fe := i+gram, at+gram
				for end < len(t) && fe < len(text) && t[end] == text[fe] {
					end, fe = end+1, fe+1
				}
				start, fs := i, at
				for low := max(0, i-4*HarnessChars); start > low && fs > 0 && t[start-1] == text[fs-1]; {
					start, fs = start-1, fs-1
				}
				if seen == nil {
					seen = map[[2]int64]int{}
				}
				seen[diagonal] = end
				if s, ok := whole(t, start, end); ok {
					spans = append(spans, span{start: s.start, end: s.end, file: p.file, json: v.json})
					covered = max(covered, end)
				}
			}
		}
		if i+gram >= len(t) {
			break
		}
		// The pieces inside a span found, up to HarnessChars bytes before its end, are
		// not looked up: a match that reaches past the end has an indexed piece after
		// that point.
		if j := covered - HarnessChars; j > i+1 {
			i, k = j, h.roll(t[j:j+gram])
			continue
		}
		k = (k-uint64(t[i])*h.top)*h.base + uint64(t[i+gram])
		i++
	}
	return spans
}

// period is the longest pattern whose repeats the index of pieces leaves out: a piece
// such as 32 bytes of =, of spaces or of "- " is found at as many places in a text as
// the text repeats it, each a match to extend. A piece of the text that repeats such a
// pattern is not looked up.
const period = 4

// periodOf is the length of the shortest pattern of up to period bytes that b
// repeats; 0 when it repeats none.
func periodOf(b []byte) int {
	for p := 1; p <= period; p++ {
		j := p
		for j < len(b) && b[j] == b[j-p] {
			j++
		}
		if j == len(b) {
			return p
		}
	}
	return 0
}

// whole is t[start:end] without the bytes of a character cut at either end, and whether
// it has HarnessChars characters.
func whole(t []byte, start, end int) (span, bool) {
	for start < end && !utf8.RuneStart(t[start]) {
		start++
	}
	for end > start && end < len(t) && !utf8.RuneStart(t[end]) {
		end--
	}
	return span{start: start, end: end}, utf8.RuneCount(t[start:end]) >= HarnessChars
}

// keep is where the bytes of v start that a match may still begin in once more bytes
// follow: the last HarnessChars-1 characters, and the last line, unless it is longer
// than every line of the files, with up to HarnessLines-1 lines before it that are
// lines of the files and up to 64 blank lines among them. It appends to spans a span
// for each line of the files that the limit of blank lines leaves out of that, up to
// HarnessLines-1 lines in all, as a later line may still make a run of them.
func (h *Harness) keep(v *view, spans []span) (int, []span) {
	t := v.text
	from := len(t)
	if h.pieces != nil {
		i, c := len(t), 0
		for i > 0 && c < HarnessChars-1 {
			i--
			if utf8.RuneStart(t[i]) {
				c++
			}
		}
		from = i
	}
	if h.triples == nil {
		return from, spans
	}
	s := len(t)
	for s > 0 && !lineBreak(t[s-1]) {
		s--
	}
	last := t[s:]
	if content, _ := numberedLine(last); len(bytes.TrimSpace(content)) > h.longest {
		return from, spans
	}
	lines := s
	found, blanks := 0, 0
	for found < HarnessLines-1 && s > 0 && blanks < 64 {
		e := s - 1
		s = e
		for s > 0 && !lineBreak(t[s-1]) {
			s--
		}
		l, ok := h.lineOf(t[s:e], s)
		if !ok {
			blanks++
			continue
		}
		if _, in := h.lines[l.key]; !in {
			if _, alt := h.lines[l.alt]; !l.numbered || !alt {
				break
			}
		}
		lines = s
		found++
	}
	for blanks == 64 && found < HarnessLines-1 && s > 0 {
		e := s - 1
		s = e
		for s > 0 && !lineBreak(t[s-1]) {
			s--
		}
		if e-s > h.longest+64 {
			break
		}
		l, ok := h.lineOf(t[s:e], s)
		if !ok {
			continue
		}
		f, in := h.fileOf(l)
		if !in {
			break
		}
		spans = append(spans, span{start: l.start, end: l.end, file: f, json: v.json})
		found++
	}
	return min(from, lines), spans
}

// fileOf is the first file that has l, and whether one has it.
func (h *Harness) fileOf(l textLine) (int32, bool) {
	f, in := h.lines[l.key]
	if !in && l.numbered {
		f, in = h.lines[l.alt]
	}
	return f, in
}

// keepMost is the most raw bytes after the start that keep gives that the writer keeps
// back: more, and capped moves that start on.
const keepMost = 64 << 10

// capped is k, the start of the bytes of v that keep gives, moved on to the last
// keepMost of the raw bytes, which number raw, when there are more; and spans, of
// which those from n on are spans of v, with spans added that mask the lines of the
// files that the move writes. When a span of v contains the new start, a span of its
// file masks the bytes from k to it; otherwise a span masks each line between k and
// the new start that is a line of the files, with the file that has it, and the last
// line of v when it repeats the pattern of a line of the files at least as long.
func (h *Harness) capped(v *view, k, raw int, spans []span, n int) (int, []span) {
	if raw-v.rawStart(k, raw) <= keepMost {
		return k, spans
	}
	t := v.text
	cut := len(t) - keepMost
	if v.from != nil {
		cut = sort.Search(len(t), func(i int) bool { return int(v.from[i]) >= raw-keepMost })
	}
	for i := 0; i < utf8.UTFMax-1 && cut > k && cut < len(t) && !utf8.RuneStart(t[cut]); i++ {
		cut--
	}
	if cut <= k {
		return k, spans
	}
	in := -1
	for j := n; j < len(spans); j++ {
		if s := spans[j]; s.start < cut && cut < s.end && (in < 0 || s.start < spans[in].start) {
			in = j
		}
	}
	if in >= 0 {
		if s := spans[in]; s.start > k {
			spans = append(spans, span{start: k, end: s.start, file: s.file, json: v.json})
		}
		return cut, spans
	}
	for s := k; s < cut; {
		e := s
		for e < len(t) && !lineBreak(t[e]) {
			e++
		}
		if l, ok := h.lineOf(t[s:e], s); ok {
			f, found := h.fileOf(l)
			if !found && e == len(t) {
				f, found = h.periodicFile(t[l.start:l.end])
			}
			if found {
				spans = append(spans, span{start: l.start, end: l.end, file: f, json: v.json})
			}
		}
		s = e + 1
	}
	return cut, spans
}

// periodicFile is the file of a line of the files that repeats the pattern line
// repeats, with its line number left out, and is at least as long; false for none.
func (h *Harness) periodicFile(line []byte) (int32, bool) {
	if len(h.periodic) == 0 {
		return 0, false
	}
	content, _ := numberedLine(line)
	content = bytes.TrimSpace(content)
	p := periodOf(content)
	if p == 0 {
		return 0, false
	}
	for _, l := range h.periodic {
		if len(l.pattern) == p && l.pattern == string(content[:p]) && l.length >= len(content) {
			return l.file, true
		}
	}
	return 0, false
}

// find is the spans of b, merged and in order, and, unless final, where the bytes of b
// start that a match may still begin in once more bytes follow; len(b) when final.
// prior is the lines of the files before b, as lineSpans counts them in b as it is.
func (h *Harness) find(b []byte, final bool, prior []textLine) ([]span, int) {
	views := []view{plainView(b)}
	if bytes.IndexByte(b, '\\') >= 0 {
		views = append(views, jsonView(b))
	}
	var spans []span
	from := len(b)
	for i := range views {
		v := &views[i]
		n := len(spans)
		if v.json {
			spans = h.lineSpans(v, spans, nil)
		} else {
			spans = h.lineSpans(v, spans, prior)
		}
		spans = h.charSpans(v, spans)
		if !final {
			var k int
			k, spans = h.keep(v, spans)
			k, spans = h.capped(v, k, len(b), spans, n)
			from = min(from, v.rawStart(k, len(b)))
		}
		for j := n; j < len(spans); j++ {
			spans[j].start, spans[j].end = v.rawStart(spans[j].start, len(b)), v.rawEnd(spans[j].end)
		}
	}
	return trimmed(b, merged(b, spans)), from
}

// trimmed is spans, each without the whitespace at its start and its end, JSON escapes
// of a line break, a tab and a carriage return included, so the line breaks around a
// replacement stay.
func trimmed(b []byte, spans []span) []span {
	out := spans[:0]
	for _, s := range spans {
		for s.start < s.end {
			if n := space(b[s.start:s.end]); n > 0 {
				s.start += n
				continue
			}
			break
		}
		for s.end > s.start {
			if n := spaceBefore(b[s.start:s.end]); n > 0 {
				s.end -= n
				continue
			}
			break
		}
		if s.start < s.end {
			out = append(out, s)
		}
	}
	return out
}

// space is the length of the whitespace or the JSON escape of whitespace that b starts
// with; 0 when b starts with neither.
func space(b []byte) int {
	switch {
	case len(b) == 0:
		return 0
	case b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r' || b[0] == '\v' || b[0] == '\f':
		return 1
	case len(b) > 1 && b[0] == '\\' && (b[1] == 'n' || b[1] == 't' || b[1] == 'r'):
		return 2
	}
	return 0
}

// spaceBefore is the length of the whitespace or the JSON escape of whitespace that b
// ends with; 0 when b ends with neither. A backslash before the escape's backslash
// makes it no escape.
func spaceBefore(b []byte) int {
	n := len(b)
	switch {
	case n == 0:
		return 0
	case b[n-1] == ' ' || b[n-1] == '\t' || b[n-1] == '\n' || b[n-1] == '\r' || b[n-1] == '\v' || b[n-1] == '\f':
		return 1
	case n > 1 && b[n-2] == '\\' && (b[n-1] == 'n' || b[n-1] == 't' || b[n-1] == 'r') && (n == 2 || b[n-3] != '\\'):
		return 2
	}
	return 0
}

// merged is spans in order of their starts, those of one file that overlap, touch or
// lie apart by whitespace alone merged into one, and of two that overlap with another
// file the later one from the end of the earlier on.
func merged(b []byte, spans []span) []span {
	if len(spans) < 2 {
		return spans
	}
	slices.SortFunc(spans, func(x, y span) int {
		if x.start != y.start {
			return x.start - y.start
		}
		return y.end - x.end
	})
	out := spans[:1]
	for _, s := range spans[1:] {
		p := &out[len(out)-1]
		if s.start <= p.end || blank(b[p.end:s.start]) {
			if s.file == p.file {
				p.end = max(p.end, s.end)
				p.json = p.json || s.json
				continue
			}
			if s.end <= p.end {
				continue
			}
			s.start = max(s.start, p.end)
		}
		out = append(out, s)
	}
	return out
}

// blank reports whether b is whitespace alone, a JSON escape of a line break, a tab
// or a carriage return included, or lines that are blank after a line number, as a
// file read with line numbers shows its blank lines, the last of them maybe only the
// start of its number.
func blank(b []byte) bool {
	for c := b; ; {
		if len(c) == 0 {
			return true
		}
		n := space(c)
		if n == 0 {
			break
		}
		c = c[n:]
	}
	for rest := b; len(rest) > 0; {
		line := rest
		i := bytes.IndexByte(rest, '\n')
		if i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		if content, _ := numberedLine(line); len(bytes.TrimSpace(content)) == 0 {
			continue
		}
		if t := bytes.TrimLeft(line, " \t\r\v\f"); i < 0 && len(t) <= 10 && digits(t) {
			continue
		}
		return false
	}
	return true
}

// digits reports whether b is ASCII digits alone.
func digits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// put is the replacement text of s.
func (h *Harness) put(s span) []byte {
	if s.json {
		return h.files[s.file].json
	}
	return h.files[s.file].put
}

// Replace is s with each piece of text that counts as a file's replaced; a nil Harness
// returns s.
func (h *Harness) Replace(s string) string {
	if h == nil || len(s) < HarnessChars && lineCount(s) < HarnessLines {
		return s
	}
	b := []byte(s)
	spans, _ := h.find(b, true, nil)
	if len(spans) == 0 {
		return s
	}
	var out []byte
	at := 0
	for _, sp := range spans {
		out = append(append(out, b[at:sp.start]...), h.put(sp)...)
		at = sp.end
	}
	return string(append(out, b[at:]...))
}

// lineCount is the most lines a view of s has: one, plus one for each line break,
// zero byte, quote and JSON escape of a line break in s.
func lineCount(s string) int {
	n := 1
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\n', s[i] == '"', s[i] == 0:
			n++
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == 'n':
			n++
		}
	}
	return n
}

// Writer returns a writer that writes to w what is written to it, with each piece of
// text that counts as a file's replaced. With a nil Harness it writes to w what it is
// given.
func (h *Harness) Writer(w io.Writer) *HarnessWriter {
	return &HarnessWriter{w: w, h: h, open: -1}
}

// HarnessWriter is the writer of [Harness.Writer]. It keeps back the end of the
// stream that a match may still begin in, and writes it with a later write or on
// Flush: the last HarnessChars-1 characters; the last line, unless it is longer than
// the longest line of the files; and up to HarnessLines-1 lines before it that are
// lines of the files, with up to 64 blank lines among them. A blank line after a line
// number, as a file read with line numbers shows it, is blank. When more blank lines
// follow those lines of the files, it writes them replaced, each with the replacement
// of a file that has the line. It remembers the last HarnessLines-1 lines of the
// files that it wrote with blank lines alone after them, so a later line that makes a
// run of lines with them is replaced too. It keeps back at most the last 64 KiB: when
// there are more, it writes the bytes before the last 64 KiB with the lines of the
// files among them replaced, with the replacement of the match that continues past
// that point when there is one, and otherwise each with the replacement of a file
// that has the line; a last line that repeats the pattern of a line of the files at
// least as long is replaced too. Once a replacement is written for a match that
// reaches the end of what was written, it keeps the end of the match as well, up to
// 64 KiB, so the rest of the match that follows in later writes is part of that
// replacement. After a write the writer keeps back at most 192 KiB, 12 bytes and the
// write: up to 64 KiB of that match, up to 64 KiB of whitespace after it, up to 64
// KiB more, and up to 12 bytes of a line number before them. Each write scans what
// the writer keeps back and the write, so the cost of a stream is linear in its
// length, and writes of one byte cost the most: on an Apple M5 Max on 2026-10-22, 0.1
// s per MiB with files of short lines, and after 100 KiB of one line, with a file of
// a line of 1 MiB, 190 s per MiB of other text and 90 s per MiB of the file's text.
// It is safe for concurrent writes.
type HarnessWriter struct {
	w  io.Writer
	h  *Harness
	mu sync.Mutex
	// buf is the stream from where the writer has not written on, after seen bytes
	// that it has written, the end of the match it wrote last.
	buf  []byte
	seen int
	// open is the file of the match the writer wrote last when that match ended at
	// seen; -1 for none.
	open int32
	// prior is what the writer remembers of the lines before buf.
	prior lineMemory
}

// lineMemory is what a HarnessWriter remembers of the lines of the stream before its
// buffer: up to HarnessLines-1 lines of the files with blank lines alone after them,
// the last in lines[n-1], and the state of the start of the buffer's first line,
// which lies before the buffer.
type lineMemory struct {
	lines  [HarnessLines - 1]textLine
	n      int
	head   lineHead
	digits int
}

// lineHead is the state of the start of a line: whitespace alone or nothing; then
// digits; then one or two bytes of the arrow after them; then the tab or the arrow
// after them and whitespace, a line number as a file read with line numbers shows it;
// or other text.
type lineHead byte

const (
	headBlank lineHead = iota
	headDigits
	headArrow1
	headArrow2
	headNumbered
	headText
)

// next is the state after c.
func (s lineHead) next(c byte, digits *int) lineHead {
	space := c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'
	switch {
	case s == headBlank && space, s == headNumbered && space:
		return s
	case (s == headBlank || s == headDigits) && '0' <= c && c <= '9':
		if s == headBlank {
			*digits = 0
		}
		if *digits++; *digits > 10 {
			return headText
		}
		return headDigits
	case s == headDigits && c == '\t':
		return headNumbered
	case s == headDigits && c == 0xe2:
		return headArrow1
	case s == headArrow1 && c == 0x86:
		return headArrow2
	case s == headArrow2 && c == 0x92:
		return headNumbered
	}
	return headText
}

// remembered is the lines of m as lineSpans takes them.
func (m *lineMemory) remembered() []textLine { return m.lines[:m.n] }

// carry is m after the writer drops the bytes of b before keep, and keep, moved back
// to the start of a line number that the bytes before it end in, with the part of an
// arrow after it, so the buffer starts with the whole number.
func (h *Harness) carry(m lineMemory, b []byte, keep int) (lineMemory, int) {
	if h.triples == nil {
		return m, keep
	}
	ls := bytes.LastIndexAny(b[:keep], "\n\x00") + 1
	head := m.head
	if ls > 0 {
		head = headBlank
	}
	start := -1
	for i := ls; i < keep && head != headText; i++ {
		was := head
		if head = head.next(b[i], &m.digits); was == headBlank && head == headDigits {
			start = i
		}
	}
	if ls > 0 {
		// The last lines of the files before ls, newest first, up to a line that ends a
		// run of lines; the lines remembered before b count only when none does.
		var found [HarnessLines - 1]textLine
		n, ended := 0, false
		for e := ls - 1; e >= 0 && n < len(found); {
			s := bytes.LastIndexAny(b[:e], "\n\x00") + 1
			l, kind := h.lineKind(b[s:e])
			switch {
			case s == 0 && m.head == headText, kind == lineEnds:
				ended = true
			case kind == lineOfFiles:
				found[n] = l
				n++
			}
			if ended {
				break
			}
			e = s - 1
		}
		if ended {
			m.n = 0
		}
		for i := n - 1; i >= 0; i-- {
			m = m.push(found[i])
		}
	}
	m.head = head
	switch {
	case head == headText:
		m.n = 0
	case (head == headDigits || head == headArrow1 || head == headArrow2) && start >= 0:
		keep, m.head = start, headBlank
	}
	return m, keep
}

// The kinds of line of lineKind.
const (
	lineBlank = iota
	lineOfFiles
	lineEnds
)

// lineKind is line, a whole line of the stream, and whether it is blank, a line of the
// files, or a line that ends a run of lines: other text, or a line longer than every
// line of the files.
func (h *Harness) lineKind(line []byte) (textLine, int) {
	if len(line) > h.longest+64 {
		return textLine{}, lineEnds
	}
	l, ok := h.lineOf(line, 0)
	if !ok {
		return l, lineBlank
	}
	if _, in := h.fileOf(l); !in {
		return l, lineEnds
	}
	return l, lineOfFiles
}

// push is m with l as its last line.
func (m lineMemory) push(l textLine) lineMemory {
	if m.n == len(m.lines) {
		copy(m.lines[:], m.lines[1:])
		m.n--
	}
	m.lines[m.n] = l
	m.n++
	return m
}

// Write writes b with each piece of text that counts as a file's replaced, keeping
// back the end a match may still begin in.
func (hw *HarnessWriter) Write(b []byte) (int, error) {
	if hw.h == nil {
		return hw.w.Write(b)
	}
	hw.mu.Lock()
	defer hw.mu.Unlock()
	hw.buf = append(hw.buf, b...)
	if err := hw.scan(false); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Flush writes what the writer keeps back, with each match replaced: the stream is
// over.
func (hw *HarnessWriter) Flush() error {
	if hw.h == nil {
		return nil
	}
	hw.mu.Lock()
	defer hw.mu.Unlock()
	return hw.scan(true)
}

// context is the most bytes of a match written last that the writer keeps, and the
// fewest it keeps.
const (
	contextMost   = 64 << 10
	contextFewest = 8 << 10
)

// scan writes the bytes of buf after seen that no match may still begin in, all of
// them when final, and keeps the rest.
func (hw *HarnessWriter) scan(final bool) error {
	b := hw.buf
	spans, from := hw.h.find(b, final, hw.prior.remembered())
	from = max(from, hw.seen)
	var out []byte
	at, open := hw.seen, hw.open
	for _, s := range spans {
		if s.end <= at {
			continue
		}
		if s.start >= from {
			break
		}
		if s.start > at {
			out = append(out, b[at:s.start]...)
			open = -1
		}
		if open != s.file {
			out = append(out, hw.h.put(s)...)
		}
		at, open = s.end, s.file
	}
	// Whitespace after the match written last may still lie between two pieces of one
	// file, which are one replacement: it is kept back with the match, up to
	// contextMost bytes.
	if at < from && (final || open < 0 || from-at > contextMost || !blank(b[at:from])) {
		out = append(out, b[at:from]...)
		at, open = from, -1
	}
	if len(out) > 0 {
		if _, err := hw.w.Write(out); err != nil {
			return err
		}
	}
	keep := at
	if open >= 0 && !final {
		keep = hw.contextStart(at)
	}
	if !final {
		hw.prior, keep = hw.h.carry(hw.prior, b, keep)
	}
	hw.buf = append(hw.buf[:0], b[keep:]...)
	hw.seen, hw.open = at-keep, open
	if final {
		hw.buf, hw.seen, hw.open, hw.prior = nil, 0, -1, lineMemory{}
	}
	return nil
}

// contextStart is where the bytes of b before at start that the writer keeps of the
// match written last: room for HarnessLines lines of the longest line of the files,
// with whitespace, a line number and JSON escapes, and at least contextFewest bytes,
// up to contextMost.
func (hw *HarnessWriter) contextStart(at int) int {
	n := HarnessLines * 6 * (hw.h.longest + 64)
	return max(0, at-min(max(n, contextFewest), contextMost))
}
