package session

import (
	"fmt"
	"strings"
	"testing"
)

// parsed is what a lineParser handed to on: each record's line number and value of "n".
type parsed []string

func parse(writes ...string) parsed {
	var out parsed
	l := &lineParser{on: func(m map[string]any, line int) {
		out = append(out, fmt.Sprintf("%d:%v", line, m["n"]))
	}}
	for _, w := range writes {
		l.Write([]byte(w))
	}
	l.flush()
	return out
}

// TestTheLineParserNumbersEveryLine pins the numbers that the session puts in line:
// empty lines and lines that are not JSON count, a line split across writes is one
// line, and the bytes after the last line break are the last line, numbered at flush.
func TestTheLineParserNumbersEveryLine(t *testing.T) {
	for _, c := range []struct {
		name   string
		writes []string
		want   string
	}{
		{"empty lines and text count", []string{"{\"n\":1}\n\nplain text\n[1,2]\n\"s\"\n{not json\n{\"n\":7}\n"}, "[1:1 7:7]"},
		{"a line split across writes", []string{"{\"n\"", ":1}\n{\"n\":", "2}\n"}, "[1:1 2:2]"},
		{"a carriage return before the break", []string{"{\"n\":1}\r\n\r\n{\"n\":3}\r\n"}, "[1:1 3:3]"},
		{"the last line without a break", []string{"text\n\n{\"n\":3}"}, "[3:3]"},
		{"a last line of text without a break", []string{"{\"n\":1}\ntext"}, "[1:1]"},
		{"no lines", nil, "[]"},
	} {
		if got := fmt.Sprint(parse(c.writes...)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// TestTheLineParserKeepsALongLineWhole pins a line far over 64 KiB, written in pieces
// of 4 KiB as a pipe delivers it: it is one line with one number, and the lines after
// it keep their numbers.
func TestTheLineParserKeepsALongLineWhole(t *testing.T) {
	long := `{"n":2,"text":"` + strings.Repeat("a", 300<<10) + `"}`
	stream := "{\"n\":1}\n" + long + "\n{\"n\":3}\n" + long
	var writes []string
	for len(stream) > 0 {
		k := min(4<<10, len(stream))
		writes = append(writes, stream[:k])
		stream = stream[k:]
	}
	var texts []int
	l := &lineParser{on: func(m map[string]any, line int) {
		if s, ok := m["text"].(string); ok {
			texts = append(texts, len(s))
		}
	}}
	for _, w := range writes {
		l.Write([]byte(w))
	}
	l.flush()
	if got, want := fmt.Sprint(parse(writes...)), "[1:1 2:2 3:3 4:2]"; got != want {
		t.Errorf("lines %s, want %s", got, want)
	}
	if fmt.Sprint(texts) != fmt.Sprint([]int{300 << 10, 300 << 10}) {
		t.Errorf("text lengths %v, want two of %d", texts, 300<<10)
	}
}
