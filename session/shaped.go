package session

import (
	"encoding/json"
	"maps"
	"sort"
	"unicode/utf8"

	"github.com/qoryai/forager/session/runtimes"
)

// The bounds of the members the session cuts in a runtime event, in bytes: text and
// content at maxCut, summary at maxSummary.
const (
	maxCut     = 64 << 10
	maxSummary = 1 << 10
)

// The runtime event types and members shapedRecord reads and writes.
const (
	typeText         = "dev.qory.runtime.text"
	typeToolResult   = "dev.qory.runtime.tool_result"
	typeToolStarted  = "dev.qory.runtime.tool_started"
	typeToolFinished = "dev.qory.runtime.tool_finished"
	typeToolFailed   = "dev.qory.runtime.tool_failed"
	fieldTruncated   = "truncated"
	fieldSummary     = "summary"
)

// shapedRecord is data of an event of type typ, already masked, with the members the
// session sets: text of dev.qory.runtime.text and content of
// dev.qory.runtime.tool_result cut at maxCut with truncated: true when they are longer;
// and summary of dev.qory.runtime.tool_started, tool_finished and tool_failed, the
// member of input that sum selects for the event's tool, cut at maxSummary. A truncated
// or a summary that the runtime's Map returned is left out. sum is nil for a runtime
// with no summaries. The session cuts after masking, so a cut never splits a secret
// before the masker sees it whole.
func shapedRecord(typ string, data map[string]any, sum runtimes.Summaries) map[string]any {
	out := maps.Clone(data)
	if out == nil {
		out = map[string]any{}
	}
	delete(out, fieldTruncated)
	delete(out, fieldSummary)
	cut := false
	switch typ {
	case typeText:
		if s, ok := out["text"].(string); ok {
			out["text"], cut = cutString(s, maxCut)
		}
	case typeToolResult:
		switch c := out["content"].(type) {
		case string:
			out["content"], cut = cutString(c, maxCut)
		case []any:
			out["content"], cut = cutArray(c, maxCut)
		}
	case typeToolStarted, typeToolFinished, typeToolFailed:
		tool, _ := out["tool"].(string)
		input, _ := out["input"].(map[string]any)
		if sum != nil && tool != "" && input != nil {
			if s, ok := sum.Summary(tool, input); ok {
				out[fieldSummary], _ = cutString(s, maxSummary)
			}
		}
	}
	if cut {
		out[fieldTruncated] = true
	}
	return out
}

// cutString is s cut to its first n bytes at the end of the last whole character, and
// whether it was cut.
func cutString(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	return s[:boundary(s, n)], true
}

// boundary is the largest index of s up to n that starts a character, or len(s) when n
// is past it.
func boundary(s string, n int) int {
	if n >= len(s) {
		return len(s)
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}

// encodedLen is the length of v as json.Marshal encodes it, the encoding an event's
// data is written in.
func encodedLen(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// cutArray is a, an array of content, with its JSON encoding at n bytes or less, and
// whether it was cut. It keeps the elements in order while the encoding fits; the
// first element that does not fit, a string or a block with a string text, is cut at
// a character boundary to the longest that fits, and the elements after it are left
// out. An element of another shape that does not fit is left out with the elements
// after it.
func cutArray(a []any, n int) ([]any, bool) {
	// The encoding of an array is its brackets, its elements and a comma between two.
	size := 2
	for i, e := range a {
		if i > 0 {
			size++
		}
		size += encodedLen(e)
	}
	if size <= n {
		return a, false
	}
	kept := []any{}
	size = 2
	for _, e := range a {
		room := n - size
		if len(kept) > 0 {
			room--
		}
		if l := encodedLen(e); l <= room {
			kept = append(kept, e)
			size += l
			if len(kept) > 1 {
				size++
			}
			continue
		}
		if c, ok := cutElement(e, room); ok {
			kept = append(kept, c)
		}
		break
	}
	return kept, true
}

// cutElement is e cut so that its encoding has room bytes at most: a string to its
// longest prefix that fits, a block with a string text with its text cut so. false for
// an element of another shape, and for one that does not fit with its text empty.
func cutElement(e any, room int) (any, bool) {
	switch v := e.(type) {
	case string:
		if room < 2 {
			return nil, false
		}
		return longestPrefix(v, room), true
	case map[string]any:
		text, ok := v["text"].(string)
		if !ok {
			return nil, false
		}
		out := maps.Clone(v)
		out["text"] = ""
		// The block with an empty text, whose "" stands for the encoded text.
		base := encodedLen(out)
		if base > room {
			return nil, false
		}
		out["text"] = longestPrefix(text, room-base+2)
		return out, true
	}
	return nil, false
}

// longestPrefix is the longest prefix of s that ends at a character boundary and
// whose JSON encoding, quotes included, has room bytes at most. room is 2 or more.
func longestPrefix(s string, room int) string {
	// The encoding of a prefix grows with the prefix, and is at least as long as the
	// prefix plus its quotes, so the prefix has room-2 bytes at most.
	top := min(len(s), room-2)
	k := sort.Search(top+1, func(k int) bool { return encodedLen(s[:boundary(s, k)]) > room })
	return s[:boundary(s, k-1)]
}
