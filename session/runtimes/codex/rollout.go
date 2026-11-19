package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Codex 0.167.2 writes one rollout per thread below $CODEX_HOME/sessions: JSON lines,
// the first a session_meta, and an event_msg of type token_count after each response
// that completed, with the thread's total so far in info.total_token_usage
// (codex-rs protocol/src/protocol.rs, TokenUsage). A child agent's rollout has
// parent_thread_id, the id of the thread that started it, in its session_meta. Its
// session_id is the parent's id too, so only id and parent_thread_id differ between
// the files. A token_count with info null, such as one with rate limits alone, has no
// total. Codex appends to a rollout and never rewrites it, a resumed thread's included.

// Tokens is one total_token_usage of a rollout, by Codex's names. Codex copies
// cached_input_tokens and cache_write_input_tokens from input_tokens_details of the
// Responses API's usage, so both are inside input_tokens, and reasoning_output_tokens
// is inside output_tokens (codex-rs codex-api/src/sse/responses.rs, From for
// TokenUsage).
type Tokens struct {
	Input           int64 `json:"input_tokens"`
	CachedInput     int64 `json:"cached_input_tokens"`
	CacheWriteInput int64 `json:"cache_write_input_tokens"`
	Output          int64 `json:"output_tokens"`
	ReasoningOutput int64 `json:"reasoning_output_tokens"`
	Total           int64 `json:"total_tokens"`
}

// MaxCount is the largest token count the session reads and writes, 2^53: a JSON
// number above it loses digits in a reader that decodes numbers as float64.
const MaxCount = 1 << 53

// ErrCount is the error of a token count above [MaxCount] or below -[MaxCount], of a
// count that is no integer, and of a launch's sum of a count above [MaxCount].
var ErrCount = errors.New("a token count is above 2^53 (9007199254740992), or the launch's sum of a count is")

// counts is t's six counts.
func (t Tokens) counts() []int64 {
	return []int64{t.Input, t.CachedInput, t.CacheWriteInput, t.Output, t.ReasoningOutput, t.Total}
}

// minus is t less o, field by field.
func (t Tokens) minus(o Tokens) Tokens {
	return Tokens{
		Input: t.Input - o.Input, CachedInput: t.CachedInput - o.CachedInput, CacheWriteInput: t.CacheWriteInput - o.CacheWriteInput,
		Output: t.Output - o.Output, ReasoningOutput: t.ReasoningOutput - o.ReasoningOutput, Total: t.Total - o.Total,
	}
}

// Usage is the usage of dev.qory.runtime.result: four counts that do not overlap.
type Usage struct {
	Input, Output, CacheRead, CacheWrite int64
}

// Map is t as [Usage]: input is input_tokens less the cached and the cache-write
// tokens, cache_read cached_input_tokens, cache_write cache_write_input_tokens, and
// output output_tokens, reasoning included. A count below 0 is 0, and clamped is true.
func Map(t Tokens) (u Usage, clamped bool) {
	at0 := func(n int64) int64 {
		if n < 0 {
			clamped = true
			return 0
		}
		return n
	}
	u = Usage{CacheRead: at0(t.CachedInput), CacheWrite: at0(t.CacheWriteInput), Output: at0(t.Output)}
	u.Input = at0(t.Input - u.CacheRead - u.CacheWrite)
	return u, clamped
}

// Add is u and o summed.
func (u Usage) Add(o Usage) Usage {
	return Usage{Input: u.Input + o.Input, Output: u.Output + o.Output, CacheRead: u.CacheRead + o.CacheRead, CacheWrite: u.CacheWrite + o.CacheWrite}
}

// Meta is what the first line of a rollout, its session_meta, contains: the thread's
// id, and the id of the thread that started it, empty for a thread no agent started.
type Meta struct {
	ThreadID, ParentID string
}

// Rollout is what the session reads of one rollout: its [Meta], the last total in the
// file, nil when the file has none, and Before, the last total in the bytes the file
// had before the launch, nil when they have none.
type Rollout struct {
	Meta
	Last, Before *Tokens
}

// errNoMeta is the error of a file whose first line is no session_meta with an id.
var errNoMeta = errors.New("its first line is no session_meta with an id")

// meta is the first line of a rollout.
type meta struct {
	Type    string `json:"type"`
	Payload struct {
		ID       string `json:"id"`
		ParentID string `json:"parent_thread_id"`
		// Source is "exec" for a thread codex exec started, and an object for a child
		// agent's.
		Source json.RawMessage `json:"source"`
	} `json:"payload"`
}

// spawned is the source of a child agent's thread.
type spawned struct {
	Subagent struct {
		ThreadSpawn struct {
			ParentID string `json:"parent_thread_id"`
		} `json:"thread_spawn"`
	} `json:"subagent"`
}

// tokenCount is a line with a total.
type tokenCount struct {
	Type    string `json:"type"`
	Payload struct {
		Type string `json:"type"`
		Info *struct {
			Total *Tokens `json:"total_token_usage"`
		} `json:"info"`
	} `json:"payload"`
}

// ParseMeta reads the [Meta] of a rollout from b, the file's first bytes: the line
// before the first newline, or all of b when it has none. The thread's parent is the
// session_meta's parent_thread_id, or else that of source.subagent.thread_spawn. It
// returns an error when that line is no session_meta with an id.
func ParseMeta(b []byte) (Meta, error) {
	first, _, _ := bytes.Cut(b, []byte("\n"))
	var m meta
	if json.Unmarshal(first, &m) != nil || m.Type != "session_meta" || m.Payload.ID == "" {
		return Meta{}, errNoMeta
	}
	r := Meta{ThreadID: m.Payload.ID, ParentID: m.Payload.ParentID}
	var src spawned
	if r.ParentID == "" && json.Unmarshal(m.Payload.Source, &src) == nil {
		r.ParentID = src.Subagent.ThreadSpawn.ParentID
	}
	return r, nil
}

// ParseRollout reads b, a rollout's bytes, of which the first before bytes are what
// the file had before the launch: 0 for none. A line that is no JSON object, such as
// the part of a line Codex had not finished writing, counts for nothing. It returns an
// error when the first line is no session_meta with an id ([ParseMeta]), when b is
// shorter than before, and [ErrCount] for a total with a count that is no integer from
// -[MaxCount] to [MaxCount].
func ParseRollout(b []byte, before int64) (Rollout, error) {
	if before < 0 || int64(len(b)) < before {
		return Rollout{}, fmt.Errorf("it has %d bytes, fewer than the %d bytes it had before the launch", len(b), before)
	}
	m, err := ParseMeta(b)
	if err != nil {
		return Rollout{}, err
	}
	r := Rollout{Meta: m}
	if r.Before, err = lastTotal(b[:before]); err != nil {
		return Rollout{}, err
	}
	if r.Last, err = lastTotal(b); err != nil {
		return Rollout{}, err
	}
	return r, nil
}

// tokenCountType is how a line with a total starts its payload; a line without it is
// not decoded.
var tokenCountType = []byte(`"token_count"`)

// lastTotal is the last total_token_usage of a token_count in b, nil for none, and
// [ErrCount] for a total with a count that is no integer from -[MaxCount] to
// [MaxCount], beyond the range of int64 included.
func lastTotal(b []byte) (*Tokens, error) {
	var last *Tokens
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		if !bytes.Contains(line, tokenCountType) {
			continue
		}
		var c tokenCount
		err := json.Unmarshal(line, &c)
		if c.Type != "event_msg" || c.Payload.Type != "token_count" || c.Payload.Info == nil || c.Payload.Info.Total == nil {
			continue
		}
		// A count that is no integer of int64 fails the decode of its field alone, and
		// the decode goes on with the rest of the line.
		var typed *json.UnmarshalTypeError
		if errors.As(err, &typed) && strings.HasPrefix(typed.Field, "payload.info.total_token_usage.") {
			return nil, ErrCount
		}
		if err != nil {
			continue
		}
		for _, n := range c.Payload.Info.Total.counts() {
			if n > MaxCount || n < -MaxCount {
				return nil, ErrCount
			}
		}
		last = c.Payload.Info.Total
	}
	return last, nil
}

// MaxDepth is the most levels of child agents below the launch's thread that
// [LaunchUsage] counts, 16; Codex 0.167.2 allows 1 unless agents.max_depth sets more
// (codex-rs core/src/config/mod.rs, DEFAULT_AGENT_MAX_DEPTH).
const MaxDepth = 16

// ErrTooDeep is the error of a child agent more than [MaxDepth] levels below the
// launch's thread.
var ErrTooDeep = fmt.Errorf("a child agent is more than %d levels below the launch's thread", MaxDepth)

// Descendants is the indexes in metas of the child agents of thread, and of their
// child agents, at any depth up to [MaxDepth], in the order of the levels: each
// rollout whose parent is thread or one of them. A thread id met again counts once.
// A child agent deeper than [MaxDepth] is [ErrTooDeep].
func Descendants(thread string, metas []Meta) ([]int, error) {
	threads := map[string]bool{thread: true}
	level := []string{thread}
	var out []int
	for depth := 1; len(level) > 0; depth++ {
		var next []string
		for i, m := range metas {
			if !slices.Contains(level, m.ParentID) || threads[m.ThreadID] {
				continue
			}
			if depth > MaxDepth {
				return nil, ErrTooDeep
			}
			threads[m.ThreadID] = true
			next = append(next, m.ThreadID)
			out = append(out, i)
		}
		level = next
	}
	return out, nil
}

// LaunchUsage is the usage of a launch whose thread's rollout is parent, with others
// the other rollouts the session read: for the parent and for each of the thread's
// [Descendants] among others, the last total less the total before the launch, mapped
// ([Map]), summed. A rollout whose last total is the one before the launch, or that
// has none, adds nothing. counted is false when no rollout adds a total. clamped is
// true when a count of a difference was below 0, which [Map] wrote as 0. A sum above
// [MaxCount] is [ErrCount].
func LaunchUsage(parent Rollout, others []Rollout) (u Usage, counted, clamped bool, err error) {
	metas := make([]Meta, len(others))
	for i, r := range others {
		metas[i] = r.Meta
	}
	below, err := Descendants(parent.ThreadID, metas)
	if err != nil {
		return Usage{}, false, false, err
	}
	rollouts := []Rollout{parent}
	for _, i := range below {
		rollouts = append(rollouts, others[i])
	}
	for _, r := range rollouts {
		if r.Last == nil || (r.Before != nil && *r.Last == *r.Before) {
			continue
		}
		t := *r.Last
		if r.Before != nil {
			t = t.minus(*r.Before)
		}
		m, c := Map(t)
		u, counted, clamped = u.Add(m), true, clamped || c
		if u.Input > MaxCount || u.Output > MaxCount || u.CacheRead > MaxCount || u.CacheWrite > MaxCount {
			return Usage{}, false, false, ErrCount
		}
	}
	return u, counted, clamped, nil
}
