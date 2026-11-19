package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Codex 0.167.2 writes one rollout per thread below $CODEX_HOME/sessions: JSON lines,
// the first a session_meta, and an event_msg of type token_count after each response
// that completed, with the thread's total so far in info.total_token_usage
// (codex-rs protocol/src/protocol.rs, TokenUsage). A child agent's rollout has
// parent_thread_id, the id of the thread that started it, in its session_meta. Its
// session_id is the parent's id too, so only id and parent_thread_id differ between
// the files. A token_count with info null, such as one with rate limits alone, has no
// total.

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

// Rollout is what the session reads of one rollout: the thread's id, the id of the
// thread that started it, empty for a thread no agent started, and the last total in
// the file, nil when the file has none. Restored is the last total in the file's first
// bytes that the session restored before the launch, nil when they have none.
type Rollout struct {
	ThreadID, ParentID string
	Last, Restored     *Tokens
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

// ParseRollout reads b, a rollout's bytes, of which the first restored bytes are what
// the session restored before the launch: 0 for none. The thread's parent is the
// session_meta's parent_thread_id, or else that of source.subagent.thread_spawn. A
// line that is no JSON object, such as the part of a line Codex had not finished
// writing, counts for nothing. It returns an error when the first line is no
// session_meta with an id, or when b is shorter than restored.
func ParseRollout(b []byte, restored int64) (Rollout, error) {
	if restored < 0 || int64(len(b)) < restored {
		return Rollout{}, fmt.Errorf("it has %d bytes, fewer than the %d bytes restored", len(b), restored)
	}
	first, _, _ := bytes.Cut(b, []byte("\n"))
	var m meta
	if json.Unmarshal(first, &m) != nil || m.Type != "session_meta" || m.Payload.ID == "" {
		return Rollout{}, errNoMeta
	}
	r := Rollout{ThreadID: m.Payload.ID, ParentID: m.Payload.ParentID}
	var src spawned
	if r.ParentID == "" && json.Unmarshal(m.Payload.Source, &src) == nil {
		r.ParentID = src.Subagent.ThreadSpawn.ParentID
	}
	r.Restored = lastTotal(b[:restored])
	r.Last = lastTotal(b)
	return r, nil
}

// tokenCountType is how a line with a total starts its payload; a line without it is
// not decoded.
var tokenCountType = []byte(`"token_count"`)

// lastTotal is the last total_token_usage of a token_count in b, nil for none.
func lastTotal(b []byte) *Tokens {
	var last *Tokens
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		if !bytes.Contains(line, tokenCountType) {
			continue
		}
		var c tokenCount
		if json.Unmarshal(line, &c) != nil || c.Type != "event_msg" || c.Payload.Type != "token_count" || c.Payload.Info == nil || c.Payload.Info.Total == nil {
			continue
		}
		last = c.Payload.Info.Total
	}
	return last
}

// MaxDepth is the most levels of child agents below the launch's thread that
// [LaunchUsage] counts, 16; Codex 0.167.2 allows 1 unless agents.max_depth sets more
// (codex-rs core/src/config/mod.rs, DEFAULT_AGENT_MAX_DEPTH).
const MaxDepth = 16

// ErrTooDeep is the error of a child agent more than [MaxDepth] levels below the
// launch's thread.
var ErrTooDeep = fmt.Errorf("a child agent is more than %d levels below the launch's thread", MaxDepth)

// LaunchUsage is the usage of a launch whose thread's rollout is parent, with others
// the other rollouts below CODEX_HOME/sessions: the parent's last total less its
// restored total, plus the last total of each rollout whose parent is the thread or one
// of its children, at any depth up to [MaxDepth]. Each total is mapped ([Map]) before
// the sum. counted is false when no total counts: the parent has none beyond the
// restored one, and no child has one. clamped is true when a count of a total was
// below 0, which [Map] wrote as 0.
func LaunchUsage(parent Rollout, others []Rollout) (u Usage, counted, clamped bool, err error) {
	add := func(t Tokens) {
		m, c := Map(t)
		u, counted, clamped = u.Add(m), true, clamped || c
	}
	if parent.Last != nil {
		if parent.Restored == nil {
			add(*parent.Last)
		} else if *parent.Last != *parent.Restored {
			add(parent.Last.minus(*parent.Restored))
		}
	}
	threads := map[string]bool{parent.ThreadID: true}
	level := []string{parent.ThreadID}
	for depth := 1; len(level) > 0; depth++ {
		var next []string
		for _, r := range others {
			if !slices.Contains(level, r.ParentID) || threads[r.ThreadID] {
				continue
			}
			if depth > MaxDepth {
				return Usage{}, false, false, ErrTooDeep
			}
			threads[r.ThreadID] = true
			next = append(next, r.ThreadID)
			if r.Last != nil {
				add(*r.Last)
			}
		}
		level = next
	}
	return u, counted, clamped, nil
}
