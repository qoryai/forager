package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
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

// ErrCount is the error of a token count the session does not write: each of
// [ErrCountAbove], [ErrCountBelow], [ErrCountNotInteger] and [ErrSumAbove] is
// ErrCount for [errors.Is], and its text is the cause that applied.
var ErrCount = errors.New("a token count is out of the range the session writes")

// countError is one cause of [ErrCount].
type countError string

func (e countError) Error() string { return string(e) }

// Is reports whether target is [ErrCount].
func (e countError) Is(target error) bool { return target == ErrCount }

// The causes of [ErrCount]: a count above [MaxCount], a count below -[MaxCount], a
// count that is not an integer, and a launch's sum of a count above [MaxCount].
var (
	ErrCountAbove      error = countError("a token count is above 2^53 (9007199254740992)")
	ErrCountBelow      error = countError("a token count is below -2^53 (-9007199254740992)")
	ErrCountNotInteger error = countError("a token count is not an integer")
	ErrSumAbove        error = countError("the launch's sum of a token count is above 2^53 (9007199254740992)")
)

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
// file, nil when the file has none, Before, the last total in the bytes the file had
// before the launch, nil when they have none, and Spawned, the ids of the threads that
// the file's spawns started ([spawnedIDs]).
type Rollout struct {
	Meta
	Last, Before *Tokens
	Spawned      []string
}

// errNoMeta is the error of a file whose first line is no session_meta with an id.
var errNoMeta = errors.New("its first line is no session_meta with an id")

// ErrMetaCut is the error of bytes that end inside their first line before the
// session_meta's id and source: [ParseMeta] of the first bytes of a file whose first
// line is longer.
var ErrMetaCut = errors.New("its first line ends before the id and source of its session_meta")

// errEnd is the error of a read past the end of the bytes an [endReader] reads.
var errEnd = errors.New("the end of the bytes")

// endReader reads r, and returns [errEnd] at its end in place of [io.EOF]: a
// [json.Decoder] returns the error of its reader as it is, so an error that is errEnd
// marks a value the bytes cut, and every other error a value of another shape.
type endReader struct{ r *bytes.Reader }

func (e endReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err == io.EOF {
		err = errEnd
	}
	return n, err
}

// metaLine is what [ParseMeta] reads of a first line: the type, and the payload's id,
// parent_thread_id and source, with source set once source is read whole.
type metaLine struct {
	typ, id, parentID string
	source            json.RawMessage
	sourceRead        bool
}

// delim reads the next token of dec, which must be d.
func delim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return errNoMeta
	}
	return nil
}

// object reads an object of dec, key by key, with value for each key; value reads the
// key's value.
func object(dec *json.Decoder, value func(key string) error) error {
	if err := delim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errNoMeta
		}
		if err := value(key); err != nil {
			return err
		}
	}
	return delim(dec, '}')
}

// skip reads one value of dec and drops it.
func skip(dec *json.Decoder) error {
	var v json.RawMessage
	return dec.Decode(&v)
}

// read reads the first line from dec, token by token, so that what comes before a cut
// counts: Codex 0.167.2 writes type, then payload with id, parent_thread_id and source
// before base_instructions (codex-rs protocol/src/protocol.rs, SessionMeta).
func (m *metaLine) read(dec *json.Decoder) error {
	return object(dec, func(key string) error {
		switch key {
		case "type":
			if err := dec.Decode(&m.typ); err != nil {
				return err
			}
			if m.typ != "session_meta" {
				return errNoMeta
			}
			return nil
		case "payload":
			return object(dec, func(key string) error {
				switch key {
				case "id":
					return dec.Decode(&m.id)
				case "parent_thread_id":
					return dec.Decode(&m.parentID)
				case "source":
					if err := dec.Decode(&m.source); err != nil {
						return err
					}
					m.sourceRead = true
					return nil
				}
				return skip(dec)
			})
		}
		return skip(dec)
	})
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
// reads the line token by token, so a line that b cuts, such as one with base
// instructions longer than b, has its Meta once its id and source are in b. It returns
// [ErrMetaCut] for a line that b cuts before them, and another error when the line is
// no session_meta with an id.
func ParseMeta(b []byte) (Meta, error) {
	first, _, whole := bytes.Cut(b, []byte("\n"))
	dec := json.NewDecoder(endReader{bytes.NewReader(first)})
	var m metaLine
	err := m.read(dec)
	if err == nil {
		if _, end := dec.Token(); !errors.Is(end, errEnd) {
			err = errNoMeta
		}
	}
	cut := !whole && errors.Is(err, errEnd)
	switch {
	case cut && m.typ == "session_meta" && m.id != "" && m.sourceRead:
	case cut:
		return Meta{}, ErrMetaCut
	case err != nil || m.typ != "session_meta" || m.id == "":
		return Meta{}, errNoMeta
	}
	r := Meta{ThreadID: m.id, ParentID: m.parentID}
	var src spawned
	if r.ParentID == "" && m.sourceRead && json.Unmarshal(m.source, &src) == nil {
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
	r.Spawned = spawnedIDs(b)
	return r, nil
}

// spawnTypes are the texts of which a line with the id of a spawned thread contains
// one; a line without any is not decoded.
var spawnTypes = [][]byte{[]byte(`"CollabAgentToolCall"`), []byte(`"SubAgentActivity"`), []byte(`"sub_agent_activity"`),
	[]byte(`"function_call"`), []byte(`"function_call_output"`), []byte(`"FunctionCallOutput"`)}

// spawnLine is what [spawnedIDs] reads of a line: its type and its payload.
type spawnLine struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// spawnPayload is what [spawnedIDs] reads of a payload: of an event_msg, its type,
// item, kind and agent_thread_id; of a response_item, its type, name, call_id and
// output.
type spawnPayload struct {
	Type          string          `json:"type"`
	Item          json.RawMessage `json:"item"`
	Kind          string          `json:"kind"`
	AgentThreadID string          `json:"agent_thread_id"`
	Name          string          `json:"name"`
	CallID        string          `json:"call_id"`
	Output        json.RawMessage `json:"output"`
}

// spawnItem is what [spawnedIDs] reads of the item of an item_completed: its type, and
// of a CollabAgentToolCall its tool and receiver_thread_ids, of a SubAgentActivity its
// kind and agent_thread_id, of a FunctionCallOutput its name and output.
type spawnItem struct {
	Type          string          `json:"type"`
	Tool          string          `json:"tool"`
	Receivers     []string        `json:"receiver_thread_ids"`
	Kind          string          `json:"kind"`
	AgentThreadID string          `json:"agent_thread_id"`
	Name          string          `json:"name"`
	Output        json.RawMessage `json:"output"`
}

// spawnAgent is the name of the tool that starts a child agent, and spawnStarted the
// kind of a SubAgentActivity of a child agent it started.
const (
	spawnAgent   = "spawn_agent"
	spawnStarted = "started"
)

// spawnOutputID is the agent_id of output, the output of a spawn_agent call with the
// feature multi_agent: a JSON string whose text is an object with agent_id, such as
// "{\"agent_id\":\"<id>\",\"nickname\":null}" (codex-rs
// core/src/tools/handlers/multi_agents/spawn.rs:207-210 and :230-249,
// multi_agents_common.rs:34-55 and tools/context.rs:599-624, in 0.167.2 and 0.169.0).
// It is empty for an output of another shape.
func spawnOutputID(output json.RawMessage) string {
	var text string
	var out struct {
		AgentID string `json:"agent_id"`
	}
	if json.Unmarshal(output, &text) != nil || json.Unmarshal([]byte(text), &out) != nil {
		return ""
	}
	return out.AgentID
}

// spawnedIDs is the ids of the threads that the spawns in b started, in the order of
// the lines, each once. Codex 0.167.2 and 0.169.0 write these lines for a spawn, by
// the history mode of the thread (codex-rs rollout/src/policy.rs:22-51, :128-163 and
// :232-286 in both):
//   - with the feature multi_agent in the paginated mode, the mode in which codex exec
//     starts a thread that is not ephemeral (exec/src/lib.rs:1475 in 0.167.2 and
//     :1542 in 0.169.0): an event_msg of type item_completed whose item is a
//     CollabAgentToolCall of the tool spawn_agent, with the ids in receiver_thread_ids
//     (core/src/tools/handlers/multi_agents/spawn.rs:181-198);
//   - with the feature multi_agent_v2 in the paginated mode: an event_msg of type
//     item_completed whose item is a SubAgentActivity of kind started, with the id in
//     agent_thread_id (core/src/tools/handlers/multi_agents_v2/spawn.rs:162-174,
//     multi_agents_v2.rs:44-52);
//   - with multi_agent_v2 in the legacy mode: an event_msg of type sub_agent_activity
//     of kind started, with the id in agent_thread_id (protocol/src/legacy_events.rs
//     :438-449 and :642-644 in 0.167.2, :451-462 and :655-657 in 0.169.0);
//   - with multi_agent in either mode: a response_item of type function_call_output
//     whose call_id is that of an earlier response_item of type function_call named
//     spawn_agent, in any namespace, with the id as agent_id in its output
//     ([spawnOutputID]). The legacy mode keeps no CollabAgentToolCall.
//
// An event_msg of type item_completed whose item is a FunctionCallOutput named
// spawn_agent, which the legacy mode keeps (policy.rs:238-252), has the id in its
// output as a function_call_output does; Codex writes that item only for an output
// that a client submits with no call_id (core/src/hook_runtime.rs:778-797 in 0.167.2,
// :781-800 in 0.169.0). A child agent takes its parent's mode
// (core/src/agent/control/spawn.rs:85-91 in 0.167.2, :86-92 in 0.169.0). A line of
// another shape counts for nothing.
func spawnedIDs(b []byte) []string {
	var ids []string
	seen, calls := map[string]bool{}, map[string]bool{}
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		if !slices.ContainsFunc(spawnTypes, func(t []byte) bool { return bytes.Contains(line, t) }) {
			continue
		}
		var l spawnLine
		var p spawnPayload
		if json.Unmarshal(line, &l) != nil || json.Unmarshal(l.Payload, &p) != nil {
			continue
		}
		switch {
		case l.Type == "response_item" && p.Type == "function_call" && p.Name == spawnAgent && p.CallID != "":
			calls[p.CallID] = true
		case l.Type == "response_item" && p.Type == "function_call_output" && calls[p.CallID]:
			add(spawnOutputID(p.Output))
		case l.Type == "event_msg" && p.Type == "sub_agent_activity" && p.Kind == spawnStarted:
			add(p.AgentThreadID)
		case l.Type == "event_msg" && p.Type == "item_completed":
			var it spawnItem
			if json.Unmarshal(p.Item, &it) != nil {
				continue
			}
			switch {
			case it.Type == "CollabAgentToolCall" && it.Tool == spawnAgent:
				for _, id := range it.Receivers {
					add(id)
				}
			case it.Type == "SubAgentActivity" && it.Kind == spawnStarted:
				add(it.AgentThreadID)
			case it.Type == "FunctionCallOutput" && it.Name == spawnAgent:
				add(spawnOutputID(it.Output))
			}
		}
	}
	return ids
}

// tokenCountType is how a line with a total starts its payload; a line without it is
// not decoded.
var tokenCountType = []byte(`"token_count"`)

// integerLiteral matches a JSON number that is an integer as written, such as one
// beyond the range of int64.
var integerLiteral = regexp.MustCompile(`^-?[0-9]+$`)

// lastTotal is the last total_token_usage of a token_count in b, nil for none, and
// [ErrCount] for a total with a count that is no integer from -[MaxCount] to
// [MaxCount], beyond the range of int64 included: [ErrCountAbove], [ErrCountBelow] or
// [ErrCountNotInteger].
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
		// the decode goes on with the rest of the line. The error's value is "number "
		// and the number as written for a number, and the JSON type otherwise.
		var typed *json.UnmarshalTypeError
		if errors.As(err, &typed) && strings.HasPrefix(typed.Field, "payload.info.total_token_usage.") {
			n, isNumber := strings.CutPrefix(typed.Value, "number ")
			switch {
			case isNumber && integerLiteral.MatchString(n) && strings.HasPrefix(n, "-"):
				return nil, ErrCountBelow
			case isNumber && integerLiteral.MatchString(n):
				return nil, ErrCountAbove
			}
			return nil, ErrCountNotInteger
		}
		if err != nil {
			continue
		}
		for _, n := range c.Payload.Info.Total.counts() {
			switch {
			case n > MaxCount:
				return nil, ErrCountAbove
			case n < -MaxCount:
				return nil, ErrCountBelow
			}
		}
		last = c.Payload.Info.Total
	}
	return last, nil
}

// MaxDepth is the most levels of child agents below the launch's thread that
// [Descendants] finds, 16; Codex 0.167.2 allows 1 unless agents.max_depth sets more
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
	children := map[string][]int{}
	for i, m := range metas {
		children[m.ParentID] = append(children[m.ParentID], i)
	}
	threads := map[string]bool{thread: true}
	level := []string{thread}
	var out []int
	for depth := 1; len(level) > 0; depth++ {
		var next []string
		for _, parent := range level {
			for _, i := range children[parent] {
				if threads[metas[i].ThreadID] {
					continue
				}
				if depth > MaxDepth {
					return nil, ErrTooDeep
				}
				threads[metas[i].ThreadID] = true
				next = append(next, metas[i].ThreadID)
				out = append(out, i)
			}
		}
		level = next
	}
	return out, nil
}

// SumUsage is the usage of a launch whose thread's rollout and child agents' are
// rollouts: for each, the last total less the total before the launch, mapped
// ([Map]), summed. A rollout whose last total is the one before the launch, or that
// has none, adds nothing. counted is false when no rollout adds a total. clamped is
// true when a count of a difference was below 0, which [Map] wrote as 0. A sum above
// [MaxCount] is [ErrSumAbove].
func SumUsage(rollouts []Rollout) (u Usage, counted, clamped bool, err error) {
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
			return Usage{}, false, false, ErrSumAbove
		}
	}
	return u, counted, clamped, nil
}
