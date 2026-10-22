package parents_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/parents"
)

// doc is a descriptor of a runtime whose hooks report tool calls and subagent starts
// and whose output reports, in each message of a subagent, the subagent's id and the
// id of the tool call that started it.
const doc = `version: 1
runtime: amp
runtime_version: "1"
sources: {output: {format: jsonl}}
parent:
  source: output
  match: {agent_id: {present: true}}
  agent_id: agent_id
  tool_use_id: parent_tool_use_id
rules:
  - source: hooks
    match: {hook_event_name: PreToolUse}
    type: dev.qory.runtime.tool_started
    data: {session_id: session_id, tool: tool_name, tool_use_id: tool_use_id, input: tool_input, agent_id: agent_id}
  - source: hooks
    match: {hook_event_name: SubagentStart}
    type: dev.qory.runtime.subagent_started
    data: {session_id: session_id, agent_id: agent_id, agent_type: agent_type}
  - source: hooks
    match: {hook_event_name: Stop}
    type: dev.qory.runtime.turn_finished
    data: {session_id: session_id, agent_id: agent_id}
  - source: output
    match: {type: result}
    type: dev.qory.runtime.result
    data: {session_id: session_id, outcome: subtype, is_error: is_error}
`

// clock is a clock whose time passes only with advance.
type clock struct {
	mu     sync.Mutex
	now    time.Duration
	timers []*timer
}

type timer struct {
	at      time.Duration
	f       func()
	stopped bool
}

func (c *clock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	tm := &timer{at: c.now + d, f: f}
	c.timers = append(c.timers, tm)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !tm.stopped
		tm.stopped = true
		return was
	}
}

// advance moves the time on by d and calls every timer whose time has come, in order.
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now += d
	var due []*timer
	for _, tm := range c.timers {
		if !tm.stopped && tm.at <= c.now {
			tm.stopped = true
			due = append(due, tm)
		}
	}
	c.mu.Unlock()
	for _, tm := range due {
		tm.f()
	}
}

// session is one mapper and what it wrote.
type session struct {
	t      *testing.T
	clock  *clock
	m      *parents.Mapper
	mu     sync.Mutex
	events []descriptor.Event
}

func newSession(t *testing.T) *session {
	t.Helper()
	d, err := descriptor.Parse("amp.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	s := &session{t: t, clock: &clock{}}
	s.m = parents.New(d, func(e descriptor.Event) {
		s.mu.Lock()
		s.events = append(s.events, e)
		s.mu.Unlock()
	}, s.clock)
	return s
}

func (s *session) record(source, js string) {
	s.t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		s.t.Fatal(err)
	}
	s.m.Handle(descriptor.Record{Source: source, Record: m})
}

// init is the first line of output, which makes the mapper keep starts back.
func (s *session) init() { s.record("output", `{"type":"system","subtype":"init","session_id":"s1"}`) }

// call is a tool call's start in the hooks, by agent, "" for the main agent.
func (s *session) call(agent, id string) {
	if agent == "" {
		s.record("hooks", fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Agent","tool_use_id":%q,"tool_input":{}}`, id))
		return
	}
	s.record("hooks", fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Agent","tool_use_id":%q,"tool_input":{},"agent_id":%q}`, id, agent))
}

func (s *session) start(agent string) {
	s.record("hooks", fmt.Sprintf(`{"hook_event_name":"SubagentStart","session_id":"s1","agent_id":%q,"agent_type":"general-purpose"}`, agent))
}

// stop is a turn's end in the hooks, by agent, "" for the main agent.
func (s *session) stop(agent string) {
	if agent == "" {
		s.record("hooks", `{"hook_event_name":"Stop","session_id":"s1"}`)
		return
	}
	s.record("hooks", fmt.Sprintf(`{"hook_event_name":"Stop","session_id":"s1","agent_id":%q}`, agent))
}

// message is a line of output of the subagent agent, which the call started.
func (s *session) message(agent, call string) {
	s.record("output", fmt.Sprintf(`{"type":"user","session_id":"s1","agent_id":%q,"parent_tool_use_id":%q,"message":{"role":"user","content":[]}}`, agent, call))
}

// written is what the mapper wrote: each event's type without its prefix, the agent
// and, after a colon, its parent_agent_id.
func (s *session) written() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		w := e.Type[len("dev.qory.runtime."):]
		if a, ok := e.Data["agent_id"].(string); ok {
			w += " " + a
		}
		if p, ok := e.Data["parent_agent_id"]; ok {
			w += ":" + p.(string)
		}
		out = append(out, w)
	}
	return out
}

func (s *session) want(want ...string) {
	s.t.Helper()
	got := s.written()
	if len(want) == 0 {
		want = nil
	}
	if !reflect.DeepEqual(got, want) {
		s.t.Errorf("written:\n %q\nwant\n %q", got, want)
	}
}

// TestALinkAfterTheStartSetsTheParent pins the order in which a subagent's start comes
// before its first message: the start and the hook events after it are kept back, and
// the message writes them in their order with the parent.
func TestALinkAfterTheStartSetsTheParent(t *testing.T) {
	s := newSession(t)
	s.init()
	s.call("", "toolu_1")
	s.start("a1")
	s.call("a1", "toolu_2")
	s.start("a2")
	s.stop("a1")
	s.want("tool_started")
	s.message("a1", "toolu_1")
	s.want("tool_started", "subagent_started a1", "tool_started a1")
	s.message("a2", "toolu_2")
	s.want("tool_started", "subagent_started a1", "tool_started a1", "subagent_started a2:a1", "turn_finished a1")
}

// TestALinkBeforeTheStartSetsTheParent pins the other order: the message comes first,
// and the start is written at once with the parent.
func TestALinkBeforeTheStartSetsTheParent(t *testing.T) {
	s := newSession(t)
	s.init()
	s.call("", "toolu_1")
	s.message("a1", "toolu_1")
	s.start("a1")
	s.call("a1", "toolu_2")
	s.message("a2", "toolu_2")
	s.start("a2")
	s.want("tool_started", "subagent_started a1", "tool_started a1", "subagent_started a2:a1")
}

// TestAStartWaitsAtMostFiveSeconds pins the bound: a start whose link does not arrive
// is written without a parent once 5 seconds have passed, with the events kept behind
// it, and a link after that changes nothing.
func TestAStartWaitsAtMostFiveSeconds(t *testing.T) {
	s := newSession(t)
	s.init()
	s.call("", "toolu_1")
	s.start("a1")
	s.stop("a1")
	s.clock.advance(parents.Hold - time.Millisecond)
	s.want("tool_started")
	s.clock.advance(time.Millisecond)
	s.want("tool_started", "subagent_started a1", "turn_finished a1")
	s.message("a1", "toolu_1")
	s.stop("")
	s.want("tool_started", "subagent_started a1", "turn_finished a1", "turn_finished")
}

// TestParallelSubagentsKeepTheirOrder pins two subagents started together: the second
// one's link comes first, and nothing is written until the first one's start is
// settled; then both are written in their order, each with its parent.
func TestParallelSubagentsKeepTheirOrder(t *testing.T) {
	s := newSession(t)
	s.init()
	s.call("", "toolu_0")
	s.message("p", "toolu_0")
	s.start("p")
	s.call("p", "toolu_1")
	s.call("p", "toolu_2")
	s.start("a1")
	s.start("a2")
	s.message("a2", "toolu_2")
	s.want("tool_started", "subagent_started p", "tool_started p", "tool_started p")
	s.message("a1", "toolu_1")
	s.want("tool_started", "subagent_started p", "tool_started p", "tool_started p", "subagent_started a1:p", "subagent_started a2:p")
}

// TestDepthTwo pins a subagent that a subagent of a subagent started: each start has
// the agent of its call as its parent.
func TestDepthTwo(t *testing.T) {
	s := newSession(t)
	s.init()
	s.call("", "toolu_1")
	s.start("a1")
	s.message("a1", "toolu_1")
	s.call("a1", "toolu_2")
	s.start("a2")
	s.message("a2", "toolu_2")
	s.call("a2", "toolu_3")
	s.start("a3")
	s.message("a3", "toolu_3")
	s.want("tool_started", "subagent_started a1", "tool_started a1", "subagent_started a2:a1", "tool_started a2", "subagent_started a3:a2")
}

// TestAnUnknownCallSetsNoParent pins a link whose call no tool_started reported: the
// start is written at the link, without a parent.
func TestAnUnknownCallSetsNoParent(t *testing.T) {
	s := newSession(t)
	s.init()
	s.start("a1")
	s.want()
	s.message("a1", "forked-command-review")
	s.want("subagent_started a1")
}

// TestWithoutOutputNothingIsKeptBack pins a session whose runtime printed no JSON line:
// an interactive one, or one whose output is text. Each event is written as it comes,
// without a parent.
func TestWithoutOutputNothingIsKeptBack(t *testing.T) {
	s := newSession(t)
	s.call("", "toolu_1")
	s.start("a1")
	s.call("a1", "toolu_2")
	s.start("a2")
	s.want("tool_started", "subagent_started a1", "tool_started a1", "subagent_started a2")
}

// TestCloseWritesWhatIsKeptBack pins the session's end: the events kept back are
// written without a parent, the timers stop, and a record after Close is written at
// once.
func TestCloseWritesWhatIsKeptBack(t *testing.T) {
	s := newSession(t)
	s.init()
	s.call("", "toolu_1")
	s.start("a1")
	s.stop("a1")
	s.m.Close()
	s.want("tool_started", "subagent_started a1", "turn_finished a1")
	s.start("a2")
	s.clock.advance(parents.Hold)
	s.want("tool_started", "subagent_started a1", "turn_finished a1", "subagent_started a2")
}

// TestOutputEventsAreNotKeptBack pins that only hook events wait: the result line is
// written while a start waits.
func TestOutputEventsAreNotKeptBack(t *testing.T) {
	s := newSession(t)
	s.init()
	s.start("a1")
	s.record("output", `{"type":"result","session_id":"s1","subtype":"success","is_error":false}`)
	s.want("result")
}

// TestHandleReturnsAtOnceWhileItKeepsEventsBack pins that the socket is not held up: on
// the real clock, a record handled while a start waits returns within 10 ms, and the
// timer writes the start once its time runs out.
func TestHandleReturnsAtOnceWhileItKeepsEventsBack(t *testing.T) {
	d, err := descriptor.Parse("amp.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan descriptor.Event, 8)
	m := parents.New(d, func(e descriptor.Event) { written <- e }, parents.Real)
	handle := func(source, js string) time.Duration {
		var r map[string]any
		if err := json.Unmarshal([]byte(js), &r); err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		m.Handle(descriptor.Record{Source: source, Record: r})
		return time.Since(begin)
	}
	handle("output", `{"type":"system","subtype":"init","session_id":"s1"}`)
	for i, js := range []string{
		`{"hook_event_name":"SubagentStart","session_id":"s1","agent_id":"a1","agent_type":"general-purpose"}`,
		`{"hook_event_name":"Stop","session_id":"s1","agent_id":"a1"}`,
	} {
		if took := handle("hooks", js); took > 10*time.Millisecond {
			t.Errorf("record %d: Handle took %s while it kept events back", i, took)
		}
	}
	select {
	case e := <-written:
		t.Fatalf("%s was written before its time ran out", e.Type)
	default:
	}
	for _, want := range []string{"dev.qory.runtime.subagent_started", "dev.qory.runtime.turn_finished"} {
		select {
		case e := <-written:
			if e.Type != want {
				t.Errorf("wrote %s, want %s", e.Type, want)
			}
			if _, ok := e.Data["parent_agent_id"]; ok {
				t.Errorf("%s has a parent", e.Type)
			}
		case <-time.After(parents.Hold + 5*time.Second):
			t.Fatalf("no %s within %s", want, parents.Hold+5*time.Second)
		}
	}
}

// mapOnly is a runtime that maps records and reports no link.
type mapOnly struct{ d *descriptor.Descriptor }

func (r mapOnly) Map(rec descriptor.Record) []descriptor.Event { return r.d.Map(rec) }

// TestARuntimeWithoutLinksKeepsNothingBack pins that a runtime that is no Linker has
// each event written as it comes, after a line of output too.
func TestARuntimeWithoutLinksKeepsNothingBack(t *testing.T) {
	d, err := descriptor.Parse("amp.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	m := parents.New(mapOnly{d}, func(e descriptor.Event) { got = append(got, e.Type) }, &clock{})
	for _, r := range []descriptor.Record{
		{Source: "output", Record: map[string]any{"type": "system"}},
		{Source: "hooks", Record: map[string]any{"hook_event_name": "SubagentStart", "session_id": "s1", "agent_id": "a1", "agent_type": "x"}},
		{Source: "hooks", Record: map[string]any{"hook_event_name": "Stop", "session_id": "s1", "agent_id": "a1"}},
	} {
		m.Handle(r)
	}
	if want := []string{"dev.qory.runtime.subagent_started", "dev.qory.runtime.turn_finished"}; !reflect.DeepEqual(got, want) {
		t.Errorf("written %q, want %q", got, want)
	}
}
