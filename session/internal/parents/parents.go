// Package parents maps a session's records to its runtime's events and sets
// parent_agent_id on each dev.qory.runtime.subagent_started whose subagent another
// subagent started.
//
// A runtime that implements [Linker] reports, in some records, a subagent's id and the
// id of the tool call that started it: a link. The [Mapper] keeps, for each
// dev.qory.runtime.tool_started it wrote, the agent that made the call, so the agent of
// a link's call is the subagent's parent when that agent is a subagent. The link may
// come after the subagent's start: once the mapper has read a record of the output
// source, it keeps a subagent's start and the hook events after it back until the
// subagent's link arrives, for at most [Hold], and then writes them in their order.
// The mapper returns at once while it keeps events back; a timer writes them.
package parents

import (
	"sync"
	"time"

	"github.com/qoryai/forager/session/internal/descriptor"
)

// Hold is how long the mapper keeps a subagent's start back while it waits for the
// subagent's link.
const Hold = 5 * time.Second

// The event types and fields the mapper reads and writes.
const (
	toolStarted     = "dev.qory.runtime.tool_started"
	subagentStarted = "dev.qory.runtime.subagent_started"
	fieldToolUseID  = "tool_use_id"
	fieldAgentID    = "agent_id"
	fieldParent     = "parent_agent_id"
)

// Runtime is what the mapper maps a record with.
type Runtime interface {
	Map(descriptor.Record) []descriptor.Event
}

// Linker is implemented by a runtime whose records report which tool call started a
// subagent: Link returns the subagent's id, the call's id and true for such a record.
type Linker interface {
	Link(descriptor.Record) (agentID, toolUseID string, ok bool)
}

// Clock starts a timer that calls f once d has passed; the returned stop prevents the
// call when it has not happened yet.
type Clock interface {
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

// Real is the clock of package time.
var Real Clock = realClock{}

type realClock struct{}

// AfterFunc is time.AfterFunc, and the stop is its timer's Stop.
func (realClock) AfterFunc(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }

// Mapper maps the records of one session. Handle and Close may be called from several
// goroutines; write is called with one event at a time, in the order the session
// writes them.
type Mapper struct {
	mu     sync.Mutex
	rt     Runtime
	linker Linker
	write  func(descriptor.Event)
	clock  Clock
	// output is true once a record of the output source was read: only then does the
	// mapper keep events back.
	output bool
	closed bool
	// calls is the agent of each tool call a tool_started reported, by the call's id;
	// the empty string for a call of the main agent.
	calls map[string]string
	// links is the id of the tool call that started each subagent, by the subagent's id.
	links map[string]string
	// queue is the hook events kept back, in their order.
	queue []*kept
}

// kept is one event the mapper keeps back. waiting is true while it is a subagent's
// start whose link has not arrived and whose time has not run out.
type kept struct {
	event   descriptor.Event
	agent   string
	waiting bool
	stop    func() bool
}

// New is a mapper that maps records with rt and writes each event with write. When rt
// is no [Linker], the mapper writes each event as it maps it and sets no parent.
func New(rt Runtime, write func(descriptor.Event), clock Clock) *Mapper {
	m := &Mapper{rt: rt, write: write, clock: clock, calls: map[string]string{}, links: map[string]string{}}
	if l, ok := rt.(Linker); ok {
		m.linker = l
	}
	return m
}

// Handle maps one record. It writes the record's events, or keeps a hook record's
// events back behind a subagent's start that waits for its link, and returns without
// waiting.
func (m *Mapper) Handle(rec descriptor.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec.Source == descriptor.SourceOutput {
		m.output = true
	}
	if m.linker != nil {
		if agent, call, ok := m.linker.Link(rec); ok {
			m.linked(agent, call)
			m.flush()
		}
	}
	for _, e := range m.rt.Map(rec) {
		k := &kept{event: e}
		switch e.Type {
		case toolStarted:
			if id, _ := e.Data[fieldToolUseID].(string); id != "" {
				agent, _ := e.Data[fieldAgentID].(string)
				m.calls[id] = agent
			}
		case subagentStarted:
			k.agent, _ = e.Data[fieldAgentID].(string)
			if k.agent != "" && m.linker != nil {
				if call, ok := m.links[k.agent]; ok {
					m.parent(k, call)
				} else if m.output && !m.closed && rec.Source == descriptor.SourceHooks {
					k.waiting = true
					k.stop = m.clock.AfterFunc(Hold, func() { m.expire(k) })
				}
			}
		}
		if rec.Source == descriptor.SourceHooks && !m.closed {
			m.queue = append(m.queue, k)
			m.flush()
			continue
		}
		m.write(k.event)
	}
}

// Close writes every event still kept back, without a parent for a start that still
// waits, and stops the timers. Events of records handled after Close are written as
// they are mapped.
func (m *Mapper) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for _, k := range m.queue {
		if k.waiting {
			k.waiting = false
			k.stop()
		}
	}
	m.flush()
}

// linked records the link of a subagent and sets the parent of its start when the
// start waits for it. A subagent's first link is the one that counts.
func (m *Mapper) linked(agent, call string) {
	if _, ok := m.links[agent]; ok {
		return
	}
	m.links[agent] = call
	for _, k := range m.queue {
		if k.waiting && k.agent == agent {
			k.waiting = false
			k.stop()
			m.parent(k, call)
		}
	}
}

// parent sets the start's parent_agent_id to the agent of the call, when the call is
// one a tool_started reported and its agent is a subagent other than this one.
func (m *Mapper) parent(k *kept, call string) {
	if p := m.calls[call]; p != "" && p != k.agent {
		if k.event.Data == nil {
			k.event.Data = map[string]any{}
		}
		k.event.Data[fieldParent] = p
	}
}

// expire ends the wait of a start whose time ran out: it is written without a parent.
func (m *Mapper) expire(k *kept) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !k.waiting {
		return
	}
	k.waiting = false
	m.flush()
}

// flush writes the kept events from the first up to the first start that still waits.
func (m *Mapper) flush() {
	i := 0
	for ; i < len(m.queue) && !m.queue[i].waiting; i++ {
		m.write(m.queue[i].event)
		m.queue[i] = nil
	}
	m.queue = m.queue[i:]
}
