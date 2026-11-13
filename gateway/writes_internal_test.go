package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/stream"
)

// emitted is a writeLog whose emits are kept as "<path> <state> <request id>".
func emitted() (*writeLog, *[]string) {
	var out []string
	l := &writeLog{emit: func(data map[string]any) {
		out = append(out, fmt.Sprint(data["path"], " ", data["state"], " ", data["request_id"]))
	}}
	return l, &out
}

// write is a write of example-org/<path> with the request id id, in state.
func write(path, id, state string) proxy.Write {
	return proxy.Write{System: "git.example", Path: "example-org/" + path, RequestID: id, State: state}
}

// TestTheWriteLogNumbersEachWriteOnce pins writeLog: a started, then its end once; an
// end of a request id that is not open is dropped; cutOpen numbers one cut per write
// still open, in the order they started, and nothing after it, an end or a started.
func TestTheWriteLogNumbersEachWriteOnce(t *testing.T) {
	l, out := emitted()
	l.observe(write("app", "1", event.WriteStarted))
	l.observe(write("lib", "2", event.WriteStarted))
	l.observe(write("doc", "3", event.WriteStarted))
	l.observe(write("lib", "2", event.WriteChanged))
	l.observe(write("lib", "2", event.WriteCut))
	l.observe(write("app", "9", event.WriteRefused))
	l.cutOpen()
	l.cutOpen()
	l.observe(write("app", "1", event.WriteChanged))
	l.observe(write("new", "4", event.WriteStarted))
	l.observe(write("new", "4", event.WriteChanged))
	want := []string{
		"example-org/app started 1", "example-org/lib started 2", "example-org/doc started 3",
		"example-org/lib changed 2",
		"example-org/app cut 1", "example-org/doc cut 3",
	}
	if !slices.Equal(*out, want) {
		t.Errorf("the log numbered\n %q\nwant\n %q", *out, want)
	}
	var none *writeLog
	none.cutOpen()
}

// TestTheRunsEndCutsAnOpenWrite pins linkRun.end on a run whose proxy hands over no
// end of a write: the end numbers the write's cut, after its started and before the
// gateway's run.exited.
func TestTheRunsEndCutsAnOpenWrite(t *testing.T) {
	dir := t.TempDir()
	g := &Gateway{cfg: Config{Dir: dir}, report: func(string) {}, stream: stream.New(stream.Config{Dir: dir}), base: context.Background(), runs: map[string]*linkRun{}}
	runID := event.NewRunID()
	st, err := g.stream.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	started := event.Event{SpecVersion: "1.0", ID: event.NewID(), Source: event.Source(runID), Type: event.RunStarted, Subject: runID,
		DataSchema: event.DataSchema(event.RunStarted), Data: map[string]any{"opened_by": "run", "forager_version": "test"}}
	if _, err := st.Accept([]event.Event{started}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	lr := &linkRun{g: g, id: runID, st: st, ctx: ctx, cancel: cancel, opened: true, seen: map[string]bool{}, done: make(chan struct{})}
	lr.writes = &writeLog{emit: func(data map[string]any) { lr.st.Emit(event.RunTargetWrite, data) }}
	lr.writes.observe(write("app", "1", event.WriteStarted))
	lr.end(batchRefused)
	<-lr.done
	b, err := os.ReadFile(filepath.Join(st.Dir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type == event.RunTargetWrite {
			got = append(got, fmt.Sprint(ev.Data["state"]))
			continue
		}
		got = append(got, ev.Type)
	}
	want := []string{event.RunStarted, event.WriteStarted, event.WriteCut, event.RunExited}
	if !slices.Equal(got, want) {
		t.Errorf("the record %q; want %q", got, want)
	}
}
