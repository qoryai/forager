// Package runtimetest is what a runtime is held to, whoever wrote it: the checks a
// [runtimes.Runtime] passes before Forager runs sessions of it. A runtime's own test
// calls [Conforms], and [Replays] with the records it was written against.
package runtimetest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/session/runtimes"
)

var (
	name      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	eventType = regexp.MustCompile(`^dev\.qory\.session\.[a-z_]+$`)
)

// Conforms checks what holds of every runtime: a name events can carry, a stop the
// session can send, and a Prepare that leaves alone what is not its own, the caller's
// program and arguments when the run has no forwarder, and the machine outside the run
// directory always.
func Conforms(t *testing.T, rt runtimes.Runtime) {
	t.Helper()
	if !name.MatchString(rt.Name()) {
		t.Errorf("the name %q is not a lower-case letter, then up to 63 lower-case letters, digits and dashes", rt.Name())
	}
	stop := rt.Stop()
	if err := runtimes.CheckStopSignal(stop.Signal); err != nil {
		t.Error(err)
	}
	if stop.Grace < 0 {
		t.Errorf("the stop grace %s is negative", stop.Grace)
	}
	if typ, _, ok := rt.Map(runtimes.Record{Source: runtimes.SourceHooks, Record: map[string]any{}}); ok {
		t.Errorf("an empty record became %s; a record that says nothing is no event", typ)
	}
	if rt.Headless(nil) {
		t.Error("no arguments at all are headless; a runtime started with none has whatever interface it has")
	}

	launch := runtimes.Launch{Command: "/usr/bin/program", Args: []string{"--flag", "value"}}
	dir := t.TempDir()
	got, err := rt.Prepare(runtimes.Attach{Launch: launch, RunDir: dir})
	if err != nil {
		t.Fatalf("Prepare with no forwarder: %v", err)
	}
	if !reflect.DeepEqual(got, launch) {
		t.Errorf("Prepare with no forwarder changed the launch: %+v", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Prepare with no forwarder wrote %d files", len(entries))
	}

	dir = t.TempDir()
	forwarder := []string{"/opt/forager/forward", "an argument's quote"}
	got, err = rt.Prepare(runtimes.Attach{Launch: launch, RunDir: dir, Forwarder: forwarder})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if got.Command != launch.Command {
		t.Errorf("Prepare starts %s, not the program it was given", got.Command)
	}
	if !reflect.DeepEqual(launch.Args, []string{"--flag", "value"}) {
		t.Errorf("Prepare changed the arguments it was given in place: %v", launch.Args)
	}
	for _, kv := range got.Env {
		if n, _, ok := strings.Cut(kv, "="); !ok || n == "" {
			t.Errorf("Prepare names the variable %q, which is not NAME=value", kv)
		}
	}
}

// Replays checks the runtime's Map against recorded cases: in every directory of fsys
// under dir, the records of records.jsonl, each {"source", "record"}, produce exactly
// the events of expected/events.jsonl, each {"type", "data"}, in order; every type is a
// session event's, and its data passes the contract's schema for it.
func Replays(t *testing.T, rt runtimes.Runtime, fsys fs.FS, dir string) {
	t.Helper()
	cases, err := fs.ReadDir(fsys, dir)
	if err != nil || len(cases) == 0 {
		t.Fatalf("no cases under %s: %v", dir, err)
	}
	for _, c := range cases {
		t.Run(c.Name(), func(t *testing.T) {
			var got []map[string]any
			lines(t, fsys, path.Join(dir, c.Name(), "records.jsonl"), func(b []byte) {
				var r runtimes.Record
				if err := json.Unmarshal(b, &r); err != nil {
					t.Fatal(err)
				}
				if typ, data, ok := rt.Map(r); ok {
					got = append(got, roundTrip(t, map[string]any{"type": typ, "data": data}))
				}
			})
			var want []map[string]any
			lines(t, fsys, path.Join(dir, c.Name(), "expected", "events.jsonl"), func(b []byte) {
				var e map[string]any
				if err := json.Unmarshal(b, &e); err != nil {
					t.Fatal(err)
				}
				want = append(want, e)
			})
			if len(got) != len(want) {
				t.Fatalf("produced %d events, want %d: %v", len(got), len(want), got)
			}
			for i := range want {
				if !reflect.DeepEqual(got[i], want[i]) {
					t.Errorf("event %d:\n got %v\nwant %v", i, got[i], want[i])
				}
				typ, _ := got[i]["type"].(string)
				if !eventType.MatchString(typ) {
					t.Errorf("event %d: %q is not a session event's type", i, typ)
					continue
				}
				schema, err := contracts.Compile("events/" + strings.TrimPrefix(typ, "dev.qory.") + ".schema.json")
				if err != nil {
					t.Errorf("event %d: %s is not an event of the contract: %v", i, typ, err)
					continue
				}
				if err := schema.Validate(got[i]["data"]); err != nil {
					t.Errorf("event %d: %s data: %v", i, typ, err)
				}
			}
		})
	}
}

func lines(t *testing.T, fsys fs.FS, name string, into func([]byte)) {
	t.Helper()
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		if len(bytes.TrimSpace(s.Bytes())) > 0 {
			into(s.Bytes())
		}
	}
}

// roundTrip puts a produced event through JSON so its numbers compare as a recorded
// one's do.
func roundTrip(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
