package gateway

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/server"
)

// TestTheKeptFilesReadBack pins the readers of the files a separate gateway keeps:
// request.json reads back as written, and decides with the same images and narrowing;
// joins.jsonl and given.jsonl read back in order, a line the gateway did not finish
// skipped and counted; the mark reads back as made and removed; and no file is none.
func TestTheKeptFilesReadBack(t *testing.T) {
	dir := t.TempDir()
	if joins, torn, err := readJoins(dir); joins != nil || torn != 0 || err != nil {
		t.Errorf("no joins.jsonl: %v %d %v", joins, torn, err)
	}
	if given, torn, err := readGiven(dir); given != nil || torn != 0 || err != nil {
		t.Errorf("no given.jsonl: %v %d %v", given, torn, err)
	}
	if _, err := readRequest(dir); err == nil {
		t.Error("no request.json read back")
	}

	req := &server.LinkRunRequest{Wall: true, Narrowing: &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Allow: []string{"api.example"}, Deny: []string{"bad.example"}}},
		Images: &server.LinkImages{Default: "base", Definitions: []server.LinkImage{{Name: "base", Ref: "registry.example/base:1", Runtime: "runsc"}}, Allow: []string{"registry.example/"}}}
	if err := writeRequest(dir, req); err != nil {
		t.Fatal(err)
	}
	k, err := readRequest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Wall || !reflect.DeepEqual(images(k.Images), images(req.Images)) || !reflect.DeepEqual(narrowingOf(k.Narrowing), narrowingOf(req.Narrowing)) {
		t.Errorf("request.json read back as %+v", k)
	}

	one := &join{session: 1, accepted: true, passes: []string{"HOME"}, model: "first", credential: "first"}
	two := &join{session: 2, passes: []string{"API_TOKEN"}, noKey: true}
	for _, j := range []*join{one, two} {
		if err := appendKept(dir, joinsFile, j.kept()); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, joinsFile), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"session":3,"accep`)
	f.Close()
	joins, torn, err := readJoins(dir)
	if err != nil || torn != 1 || len(joins) != 2 {
		t.Fatalf("joins.jsonl: %+v %d %v", joins, torn, err)
	}
	for i, want := range []*join{one, two} {
		if got := joins[i].join(); !reflect.DeepEqual(got, want) {
			t.Errorf("join %d read back as %+v; want %+v", i+1, got, want)
		}
	}

	given := []map[string]any{{"mode": "enforce", "allow": []any{"api.example"}}, {"mode": "monitor", "allow": []any{}}}
	for _, a := range given {
		if err := appendKept(dir, givenFile, a); err != nil {
			t.Fatal(err)
		}
	}
	got, torn, err := readGiven(dir)
	if err != nil || torn != 0 || !reflect.DeepEqual(got, given) {
		t.Errorf("given.jsonl: %v %d %v", got, torn, err)
	}

	for _, passed := range []bool{true, true, false, false} {
		if err := markLimit(dir, passed); err != nil {
			t.Fatal(err)
		}
		if marked, err := limitMarked(dir); err != nil || marked != passed {
			t.Errorf("after markLimit(%v): marked %v, %v", passed, marked, err)
		}
	}
	for _, name := range []string{requestFile, joinsFile, givenFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", name, info, err)
		}
	}
	if !slices.Equal(one.kept().Passes, []string{"HOME"}) || (&join{}).kept().Passes == nil {
		t.Error("a join's line has no passes array")
	}
}

// TestTheSweepLeavesAReopenAlone pins the sweep beside a reopen: the CA files of a run
// whose reopen is in flight stay, however old its record, and go once it is not.
func TestTheSweepLeavesAReopenAlone(t *testing.T) {
	dir := t.TempDir()
	runID := "0b2f1e3c-4d5a-4b6c-8d7e-9f0a1b2c3d4e"
	rec := filepath.Join(dir, "runs", runID)
	if err := os.MkdirAll(rec, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, name := range []string{"events.jsonl", "ca.pem", "ca.key"} {
		if err := os.WriteFile(filepath.Join(rec, name), []byte("fake\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(rec, "events.jsonl"), old, old); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{cfg: Config{Dir: dir}, report: func(string) {}, runs: map[string]*linkRun{}, reopening: map[string]*reopenCall{runID: {done: make(chan struct{})}}}
	g.sweep(time.Now(), time.Minute)
	if _, err := os.Stat(filepath.Join(rec, "ca.key")); err != nil {
		t.Errorf("the sweep removed the CA key of a run being reopened: %v", err)
	}
	delete(g.reopening, runID)
	g.sweep(time.Now(), time.Minute)
	if _, err := os.Stat(filepath.Join(rec, "ca.key")); err == nil {
		t.Error("the sweep kept the CA key once no reopen was in flight")
	}
}
