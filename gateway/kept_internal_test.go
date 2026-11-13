package gateway

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/stream"
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
		if reason, marked, err := limitMarked(dir); err != nil || marked != passed || reason != "" {
			t.Errorf("after markLimit(%v): marked %v, reason %q, %v", passed, marked, reason, err)
		}
	}
	// The stop's reason in the mark: a Pass after it keeps it, a Resume removes it, and
	// a mark whose contents are no reason is a mark with none.
	for _, want := range []string{"model_key_limit", "model_key_switch", "model_key_unauthorized"} {
		if err := markStop(dir, want); err != nil {
			t.Fatal(err)
		}
		if err := markLimit(dir, true); err != nil {
			t.Fatal(err)
		}
		if reason, marked, err := limitMarked(dir); err != nil || !marked || reason != want {
			t.Errorf("after markStop(%s): marked %v, reason %q, %v", want, marked, reason, err)
		}
	}
	if err := writeKept(dir, limitMark, []byte("model_key_lim")); err != nil {
		t.Fatal(err)
	}
	if reason, marked, err := limitMarked(dir); err != nil || !marked || reason != "" {
		t.Errorf("a torn mark: marked %v, reason %q, %v; want marked with no reason", marked, reason, err)
	}
	if err := markLimit(dir, false); err != nil {
		t.Fatal(err)
	}
	if _, marked, err := limitMarked(dir); err != nil || marked {
		t.Errorf("after the Resume: marked %v, %v", marked, err)
	}

	// The keys out of use after a 401: written and read back, and removed when none is left.
	at := time.Date(2026, 11, 13, 12, 0, 4, 0, time.UTC)
	keys := []modelkey.Unauthorized{{Credential: "model", At: at, Out: true}, {Credential: "model-2", At: at.Add(time.Second)}}
	if err := writeUnauthorized(dir, keys); err != nil {
		t.Fatal(err)
	}
	if got, err := readUnauthorized(dir); err != nil || !reflect.DeepEqual(got, keys) {
		t.Errorf("model-keys-unauthorized.json read back as %+v, %v; want %+v", got, err, keys)
	}
	if info, err := os.Stat(filepath.Join(dir, unauthorizedFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v %v", unauthorizedFile, info, err)
	}
	if err := writeUnauthorized(dir, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := readUnauthorized(dir); err != nil || got != nil {
		t.Errorf("after every key came back: %+v, %v; want none", got, err)
	}
	if err := writeKept(dir, unauthorizedFile, []byte(`{"version":1,"keys":[`)); err != nil {
		t.Fatal(err)
	}
	if _, err := readUnauthorized(dir); err == nil {
		t.Error("a torn model-keys-unauthorized.json reads with no error")
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

// TestTheSweepLeavesAReopenAlone pins the sweep beside a reopen: the CA files and the
// run request of a run whose reopen is in flight stay, however old its record, and go
// once it is not; and no reopen starts on a record the sweep marked.
func TestTheSweepLeavesAReopenAlone(t *testing.T) {
	dir := t.TempDir()
	runID := "0b2f1e3c-4d5a-4b6c-8d7e-9f0a1b2c3d4e"
	rec := filepath.Join(dir, "runs", runID)
	if err := os.MkdirAll(rec, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, name := range []string{"events.jsonl", "ca.pem", "ca.key", "request.json"} {
		if err := os.WriteFile(filepath.Join(rec, name), []byte("fake\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(rec, "events.jsonl"), old, old); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{cfg: Config{Dir: dir}, report: func(string) {}, stream: stream.New(stream.Config{Dir: dir}), runs: map[string]*linkRun{},
		reopening: map[string]*reopenCall{runID: {done: make(chan struct{})}}, sweeping: map[string]bool{}, spent: map[string]spentRun{}}
	g.sweep(time.Now(), time.Minute)
	for _, name := range []string{"ca.key", "request.json"} {
		if _, err := os.Stat(filepath.Join(rec, name)); err != nil {
			t.Errorf("the sweep removed %s of a run being reopened: %v", name, err)
		}
	}
	delete(g.reopening, runID)
	g.sweeping[runID] = true
	if lr, final := g.reopenRun(context.Background(), runID, presented{}); lr != nil || final || g.reopening[runID] != nil {
		t.Errorf("a reopen of a record the sweep marked: %v, final %v, in flight %v", lr, final, g.reopening[runID] != nil)
	}
	delete(g.sweeping, runID)
	g.sweep(time.Now(), time.Minute)
	for _, name := range []string{"ca.key", "ca.pem", "request.json"} {
		if _, err := os.Stat(filepath.Join(rec, name)); err == nil {
			t.Errorf("the sweep kept %s once no reopen was in flight", name)
		}
	}
	if len(g.sweeping) != 0 {
		t.Errorf("the sweep left its marks %v", g.sweeping)
	}
}

// TestAnAppendAfterATornLineStartsALine pins appendKept on a file whose last line the
// gateway did not finish: the line it adds starts a line, so it reads back, and the
// torn line is counted alone.
func TestAnAppendAfterATornLineStartsALine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, givenFile), []byte(`{"mode":"enforce"}`+"\n"+`{"mode":"obs`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendKept(dir, givenFile, map[string]any{"mode": "observe"}); err != nil {
		t.Fatal(err)
	}
	given, torn, err := readGiven(dir)
	if err != nil || torn != 1 || len(given) != 2 || given[1]["mode"] != "observe" {
		t.Errorf("given %v, %d torn, %v; want the line appended after the torn one", given, torn, err)
	}
	if err := appendKept(dir, givenFile, map[string]any{"mode": "enforce"}); err != nil {
		t.Fatal(err)
	}
	if given, torn, _ := readGiven(dir); torn != 1 || len(given) != 3 {
		t.Errorf("given %v, %d torn after a second append", given, torn)
	}
}
