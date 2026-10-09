package runcredential

import (
	jsonv2 "encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndedSurvivesARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	clock := now
	at := func() time.Time { return clock }
	e, err := openEnded(dir, at)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil {
		t.Fatalf("the directory: %v", err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("the directory: %v", info.Mode())
	}
	exp := now.Add(10 * time.Minute)
	if e.Has(exampleIssuer, "rk-0001", now) {
		t.Fatal("a run key ended before it was added")
	}
	if err := e.Add(exampleIssuer, "rk-0001", exp); err != nil {
		t.Fatal(err)
	}
	if !e.Has(exampleIssuer, "rk-0001", now) {
		t.Error("an ended run key is not kept")
	}
	if e.Has("https://issuer-b.example", "rk-0001", now) || e.Has(exampleIssuer, "rk-0002", now) {
		t.Error("another issuer's run key, or another run key, has ended")
	}
	info, err := os.Stat(filepath.Join(dir, EndedFile))
	if err != nil {
		t.Fatalf("the file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v", info.Mode())
	}

	// A restart: the run key is still refused.
	again, err := openEnded(dir, at)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Has(exampleIssuer, "rk-0001", now) {
		t.Error("a restart reopened an ended run key")
	}
	// It is kept until exp plus MaxLeeway, the latest a run credential of that exp is
	// accepted under any leeway.
	if !again.Has(exampleIssuer, "rk-0001", exp.Add(MaxLeeway-time.Second)) {
		t.Error("the run key is dropped before exp plus MaxLeeway")
	}
	if again.Has(exampleIssuer, "rk-0001", exp.Add(MaxLeeway)) {
		t.Error("the run key is kept past exp plus MaxLeeway")
	}
	// Past its time, a restart drops it from the file.
	clock = exp.Add(MaxLeeway)
	if _, err := openEnded(dir, at); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, EndedFile))
	if strings.Contains(string(b), "rk-0001") {
		t.Errorf("the file keeps a run key past its time: %s", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the directory holds %d files; want the one file, no temporary one", len(entries))
	}
}

func TestEndedAddKeepsTheLaterTimeAndPrunes(t *testing.T) {
	clock := now
	e, err := openEnded(t.TempDir(), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	late, early := now.Add(time.Hour), now.Add(time.Minute)
	if err := e.Add(exampleIssuer, "rk-0001", late); err != nil {
		t.Fatal(err)
	}
	if err := e.Add(exampleIssuer, "rk-0001", early); err != nil {
		t.Fatal(err)
	}
	if !e.Has(exampleIssuer, "rk-0001", late) {
		t.Error("an earlier exp shortened how long the run key is kept")
	}
	if err := e.Add(exampleIssuer, "rk-0002", early); err != nil {
		t.Fatal(err)
	}
	clock = early.Add(MaxLeeway)
	if err := e.Add(exampleIssuer, "rk-0003", late); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	_, kept := e.entries[endedKey{exampleIssuer, "rk-0002"}]
	e.mu.Unlock()
	if kept {
		t.Error("Add keeps an entry past its time")
	}
	if err := e.Add("", "rk-0001", late); err == nil {
		t.Error("Add accepts no issuer")
	}
	if err := e.Add(exampleIssuer, "", late); err == nil {
		t.Error("Add accepts no run key")
	}
}

func TestEndedWrittenIsWhatTheFileHolds(t *testing.T) {
	dir := t.TempDir()
	e, err := openEnded(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	soon, late := now.Add(time.Minute), now.Add(time.Hour)
	if err := e.Add(exampleIssuer, "rk-0001", soon); err != nil {
		t.Fatal(err)
	}
	// A directory that is not empty at the file's path: the rename over it fails, for
	// root too. The file as written is set aside, and put back below.
	path := filepath.Join(dir, EndedFile)
	aside := filepath.Join(t.TempDir(), EndedFile)
	if err := os.Rename(path, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "blocked"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := e.Add(exampleIssuer, "rk-0001", late); err == nil {
		t.Fatal("a write over a directory")
	}
	if err := e.Add(exampleIssuer, "rk-0002", late); err == nil {
		t.Fatal("a write over a directory")
	}
	past := soon.Add(MaxLeeway + time.Second)
	switch {
	case !e.Has(exampleIssuer, "rk-0001", past) || !e.Has(exampleIssuer, "rk-0002", now):
		t.Error("an Add that failed to write is not kept in memory")
	case !e.Written(exampleIssuer, "rk-0001", now):
		t.Error("the run key written once is not the file's")
	case e.Written(exampleIssuer, "rk-0001", past):
		t.Error("the file holds the extension that failed to write")
	case e.Written(exampleIssuer, "rk-0002", now):
		t.Error("the file holds a run key never written")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, path); err != nil {
		t.Fatal(err)
	}
	reopened, err := openEnded(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Written(exampleIssuer, "rk-0001", now) || reopened.Written(exampleIssuer, "rk-0002", now) {
		t.Error("the file as read at open")
	}
}

func TestOpenEndedRefuses(t *testing.T) {
	// A directory others may write.
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEnded(open); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Errorf("a directory others write: %v", err)
	}
	// A file where the directory should be.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := OpenEnded(file); err == nil {
		t.Error("a file as the directory")
	}
	for name, content := range map[string]string{
		"not JSON":          "ended",
		"an unknown member": `{"ended": [], "other": 1}`,
		"a member twice":    `{"ended": [], "ended": []}`,
		"no run key":        `{"ended": [{"issuer": "https://issuer.example", "until": 1700000600}]}`,
		"null":              `null`,
		"an empty object":   `{}`,
		"ended null":        `{"ended": null}`,
		"an entry null":     `{"ended": [null]}`,
		"an unknown entry":  `{"ended": [{"issuer": "https://issuer.example", "run_key": "rk-0001", "until": 1700000600, "x": 1}]}`,
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, EndedFile), []byte(content), 0o600)
		if _, err := OpenEnded(dir); err == nil {
			t.Errorf("%s: OpenEnded accepts it", name)
		}
	}
	// A file others may read or write.
	for _, mode := range []os.FileMode{0o640, 0o604, 0o620, 0o602, 0o666} {
		dir := t.TempDir()
		f := filepath.Join(dir, EndedFile)
		os.WriteFile(f, []byte(`{"ended": []}`), 0o600)
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenEnded(dir); err == nil || !strings.Contains(err.Error(), "by others than its owner") {
			t.Errorf("a file of mode %o: %v", mode, err)
		}
	}
	// A symbolic link in place of the file.
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	os.WriteFile(target, []byte(`{"ended": []}`), 0o600)
	if err := os.Symlink(target, filepath.Join(dir, EndedFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEnded(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a symbolic link: %v", err)
	}
	// An empty document is no ended run key.
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, EndedFile), []byte(`{"ended": []}`), 0o600)
	if e, err := OpenEnded(dir); err != nil || e.Has(exampleIssuer, "rk-0001", now) {
		t.Errorf("an empty document: %v", err)
	}
}

// TestEndedKeepsTheOutcome pins how a run key's run ended: kept with the outcome and the
// reason its first hold gave, which a later hold of it, with or without one, leaves as
// they are, and a restart reads again; a hold past its time takes a new one; and the
// file holds them as members a gateway before them refuses.
func TestEndedKeepsTheOutcome(t *testing.T) {
	dir := t.TempDir()
	clock := now
	at := func() time.Time { return clock }
	e, err := openEnded(dir, at)
	if err != nil {
		t.Fatal(err)
	}
	exp := now.Add(10 * time.Minute)
	if err := e.AddOutcome(exampleIssuer, "rk-0001", exp, "succeeded", "all_checks_passed"); err != nil {
		t.Fatal(err)
	}
	if err := e.AddOutcome(exampleIssuer, "rk-0001", exp.Add(time.Hour), "failed", "checks_failed"); err != nil {
		t.Fatal(err)
	}
	if err := e.Add(exampleIssuer, "rk-0001", exp.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := e.Add(exampleIssuer, "rk-0002", exp); err != nil {
		t.Fatal(err)
	}
	if err := e.AddOutcome(exampleIssuer, "rk-0002", exp, "cancelled", "no_longer_needed"); err != nil {
		t.Fatal(err)
	}
	if err := e.AddOutcome(exampleIssuer, "rk-0003", exp, "cancelled", "timeout"); err != nil {
		t.Fatal(err)
	}
	check := func(what string, e *Ended) {
		t.Helper()
		for _, c := range []struct{ key, outcome, reason string }{
			{"rk-0001", "succeeded", "all_checks_passed"},
			{"rk-0002", "", ""},
			{"rk-0003", "cancelled", ""},
		} {
			if o, r, ok := e.Outcome(exampleIssuer, c.key, now); !ok || o != c.outcome || r != c.reason {
				t.Errorf("%s: %s: %q %q %v", what, c.key, o, r, ok)
			}
		}
		if !e.Has(exampleIssuer, "rk-0001", exp.Add(2*time.Hour)) {
			t.Errorf("%s: the later exp is not kept", what)
		}
	}
	check("as added", e)
	b, _ := os.ReadFile(filepath.Join(dir, EndedFile))
	if !strings.Contains(string(b), `"outcome": "succeeded"`) || !strings.Contains(string(b), `"reason": "all_checks_passed"`) {
		t.Errorf("the file: %s", b)
	}
	// A gateway before the outcome reads each entry with three members, and refuses
	// any other.
	type before struct {
		Ended *[]struct {
			Issuer string `json:"issuer"`
			RunKey string `json:"run_key"`
			Until  int64  `json:"until"`
		} `json:"ended"`
	}
	if err := jsonv2.Unmarshal(b, new(before), jsonv2.RejectUnknownMembers(true)); err == nil {
		t.Error("a gateway before the outcome reads the file")
	}
	again, err := openEnded(dir, at)
	if err != nil {
		t.Fatal(err)
	}
	check("after a restart", again)
	// Past its time, a run key's next hold has the outcome of its own.
	clock = exp.Add(MaxLeeway)
	if err := again.AddOutcome(exampleIssuer, "rk-0002", exp.Add(time.Hour), "failed", "checks_failed"); err != nil {
		t.Fatal(err)
	}
	if o, r, ok := again.Outcome(exampleIssuer, "rk-0002", clock); !ok || o != "failed" || r != "checks_failed" {
		t.Errorf("a new hold after the last lapsed: %q %q %v", o, r, ok)
	}
}

// TestOpenEndedRefusesAnOutcomeNoStarterGives pins the check of the file's outcome and
// reason when it is read: one a run's starter could not give is no entry this gateway
// wrote, and the file is refused.
func TestOpenEndedRefusesAnOutcomeNoStarterGives(t *testing.T) {
	entry := func(members string) string {
		return `{"ended": [{"issuer": "https://issuer.example", "run_key": "rk-0001", "until": 1700000600` + members + `}]}`
	}
	for name, content := range map[string]string{
		"an unknown outcome":        entry(`, "outcome": "lost"`),
		"a reason without outcome":  entry(`, "reason": "checks_failed"`),
		"a reserved reason":         entry(`, "outcome": "cancelled", "reason": "stopped"`),
		"an old name":               entry(`, "outcome": "cancelled", "reason": "issuer_unreachable"`),
		"a reason that is no code":  entry(`, "outcome": "failed", "reason": "Checks failed"`),
		"an outcome that is no str": entry(`, "outcome": 1`),
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, EndedFile), []byte(content), 0o600)
		if _, err := openEnded(dir, func() time.Time { return time.Unix(1700000000, 0) }); err == nil {
			t.Errorf("%s: OpenEnded accepts it", name)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, EndedFile), []byte(entry(`, "outcome": "failed", "reason": "checks_failed"`)), 0o600)
	e, err := openEnded(dir, func() time.Time { return time.Unix(1700000000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if o, r, ok := e.Outcome("https://issuer.example", "rk-0001", time.Unix(1700000000, 0)); !ok || o != "failed" || r != "checks_failed" {
		t.Errorf("a good entry: %q %q %v", o, r, ok)
	}
}
