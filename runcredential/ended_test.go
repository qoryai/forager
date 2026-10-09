package runcredential

import (
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
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the directory: %v, %v", info.Mode(), err)
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
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v, %v", info.Mode(), err)
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
		"an unknown entry":  `{"ended": [{"issuer": "https://issuer.example", "run_key": "rk-0001", "until": 1700000600, "x": 1}]}`,
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, EndedFile), []byte(content), 0o600)
		if _, err := OpenEnded(dir); err == nil {
			t.Errorf("%s: OpenEnded accepts it", name)
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
