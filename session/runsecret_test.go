package session_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
)

// runSecretFile is the file of the run directory that keeps the run's secret behind a
// separate gateway.
const runSecretFile = "run-secret"

// runSecretShape is a run secret's form, link-run-answer.schema.json's run_secret.
var runSecretShape = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)

// keptRunSecret is the run secret the run directory keeps, failing the test unless it
// is there, mode 0600, the secret and one newline.
func keptRunSecret(t *testing.T, dir string) string {
	t.Helper()
	file := filepath.Join(dir, runSecretFile)
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatalf("the run secret's file: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("the run secret's file is %v, want a file of mode 0600", info.Mode())
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := strings.CutSuffix(string(b), "\n")
	if !ok || !runSecretShape.MatchString(secret) {
		t.Errorf("the run secret's file holds %d bytes, not a run secret and a newline", len(b))
	}
	return secret
}

// noRunSecret fails the test if the run directory keeps a run secret.
func noRunSecret(t *testing.T, what, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, runSecretFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s: the run directory keeps its run secret: %v", what, err)
	}
}

// TestASessionCarriesItsRunSecretOnTheLocalLink pins the run secret on the local link:
// the session carries the run answer's run_secret on every reload and batch, once each,
// and keeps no file of it, since nothing on one machine sends the session's record
// again.
func TestASessionCarriesItsRunSecretOnTheLocalLink(t *testing.T) {
	sp, g := specGateway(t)
	sleeps(&sp, time.Second)
	g.SetRunDigest("sha256=" + strings.Repeat("1", 64))
	g.OnBatch(func([]map[string]any) linktest.Reply {
		// Another digest: the session reloads.
		g.SetRunDigest("sha256=" + strings.Repeat("2", 64))
		return linktest.Reply{Status: 200}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	secrets := g.RunSecrets()
	if len(g.Reloads()) == 0 || len(secrets) != len(g.Reloads())+len(g.Batches()) {
		t.Fatalf("%d reloads, %d batches, %d run secrets", len(g.Reloads()), len(g.Batches()), len(secrets))
	}
	for i, got := range secrets {
		if got != linktest.RunSecret {
			t.Errorf("request %d carried %q, want the run answer's run secret once", i, got)
		}
	}
	noRunSecret(t, "on the local link", res.Dir)
}
