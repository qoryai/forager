package session_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
)

// TestASessionNamesItsRunOnTheLocalLink pins X-Qory-Run-Id on the local link: every
// batch of the session's names its run, once, and the reloads by the run's id in their
// path carry nothing more; the run directory holds no secret of the link's.
func TestASessionNamesItsRunOnTheLocalLink(t *testing.T) {
	sp, g := specGateway(t)
	sleeps(&sp, time.Second)
	g.SetRunDigest("sha256=" + strings.Repeat("1", 64))
	g.OnBatch(func([]map[string]any) linktest.Reply {
		// Another digest: the session reloads.
		g.SetRunDigest("sha256=" + strings.Repeat("2", 64))
		return linktest.Reply{Status: 200}
	})
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	ids := g.RunIDs()
	if len(g.Reloads()) == 0 || len(ids) == 0 || len(ids) != len(g.Batches()) {
		t.Fatalf("%d reloads, %d batches, %d run ids", len(g.Reloads()), len(g.Batches()), len(ids))
	}
	runID := filepath.Base(res.Dir)
	for i, got := range ids {
		if got != runID {
			t.Errorf("batch %d named %q, want the run %s once", i, got, runID)
		}
	}
	for i, evs := range g.Batches() {
		for _, e := range evs {
			if e["subject"] != runID {
				t.Errorf("batch %d holds an event of the subject %v", i, e["subject"])
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(res.Dir, "run-secret")); !os.IsNotExist(err) {
		t.Errorf("the run directory holds a run-secret: %v", err)
	}
}
