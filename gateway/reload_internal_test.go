package gateway

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/server"
)

// TestAReloadThatPanicsLetsTheNextAnswerReload pins that a reload pass that panics is
// reported under the run's id, and that the next answer whose digest differs starts
// another pass: the reload is no longer running once the pass that panicked ended.
func TestAReloadThatPanicsLetsTheNextAnswerReload(t *testing.T) {
	reports := make(chan string, 4)
	// Without a client, a pass panics as it discovers the configuration again.
	l := newLive(context.Background(), nil, &server.Configuration{}, "sha256=start", "run-a", func(line string) { reports <- line })
	defer l.stop()
	l.start(func(*policy.Loaded) error { return nil })
	for i := range 2 {
		l.digests(server.Digests{Configuration: fmt.Sprintf("sha256=%d", i)})
		select {
		case got := <-reports:
			if first, _, _ := strings.Cut(got, "\n"); first != "run run-a: "+routine.Panicked {
				t.Errorf("answer %d: the report's first line is %q", i, first)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("answer %d started no reload pass", i)
		}
	}
}

// TestAFailedReloadReportsItsFixFirst pins the report of a failed reload. A
// [run.FixFirstError] has its fix on the first line and "the reload failed: " before its
// cause on the second, a cause with qak_ shown as the phrase; any other error is "the
// reload failed: " and its text, as before the fix-first refusals.
func TestAFailedReloadReportsItsFixFirst(t *testing.T) {
	var got []string
	l := newLive(context.Background(), nil, &server.Configuration{}, "sha256=start", "run-a", func(line string) { got = append(got, line) })
	defer l.stop()
	const fix = "Start a new run to use other credentials."
	l.failed(&run.FixFirstError{Fix: fix, Cause: "run configuration https://apiary.example/v1/runs: the credentials differ; the policy in force stays"})
	l.failed(&run.FixFirstError{Fix: fix, Cause: "run configuration https://apiary.example/v1/qak_not-a-real-secret/runs: the credentials differ"})
	l.failed(errors.New("start another run to use other stack hosts: a run's stack_hosts are fixed when it starts"))
	l.failed(errors.New("run configuration https://apiary.example/v1/qak_not-a-real-secret/runs: refused"))
	want := []string{
		fix + "\nthe reload failed: run configuration https://apiary.example/v1/runs: the credentials differ; the policy in force stays",
		fix + "\nthe reload failed: (a value that contains an access key secret)",
		"the reload failed: start another run to use other stack hosts: a run's stack_hosts are fixed when it starts",
		"the reload failed: (a value that contains an access key secret)",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the reports:\n got %q\nwant %q", got, want)
	}
}
