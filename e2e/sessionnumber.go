package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
)

// modeSessionNumber is the program of a session that prints a report with the value
// of QORY_SESSION, [sessionNumber].
const modeSessionNumber = "session-number"

// sessionNumber is [modeSessionNumber]'s program: it prints a report whose
// session_number is the value of QORY_SESSION, or "unset" when the variable is not set.
func sessionNumber() int {
	v, ok := os.LookupEnv(session.EnvSession)
	if !ok {
		v = "unset"
	}
	b, _ := json.Marshal(report{SessionNumber: v})
	fmt.Println(probePrefix + string(b))
	return 0
}

// sessionNumbers checks QORY_SESSION in three sessions of one walled run: the first
// session runs the runtime, two sessions with no runtime join after it, and each reads
// the number the gateway assigned to its join, 1, 2 and 3.
func sessionNumbers(t *testing.T, o Options, h hosts, outside string) {
	t.Run("each session of a run reads its number in QORY_SESSION", func(t *testing.T) {
		var later []string
		afterSession := func(run *session.Run, workspace string) {
			for range 2 {
				var out, errs bytes.Buffer
				res, err := run.Join(t.Context(), session.SessionSpec{
					Command: o.Probe,
					Args:    []string{modeSessionNumber},
					Env:     []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
					Dir:     workspace,
					Stdin:   strings.NewReader(""),
					Stdout:  &out,
					Stderr:  &errs,
					Exec:    o.Exec,
				})
				if err != nil || res.ExitCode != 0 {
					t.Errorf("a session with no runtime: %v, %+v\nstdout:\n%s\nstderr:\n%s", err, res, out.String(), errs.String())
					return
				}
				later = append(later, reportedNumber(t, out.String()))
			}
		}
		r, err := runIn(t, o, variant{mode: modeSessionNumber, afterSession: afterSession}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		got := append([]string{r.probe.SessionNumber}, later...)
		if want := []string{"1", "2", "3"}; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("the sessions read %s as %q, want %q", session.EnvSession, got, want)
		}
		var numbers []any
		for _, e := range r.events {
			if e["type"] == event.SessionStarted {
				numbers = append(numbers, e["data"].(map[string]any)["session"])
			}
		}
		if want := []any{1.0, 2.0, 3.0}; fmt.Sprint(numbers) != fmt.Sprint(want) {
			t.Errorf("the record has the sessions %v, want %v", numbers, want)
		}
	})
}

// reportedNumber is the session_number of the one report in out, or "no report".
func reportedNumber(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), probePrefix); ok {
			var r report
			if err := json.Unmarshal([]byte(rest), &r); err != nil {
				t.Errorf("the report of a session: %v\n%s", err, rest)
				return "no report"
			}
			return r.SessionNumber
		}
	}
	return "no report"
}
