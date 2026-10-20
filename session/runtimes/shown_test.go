package runtimes_test

import (
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
)

// TestADescriptorsErrorPrintsAPhraseForASecret pins the errors of Described and
// CheckStopSignal: a document's name or a signal that contains qak_ or qrk_ is the
// phrase, and a clean one prints as before.
func TestADescriptorsErrorPrintsAPhraseForASecret(t *testing.T) {
	doc := strings.Replace(other, "  output: {format: jsonl}\n", "  hooks: {install: claude-settings, events: [Stop]}\n", 1)
	for name, want := range map[string]string{
		"/d/qak_x/other-agent.yaml": "(a value that contains an access key secret): hook installer \"claude-settings\" is not one Forager implements",
		"other-agent.yaml":          "other-agent.yaml: hook installer \"claude-settings\" is not one Forager implements",
	} {
		if _, err := runtimes.Described(name, []byte(doc), nil); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	for signal, want := range map[string]string{
		"QRK_y":  "the stop signal (a name that contains a run key) is not one of SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2",
		"SIGFOO": `the stop signal "SIGFOO" is not one of SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2`,
	} {
		if err := runtimes.CheckStopSignal(signal); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", signal, err, want)
		}
	}
}
