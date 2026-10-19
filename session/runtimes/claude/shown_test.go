package claude_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// TestSettingsPrintsAPhraseForASecret pins the errors of settings the launch passes
// that cannot be read: a path or a document that contains qak_ or qrk_ is the phrase,
// the reason included, and a clean one prints as before.
func TestSettingsPrintsAPhraseForASecret(t *testing.T) {
	base := t.TempDir()
	clean := filepath.Join(base, "absent.json")
	for _, c := range []struct{ settings, want string }{
		{filepath.Join(base, "qak_x", "absent.json"),
			"Pass a --settings path that exists on this machine. The check of --settings (a value that contains " +
				"an access key secret) failed: (a value that contains an access key secret)"},
		{`{"hooks": QRK_y}`, "Pass a valid JSON object to --settings. The check of --settings (a value that contains a run key) " +
			"failed: invalid character 'Q' looking for beginning of value"},
		{`{"hooks": nothing}`, `Pass a valid JSON object to --settings. The check of --settings {"hooks": nothing} failed: ` +
			`invalid character 'o' in literal null (expecting 'u')`},
		// The reason of a clean path is the system's, which names the path as resolved.
		{clean, "Pass a --settings path that exists on this machine. The check of --settings " + clean + " failed: "},
	} {
		_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
			Launch: runtimes.Launch{Args: []string{"--settings", c.settings}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
		})
		if c.settings == clean {
			if err == nil || !strings.HasPrefix(err.Error(), c.want) || !strings.HasSuffix(err.Error(), "absent.json: no such file or directory") {
				t.Errorf("%s: %v, want %q and the system's reason", c.settings, err, c.want)
			}
			continue
		}
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.settings, err, c.want)
		}
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "qak_") {
			t.Errorf("%s: %v", c.settings, err)
		}
	}
}
