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
		{filepath.Join(base, "QRK_y", "absent.json"),
			"Pass a --settings path that exists on this machine. The check of --settings (a value that contains " +
				"a run key) failed: (a value that contains a run key)"},
		{`{"hooks": QRK_y}`, "Pass a valid JSON object to --settings. The check of --settings (a --settings value) " +
			"failed: it is no JSON object"},
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

// TestSettingsJSONValueIsAPhrase pins that a --settings value that contains "{" or "[",
// or starts with white space or a format character, is shown as a phrase, and so is the
// reason, in either form, so a token in it is not printed.
func TestSettingsJSONValueIsAPhrase(t *testing.T) {
	tok := `"Authorization":"Bearer fake-token-123"`
	noObject := "Pass a valid JSON object to --settings. The check of --settings (a --settings value) failed: it is no JSON object"
	noFile := "Pass a --settings path that exists on this machine. The check of --settings (a --settings value) failed: it is no file"
	for _, c := range []struct{ value, want string }{
		{`{"env":{` + tok + `},}`, noObject},
		{`{"env": nothing, ` + tok + `}`, noObject},
		{`[{"env":{` + tok + `}}]`, noFile},
		{"\ufeff" + `{"env":{` + tok + `}}`, noFile},
		{"\u200b" + `{"env":{` + tok + `}}`, noFile},
	} {
		for _, args := range [][]string{{"--settings", c.value}, {"--settings=" + c.value}} {
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch: runtimes.Launch{Args: args}, RunDir: t.TempDir(), Forwarder: []string{"q"},
			})
			if err == nil || err.Error() != c.want || strings.Contains(err.Error(), "fake-token-123") {
				t.Errorf("%q: %v, want %q", args, err, c.want)
			}
		}
	}
}
