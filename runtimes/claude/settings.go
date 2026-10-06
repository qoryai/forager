package claude

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/qoryai/runner/runtimes"
)

// hookTimeout is the seconds a runtime gives the forwarder before cancelling it.
const hookTimeout = 5

// SettingsInstaller is the name a descriptor gives [Settings].
const SettingsInstaller = "claude-settings"

// Settings installs the forwarder as a command hook for each event in the JSON settings
// Claude Code reads. It reads the file the arguments name after --settings, or the
// document they hold there, or starts from an empty one when they name none, adds a
// hook group per event under "hooks", writes the result as settings.json in the run
// directory, and names that file instead. The file the launch passed is not modified.
// An interactive launch whose API key is the run's stand-in is then started through
// the script of [ApproveScript], so Claude Code uses the stand-in at once.
func Settings(events []string, a runtimes.Attach) (runtimes.Launch, error) {
	launch := a.Launch
	args, err := settingsArgs(events, launch.Args, a.RunDir, a.Forwarder)
	if err != nil {
		return runtimes.Launch{}, err
	}
	launch.Args = args
	return approve(a, launch)
}

func settingsArgs(events []string, args []string, dir string, forwarder []string) ([]string, error) {
	settings := map[string]any{}
	at := -1
	for i, a := range args {
		if a == "--settings" && i+1 < len(args) {
			at = i + 1
			break
		}
		if v, ok := strings.CutPrefix(a, "--settings="); ok {
			at = i
			args = append(append([]string(nil), args[:i]...), append([]string{"--settings", v}, args[i+1:]...)...)
			at = i + 1
			break
		}
	}
	if at >= 0 {
		var b []byte
		var err error
		if strings.HasPrefix(strings.TrimSpace(args[at]), "{") {
			b = []byte(args[at])
		} else if b, err = os.ReadFile(args[at]); err != nil {
			return nil, fmt.Errorf("settings %s: %w", args[at], err)
		}
		if err := json.Unmarshal(b, &settings); err != nil {
			return nil, fmt.Errorf("settings %s: %w", args[at], err)
		}
	}
	groups, _ := settings["hooks"].(map[string]any)
	if groups == nil {
		groups = map[string]any{}
	}
	entry := map[string]any{"type": "command", "command": shellLine(forwarder), "timeout": hookTimeout}
	for _, ev := range events {
		existing, _ := groups[ev].([]any)
		groups[ev] = append(existing, map[string]any{"hooks": []any{entry}})
	}
	settings["hooks"] = groups
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return nil, err
	}
	if at >= 0 {
		args = append([]string(nil), args...)
		args[at] = path
		return args, nil
	}
	return append(append([]string(nil), args...), "--settings", path), nil
}

// shellLine quotes a command for a shell, since a command hook runs under sh -c.
func shellLine(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = shellQuote(w)
	}
	return strings.Join(quoted, " ")
}

func shellQuote(w string) string {
	if w != "" && strings.IndexFunc(w, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./=:@%+,", r))
	}) < 0 {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}
