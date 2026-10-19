package claude

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/hostfile"
	"github.com/qoryai/forager/session/runtimes"
)

// hookTimeout is the seconds a runtime gives the forwarder before cancelling it.
const hookTimeout = 5

// SettingsInstaller is the name a descriptor gives [Settings].
const SettingsInstaller = "claude-settings"

// maxSettings is the largest settings file, in bytes, [Settings] reads: 1 MiB.
const maxSettings = 1 << 20

// Settings installs the forwarder as a command hook for each event in the JSON settings
// Claude Code reads. It reads the file the arguments name after --settings, or the
// document they hold there, or starts from an empty one when they name none, adds a
// hook group per event under "hooks", writes the result as settings.json in the run
// directory, and names that file instead. The file the launch passed is not modified.
// A file is read only when its path has no ".." name, [runtimes.Attach.Readable] passes
// it, its last part is no link, it is a regular file, it is the file Readable judged
// and it holds at most 1 MiB.
// An interactive launch whose API key is the run's stand-in is then started through
// the script of [ApproveScript], so Claude Code uses the stand-in at once.
func Settings(events []string, a runtimes.Attach) (runtimes.Launch, error) {
	launch := a.Launch
	args, err := settingsArgs(events, launch.Args, a.RunDir, a.Forwarder, a.Readable, a.Inside)
	if err != nil {
		return runtimes.Launch{}, err
	}
	launch.Args = args
	return approve(a, launch)
}

func settingsArgs(events []string, args []string, dir string, forwarder []string,
	readable func(string) (string, error), inside func(string) string) ([]string, error) {
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
		} else if b, err = readSettings(args[at], readable); err != nil {
			return nil, fmt.Errorf("settings %s: %w", accesskey.ShownValue(args[at], false), accesskey.ShownError(err))
		}
		if err := json.Unmarshal(b, &settings); err != nil {
			return nil, fmt.Errorf("settings %s: %w", accesskey.ShownValue(args[at], false), accesskey.ShownError(err))
		}
		if inside != nil {
			settings = insideValues(settings, inside).(map[string]any)
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

// insideValues is v with every string in it, at any depth, written as inside writes
// it: the settings' paths, a hook's command say, as the enclosure sees them. Names of
// members are left as they are.
func insideValues(v any, inside func(string) string) any {
	switch v := v.(type) {
	case string:
		return inside(v)
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = insideValues(e, inside)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[k] = insideValues(e, inside)
		}
		return out
	}
	return v
}

// readSettings reads the settings file path names. A path with a ".." name is refused,
// since the system applies it after a link and a check of the clean path would judge
// another file. The path is made absolute once, and readable judges the same path
// that is read: it passes the file and returns where the path resolves, and the file
// opened must be the one there when it was judged. It is read as [hostfile.Read] reads
// one: never through a link as its last part, only a regular file, and at most
// maxSettings bytes. Without readable, the file judged is the one the path resolves to.
func readSettings(path string, readable func(string) (string, error)) ([]byte, error) {
	if hostfile.DotDot(path) {
		return nil, hostfile.ErrDotDot
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resolve := filepath.EvalSymlinks
	if readable != nil {
		resolve = readable
	}
	resolved, err := resolve(abs)
	if err != nil {
		return nil, err
	}
	judged, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	return hostfile.Read(abs, maxSettings, judged)
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
