package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/hostfile"
	"github.com/qoryai/forager/session/internal/runfile"
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
// and it holds at most 1 MiB. Of its "env" object, the copy keeps no member whose
// name is in [runtimes.Attach.ModelVariables]. In a walled launch whose last
// argument is a bare --settings, that flag is given the path of the run's settings.
// A walled launch whose arguments pass --settings more than once is refused before
// anything is read: Claude Code reads only the last one, so the run would start
// without Forager's hooks and with a file that was not checked. So is a walled launch
// that passes --project-config-root, counted the same way: Claude Code reads project
// settings, .mcp.json and the .claude trees from that directory. A walled launch's
// --mcp-config, --agents, --plugin-dir, --plugin-dir-no-mcp, --add-dir and
// system-prompt file values are then checked as [walledPaths] checks them, before the
// settings are read.
// An interactive launch whose API key is the run's stand-in is then started through
// the script of [ApproveScript], so Claude Code uses the stand-in at once.
func Settings(events []string, a runtimes.Attach) (runtimes.Launch, error) {
	launch := a.Launch
	if a.Walled && flagCount(launch.Args, "--settings") > 1 {
		return runtimes.Launch{}, errSettingsMoreThanOnce
	}
	if a.Walled && flagCount(launch.Args, projectConfigRootFlag) > 0 {
		return runtimes.Launch{}, errProjectConfigRoot
	}
	if a.Walled {
		var err error
		if launch.Args, err = walledPaths(launch.Args, a); err != nil {
			return runtimes.Launch{}, err
		}
	}
	args, err := settingsArgs(events, launch.Args, a.RunDir, a.Forwarder, a.Readable, a.Inside, a.ModelVariables, a.Walled)
	if err != nil {
		return runtimes.Launch{}, err
	}
	launch.Args = args
	return approve(a, launch)
}

// errSettingsMoreThanOnce refuses a walled launch that passes --settings more than once.
var errSettingsMoreThanOnce = errors.New("Pass one --settings file. This launch passes --settings more than once, " +
	"and Claude Code reads only the last one, so the run does not start.")

// settingsFlag is the flag whose file or document Claude Code reads its settings from.
const settingsFlag = "--settings"

// settingsRefused is the refusal of the settings file at path, which could not be
// read, in the form of the other flags' files: the fix first, then the reason. A path
// with a ".." part gets the text of [pathRules].
func settingsRefused(path string, err error) error {
	v := flagValue{flag: settingsFlag, value: path}
	if errors.Is(err, hostfile.ErrDotDot) {
		return dotDot(v)
	}
	return fileRefused(v, err)
}

// notAnObject is the refusal of settings, a file's path or a document, that are not
// a JSON object: the fix first, then the reason, a phrase for a value that [shownPath]
// shows as one.
func notAnObject(value string, err error) error {
	shown, phrase := shownPath(flagValue{flag: settingsFlag, value: value})
	fix := "Make the file " + shown + " a JSON object."
	if strings.HasPrefix(strings.TrimSpace(value), "{") {
		fix = "Pass a valid JSON object to --settings."
	}
	reason := accesskey.ShownError(err)
	if phrase {
		reason = errors.New("it is no JSON object")
	}
	return fmt.Errorf("%s The check of --settings %s failed: %w", fix, shown, reason)
}

// projectConfigRootFlag is the flag whose directory Claude Code reads project settings,
// .mcp.json and the .claude trees from, in place of the working directory.
const projectConfigRootFlag = "--project-config-root"

// errProjectConfigRoot refuses a walled launch that passes --project-config-root.
var errProjectConfigRoot = errors.New("Remove --project-config-root from the walled launch. This launch passes " +
	"--project-config-root, and Claude Code reads project settings, .mcp.json and the .claude trees from that " +
	"directory, which Forager does not check, so the run does not start.")

// flagCount counts the arguments that are flag or start with flag and "=", wherever
// they are: after --, and as the value of another option, though Claude Code reads
// neither as the flag. A count above the flags Claude Code reads only refuses more
// launches; one below would let a later file through unchecked.
func flagCount(args []string, flag string) int {
	n := 0
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			n++
		}
	}
	return n
}

func settingsArgs(events []string, args []string, dir string, forwarder []string,
	readable func(string) (string, error), inside func(string) string, model []string, walled bool) ([]string, error) {
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
		} else if b, _, err = readSettings(args[at], readable); err != nil {
			return nil, settingsRefused(args[at], err)
		}
		if err := json.Unmarshal(b, &settings); err != nil {
			return nil, notAnObject(args[at], err)
		}
		// JSON null decodes into a map as nil, with no error.
		if settings == nil {
			return nil, notAnObject(args[at], errors.New("it is null"))
		}
		if inside != nil {
			settings = insideValues(settings, inside).(map[string]any)
		}
		// Claude Code applies the env object to its environment, over the start key's
		// variable and endpoint the session sets.
		if env, ok := settings["env"].(map[string]any); ok {
			for _, name := range model {
				delete(env, name)
			}
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
	if err := runfile.Replace(path, append(out, '\n'), 0o644); err != nil {
		return nil, accesskey.ShownError(err)
	}
	if at >= 0 {
		args = append([]string(nil), args...)
		args[at] = path
		return args, nil
	}
	// Claude Code takes the argument after --settings as its value, even one that is
	// --settings, so a second flag after a bare last one would name a file called
	// --settings in its working directory. Behind a wall that flag is given the path.
	if walled && len(args) > 0 && args[len(args)-1] == "--settings" {
		return append(append([]string(nil), args...), path), nil
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
// It returns the file's content and its permission bits.
func readSettings(path string, readable func(string) (string, error)) ([]byte, fs.FileMode, error) {
	if hostfile.DotDot(path) {
		return nil, 0, hostfile.ErrDotDot
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, accesskey.ShownError(err)
	}
	resolve := filepath.EvalSymlinks
	if readable != nil {
		resolve = readable
	}
	resolved, err := resolve(abs)
	if err != nil {
		return nil, 0, accesskey.ShownError(err)
	}
	judged, err := os.Stat(resolved)
	if err != nil {
		return nil, 0, accesskey.ShownError(err)
	}
	b, err := hostfile.Read(abs, maxSettings, judged)
	return b, judged.Mode().Perm(), accesskey.ShownError(err)
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
