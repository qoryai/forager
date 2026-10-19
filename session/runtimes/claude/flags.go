package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/hostfile"
	"github.com/qoryai/forager/session/runtimes"
)

// The flags beside --settings whose values Claude Code reads as paths and a walled
// launch is checked for.
const (
	mcpConfigFlag  = "--mcp-config"
	agentsFlag     = "--agents"
	pluginDirFlag  = "--plugin-dir"
	pluginDirNoMCP = "--plugin-dir-no-mcp"
	addDirFlag     = "--add-dir"

	systemPromptFileFlag   = "--system-prompt-file"
	appendPromptFileFlag   = "--append-system-prompt-file"
	subagentPromptFileFlag = "--append-subagent-system-prompt-file"
)

// copyNames are the names of the copies of the flags' files in the run directory, by
// their place among the flag's files, from 1.
var copyNames = map[string]string{
	mcpConfigFlag:          "mcp-config-%d.json",
	agentsFlag:             "agents-%d.json",
	systemPromptFileFlag:   "system-prompt-file-%d.md",
	appendPromptFileFlag:   "append-system-prompt-file-%d.md",
	subagentPromptFileFlag: "append-subagent-system-prompt-file-%d.md",
}

// promptText is, for each system-prompt file flag, the flag that passes the text itself.
var promptText = map[string]string{
	systemPromptFileFlag:   "--system-prompt",
	appendPromptFileFlag:   "--append-system-prompt",
	subagentPromptFileFlag: "--append-subagent-system-prompt",
}

// jsonWhitespace is the white space JSON allows around a value.
const jsonWhitespace = " \t\n\r"

// variadic says, for each flag of a walled launch's check, whether Claude Code takes
// several words as its values: after the first, every word up to the next one that
// starts with "-" and is longer than one character.
var variadic = map[string]bool{
	mcpConfigFlag:  true,
	agentsFlag:     false,
	pluginDirFlag:  false,
	pluginDirNoMCP: false,
	addDirFlag:     true,

	systemPromptFileFlag:   false,
	appendPromptFileFlag:   false,
	subagentPromptFileFlag: false,
}

// flagValue is one value of a flag of [variadic] in a launch's arguments: the flag, the
// value, the index of the argument the value is in, and whether that argument is the
// --flag=value form.
type flagValue struct {
	flag, value string
	at          int
	joined      bool
}

// flagValues lists every value of the flags of [variadic] in args, in order, as Claude
// Code's parser takes them: the word after the flag whatever it is, then for a
// variadic flag every word up to one that starts with "-" and is longer than one
// character, and the part after "=" of --flag=value. The list ends at a "--" that no
// option before it could take as its value: one after a word that starts with "-",
// other than a --name=value word, may be that option's value, and the words after it
// are listed too. Listing a word Claude Code does not take as a path only refuses
// more launches; leaving out one it takes would let a file through unchecked.
func flagValues(args []string) []flagValue {
	var out []flagValue
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" && (i == 0 || !takesValue(args[i-1])) {
			break
		}
		if many, ok := variadic[a]; ok {
			if i+1 == len(args) {
				break
			}
			i++
			out = append(out, flagValue{flag: a, value: args[i], at: i})
			for many && i+1 < len(args) && !maybeOption(args[i+1]) {
				i++
				out = append(out, flagValue{flag: a, value: args[i], at: i})
			}
			continue
		}
		if name, v, ok := strings.Cut(a, "="); ok {
			if _, ok := variadic[name]; ok {
				out = append(out, flagValue{flag: name, value: v, at: i, joined: true})
			}
		}
	}
	return out
}

// maybeOption is Claude Code's parser's test of a word that may be an option: it starts
// with "-" and is longer than one character.
func maybeOption(w string) bool { return len(w) > 1 && w[0] == '-' }

// takesValue reports whether the word may be an option that takes the next word as its
// value: one that may be an option and does not carry its value after "=".
func takesValue(w string) bool {
	return maybeOption(w) && !(strings.HasPrefix(w, "--") && strings.Contains(w, "="))
}

// walledPaths checks the values of the flags of [variadic] in a walled launch's
// arguments and returns the arguments Claude Code is started with. A value of
// --mcp-config or --agents that Claude Code takes as JSON passes as it is. Any other
// value is a path, refused when it starts with "~", is relative, or has a ".." name.
// A file of --mcp-config or --agents is then checked and read as the settings are, and
// copied into the run directory, as mcp-config-<n>.json or agents-<n>.json, with its
// strings written as the enclosure sees them when [runtimes.Attach.Inside] is set; the
// argument is given the copy's path. A file of --system-prompt-file,
// --append-system-prompt-file or --append-subagent-system-prompt-file is checked and
// read the same way and copied as it was read, as <flag>-<n>.md without the leading
// "--". A value of --plugin-dir, --plugin-dir-no-mcp or --add-dir is checked as
// [checkDir] checks it, and passes as it is. Every value is checked before a copy is
// written, so a refused launch leaves none.
func walledPaths(args []string, a runtimes.Attach) ([]string, error) {
	type copied struct {
		v       flagValue
		path    string
		content []byte
	}
	var copies []copied
	n := map[string]int{}
	for _, v := range flagValues(args) {
		if inline(v.flag, v.value) {
			continue
		}
		if err := pathRules(v); err != nil {
			return nil, err
		}
		name, ok := copyNames[v.flag]
		if !ok {
			if err := checkDir(v, a); err != nil {
				return nil, err
			}
			continue
		}
		var b []byte
		var err error
		if _, prompt := promptText[v.flag]; prompt {
			if b, err = readSettings(v.value, a.Readable); err != nil {
				return nil, fileRefused(v, err)
			}
		} else if b, err = readCopy(v, a); err != nil {
			return nil, err
		}
		n[v.flag]++
		copies = append(copies, copied{v, filepath.Join(a.RunDir, fmt.Sprintf(name, n[v.flag])), b})
	}
	if len(copies) == 0 {
		return args, nil
	}
	args = append([]string(nil), args...)
	for _, c := range copies {
		if err := os.WriteFile(c.path, c.content, 0o644); err != nil {
			return nil, accesskey.ShownError(err)
		}
		if c.v.joined {
			args[c.v.at] = c.v.flag + "=" + c.path
		} else {
			args[c.v.at] = c.path
		}
	}
	return args, nil
}

// inline reports whether Claude Code takes the value of the flag as JSON, not as a
// path: for --mcp-config a value that parses as JSON whose value is truthy, and for
// --agents one that starts with "{" after white space or parses as JSON other than
// null, which Claude Code takes for no JSON. The white space taken off is JSON's alone,
// so a value is never taken for JSON that Claude Code reads as a path.
func inline(flag, value string) bool {
	trimmed := strings.Trim(value, jsonWhitespace)
	switch flag {
	case mcpConfigFlag:
		if !json.Valid([]byte(trimmed)) {
			return false
		}
		d := json.NewDecoder(strings.NewReader(trimmed))
		d.UseNumber()
		var v any
		return d.Decode(&v) == nil && truthy(v)
	case agentsFlag:
		return strings.HasPrefix(trimmed, "{") || (json.Valid([]byte(trimmed)) && trimmed != "null")
	}
	return false
}

// truthy is whether a JSON value is true in JavaScript: anything but null, false, 0
// and "". A number that cannot be read as one is taken as false.
func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		return err == nil && f != 0
	}
	return true
}

// pathRules refuses a path value that starts with "~", is relative or has a ".." name.
func pathRules(v flagValue) error {
	shown := accesskey.ShownValue(v.value, false)
	switch {
	case strings.HasPrefix(v.value, "~"):
		return fmt.Errorf("Replace %s with an absolute path. This launch passes %s %s, and inside the wall ~ is "+
			"the home of the wall's user, which Forager cannot check, so the run does not start.", shown, v.flag, shown)
	case !filepath.IsAbs(v.value):
		return fmt.Errorf("Replace %s with an absolute path outside the workspace. This launch passes %s %s, "+
			"a relative path that Claude Code reads from the workspace, which a walled run can write, "+
			"so the run does not start.", shown, v.flag, shown)
	case hostfile.DotDot(v.value):
		return dotDot(v)
	}
	return nil
}

// dotDot is the refusal of a path value of v that has a ".." part.
func dotDot(v flagValue) error {
	shown := accesskey.ShownValue(v.value, false)
	return fmt.Errorf(`Pass the path %s without "..". This launch passes %s %s, and the path has a ".." part, `+
		`so the run does not start.`, shown, v.flag, shown)
}

// readCopy checks and reads the file of v as [readSettings] reads the settings, and
// returns what its copy holds. With [runtimes.Attach.Inside] set, a file that is JSON
// is copied with every string in it as the enclosure sees it; any other is copied as it
// was read, and Claude Code reports what is wrong with it.
func readCopy(v flagValue, a runtimes.Attach) ([]byte, error) {
	b, err := readSettings(v.value, a.Readable)
	if err != nil {
		return nil, fileRefused(v, err)
	}
	if a.Inside == nil {
		return b, nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var doc any
	if d.Decode(&doc) != nil || d.More() {
		return b, nil
	}
	out, err := json.MarshalIndent(insideValues(doc, a.Inside), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// fileRefused is the refusal of a walled launch whose file of v could not be read, the
// fix first: for a place a walled run can write, what to do instead; for a refusal of
// the file itself, such as "it is a link", the fix for it and that refusal; and
// otherwise [checkFailed]'s text.
func fileRefused(v flagValue, err error) error {
	shown := accesskey.ShownValue(v.value, false)
	var written *runtimes.WrittenError
	if errors.As(err, &written) {
		what := "the servers as a JSON string"
		if v.flag == agentsFlag {
			what = "the agents as a JSON object"
		} else if v.flag == settingsFlag {
			what = "the settings as a JSON object"
		} else if text, ok := promptText[v.flag]; ok {
			what = "the text with " + text
		}
		return fmt.Errorf("Move %s to a directory no walled run writes, or pass %s. This launch passes %s %s, "+
			"which %s %s, a place a walled run can write, so the run does not start.",
			shown, what, v.flag, shown, written.How, written.Place)
	}
	if rest, ok := strings.CutPrefix(err.Error(), "it "); ok {
		return fmt.Errorf("%s This launch passes %s %s, and that file %s, so the run does not start.",
			readFix(v, rest), v.flag, shown, rest)
	}
	return checkFailed(v, err)
}

// readFix is the fix for the refusal of the file of v by the read, whose reason, after
// "it ", is rest: a link, a file that is not a regular one, one larger than maxSettings
// bytes, or one that changed while it was checked.
func readFix(v flagValue, rest string) string {
	shown := accesskey.ShownValue(v.value, false)
	switch {
	case rest == "is a link":
		return "Pass the path of the file that " + shown + " links to."
	case rest == "is not a regular file":
		return "Pass a " + v.flag + " path to a regular file."
	case strings.HasPrefix(rest, "is larger than "):
		return fmt.Sprintf("Pass a %s file of at most %d bytes.", v.flag, maxSettings)
	case rest == "changed while it was checked":
		return "Start the run again when no process is writing " + shown + "."
	}
	return "Pass another " + v.flag + " path."
}

// checkFailed is the refusal of a value of v for any other reason, a file that does
// not exist say: the fix of [checkFix], then the flag, the value and the reason.
func checkFailed(v flagValue, err error) error {
	return fmt.Errorf("%s The check of %s %s failed: %w", checkFix(v, err), v.flag,
		accesskey.ShownValue(v.value, false), accesskey.ShownError(err))
}

// checkFix is the fix for err, the reason the check of v failed: for a value that does
// not exist, a path that does; for a path the check had no permission for, access to
// it; and otherwise the reason itself, or another path.
func checkFix(v flagValue, err error) string {
	path := v.value
	var pe *fs.PathError
	if errors.As(err, &pe) {
		path = pe.Path
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if _, statErr := os.Stat(v.value); errors.Is(statErr, fs.ErrNotExist) {
			return "Pass a " + v.flag + " path that exists on this machine."
		}
	case errors.Is(err, fs.ErrPermission):
		return "Give the user that runs Forager access to " + accesskey.ShownValue(path, false) +
			", or pass another " + v.flag + " path."
	}
	return "Fix the error at the end of this message, or pass another " + v.flag + " path."
}
