package claude

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/qoryai/runner/runtimes"
)

// apiKeyVar is the variable Claude Code reads an API key from.
const apiKeyVar = "ANTHROPIC_API_KEY"

// ApproveScript is the script, in the run directory, that an interactive Claude Code
// with the API key's stand-in is started through.
const ApproveScript = "approve-key.sh"

// approvedLen is how much of a key Claude Code keeps as the key's approval: its last 20
// characters, after trimming the space around it.
const approvedLen = 20

// approved is the entry Claude Code keeps, under customApiKeyResponses.approved in the
// configuration it reads, for the stand-in once a person approves it: the stand-in's
// last 20 characters.
func approved() string {
	s := strings.TrimSpace(runtimes.Placeholder)
	return s[len(s)-approvedLen:]
}

// approveScript adds the entry of approved, written in place of @APPROVED@, to the
// configuration Claude Code reads, and then starts the command its arguments hold.
// Claude Code reads ~/.claude/.config.json when that file exists and ~/.claude.json
// otherwise, with CLAUDE_CONFIG_DIR, when set, in place of ~/.claude for the first and
// of ~ for the second. A file that is missing or empty becomes a configuration holding
// the approval alone, readable by its owner alone. A JSON object without
// customApiKeyResponses gets the approval as its first member, and the rest of the file
// stays as it was, byte for byte. A file that has customApiKeyResponses already, or is
// no object, stays as it is, and Claude Code shows its approval prompt as it would
// without the script. The script writes nothing else, and whatever it fails at, the
// command starts.
const approveScript = `# Adds the approval of the stand-in Claude Code reads its API key from to the
# configuration it reads, then starts it. Written by the runner for one run.
approve() {
	base=${CLAUDE_CONFIG_DIR:-$HOME}
	[ -n "$base" ] || return 0
	f=${CLAUDE_CONFIG_DIR:-$HOME/.claude}/.config.json
	[ -f "$f" ] || f=$base/.claude.json
	entry='"customApiKeyResponses":{"approved":["@APPROVED@"],"rejected":[]}'
	if [ ! -s "$f" ]; then
		(umask 077 && printf '{%s}\n' "$entry" > "$f")
		return 0
	fi
	c=$(cat "$f") || return 0
	case $c in *'"customApiKeyResponses"'*) return 0 ;; esac
	c=${c#"${c%%[![:space:]]*}"}
	case $c in '{'*) ;; *) return 0 ;; esac
	rest=${c#?}
	case ${rest#"${rest%%[![:space:]]*}"} in '}'*) sep= ;; *) sep=, ;; esac
	printf '{%s%s%s\n' "$entry" "$sep" "$rest" > "$f"
}
approve 2>/dev/null
exec "$@"
`

// approve starts an interactive Claude Code with the API key's stand-in through the
// script of [ApproveScript], which it writes into the run directory: Claude Code then
// uses the stand-in without waiting for a person to approve it. A launch that is
// headless, or whose API key is no stand-in, is returned as it is: Claude Code shows no
// approval prompt for the first, and a key of a person's own is theirs to approve.
func approve(a runtimes.Attach, launch runtimes.Launch) (runtimes.Launch, error) {
	if !a.Interactive || !slices.Contains(a.Placeholders, apiKeyVar) {
		return launch, nil
	}
	script := strings.Replace(approveScript, "@APPROVED@", approved(), 1)
	path := filepath.Join(a.RunDir, ApproveScript)
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		return runtimes.Launch{}, err
	}
	launch.Args = append([]string{path, launch.Command}, launch.Args...)
	launch.Command = "/bin/sh"
	return launch, nil
}
