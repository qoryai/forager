package claude

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/qoryai/runner/session/runtimes"
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
// of ~ for the second. A missing file becomes one with the entry alone, mode 0600; an
// empty one gets the entry and keeps its mode. A JSON object without
// customApiKeyResponses gets the entry as its first member and keeps every byte before
// and after its opening brace, ending in one newline. A file with
// customApiKeyResponses, one that is no object, and a path that is neither a regular
// file nor missing, such as a FIFO, stay as they are; Claude Code then shows its
// approval prompt unless that list approves the stand-in already. The new content goes
// to a temporary file beside the configuration first and is then copied over it,
// through a link when the configuration is one, and the temporary file is removed. The
// script writes nothing else, and whatever it fails at, the command starts, with the
// umask the script started with.
const approveScript = `# Adds the approval of the stand-in Claude Code reads its API key from to the
# configuration it reads, then starts it. Written by the runner for one run.
approve() {
	umask 077
	base=${CLAUDE_CONFIG_DIR:-$HOME}
	[ -n "$base" ] || return 0
	f=${CLAUDE_CONFIG_DIR:-$HOME/.claude}/.config.json
	[ -f "$f" ] || f=$base/.claude.json
	[ -f "$f" ] || [ ! -e "$f" ] || return 0
	entry='"customApiKeyResponses":{"approved":["@APPROVED@"],"rejected":[]}'
	if [ -s "$f" ]; then
		c=$(cat "$f") || return 0
		case $c in *'"customApiKeyResponses"'*) return 0 ;; esac
		lead=${c%%[![:space:]]*}
		c=${c#"$lead"}
		case $c in '{'*) ;; *) return 0 ;; esac
		rest=${c#?}
		case ${rest#"${rest%%[![:space:]]*}"} in '}'*) sep= ;; *) sep=, ;; esac
		new=$(printf '%s{%s%s%s' "$lead" "$entry" "$sep" "$rest") || return 0
	else
		new="{$entry}"
	fi
	tmp=$f.qory-$$
	[ ! -e "$tmp" ] || return 0
	if ! (set -C && printf '%s\n' "$new" > "$tmp"); then
		rm -f "$tmp"
		return 0
	fi
	cat "$tmp" > "$f"
	rm -f "$tmp"
}
(approve) 2>/dev/null
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
