package link

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// ToolDirPrefix begins the name of the private directory the gateway makes, in the
// system's temporary directory, for a tool's socket when the tool starts. Every such
// directory on the machine is one of Forager's files, which no walled run binds.
const ToolDirPrefix = "qory-tool-"

// Local is what a session needs of a gateway on the same machine, the local link: the
// gateway hands it to whoever starts the session.
//
// Its Secret is never printed: every verb of the fmt package, String, GoString, a value
// logged with log/slog and its JSON show it as [redacted], so a Local can be logged
// whole.
type Local struct {
	// Socket is the path of the gateway's link socket, [LinkSocketName] in a private
	// directory that begins with [LinkDirPrefix].
	Socket string
	// Secret is the link secret, which opens every connection to Socket after
	// [LinkPreamble]. It is never logged and never set in an environment, the agent's,
	// a tool's or the session's own.
	Secret string
	// Proxy is the gateway's proxy address on loopback, host:port. Every connection to
	// it opens with [RelayPreamble] and the run's proxy secret.
	Proxy string
	// Files are the gateway's own files, which a walled run must not mount: its
	// credential files, the directories of its adapter and tool programs, its state
	// directory, and the patterns of the tools' socket directories ([ToolDirPrefix])
	// and of the link's directory ([LinkDirPrefix]).
	Files []File
	// Reserved are the names of the variables the machine's credentials are read from:
	// a walled run that passes one is refused with variable_reserved, and an unwalled
	// run has its value left out.
	Reserved []string
}

// File is one of the gateway's own files: its path, or a pattern of paths, and what it
// is, the phrase a refused mount names it by, such as "the file the credential model is
// read from".
type File struct {
	Path string
	What string
	// Kept says the file is one of the gateway's own directories, where it keeps its link
	// or the runs' records, and not a file of the machine's credentials or tools: a
	// session checks it last, after every other file of Forager's, its own, the wall's,
	// the run directories and the registry of walled runs, so a mount that holds one of
	// those as well is refused for that one, as it always was.
	Kept bool
}

// redacted is what Local's Secret is shown as when it is set.
const redacted = "[redacted]"

// shown is Local without its methods and with its Secret redacted, which fmt prints
// the way it prints any struct.
type shown struct {
	Socket   string
	Secret   string
	Proxy    string
	Files    []File
	Reserved []string
}

func (l Local) shown() shown {
	s := shown(l)
	if s.Secret != "" {
		s.Secret = redacted
	}
	return s
}

// Format prints l as fmt prints a struct, under every verb and flag, with its Secret
// redacted.
func (l Local) Format(f fmt.State, verb rune) {
	s := l.shown()
	if verb == 'v' && f.Flag('#') {
		fmt.Fprintf(f, "link.Local{Socket:%#v, Secret:%#v, Proxy:%#v, Files:%#v, Reserved:%#v}",
			s.Socket, s.Secret, s.Proxy, s.Files, s.Reserved)
		return
	}
	fmt.Fprintf(f, fmt.FormatString(f, verb), s)
}

// String is l as %v prints it, its Secret redacted.
func (l Local) String() string { return fmt.Sprintf("%v", l) }

// GoString is l as %#v prints it, its Secret redacted.
func (l Local) GoString() string { return fmt.Sprintf("%#v", l) }

// LogValue is l as log/slog logs it, its Secret redacted.
func (l Local) LogValue() slog.Value {
	s := l.shown()
	return slog.GroupValue(
		slog.String("socket", s.Socket),
		slog.String("secret", s.Secret),
		slog.String("proxy", s.Proxy),
		slog.Any("files", s.Files),
		slog.Any("reserved", s.Reserved),
	)
}

// MarshalJSON is l as encoding/json writes a struct, its Secret redacted. A Local is
// never handed on as JSON; this is for a log or a dump that writes it so.
func (l Local) MarshalJSON() ([]byte, error) { return json.Marshal(l.shown()) }
