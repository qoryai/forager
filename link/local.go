package link

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"

	"github.com/qoryai/forager/accesskey"
)

// ToolDirPrefix begins the name of the private directory the gateway makes, in the
// system's temporary directory, for a tool's socket when the tool starts. Every such
// directory on the machine is one of Forager's files, which no walled run binds.
const ToolDirPrefix = "qory-tool-"

// Local is what a session needs of a gateway on the same machine, the local link: the
// gateway hands it to whoever starts the session. It holds no secret: the socket's mode
// and its peer's uid authenticate both ends.
//
// A gateway in this process hands out a Local that reaches it in memory, [Local.InMemory]:
// [Local.DialContext] then never touches the socket's path, which another process of the
// same user could have put its own listener at. The socket serves a session in another
// process.
type Local struct {
	// Socket is the path of the gateway's link socket, [LinkSocketName] in a private
	// directory that begins with [LinkDirPrefix].
	Socket string
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

	// dial, when not nil, opens a connection to the gateway in this process's memory, in
	// place of the socket.
	dial func(context.Context) (net.Conn, error)
}

// InMemory returns l with dial as the way to the gateway: a gateway in this process sets
// it on the Local it hands out, and every connection then comes from dial, never from
// the socket's path. Copies of the Local keep it.
func (l Local) InMemory(dial func(context.Context) (net.Conn, error)) Local {
	l.dial = dial
	return l
}

// IsInMemory reports whether l reaches its gateway in memory, [Local.InMemory].
func (l Local) IsInMemory() bool { return l.dial != nil }

// DialContext opens one connection to the gateway's link: in memory when l has that
// way, else to the Unix socket at Socket. A connection to the socket is a
// *net.UnixConn, whose peer the caller checks before it sends anything; one in memory
// is the gateway's in this process.
func (l Local) DialContext(ctx context.Context) (net.Conn, error) {
	if l.dial != nil {
		return l.dial(ctx)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", l.Socket)
	if err != nil {
		// The error quotes the socket's path.
		return nil, accesskey.ShownError(err)
	}
	return c, nil
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

// shown is Local without its methods and without its way in memory, which fmt prints
// the way it prints any struct, so a Local prints the same whichever way it reaches its
// gateway.
type shown struct {
	Socket   string
	Proxy    string
	Files    []File
	Reserved []string
}

// shown is l as it prints: a path or a name that contains qak_, qrk_, qecr_, qecn_, qecp_,
// qecg_ or qeci_ in any case is accesskey.ShownValue's or accesskey.ShownName's phrase in
// its place.
func (l Local) shown() shown {
	files := make([]File, len(l.Files))
	for i, f := range l.Files {
		f.Path = accesskey.ShownValue(f.Path, false)
		files[i] = f
	}
	if l.Files == nil {
		files = nil
	}
	return shown{Socket: accesskey.ShownValue(l.Socket, false), Proxy: l.Proxy, Files: files, Reserved: accesskey.ShownNames(l.Reserved)}
}

// Format prints l as fmt prints a struct, under every verb and flag, without its way
// in memory.
func (l Local) Format(f fmt.State, verb rune) {
	s := l.shown()
	if verb == 'v' && f.Flag('#') {
		fmt.Fprintf(f, "link.Local{Socket:%#v, Proxy:%#v, Files:%#v, Reserved:%#v}",
			s.Socket, s.Proxy, s.Files, s.Reserved)
		return
	}
	fmt.Fprintf(f, fmt.FormatString(f, verb), s)
}

// String is l as %v prints it.
func (l Local) String() string { return fmt.Sprintf("%v", l) }

// GoString is l as %#v prints it.
func (l Local) GoString() string { return fmt.Sprintf("%#v", l) }

// LogValue is l as log/slog logs it.
func (l Local) LogValue() slog.Value {
	s := l.shown()
	return slog.GroupValue(
		slog.String("socket", s.Socket),
		slog.String("proxy", s.Proxy),
		slog.Any("files", s.Files),
		slog.Any("reserved", s.Reserved),
	)
}

// MarshalJSON is l as encoding/json writes a struct, without its way in memory. A
// Local is never handed on as JSON; this is for a log or a dump that writes it so.
func (l Local) MarshalJSON() ([]byte, error) { return json.Marshal(l.shown()) }
