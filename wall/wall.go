// Package wall builds the enclosure an agent runs in: a place with no route out except
// to the session runner's proxy.
//
// The session runner stays outside. It owns the proxy, the policy decision and the
// record; a [Wall] owns only what makes a connection around the proxy fail rather than
// succeed unseen. An adapter wraps the launch and nothing else: the session runner asks
// the [Enclosure] where its proxy must listen, starts the wrapped command on the
// pseudo-terminal or the pipes it already owns, and closes the enclosure at exit.
//
// What every wall guarantees is one list, contracts/runner/v1/README.md §The wall, the
// same for every adapter, and the conformance suite in the walltest package checks it
// from inside the enclosure. An adapter ships when the suite passes for it. [Docker] is
// the first.
package wall

import "context"

// Wall is one way of building an enclosure: one implementation per container
// interface.
type Wall interface {
	// Name names the adapter in the run's record: docker.
	Name() string
	// Prepare builds what must exist before the proxy listens. The caller closes the
	// enclosure it returns, whatever happens after.
	Prepare(ctx context.Context, req Request) (Enclosure, error)
}

// Setter is a wall that sets variables in the enclosure's environment itself, beside
// the launch's: a server's variable of such a name is left out of the run.
type Setter interface {
	// Sets lists the names of the variables the wall sets.
	Sets() []string
}

// Reaper is a wall that can remove what it left of a run whose runner died before it
// closed the enclosure. It is asked only for a run known to be over.
type Reaper interface {
	// Reap removes everything the wall created for the run and reports how many
	// things that was. Nothing left is not an error.
	Reap(ctx context.Context, runID string) (int, error)
}

// Request is what a wall is told about the run it encloses.
type Request struct {
	// RunID names what the wall creates, so two runs never share anything.
	RunID string
	// Image is the agent's image: the runtime and the project's toolchain, built and
	// pinned by the caller. The wall builds nothing.
	Image string
	// Runtime is the container runtime the image is started under, one the engine
	// has; empty is the engine's default.
	Runtime string
	// Docker gives the agent a Docker daemon of its own inside the enclosure. The image
	// holds dockerd; the wall starts it as the enclosure's root, on a Unix socket alone,
	// and the agent as its user in the socket's group. It needs a Runtime that runs a
	// daemon in a container without privileges, whose root is a user of the machine's
	// that is not root. Experimental: see contracts/runner/v1/README.md §The wall.
	Docker bool
}

// Enclosure is one run's wall, built.
type Enclosure interface {
	// ProxyAddr is where the session runner's proxy must listen, host:port, for the
	// enclosure to reach it; port 0 leaves the port to the system.
	ProxyAddr() string
	// Wrap returns the launch that starts l inside the enclosure, on the terminal or
	// the pipes of whoever starts it. It is called once, after the proxy listens.
	Wrap(ctx context.Context, l Launch) (Launch, error)
	// Close removes everything the wall created, within the context's deadline. It is
	// safe to call after a failed Wrap and more than once.
	Close(ctx context.Context) error
}

// Launch is a command to start. Given to [Enclosure.Wrap] it is the agent's, with what
// must cross the wall beside it; returned from Wrap it is the adapter's own command,
// and only Command, Args, Env and Dir are set.
type Launch struct {
	Command string
	Args    []string
	// Env is the whole environment, NAME=value. Given to Wrap, it is everything the
	// enclosure gets besides the proxy and socket variables, which the enclosure sets
	// itself because it knows the addresses inside. Returned from Wrap, nil means the
	// starting process's own.
	Env []string
	// Dir is the working directory, the run's workspace. The enclosure shows it at the
	// same path, writable.
	Dir string
	// Interactive says the command runs on a pseudo-terminal.
	Interactive bool
	// Proxy is the address the proxy listens on, host:port with the port it got.
	Proxy string
	// ProxyToken is what the proxy requires every connection to open with, when it is
	// not empty. An adapter gives it to its relay and to nothing inside the enclosure,
	// so the proxy serves this run's relay alone, whoever else reaches its address.
	ProxyToken string
	// CA, when not empty, is the certificate of the run's authority, PEM: the proxy
	// answers as some hosts itself, to set a credential the enclosure never holds, and
	// what runs inside must trust it for those. An adapter shows the enclosure one
	// bundle, the image's own authorities and this one, and points the variables
	// programs read a bundle's path from at it. The key never crosses.
	CA []byte
	// Socket is the path of the hook socket on the host, empty when there is none.
	Socket string
	// Mounts are the files and directories of the host the run lists beside Dir: the
	// checkout around Dir, a composed home, the run directory read-only. The
	// enclosure shows each at the same path, and nothing of the host besides them.
	Mounts []Mount
	// Limits are the resources the agent gets; the zero value leaves each to the
	// adapter's engine.
	Limits Limits
}

// Limits are the resources an enclosure gives the agent. A zero field is no limit of
// the run's: the engine's own default stands.
type Limits struct {
	// CPUs is how many processors' worth of time, a decimal number: 2, 1.5.
	CPUs string
	// Memory is the most memory, a number of bytes with an optional unit of b, k, m or
	// g: 8g.
	Memory string
	// PIDs is the most processes and threads.
	PIDs int
	// ShmSize is the size of /dev/shm, written as Memory is. A browser needs more than
	// an engine's default.
	ShmSize string
}

// Mount is one file or directory of the host an enclosure shows, at the same path.
type Mount struct {
	Path string
	// ReadOnly says the enclosure cannot change it.
	ReadOnly bool
}
