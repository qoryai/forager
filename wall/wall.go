// Package wall builds the enclosure an agent runs in: a place with no route out except
// to the gateway.
//
// The session and the gateway stay outside, with the proxy, the policy decision and the
// record; a [Wall] owns only what makes a connection around the proxy fail rather
// than succeed unseen. An adapter wraps the launch and nothing else: the session
// prepares the [Enclosure] as the run opens and reads from it where the gateway must
// listen, starts each session's wrapped command on the pseudo-terminal or the pipes it
// already has, and closes the enclosure as the run closes.
//
// What every wall guarantees is one list, contracts/forager/v1/README.md §The wall, the
// same for every adapter, and the conformance suite in package e2e checks it from
// inside the enclosure. An adapter ships when the suite passes for it. [Docker] is the
// first.
package wall

import (
	"context"
)

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

// AuthoritySetter is a [Setter] some of whose names it sets only for a run with an
// authority, [Launch.CA]: a run without one gets none of them from the wall.
type AuthoritySetter interface {
	// SetsWithAuthority lists the names of [Setter.Sets] that the wall sets only for a
	// run with an authority.
	SetsWithAuthority() []string
}

// Filer is a wall with files of its own on this machine: the programs it starts outside
// the enclosure and what configures them. A walled run refuses a mount that is, contains
// or lies inside one of them, since an agent that changes one of them changes what runs
// outside the wall.
type Filer interface {
	// Files lists the absolute paths of the wall's files, directories included.
	Files() []string
}

// Binder is a wall, or an enclosure, that binds files and directories of this machine
// of its own, beside the launch's mounts: for [Docker], its helper, the hook socket's
// directory and the private directory that holds the run's environment files and, with
// a CA, the bundle the enclosure binds. A walled run checks them, as it checks its
// mounts, against the other walled runs still going: the wall's when the run starts,
// with a pattern for what the enclosure makes later, and the enclosure's just before
// it binds them.
type Binder interface {
	// Binds lists them. A wall lists what it knows before it prepares an enclosure; an
	// enclosure lists them for the launch about to be wrapped, with its Socket and CA
	// set.
	Binds(l Launch) ([]Bind, error)
}

// Bind is one file or directory of this machine an enclosure binds of its own.
type Bind struct {
	// Path is the path as the caller defined it, or as the enclosure made it.
	Path string
	// ReadOnly says the enclosure cannot change it.
	ReadOnly bool
	// Helper says it is Forager's helper program, rather than a directory of
	// Forager's.
	Helper bool
	// Pattern says Path is a pattern of [path/filepath.Match]: where the enclosure
	// makes the directory, before it makes it.
	Pattern bool
}

// Reaper is a wall that can remove what it left of a run whose session died before it
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
	// that is not root. Experimental: see contracts/forager/v1/README.md §The wall.
	Docker bool
	// RelayImage is the image the relay starts from, the machine's default; empty is
	// Image.
	RelayImage string
	// Pull is set when Image is the run's image by reference, pinned by digest: a
	// [Puller] fetches it before the enclosure starts the first container of it, which
	// finds it by that digest and pulls nothing. Such an image never gets nested Docker.
	Pull bool
}

// Puller is a wall that fetches a run's image by reference, for a [Request] with Pull,
// before the enclosure starts the first container of it: the engine pulls it unless it
// holds it by that digest, and an image whose user is root is refused, image_user_root.
// An image its registry does not have is refused too, image_missing. The session runs
// Pull as the run's image step.
type Puller interface {
	// Pull fetches req.Image; a request without Pull fetches nothing. With ca, the run's
	// certificate as PEM, the engine trusts ca for the registry host of req.Image and for
	// each of hosts during the pull alone: Pull removes the files that make the engine
	// trust it before it returns, also when the pull fails or ctx ends.
	Pull(ctx context.Context, req Request, ca []byte, hosts []string) error
}

// Enclosure is one run's wall, built. The session prepares it as the run opens and
// closes it as the run closes.
type Enclosure interface {
	// ProxyAddr is where the gateway must listen, host:port, for the
	// enclosure to reach it; port 0 leaves the port to the system.
	ProxyAddr() string
	// Wrap returns the launch that starts l inside the enclosure, on the terminal or
	// the pipes of whoever starts it. It is called once for each session, after the
	// proxy listens.
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
	// Dir is the working directory, the run's workspace, as the enclosure sees it: at the
	// same path inside, or under the Target of the mount that holds it. A mount whose
	// path inside holds it, by whole components, shows it; a launch whose Dir no mount
	// holds is not wrapped. Returned from Wrap, it is a directory of this machine's.
	Dir string
	// Interactive says the command runs on a pseudo-terminal.
	Interactive bool
	// Proxy is the address the proxy listens on, host:port with the port it got.
	Proxy string
	// ProxyToken is what the proxy requires every connection to open with, when it is
	// not empty: the run's proxy secret on one machine, and behind a separate gateway a
	// token the session's forwarder checks and replaces with the proxy secret inside
	// TLS. An adapter gives it to its relay and to nothing inside the enclosure, so the
	// proxy serves this run's relay alone, whoever else reaches its address.
	ProxyToken string
	// CA, when not empty, is the certificate of the run's authority, PEM: the proxy
	// answers as some hosts itself, to set a credential the enclosure never holds, and
	// what runs inside must trust it for those. An adapter shows the enclosure one
	// bundle, the image's own authorities and this one, and points the variables
	// programs read a bundle's path from at it. The key never crosses.
	CA []byte
	// Socket is the path of the hook socket on the host, empty when there is none.
	Socket string
	// Mounts are the files and directories of the host the run lists: the checkout
	// around Dir, a composed home, the run directory read-only. The enclosure shows each
	// at the same path, or at its Target, and nothing of the host besides them and Dir.
	// From the session, none lies inside another, and one of them holds Dir.
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

// Mount is one file or directory of the host an enclosure shows, at the same path or
// at Target.
type Mount struct {
	Path string
	// ReadOnly says the enclosure cannot change it.
	ReadOnly bool
	// Target is the path inside the enclosure it is shown at, absolute and apart from
	// the wall's paths, such as /qory; empty is Path. The session sets it for the workspace of a
	// run whose image is named by its reference, /workspace.
	Target string
}
