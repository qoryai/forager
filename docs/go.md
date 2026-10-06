# The runner from Go

The runner is the security boundary around one coding agent session. It is a Go module,
`github.com/qoryai/runner`. The [`qory`](https://github.com/qoryai/qory) command imports
it, and ships `qory run` in front of it. The module has no command of its own.

The runner:

- starts the agent on a composed harness;
- pins a policy that can only narrow what the binary allows;
- observes and enforces egress through a proxy it owns;
- keeps the runner's credentials out of the session;
- heartbeats while the session runs;
- reports the session's output and its own observations as CloudEvents: to files
  always, to a server when one is configured;
- optionally, starts the agent behind a wall, a container with no route out except to
  that proxy.

## One entry point

The module is a library with one entry point. A caller builds a
[`session.Spec`](../session/session.go): the program to start, and how. It gets a
[`session.Result`](../session/session.go) back once the runtime has exited and the sinks
are flushed:

```go
rt, err := catalog.Lookup("claude", "")           // a runtime by its name, see below
res, err := session.Run(ctx, session.Spec{
	Runtime:   rt,
	Command:   "claude",
	Args:      []string{"--settings", settings, "-p", "Reply pong."},
	Policy:    &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "enforce", Allow: hosts}},
	Server:    nil,                               // files only; a *session.Server reports as well
	Forwarder: []string{exe, "forward"},          // the hook command, see below
})
if err != nil {                                   // the run did not start
	return err
}
os.Exit(res.ExitCode)                             // the runtime's status; res.Dir is the record
```

[`session/example_test.go`](../session/example_test.go) is the example above, compiled
with the tests.

## The runtime

`Runtime` is the program as the runner needs to know it: a
[`runtimes.Runtime`](../runtimes/runtimes.go). It defines:

- how its launch is prepared,
- what its records mean,
- how it is stopped,
- the secrets it declares, through the optional `runtimes.Secrets`; a runtime without
  it declares nothing.

`catalog.Lookup(name, dir)` resolves a name to the first of these that applies:

1. A descriptor `<name>.yaml` in `dir`. This is how a machine describes a runtime nothing
   ships for.
2. The contract's own descriptor. Today that is Claude Code's.
3. A bare runtime, for a name with neither. It is run and recorded, with no session
   events.

A program that needs code of its own implements the interface. `runtimes/runtimetest`
runs the same checks on it.

## The spec

- `Declared` is the egress the harness declared. The record reports it as
  `harness_hosts`, and it decides nothing. `nil` means no declaration.
- `Interactive` runs the session on a pseudo-terminal.
  - The exception: an argument the runtime's descriptor lists as headless is among
    `Args`, such as `-p` for Claude Code. Then the session runs on pipes.
  - Without `Interactive`, the session runs on pipes as well.
  - On pipes, the runner reads the runtime's structured output.
- `Forwarder` is the command installed as the runtime's hook. It must call
  `session.Forward(ctx, os.Stdin)`. That passes the hook's input to the run, over a
  socket whose address is in the environment.
- `Wall` starts the runtime behind a wall. See [the wall](wall.md#from-go).
- `Server` defines the server the run reports to. See [the server](server.md).
- `Events` is any stream that gets every event as well. See
  [the record](events.md#following-a-run).

The whole sequence, every event type and every file are in the
[contract](../contracts/runner/v1/README.md).

## Layout

- `contracts/runner/v1/`: the contract. It contains the documents, a JSON schema for
  each, the runtime descriptors and the fixtures.
  [Its README](../contracts/runner/v1/README.md) is the specification.
- `contracts/`: the Go package that embeds the contract and validates every fixture.
- `session/`: the session runner.
  - `session.Run` takes a launch spec, with the policy, the server and the wall as
    values, and returns the exit status.
  - `session.Forward` is the hook forwarder behind it.
- `runtimes/`: the runtime. `runtimes.Runtime` is the interface between the runner and
  the program it runs: how a launch is prepared, what the program's records mean, how it
  is stopped.
  - `Described` is a runtime written as a descriptor.
  - `Bare` is a program the runner runs and does not read.
  - `runtimes/claude` is Claude Code.
  - `runtimes/catalog` resolves a name to a runtime.
  - `runtimes/runtimetest` is the conformance suite every runtime passes.
- `wall/`: the wall.
  - The adapter interface, and the Docker adapter.
  - `wall.Relay`, the one peer an enclosure reaches.
  - `wall.Nest`, which starts a Docker of the agent's own inside it. Experimental.
  - `wall/walltest` is the conformance suite every adapter passes before it ships.
- `receiver/`: a server of the contract that is not a control plane. It is the handler
  the tests run the runner against. It is tested against the signed fixtures. It is a
  worked example of the contract's receiving rules.
- `internal/`: what the layers share: `policy`, `proxy`, `credential`, `tool`, `event`,
  `sink`, `server`, `descriptor`, `socket`, `chunk`.
- `node/`: the node runner's fleet layer, not built yet. See
  [the node runner](node.md).

`qory run` calls `session.Run` with the spec it builds from the composed home and the
launch template. The hook command it installs calls `session.Forward`.

## Two invariants

**The runner takes a spec.** `qory` imports `runner`; `runner` imports nothing of
`qory`. Stacks, modules, homes and reports stay in `qory`. Inside the module:

- `node` imports `session`, and `session` never imports `node`.
- `session` imports `wall` for the interface.
- Only `wall/walltest` imports `session`.

**Documents select; releases add.** A policy, a server document and a descriptor select
among what the binary does. They never add to it. New behaviour arrives only in a
release.
