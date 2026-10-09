# Forager from Go

Forager is the security boundary around one coding agent session. It is a Go module,
`github.com/qoryai/forager`. The [`qory`](https://github.com/qoryai/qory) command imports
it, and ships `qory run` in front of it. The module has no command of its own.

Forager:

- starts the agent on a composed harness;
- pins a policy that can only narrow what the binary allows;
- observes and enforces egress through a proxy it owns;
- keeps its own credentials out of the session;
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

`Runtime` is the program as Forager needs to know it: a
[`runtimes.Runtime`](../session/runtimes/runtimes.go). It defines:

- how its launch is prepared,
- what its records mean,
- how it is stopped,
- the secrets it declares, through the optional `runtimes.Secrets`; a runtime without
  it declares nothing.

`catalog.Lookup(name, dir)` resolves a name to the first of these that applies:

1. A descriptor `<name>.yaml` in `dir`. This is how a machine describes a runtime nothing
   ships for.
2. The contract's own descriptor: Claude Code's.
3. A bare runtime, for a name with neither. It is run and recorded, with no session
   events.

A program that needs code of its own implements the interface.
`session/runtimes/runtimetest` runs the same checks on it.

## The spec

- `Declared` is the egress the harness declared. The record reports it as
  `harness_hosts`, and it decides nothing. `nil` means no declaration.
- `Interactive` runs the session on a pseudo-terminal.
  - The exception: an argument the runtime's descriptor lists as headless is among
    `Args`, such as `-p` for Claude Code. Then the session runs on pipes.
  - Without `Interactive`, the session runs on pipes as well.
  - On pipes, the session reads the runtime's structured output.
- `Forwarder` is the command installed as the runtime's hook. It must call
  `session.Forward(ctx, os.Stdin)`. That passes the hook's input to the run, over a
  socket whose address is in the environment.
- `Wall` starts the runtime behind a wall. See [the wall](wall.md#from-go).
  `Mounts` are what else of the machine the wall shows, and `ForagerFiles` the caller's
  own files, which no mount may hold. See [Forager's files](wall.md#foragers-files).
- `Server` defines the server the run reports to. See [the server](server.md).
- `Policy` is the node's policy. Without a server's policy it is the run's; with one it
  narrows it. See [the policy](policy.md#the-node-narrows-the-servers-policy).
- The variables come from several sources, and for each name the highest wins. See
  [variables](server.md#variables).
  - `LaunchFixed` is the values the harness computes itself. They win over every source
    but the session's own names. The server's variables come next.
  - `Variables.Run` is the run's own, `--env`, and `Variables.Machine` the machine's,
    `wall.env`. `Variables` also holds the deny entries and how an unwalled run takes
    the server's.
  - `LaunchDefaults` is the values the harness's author wrote as defaults, and `Env`
    what the run inherits, the lowest.
  - `HarnessHome` is the harness's home as the agent sees it. The session sets
    `QORY_HARNESS_HOME` to it.
  - `OnVariables` receives each name, its source and the values that lost, once, before
    the agent starts.
- A run refused before it starts returns a `*session.Refusal`, with the contract's code
  and the names it concerns. `errors.As` finds it.
- `Events` is any stream that gets every event as well. See
  [the record](events.md#following-a-run).

The whole sequence, every event type and every file are in the
[contract](../contracts/forager/v1/README.md).

## Layout

The module is a core and three parts over it, the session, the gateway and the wall,
with `e2e` to check them together.

- `contracts/forager/v1/`: the contract. It contains the documents, a JSON schema for
  each, the runtime descriptors and the fixtures.
  [Its README](../contracts/forager/v1/README.md) is the specification.
- The core, at the module's root, which every part may import:
  - `contracts/`: the Go package that embeds the contract and validates every fixture.
  - `accesskey/`: the access key: its secret and Ed25519 key, the signed requests and
    answers, the pin of the server's keys, enrolment, the instance id and its file, and
    the refusal codes of the server's answers.
  - `receiver/`: a server of the contract that is not a control plane. It is the
    handler the tests run Forager against. It is tested against the signed fixtures.
    It is a worked example of the contract's receiving rules.
  - `policy/`, `refusal/`, `event/`, `sink/`, `server/` (the client of the contract) and
    `program/`.
  - `runcredential/`: the run credential an issuer gives a run: the configuration of the
    issuers a gateway accepts and its checks, the checks of a run credential's header and
    of its verified claims, and the mapping of its claims to the run's labels and
    `about.details`. See [run credentials](gateway-run-credentials.md).
  - `link/`: the names the parts agree on: the proxy variables, the relay preamble, the
    loopback address, the variables that name the run's socket and a tool's socket, the
    headers the proxy sets for a tool, and the placeholder value.
  - `internal/`: `jcs`, and `importrules`, the test of the rules below.
- `session/`: the session.
  - `session.Run` takes a launch spec, with the policy, the server and the wall as
    values, and returns the exit status.
  - `session.Forward` is the hook forwarder behind it.
  - `session/runtimes/`: the runtime. `runtimes.Runtime` is the interface between the
    session and the program it runs: how a launch is prepared, what the program's records
    mean, how it is stopped.
    - `Described` is a runtime written as a descriptor.
    - `Bare` is a program the session runs and does not read.
    - `session/runtimes/claude` is Claude Code.
    - `session/runtimes/catalog` resolves a name to a runtime.
    - `session/runtimes/runtimetest` is the conformance suite every runtime passes.
  - `session/internal/`: what the session alone uses: `chunk`, `descriptor`, `socket`
    and `variables`.
- `gateway/`: the proxy, the credentials and the tools, in `gateway/internal/`.
  Package `gateway` holds the types and functions the session drives them by.
- `wall/`: the wall.
  - The adapter interface, and the Docker adapter.
  - `wall.Relay`, the one peer an enclosure reaches.
  - `wall.Nest`, which starts a Docker of the agent's own inside it. Experimental.
- `e2e/`: the conformance suite every wall adapter passes before it ships: a real
  session behind the wall, with the gateway between.

`qory run` calls `session.Run` with the spec it builds from the composed home and the
launch template. The hook command it installs calls `session.Forward`.

## Two invariants

**Forager takes a spec.** `qory` imports Forager; Forager imports nothing of
`qory`. Stacks, modules, homes and reports stay in `qory`. Inside the module, a test
holds the imports to these rules:

- The core imports no part.
- `gateway` and `wall` import the core.
- `session` imports the core, `wall` for the interface, and package `gateway`.
- Only `e2e` imports `session`, and it imports every part.
- No part imports the core's `internal/` packages, or another part's.

**Documents select; releases add.** A policy, a server document and a descriptor select
among what the binary does. They never add to it. New behaviour arrives only in a
release.
