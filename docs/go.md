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
- keeps the policy, the credentials, the tools and the access key in a gateway, which
  the session speaks to over a local link;
- reports the session's output and its own observations as CloudEvents: to files
  always, to a server when one is configured;
- optionally, starts the agent behind a wall, a container with no route out except to
  that proxy.

## Two entry points

The module is a library with two entry points: the gateway and the session.

- A caller starts a gateway, [`gateway.Start`](../gateway/start.go), with a
  [`gateway.Config`](../gateway/config.go): the machine's policy, its credentials and
  tools, the server it reports to, and where each run's record goes. The gateway holds
  all of it: the proxy, the policy, the credentials, the tools and the access key.
  `gateway.Config.NoLinkSocket` makes no link socket and no link directory: the link is
  served in memory alone, to a session in the gateway's process, as `qory run` starts
  it; without it the socket serves a session in another process too.
- It then builds a [`session.Spec`](../session/session.go): the program to start, and
  how, and the gateway it speaks to, `session.LocalGateway(g.LocalLink())`. The session
  holds no policy, no credential and no server. It speaks to the gateway alone, over the
  gateway's local link (the contract's
  [§The gateway's link](../contracts/forager/v1/README.md#the-gateways-link)).
- It gets a [`session.Result`](../session/session.go) back once the runtime has exited
  and the session's events are flushed to the gateway. Closing the gateway flushes the
  run's stream to the server.

```go
g, err := gateway.Start(ctx, gateway.Config{
	Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: hosts}},
	Server: nil,                                  // files only; a *gateway.Server reports as well
	Dir:    stateDir,                             // the gateway's directory; runs/<id> is each run's record
})
if err != nil {                                   // no gateway, no run
	return err
}
rt, err := catalog.Lookup("claude", "")           // a runtime by its name, see below
res, err := session.Run(ctx, session.Spec{
	Runtime:   rt,
	Command:   "claude",
	Args:      []string{"--settings", settings, "-p", "Reply pong."},
	Gateway:   session.LocalGateway(g.LocalLink()), // the link's secret stays in this process
	Forwarder: []string{exe, "forward"},          // the hook command, see below
})
g.Close(ctx)                                      // delivers the runs' last events, before the exit
if err != nil {                                   // the run did not start
	return err
}
os.Exit(res.ExitCode)                             // the runtime's status; res.Dir is the record
```

[`session/example_test.go`](../session/example_test.go) is the example above, compiled
with the tests.

## The session and its gateway

For each run the session, over the gateway's link:

1. asks the gateway's discovery where the run request, the events and the proxy are,
   and the heartbeat interval;
2. sends the run request: the run id, whether the run is walled, its labels, what it is
   about, the names, never the values, of the variables it passes a value for, and,
   behind a wall, the machine's images;
3. applies the run answer: the proxy secret goes to the session's forwarder, or behind a
   wall to the wall's relay, and never into the agent's environment; behind a wall, the
   run's certificate authority and the placeholders go into the enclosure; the image is
   the one the answer names; the variables the gateway sets are not the session's to
   set;
4. records `dev.qory.run.started` with the gateway's labels and
   `dev.qory.run.policy_applied` with the members the gateway decides, its own
   variables and the harness's hosts beside them, and posts every event of the run to
   the gateway, a heartbeat every interval among them;
5. fetches the run's configuration again whenever the gateway's answers carry a new
   run-configuration digest, and records it in another `dev.qory.run.policy_applied`;
6. ends the run when the gateway or the server closes it: a `410` on the link, or the
   gateway's `400` to a batch.

The agent reaches the gateway's proxy through the session's forwarder, on loopback.
Every connection to the proxy opens with the relay's preamble and the run's proxy
secret: without a wall the forwarder writes it, behind one the wall's relay does.
Behind a separate gateway the forwarder reaches the gateway's one address over TLS
instead: see [the session behind a separate gateway](#the-session-behind-a-separate-gateway).

A refusal the gateway or the server answers with a code returns a `*session.Refusal`,
with the code, the names it concerns and `From`, `apiary` or `gateway`. Its `Error` is
the refusal's `message`, the text such a run always returned, such as
`ping https://qory.example/v1/events: instance_limit (status 409)`. A run whose policy
needs a wall and has none returns the error such a run always had, and so does a run
the gateway could not open for a reason without a code.

## A separate gateway

A gateway serves the sessions of other machines, and clients with no session, on one
address of its own, beside its local link. Its `gateway.Config` sets it:

- `Listen`, the one address, `host:port`. Empty means the local link alone. Every
  connection is routed by its first bytes, after the TLS handshake: `QORY-RELAY` and a
  run's proxy secret go to that run's proxy; a proxy request, `CONNECT` or an
  absolute-form target, to the proxy of the run its `Proxy-Authorization` names; any
  other request to the contract, where every request carries
  `Authorization: Bearer <run credential>`
  ([§The gateway's link](../contracts/forager/v1/README.md#the-gateways-link)). The
  proxy of every run served there is guarded, wall or none. `Gateway.Addr` is this
  address.
- `TLS`, `{CertFile, KeyFile}`, the operator's certificate and key, in PEM: the one
  address speaks TLS 1.3 alone. Without it, `Listen` must be a loopback address.
- `RunCredentials`, the issuers whose run credentials open a run there, required with
  `Listen` ([run credentials](gateway-run-credentials.md)). A run's labels and
  `about.details` are its run credential's. The gateway tracks run keys and does not
  require them to be unique; each period of activity is a run.
- `Runs.Quiet`, how long a run with no session lasts with no connection: 30 minutes when
  zero.
- `Dir` is required with `Listen`: the gateway keeps its own certificate authority there,
  `authority/ca.pem`, which the machines of the clients with no session trust, and the
  run keys it refuses after the issuer's end, `ended-run-keys.json`, so a restart refuses
  them too.

A run of the one address ends as a local run does, and also at its run credential's
`exp` with no fresher one, `credential_expired`, and when the issuer's introspection no
longer holds the run credential active, or the issuer ended another run of the same run
key, `run_ended_at_issuer`. The gateway writes its
`dev.qory.run.exited`; a session's later requests get the `410` with that code in
`Delivery.Reason`. A run with no session also ends after `Runs.Quiet` with no
connection, `quiet`. After `run_ended_at_issuer`, the gateway refuses every request of a
run of the run key until the latest `exp` of the run credentials of the key the gateway
still holds, and of any presented during the hold, plus `runcredential.MaxLeeway`, 5
minutes.

`Start` refuses, before anything starts, what it cannot serve: a `Listen` that is not
`host:port`, one that is not loopback without `TLS`, certificate and key files it cannot
read or that do not match, `TLS` without `Listen`, `Listen` without `RunCredentials`
or `Dir`, and with `Listen` a `Dir` it cannot create a file in, "the ended run keys:
<directory> cannot be written: <error>".

### The session behind a separate gateway

A session on another machine names the gateway with a `session.RemoteGateway` in place
of `session.LocalGateway`:

```go
res, err := session.Run(ctx, session.Spec{
	// …the runtime, the command and the rest, as on one machine
	Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project"},
	Gateway: session.RemoteGateway{
		URL:               "https://gateway.example:8443", // its one address
		CAFile:            caFile,                          // empty: the system's roots
		CertificateSHA256: pin,                             // empty: no pin
		Credential: func(context.Context) (string, error) { // asked before every request
			b, err := os.ReadFile(runCredentialFile)
			return strings.TrimSpace(string(b)), err
		},
	},
})
```

- `URL` is `https` and a host with an optional port, `443` when it has none, and no user
  information, path, query or fragment. The link is TLS 1.3 alone. The session verifies
  the gateway's certificate chain for the URL's host name against the system's roots,
  or, with `CAFile`, against the authorities of that PEM file alone, which replace the
  system's roots. With `CertificateSHA256`, the SHA-256 of the certificate's DER
  SubjectPublicKeyInfo in standard base64 with padding, it accepts only a certificate
  with that key, and still checks its chain. No proxy of the environment is used, and no
  redirect is followed.
- `Credential` returns the run credential. Every request on the link carries it as
  `Authorization: Bearer <run credential>`, and the session asks for it before each
  request, so a run credential its issuer refreshes in a file is sent from then on. Its
  error is the request's, and must not hold the run credential. A `RemoteGateway`
  without `Credential` is no run. The run credential is never printed, logged,
  recorded or contained in an error: a `session.RemoteGateway` prints as its URL, its
  `CAFile` and its pin.
- The run credential's file must not sit in a directory a walled run mounts, and an
  unwalled agent's environment must not carry it. Keeping it out of both is the
  caller's job. As a backstop, the session leaves `QORY_RUN_CREDENTIAL_SECRET` out of the
  agent's environment, walled or not, whatever brought it, as it does the access key's
  variables.
- No access key is involved, and the gateway holds no files on the session's machine, so
  none of its files are checked against a walled run's mounts, and it reserves no
  variables there.
- The discovery must list URLs of the gateway's origin alone, and name the gateway's one
  address, the URL's host and port, as its proxy; the loopback check of the local link
  does not apply. The run request carries the spec's `Labels`, `forge` and `repository`
  among them, and `About`. The run's labels are the run credential's, and the run
  request carries no narrowing: `Spec` has none.
- The gateway's refusals return a `*session.Refusal` as on one machine, its `Error` the
  refusal's `message`: `run_credential_refused`, a `401` that may come to discovery as
  well, before anything is recorded; `target_differs_from_credential` and
  `differs_from_credential`, whose names are `<member>=<the run credential's value>`;
  and `run_id_used`. A refusal of the run request is recorded in the session's record
  alone.
- Agent traffic goes to the gateway's one address over TLS, with the link's trust,
  through the session's forwarder. Without a wall, the agent's proxy URL is the
  forwarder on loopback with the run's proxy secret as its password,
  `http://qory:<proxy secret>@127.0.0.1:<port>`, as the contract has it: the agent's
  environment holds the proxy secret, and every program the agent starts can read it,
  and print it into the run's output. It is the run's alone, refused once the run ends,
  and never the run credential. Behind a wall, the proxy secret stays in the session's
  memory: see [the relay to a separate gateway](wall.md#the-relay-to-a-separate-gateway).

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
- `Gateway` is the gateway the run speaks to, `session.LocalGateway(l)` with the local
  link the gateway hands out, `(*gateway.Gateway).LocalLink()`, or a
  `session.RemoteGateway` on a machine of its own (see
  [the session behind a separate gateway](#the-session-behind-a-separate-gateway)). The session reaches
  a gateway of its own process in memory, never by its socket's path, which serves a
  session in another process, and which a gateway started with `NoLinkSocket` does not
  make. The link's secret stays in the process's memory: a `session.Gateway` is printed
  and logged by its socket or, behind a separate gateway, its URL, CA file and pin,
  never a secret, and a `*gateway.Gateway` by its proxy's address and its socket. A nil
  `Gateway` is no run. The server the run reports to and the node's
  policy are the gateway's, `gateway.Config.Server` and `gateway.Config.Policy`. See
  [the server](server.md) and
  [the policy](policy.md#the-node-narrows-the-servers-policy).
- `Labels` and `About` go to the gateway in the run request. `dev.qory.run.started` has
  the labels the gateway answers with, and in `about.details` the details the gateway
  decides, such as those a run credential's claims set.
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
- The stream that gets every event as well is the gateway's, `gateway.Config.Events`.
  See [the record](events.md#following-a-run).

## The result

`session.Result` is what the run came to, as the session knows it:

- `RunID`, and `Dir`, the run directory with the session's record. See
  [the record](events.md#where-the-record-is).
- `ExitCode`, `Signal` and `State`, the runtime's; `TimedOut` when it was stopped at
  `Timeout`.
- `Undelivered`, how many of the session's events the gateway did not accept.
- `RunClosed` when the run was closed from outside: `ClosedBy` says who, `apiary`, the
  server, or `gateway`, and `ClosedReason` the code of the gateway's `410`, unchanged:
  `run_closed`, `credential_expired` or `run_ended_at_issuer`; from `gateway`,
  `session_lost` when it heard nothing from the session for 3 heartbeat intervals and
  `batch_refused` when it refused a batch of the session's. The runtime was stopped as
  at its time limit.

What reached the server is the gateway's to say: `(*gateway.Gateway).Close` returns a
`gateway.Delivery`.

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
    issuers a gateway accepts and its checks, the verifier of a run credential (its
    serialisation, header, signature, claims and scope), the mapping of its claims to the
    run's labels and `about.details`, the client of an issuer's introspection endpoint,
    and the run keys a gateway refuses, kept in its state directory. See
    [run credentials](gateway-run-credentials.md).
  - `link/`: the names the parts agree on: the proxy variables, the relay preamble, the
    loopback address, the variables that name the run's socket and a tool's socket, the
    headers the proxy sets for a tool, the placeholder value, and the names of the
    gateway's link: its preamble `QORY-LINK`, the `Bearer` scheme a run credential is
    presented in, and the prefix `qory-link-` of its socket's directory, the socket's
    name and the modes of both.
  - `internal/`: `jcs`, and `importrules`, the test of the rules below.
- `session/`: the session.
  - `session.Run` takes a launch spec, with the gateway and the wall as values, and
    returns the exit status. It speaks to the gateway over its local link alone.
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
- `gateway/`: the gateway. `gateway.Start` serves sessions on a local link, and with
  `Config.Listen` on one address of its own, with the proxy, the credentials and the
  tools in `gateway/internal/`, and reports every run to the server. `gateway.Resend` sends a run's record again. `Start` with its `Config`
  and the `Gateway` it returns, `Resend` with its `ResendConfig`, and the types their
  fields need are the package's whole surface.
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
- `session` imports the core and `wall` for the interface, and no gateway package: it
  speaks to the gateway over its local link alone. Its tests import
  `internal/linktest`, a fake gateway's link, and package `gateway`, to run a session
  against a real one, using only its surface.
- Package `gateway` exports its surface alone. A new export fails the test until its
  list names it.
- Only `e2e` imports `session`, and it imports every part.
- No part imports the core's `internal/` packages, or another part's. The fake gateway
  of `internal/linktest` is for tests alone.

**Documents select; releases add.** A policy, a server document and a descriptor select
among what the binary does. They never add to it. New behaviour arrives only in a
release.
