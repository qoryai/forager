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
  it; without it the socket serves a session in another process too. A separate
  gateway, below, serves no local link either way.
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
	Gateway:   session.LocalGateway(g.LocalLink()), // reached in memory, in this process
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
2. sends the run request: the run id, whether the run is walled, on the local link its
   labels and what it is about, the names, never the values, of the variables it passes a value for, and,
   behind a wall, the machine's images;
3. applies the run answer: on the local link the proxy secret goes to the session's
   forwarder, or behind a wall to the wall's relay, and never into the agent's
   environment; behind a wall, the
   run's certificate authority and the placeholders go into the enclosure; the image is
   the one the answer names; the variables the gateway sets are not the session's to
   set;
4. records `dev.qory.run.started`, with the gateway's labels on the local link, and
   `dev.qory.run.policy_applied` with the members the gateway decides, its own
   variables and the harness's hosts beside them, and posts every event of the run to
   the gateway, a heartbeat every interval among them;
5. fetches the run's configuration again whenever the gateway's answers carry a new
   run-configuration digest, and records it in another `dev.qory.run.policy_applied`;
6. ends the run when the gateway closes it: a `410` on the link, or the gateway's `400`
   to a batch.

On the local link every batch names its run in `X-Qory-Run-Id`; the link carries no
secret, since the session and the gateway check that the socket's peer is their own
user. That uid is the whole of the local link's trust: a process of the same user that
reaches the socket can post a batch into a local run whose id it knows, fetch the run's
configuration again, or end the run. `gateway.Start` with `gateway.Config.NoLinkSocket`
serves no socket, only the link in memory, to a session in the gateway's own process.

The agent reaches the gateway's proxy through the session's forwarder, on loopback.
On the local link every connection to the proxy opens with the relay's preamble and the
run's proxy secret: without a wall the forwarder writes it, behind one the wall's relay
does. Without a wall the agent's proxy URL is the forwarder on loopback with a password,
`http://qory:<password>@127.0.0.1:<port>`, the password a secret the session makes for
the run's forwarder alone, 32 bytes from the system's random source in base64url, which
lives as long as the run and is never logged or recorded. A connection to the forwarder
carries one request, a `CONNECT` and its tunnel or one plain HTTP request and its reply,
so every request is checked: it must carry the password in its one
`Proxy-Authorization`, Basic, the user name ignored. The forwarder takes the header off,
passes the request on with `Connection: close`, passes on nothing the agent sends after
a plain request, and closes the connection at the end of its reply; a plain request
that asks for an upgrade goes on with `Connection: Upgrade` instead, and a `101` reply
makes the connection a tunnel. It closes a connection without the password unanswered,
before anything reaches the gateway, so another process of the machine that reaches the
port reaches nothing. Behind a separate gateway the forwarder reaches the gateway's one
address over TLS instead, where a bound connection opens the run's proxy with the run
key: see [the session behind a separate gateway](#the-session-behind-a-separate-gateway).

A refusal the gateway or the server answers with a code returns a `*session.Refusal`,
with the code, the names it concerns and `From`, `apiary` or `gateway`. Its `Error` is
the refusal's `message`, the text such a run returns, such as
`register https://qory.example/v1/runs: instance_limit (status 409)`. A run whose policy
needs a wall and has none returns the error such a run always had, and so does a run
the gateway could not open for a reason without a code.

## A separate gateway

A gateway serves the sessions of other machines on one address of its own, in place of
its local link. Its `gateway.Config` sets it:

- `Listen`, the one address, `host:port`. Empty means the local link alone. Every
  connection is routed by its first bytes, after the TLS handshake: one that opens with
  `QORY-BIND` is bound to its TLS, the gateway answering with its `QORY-BOUND` line
  under its access key, and then carries the link, every request with
  `Authorization: Bearer <run key>`, or `QORY-RELAY`, a space and a run key, for that
  run's proxy; any other is the relay of the server's enrolment, discovery,
  registration and outcome
  ([§The gateway's link](../contracts/forager/v1/README.md#the-gateways-link)), for a
  keyed machine or a starter whose server document holds `via` (`server.Via`). The
  gateway a request is relayed through sees the registration answer's run key, so `via`
  names a gateway trusted at least as much as the run's own gateway. The proxy of every
  run served there is guarded, wall or none. `Gateway.Addr` is this address.
- `TLS`, `{CertFile, KeyFile}`, the operator's certificate and key, in PEM: the one
  address speaks TLS 1.3 alone. `Listen` needs it.
- `Server`, whose access key is a gateway's, `ng_`: the gateway verifies each run key
  under the server's pin, on every request of the run and every proxy connection, not
  only the first, so once the gateway restarts with a server key out of the pin, a run
  whose run key that key signed gets `400` `run_key_invalid` on its next request and its
  proxy connections are closed unanswered; it attaches each run at the server under its
  own access key (`server.Client.Attach`), signs the binding and every answer of the
  link, and relays to the server's origin. The gateway's calls to the server, the attach
  and the relay among them, use the proxy of the environment, `HTTPS_PROXY` and
  `NO_PROXY`, and check the server's certificate against the system's roots;
  `HTTP_PROXY` does not apply, since a server over http is on loopback, which Go never
  proxies. A proxy that ends their TLS with a certificate the gateway's machine trusts
  sees the run keys they carry, in each attach and in each accepted registration answer
  the gateway relays; one that only tunnels them sees the server's host and port.
  `Listen` needs it.

A separate gateway runs no sessions of its own machine: it makes no local link, in
memory or on a socket, and no proxy listener on loopback, and a session that dials its
`LocalLink` gets "the gateway serves other machines on its address, and runs no
sessions". Every run there opens by its run key: the gateway refuses one with
`run_key_invalid`, `run_key_expired`, `wrong_gateway` or `workspace_not_served` before it
asks the server, attaches the run, writes the record's `dev.qory.run.registered` from
the run key and the attach's answer, and gives a run answer with no labels and no proxy
secret. When the server's answer to a batch carries the outcome the run's starter
gave, it ends the run `stopped` with that state and reason, as a direct node's gateway
does. A gateway that starts again attaches again a run whose open never answered its
session, and answers a run that was open before `410` `run_closed`.

`Start` refuses, before anything starts, what it cannot serve: a `Listen` that is not
`host:port`, a `Listen` without `TLS`, "the gateway's address <address> needs TLS, a
certificate and its key: every connection of the link there is bound to its TLS", or
without a `Server`, "the gateway's address <address> needs a server and a gateway's
access key: the gateway attaches each run there", certificate and key files it cannot
read or that do not match, and `TLS` without `Listen`; and once discovery is read, an
access key that is not a gateway's, "the access key's node <node id> is not a gateway,
ng_: the gateway's address <address> needs a gateway's access key".

### The session behind a separate gateway

A session on another machine names the gateway with a `session.RemoteGateway` in place
of `session.LocalGateway`: the run's run key, the one Qory Apiary answered the run's
registration with, which the command hands the session from `QORY_RUN_KEY`. The session
reads no variable itself, and takes `QORY_RUN_KEY` (`session.EnvRunKey`) out of every
agent's environment, the one it inherits among them, as it takes out the access key's
variables.

```go
res, err := session.Run(ctx, session.Spec{
	// …the runtime, the command and the rest, as on one machine
	Gateway: session.RemoteGateway{RunKey: os.Getenv("QORY_RUN_KEY")}, // names the gateway and its keys
})
```

- The session reads the run key unverified, as a runner reads one (`runkey.Parse`): its
  `gateway_url` is the one address the run key is ever sent to, and its
  `gateway_public_key` the keys the gateway must prove it holds. One it cannot read is
  no run, "QORY_RUN_KEY is not a run key: " and the part that is wrong. The run's id is
  the run key's; a `Spec.RunID` that is another is refused, "the run id <id> is not the
  one QORY_RUN_KEY names, <its id>".
- The link is TLS 1.3 alone. The session verifies the gateway's certificate chain for
  the host name of `gateway_url` against the system's roots. Every connection, the
  link's and the proxy's, then opens with the binding: `QORY-BIND`, and the gateway's
  `QORY-BOUND`, its proof over the connection's TLS exporter value that it holds a key
  the run key names ([the binding](../contracts/forager/v1/README.md#the-gateways-link)).
  Only then is the run key sent: `Authorization: Bearer` on every request, and the
  relay's preamble, `QORY-RELAY` and the run key, on a proxy connection. Every answer
  must be signed under a key the run key names, for that connection and request. A
  gateway that fails the proof is "the gateway at <url> could not prove it holds a key
  the run key names", and an answer under another key, or none, "the gateway at <url>
  answered under a key the run key does not name": `*server.GatewayKeyError`, its
  `Unproven` telling the two apart. No proxy of the environment is used, and no redirect
  is followed.
- A `session.RemoteGateway` prints as the URL its run key names, `(no run key)` or
  `(not a run key)`, never the run key.
- No access key is involved, and the gateway holds no files on the session's machine, so
  none of its files are checked against a walled run's mounts, and it reserves no
  variables there.
- The run directory on the session's machine holds the session's record,
  `session.jsonl` and `output.log`, its mark, `separate-gateway` (`session.GatewayMark`),
  an empty file no other writer of a run directory writes, what the gateway accepted of
  the record, `delivered.log`, and the batches it did not, `undelivered/`; never the run
  key. The gateway's record,
  `events.jsonl`, with its own delivery state toward the server, is on the gateway's
  machine ([where the record is](events.md#where-the-record-is)).
  `session.BehindGateway(dir string) (bool, error)` reports whether a run directory holds
  a record a session made behind a separate gateway, which `session.Resend` sends:
  whether `dir` holds `separate-gateway` as a regular file, not followed if it is a
  symbolic link, whatever else it holds and wherever the directory is. A directory
  without it is false; an error other than a missing name is returned.
- The discovery is `GET /qory-link/configuration`, and must list URLs of the gateway's
  origin under `/qory-link/` alone, and name the gateway's one address, the host and
  port of `gateway_url`, as its proxy; the loopback check of the local link does not
  apply. The run request carries no labels and no `About`, which are the run's
  registration's, and no narrowing: `Spec` has none. The run answer has no labels and no
  proxy secret, and the session's `dev.qory.run.started` has no labels.
- The gateway's refusals return a `*session.Refusal` as on one machine, its `Error` the
  refusal's `message`: the run key's refusals the gateway passes on, `400`
  `run_key_invalid`, and `409` `wrong_gateway`, `workspace_not_served`,
  `run_key_expired` and `run_attached`, which may come at the discovery, before
  anything is recorded, and the attach's. A refusal of the run request is recorded in
  the session's record alone. A `410` with a state and a
  reason ends the run as on one machine: `Result.RunClosed`, `State` and `Reason`.
- Agent traffic goes to the gateway's one address over TLS through the session's
  forwarder, each connection bound and opened with the run key. Without a wall, the
  agent's proxy URL is the forwarder on loopback with its password,
  `http://qory:<password>@127.0.0.1:<port>`, which the forwarder checks as on the local
  link (above) before anything reaches the gateway. Behind a wall, the relay reaches the
  forwarder with a value the session makes for the run's forwarder alone, which the
  forwarder takes off: see
  [the relay to a separate gateway](wall.md#the-relay-to-a-separate-gateway). The run key
  stays in the session's memory, in no environment and no file.

### Sending the session's record again

`session.Resend` sends a separate gateway what the session's run directory says it did
not accept: after a session that died, or a gateway that was out of reach. It reaches
the gateway as the run did, by the run's run key, which the caller passes from
`QORY_RUN_KEY`, since the run directory never holds it:

```go
res, err := session.Resend(ctx, session.ResendSpec{
	Gateway:        session.RemoteGateway{RunKey: os.Getenv("QORY_RUN_KEY")},
	Dir:            filepath.Join(runsDir, runID),
	ForagerVersion: version,
	Report:         func(line string) { fmt.Fprintln(os.Stderr, line) },
})
```

- A record its session still holds is `session.ErrRunning`; a directory with no
  `session.jsonl` is `fs.ErrNotExist`; a directory with the run's stream, `events.jsonl`,
  is a gateway's record, which `gateway.Resend` sends.
- Every event of `session.jsonl` the link takes that `delivered.log` does not name is
  posted to the discovery's events URL, in order, in the link's batches, until the
  gateway accepts it or `ctx` ends; what it still has not accepted is under
  `undelivered/` again, unless the gateway ended the run. The events the session
  records in its own record alone are not sent. A record that owes nothing is sent
  nothing, with no request, and the result is the zero `ResendResult`.
- A record with no `delivered.log` is of a run that never opened at the gateway, a run
  refused at its run request say: `ResendResult.NotOpened` says so, the record is left
  as it is, and nothing is sent, with no request. A record that owes nothing has a
  `delivered.log`, and `NotOpened` false.
- `ResendResult` has `Sent`, the events the gateway accepted now, and `Undelivered`,
  those it still has not. `RunClosed` says the gateway had ended the run: its `410`,
  with `ClosedReason`, its code, as `Result` has it; nothing more is sent, and the
  events stay in the run directory. Once something was sent, `State` and `Reason` say
  how the run ended where that is known, as `Result` has them: the state and the
  reason the gateway's `410` says, as the session records them, and otherwise, a `410`
  `run_closed` among them, those of the `dev.qory.run.exited` in `session.jsonl`; both
  empty when neither says.
- The `dev.qory.run.exited` the session posted, with the state and the reason of the
  runtime's exit, is sent again like any other event. The
  one the session records after the gateway ended the run is in its record alone, and
  is never sent: `delivered.log` says `stopped` before it is written, whether the `410`
  answered a batch or a reload.
- A record that owes something needs the run key, checked before any request: without
  one, "resend <dir>: the run key is needed to send to its gateway; set QORY_RUN_KEY";
  one it cannot read, "QORY_RUN_KEY is not a run key: " and the part that is wrong; one
  of another run, "resend <dir>: QORY_RUN_KEY names the run <id>, not this one". A
  record that owes nothing, or of a run that never opened, needs none.
- A refusal of the run key the gateway passes on, `400` `run_key_invalid`, or `409`
  `wrong_gateway`, `workspace_not_served`, `run_key_expired` or `run_attached`, at the
  discovery or at a batch, is a `*session.Refusal` from `gateway`, its code and status
  the gateway's and its text the gateway's message, with the events left under
  `undelivered/`; nothing more is sent after it. A `401` `unauthorized` stops the resend
  the same way, though the gateway sends none, so a resend never sends again into one.
  Any other refusal of a batch is sent again, as the session sends it. A batch for a run
  the gateway no longer holds is its `410`, the run's end while the gateway keeps it and
  then `run_closed`, which closes the resend, as long as the gateway still has the run's
  record. Once the run key's `attach_by` plus a skew of 300 seconds has passed, by the
  gateway's clock, a batch for a run the gateway holds nothing of, its record included,
  is `409` `run_key_expired` instead, which stops the resend as the refusals above do.
- `session.jsonl` is never completed: the gateway writes the end of a run whose session
  was lost.
- After a gateway restarts, it holds no run of before: the gateway's own resend,
  `gateway.Resend`, completes the run `gateway_lost`.

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
  make. A `session.Gateway` is printed and logged by its socket or, behind a separate
  gateway, the URL its run key names, never the run key, and a `*gateway.Gateway` by its
  proxy's address and its socket, or a separate gateway by its one address. A nil
  `Gateway` is no run. The server the run reports to and the node's
  policy are the gateway's, `gateway.Config.Server` and `gateway.Config.Policy`. See
  [the server](server.md) and
  [the policy](policy.md#the-node-narrows-the-servers-policy).
- `Labels` and `About` go to the gateway in the run request. `dev.qory.run.started` has
  the labels the gateway answers with, and `About` as the caller passed it.
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
- `ExitCode` and `Signal`, the runtime's, whatever the run's state.
- `State` and `Reason`, the state and the reason of the session's
  `dev.qory.run.exited`, how the run ended:
  - When the runtime exits by itself, its exit decides: `succeeded` on 0, `failed`
    otherwise, with no reason.
  - At `Timeout`, `cancelled` and `timeout`, with `TimedOut`, when the session's stop
    signal reached the runtime at the limit before its exit was observed. A runtime that
    exited by itself before that signal is decided by its exit.
  - When the run was stopped from where it was started, a Ctrl-C or a signal to the
    caller, which ends the context, `cancelled` and `interrupted`, with `Cancelled`.
    `ExitCode` and `Signal` are the runtime's, whatever they are.
  - A runtime that exits 0 at the session's stop, at the context's end or at the
    limit, has exited 0: `Run` records its `dev.qory.run.exited` and returns its
    `Result`, with no error.
  - When the gateway closed the run, `RunClosed`, the state and the reason its `410`
    says, such as `cancelled` and `no_longer_needed`; `batch_refused` as the reason after
    a refused batch; and `failed` with the code as the reason for an end that carries
    no state, `run_closed` among them.
- `Cancelled` when the run's context had ended at the moment the session observed the
  runtime's exit, whatever the exit status or the signal, and whoever stopped the
  runtime: the session at the context's end, or the runtime itself at a Ctrl-C that
  reached both. In a race it is whichever the session saw first. A context that ends
  after the exit, while the sinks close, leaves it false, as do the time limit, which is `TimedOut`, a run the gateway closed before
  the context ended, which is `RunClosed`, and a signal from elsewhere while the
  context lasts: `Cancelled` is never true with `TimedOut` or with `RunClosed`. On
  pipes, the exit is observed when the runtime's standard output and standard error
  close: a descendant that holds them open delays it by up to the stop grace, and what
  it writes after the grace is not kept. When it is true, `dev.qory.run.exited` is
  `cancelled` with `interrupted`.
- `Undelivered`, how many of the session's events the gateway did not accept; behind a
  separate gateway they are under the run directory's `undelivered/`.
- `RunClosed` when the gateway closed the run, and `ClosedReason` the code of the
  gateway's `410`, unchanged: `run_closed`, `stopped` when the run's starter ended it,
  `session_lost` when it heard nothing from the session for 3 heartbeat intervals, and
  `batch_refused` when it refused a batch of the session's. The runtime was stopped as at its time limit. A server's
  `410` closes no run: Qory Apiary records what a run reports and never ends a run it
  did not start.

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
  - `link/`: the names the parts agree on: the proxy variables, the relay preamble and
    its line, `RelayLine`, the loopback address, the variables that name the run's socket
    and a tool's socket, the headers the proxy sets for a tool, the placeholder value,
    the names of the gateway's local link: the prefix `qory-link-` of its socket's
    directory, the socket's name and the modes of both; and the wire of a separate
    gateway's link: the binding's words and lines, `BindWord`, `BoundWord`, `BindLine`
    and `BoundLine`, its exporter, `BindingLabel` and `BindingSize`, the message the
    gateway signs, `BindingDomain` and `BindingMessage`, `MaxBoundLine`, the paths,
    `RemotePathPrefix` and `RemoteDiscoveryPath`, and the third line of an answer's
    signature, `AnswerRequest`. `accesskey.LinkAnswerDomain`, `Answer.Link` and
    `PublicKey.VerifyAnswer` sign and verify those answers, and
    `server.NewRemoteLink(runKey, trust, userAgent, digests)` is the session's client
    of the link, `server.HeaderRunID` the header a local batch names its run in.
  - `internal/`: `jcs`, and `importrules`, the test of the rules below.
- `session/`: the session.
  - `session.Run` takes a launch spec, with the gateway and the wall as values, and
    returns the exit status. It speaks to the gateway over the gateway's link alone:
    the local link on one machine, or a separate gateway's one address over TLS.
  - `session.Resend` sends a separate gateway what a run's session did not deliver.
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
- `gateway/`: the gateway. `gateway.Start` serves sessions on a local link, or with
  `Config.Listen` the sessions of other machines on one address of its own, with the proxy, the credentials and the
  tools in `gateway/internal/`, and reports every run to the server. `gateway.Resend` sends a run's record again. `Start` with its `Config`
  and the `Gateway` it returns, `Resend` with its `ResendConfig` and its lines of a
  run that never opened and of torn lines, `ResendNoServer`, `ResendNotOpened` and
  `ResendTorn`, and the types their fields need are the package's whole surface.
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
  speaks to the gateway over the gateway's link alone, the local link on one machine or
  a separate gateway's one address over TLS. Its tests import
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
