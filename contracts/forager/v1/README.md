# Forager contract, v1

What Forager reads, and what it emits. Forager is the security boundary around one
coding agent session: the only thing between the agent and the world. This directory is
its contract: the documents, one JSON schema per document, and the fixtures a reader or
a receiver is tested against.

## Versions

Every document here contains `version: 1`, an integer, and its schema is addressed by
URL under `https://qory.dev/contracts/forager/v1/`. The harness contract of `qory`
spells its version differently, `apiVersion: qory.dev/v1alpha1`, and the difference is
the rule, not an accident. A document a person writes and commits, the stack and the
module manifest, contains the group and the version together, the way a Kubernetes
object does, because the file is read by itself and its format evolves with the product.
A document addressed by a schema URL, read or written by a program, contains an integer
that guards its reader, because the URL already contains the group and the generation.
The policy, the server document, the documents a server returns and the descriptor are
on this side: the objects the command passes to Forager and the ones a control plane
sends over the wire, and the compose report `qory` writes is versioned the same way.
CloudEvents adds its `specversion: 1.0`, which is not ours to change.

**Revisions.** This is `v1`, revision 1. Forager sends the revision as one integer:
the header `X-Qory-Contract-Version: 1` on every request to the server, and
`contract_version: 1` in the body of the run's registration. Forager on revision N reads every section
defined up to N and ignores any other section, and a server may rely on the sections up
to N and no more. An addition is a new revision; a breaking change is `v2`. An addition
made while no release of Forager is in use goes into the revision Forager sends; the
revision is raised only when a release of Forager is in use. Revision 1 is everything this
document describes: the server (§The server), the gateway's link (§The gateway's link),
a run's variables (§Variables), tools (§Tools) and images (§Images), where
`container_runtime` and `docker` belong to an option that is experimental (§The wall),
and nodes, access keys, instances and enrolment (§The server).

`v1` is the first generation of this namespace, not a stability promise. The Forager
module is at `v0`, which under Go's rules promises no compatibility: while the module is
at `v0`, a document or an event here may change in a way that breaks a reader, and the
changelog lists each such change. With the module at `v1`, a breaking change is a new
event type or a new directory, `v2`, never a change in place.

## The boundary

Forager's duties, in the order that matters when they conflict:

1. **Policy.** Forager reads one policy document, pinned for the run, that can only
   narrow what the binary allows: the egress mode, the allow list, the deny list, the
   paths of a host, and which of the machine's credentials the run may use. A policy
   that cannot be read means no run. No policy means observe everything, with no
   list to deny by. Nothing in a policy grants; a stale or failed policy degrades toward more
   restrictive, never toward more permissive.
2. **Egress.** Forager runs its gateway, an HTTP proxy, on loopback or, behind a wall, on
   the one address the enclosure reaches (§The wall), and starts the session behind it.
   Every connection the session opens through the proxy is observed and recorded as one
   event: the host, the port, whether it was a `CONNECT` tunnel or a plain request, the
   decision, and the rule that made it. A connection to a host the deny list covers is
   denied in either mode; in enforce mode a connection to a host outside the allow
   list is denied as well. A denied attempt is recorded and the session continues; a
   denial never ends a run.
3. **Credentials.** The session's environment and files contain none of Forager's. On a
   developer machine the session runs with the developer's environment, and the server's
   variables only when the launch spec accepts them (§Variables). With or without a
   wall the gateway keeps the credentials the run's policy selects in memory, outside
   the session, and sets each on the requests to the hosts it is for
   (§Credentials): the session reaches a code host and a model endpoint as itself, and
   its environment and files contain at most a placeholder for the credential. Behind a
   wall the tools the policy selects run outside as well, and the proxy sends them the
   requests to the hosts they serve (§Tools).
4. **Liveness.** A heartbeat while the session runs; the exit as the result.
5. **Reporting.** The session's terminal bytes as log chunks, Forager's observations
   as events, the runtime's output mapped to session events by a descriptor. Every event
   goes to files. When a server is configured, every event its configuration lists goes
   there too. When the caller passes a stream, such as standard output, every event goes
   there as well, as the line `events.jsonl` contains; that is how a run with no
   receiver is followed.
6. **The harness reports over a local socket**, never over a network. A hook the
   runtime calls forwards what it received to the session's socket; the gateway is the
   only thing that sends to a receiver.

## Limits

Stated so a receiver reads the record for what it is.

- The proxy sees host names and ports, never the content of a TLS connection: a
  `CONNECT` tunnel is a blind relay once established. The exception is stated in the
  run's record: for a host the run has a credential for, with or without a wall, and
  behind a wall for a host with path rules or one a tool serves, the proxy ends the
  session's TLS itself and reads each request's method
  and path. `dev.qory.run.policy_applied` lists those hosts as `terminated`, and no
  other host is read. A credential's `*.` entry there is not for a name under it that
  ends in `.local`, `.internal` or `.home.arpa`, such as `x.home.arpa` under `*.arpa`
  (§Credentials). An entry under which every name has such an ending, such as
  `*.local`, is not listed for the credential; it is listed when a tool serves it or
  it has path rules.
- On a terminated host the session's side of the connection is HTTP/1.1, so a protocol
  that needs HTTP/2 end to end, such as gRPC, does not work there, and a program that
  pins the host's certificate refuses the run's. A host that sends a request's headers
  back, an echo service, returns to the session the credential the proxy set. A path rule
  reads a path and nothing else: where a host, such as a GraphQL endpoint, takes every
  request on one path, the path is reachable or it is not, and what the request may
  touch behind it is bounded by the credential's scope, not by the gateway.
- Only proxy-aware programs are seen. The agent CLIs, git over HTTPS, curl, the package
  managers and the language runtimes read the proxy variables; SSH, and any program that
  ignores the variables, is not seen. Without a wall, enforce mode is
  advisory against such a program. Enforcement against bypass belongs to the wall (§The
  wall): the session runs outside and the agent in an enclosure whose only route
  out leads to the proxy. The three outcomes: a connection through the proxy is decided
  by the policy and recorded, on any machine; a connection around the proxy succeeds
  unseen without a wall, and fails unseen behind one. The gateway records what passes
  through it and nothing else; a record of attempts a wall refuses is the container
  layer's logging, or the network's.
- Without a wall, Forager gives the run only placeholders, but the agent can read every credential the machine already holds; run a brokered run on a machine that holds none.
  An unwalled run inherits the starting process's environment, apart from the
  variables the machine's credentials are read from, and it can read the machine's
  files. A connection it opens around the proxy carries the placeholder alone, and is
  not recorded.
- A wall decides which process may connect, not where the machine may connect. A packet
  filter in front of a node cannot distinguish the agent from the gateway, so its list is
  the union of both; the run's policy can only be enforced at the proxy. Neither
  distinguishes two accounts on one allowed host: a code host, an object store and a
  model endpoint each deliver data to whoever owns the account the request specifies.
- A credential the run passes into the enclosure's environment is the agent's; one the
  policy selects stays outside (§Credentials). What is passed in is the agent's: a
  checkout that keeps a secret in the repository's configuration passes the secret in with
  the workspace. Behind a wall the run directory is shown read-only and lies outside
  every place the run binds writable, so the agent can neither change nor move
  `events.jsonl`. The server's copy is out of reach as well.
- Behind a wall the exit status is the adapter's command's. With Docker that is the
  runtime's status, except that `125` is the engine failing to start the container,
  `126` and `127` the program not being startable in the image, and a runtime killed by
  a signal arrives as `128` plus the signal's number, with `signal` absent.
- The proxy behind a wall listens where the enclosure reaches it, which other
  containers of the same engine, or other processes of the machine, reach too. It
  serves none of them: the run has a secret that only its relay receives, every connection
  the relay forwards opens with `QORY-RELAY`, a space, the secret and a newline before
  the first byte of HTTP, and a connection that opens otherwise is closed unanswered
  and reported once. The secret is never inside the enclosure.
- On an engine inside a virtual machine, such as a Mac's, the hook socket does not cross the
  file share, so a walled run there has no session events from hooks; the log, the
  egress record and the structured output are unaffected. The forwarder's only
  transport is the local socket (§The local socket).
- The runtime's session events are what the runtime reports through its hooks and its
  structured output. A runtime that reports nothing produces no session events; the log
  and the egress record come from Forager and are always there. In an image by
  reference the image can change or forge the session events, and the runtime's
  settings and hooks are no boundary (§Images).
- A descriptor matches and copies. It never computes, so a mapping that needs a program
  is a Forager change, never a configuration change.
- The server is trusted with what it is sent. The access key authenticates Forager to
  the server. Every answer is signed under the key Forager pins, so Forager
  authenticates the server over `https` and over loopback `http` alike.

## Sequence

One run, on a developer machine, with a server configured:

1. Forager receives a launch spec: the program, its arguments, its environment and
   directory, whether the session is interactive, the policy document, the server
   document with the access key secret and the instance id and name, the egress the
   harness declared, the run's and the machine's variables, the harness's computed
   values and defaults, and the runtime name. The spec comes from the `qory` command,
   which reads the policy and the server from its configuration; Forager receives
   nothing about what composed it or where it was read.
2. The session creates a run id, a UUID version 7, and the run directory `<id>/` in the
   runs directory the caller passes, else in `.qory/runs/` in the checkout. A walled
   run's runs directory lies outside every place the run binds (§The wall).
3. It validates the server document once, when one is passed; without a pinned
   `apiary_public_key` the run does not start, `apiary_public_key_missing`, before any
   request. It fetches the server's configuration document with a signed `GET` (§The
   server), and verifies every answer's signature under the pin before it reads the
   body or the headers. It registers the run with one signed `POST` to the run endpoint
   the document defines, `run.url`, whose body carries the run id, its labels, what it is
   about and the heartbeat interval, and waits for a signed `200`, whose body is the
   run's run configuration; heartbeats start once the registration is accepted. A fetch
   that fails, a document the schema refuses, an answer that does not verify, or a
   registration not accepted means the run does not start: a run configured to be
   observed never runs unobserved by accident. The gateway tries the registration up to
   3 times as a run opens, with the same bytes each time (§The gateway's link, Tries as
   a run opens).
   The `--local` flag of the command runs with the file sink alone and contacts no
   server. With no server configured there is no fetch and no registration, and the run
   starts at once, files only.
4. It determines the policy. With a server, the run configuration the registration's
   answer carries decides it: its `security_policy`, narrowed by the policy the command
   passes, is the policy, and its `variables` are the server's (§Variables); anything but
   a signed `200` to the registration is no run. Without a server, or when the run
   configuration has no `security_policy`, the policy is the one the command passes. It
   validates the policy once.
   Refused by the schema: the run does not start. Absent: mode `observe`, everything
   allowed and recorded. Present: pinned, with the digest of its canonical JSON as its
   stamp. The allow list and the deny list are the policy's entries; the hosts the
   harness declared are reported and decide nothing (§The policy).
5. It starts the proxy on a loopback port and sets `HTTP_PROXY`, `HTTPS_PROXY` and
   `NO_PROXY` in the session's environment, in upper and lower case, with
   `NO_PROXY=localhost,127.0.0.1,::1` so a local MCP server or model endpoint still
   answers. Without a wall the proxy URL carries a password of the run's forwarder
   alone, which the forwarder checks (§The gateway's link, Agent traffic). It opens the
   local socket and sets `QORY_RUN_SOCKET` to its path, `QORY_RUN_ID` to the run id, and
   `QORY_HARNESS_HOME` to the harness's home when the launch spec has one. Nothing else
   of Forager's enters the environment but the variables (§Variables) and the
   placeholders; in a walled run the runtime's declared, reserved and denied variables
   and the node's denied ones that nothing sets are unset inside (§The wall).
6. It has the runtime prepare the launch (§The runtime): for a runtime that takes hooks,
   Forager's forwarder as a command hook for each event the runtime lists. For Claude
   Code that is a copy of the first settings file the launch passes, written as
   `settings.json` in the run directory and passed in its place, and, for an
   interactive session whose API key is a placeholder, a script that pre-approves the
   placeholder value in Claude Code's configuration before it starts (§The descriptor).
   What is prepared goes into the run directory; the composed home is not modified.
   Claude Code reads only the last `--settings` it is passed. A walled launch that
   passes `--settings` more than once, counted anywhere in its arguments, does not
   start: "This launch passes --settings more than once, and Claude Code reads only the
   last one, so the run does not start. Pass one --settings file." An unwalled launch
   that passes it more than once starts, and Claude Code reads the last `--settings` it
   passes, without Forager's hooks.
   A settings file that lies in a place a walled run can write, whose path has a `..`
   name, that is a link or that is not a regular file of at most 1 MiB is not read, and
   the run does not start. The
   places are the ones the caller records as written by walled runs, the writable binds
   of the other walled runs in the registry and, behind a wall, the run's writable
   binds.
7. It emits `dev.qory.run.started` and `dev.qory.run.policy_applied`, then starts the
   program: on a pseudo-terminal when the caller is interactive and no argument the
   descriptor lists as headless is among the runtime's, on pipes otherwise.
   `dev.qory.run.started` records the command and the arguments as the runtime prepared
   them: for an interactive Claude Code whose API key is a placeholder, `command` is
   `/bin/sh` and `args` hold the script in the run directory, then `claude` and its
   arguments.
8. While the program runs: every chunk of output is one `dev.qory.run.log`; on a
   pseudo-terminal every resize is one `dev.qory.run.resized`; every connection through
   the proxy is one `dev.qory.run.egress`; every record the descriptor matches is one
   session event; every thirty seconds one `dev.qory.run.heartbeat`, from the accepted
   registration with a server and from step 7 without one, until the final event.
9. The program exits. The session drains the socket, so a hook on the runtime's last
   event is still read, emits `dev.qory.run.exited`, waits up to fifteen seconds for the
   sinks to flush, reports what the server has not accepted, and returns the program's exit
   status. A runtime killed by a signal exits as `-1` with `signal` set.

A run may have a time limit. When the runtime still runs at the limit the session stops
it, and `dev.qory.run.exited` contains `reason: timeout` with the state `cancelled`; step 9
is otherwise the same. A runtime that exited by itself before the session's stop signal
is decided by its exit.

A run stopped from where it was started (a Ctrl-C, or a signal to the program that runs
the session) is stopped the same way: when that stop came before the session observed
the runtime's exit, `dev.qory.run.exited` contains `reason: interrupted` with the state
`cancelled`, beside the runtime's `exit_code` and `signal`, whatever they are; step 9 is
otherwise the same. A denied connection never ends a run; the limit is the one thing of
Forager's that does. A server's `410` never ends a run: Qory Apiary records what a run
reports and never ends a run it did not start, so its signed `410` stops the deliveries
alone, and the run goes on (§The server).

The session stops a runtime the same way at the limit and when the session's context
ends: a signal that requests the runtime's exit, then SIGKILL after a grace. The signal
is one of SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2, since runtimes differ
in what each means: one closes its session on SIGINT and drops it on SIGTERM, another
the other way round. So the runtime defines which and how long (§The runtime), the run
may set others over it, and with neither it is SIGTERM and ten seconds. Behind a wall
the enclosure passes the same signal on to the runtime inside.

Forager makes the run id, a UUID version 7, unless the caller already has one: a
caller's id is a UUID in the canonical lower-case form, since it is every event's
`subject` and the run directory's name, and anything else is no run. What else the caller
identifies the run by, a key in its queue, a repository, an issue, goes in `labels` on
`dev.qory.run.started`: at most 16, a key of 1 to 64 of `a-z`, `0-9`, `_`, `.` and `-`, a
value of at most 256 bytes. Forager reads nothing into them, except that a separate
gateway's selection of credentials can take a credential's argument from one. It copies
them into `dev.qory.run.started`, and no other event repeats them: a receiver joins on
`subject`.
It sends them, all of them, in the body of the run's registration (§The server), never
in a URL, and the server decides which labels identify what the run works on. The `qory` command, for one,
labels a run in a git checkout with `forge` and `repository` from its origin remote, and
a server that keys its policies on those finds them there.

Behind a wall, three steps differ and no event does. Before step 5 the gateway starts the
tools the policy selects and waits until each listens (§Tools), then has the wall
prepare the enclosure and listens on the address the wall returns, not on loopback.
After step 6 it passes the wall the launch, the proxy's address, the socket and the
run directory, read-only, and starts the command the wall returns, on the same pseudo-terminal or
pipes; the proxy and socket variables inside contain the addresses the enclosure reaches
them on. After step 9 it closes the wall, which removes everything it created, and stops
the tools.
`dev.qory.run.started` contains `wall` and `image`, and `image_name`, `container_runtime`
and `docker` when the image is one the machine defines, and `image_fetch_ms` when the
policy names it by reference (§Images).

When the session and the gateway are two processes, the requests of steps 3 and 8 go
to the gateway over its link, unsigned, and the gateway is the node toward the server
(§The gateway's link): the session fetches the link's discovery, opens the run with a
`POST` of its run request, and posts its events without `sequence`; the gateway
registers the run with the server. No access key and no server key pin are on the
link.

### What a run is about

What the run is about, as the caller passed it, goes in `about` on
`dev.qory.run.started`. Every member is optional, and Forager copies it and reads
nothing into it:

- `kind`: the kind of run, the caller's word, 1 to 64 bytes.
- `title`: the run's title, 1 to 256 bytes.
- `subjects`: what the run works on, 1 to 16, each an object of `type` and `ref`, and
  `url` and `title` when the caller has them. `type` is an open name the caller
  chooses: words of `a-z` and `0-9`, each joined to the next by one space, underscore,
  dot or dash, at most 64 bytes. `ref` is the subject's reference, 1 to 256 bytes;
  `url` is where the subject is shown, an absolute `http` or `https` URL of at most
  2048 bytes, and a `url` never carries a user name or password; `title` is the
  subject's title, 1 to 256 bytes. No two subjects have the same `type` and `ref`: a
  subject is identified by its type and ref.
- `details`: a JSON object of the caller's, at most 8192 bytes as the event contains
  it, compacted, with `<`, `>` and `&` written as `\u003c`, `\u003e` and `\u0026`, and
  nested at most 4 levels deep: `details` is level 1, and an object or an array inside
  it is level 2. A key is 1 to 64 bytes. `details` is shown to every reader of the run,
  so it never holds a secret.

No string in `about`, key or value, contains a control character: U+0000 to U+001F,
U+007F to U+009F, U+2028 and U+2029. The schema states every rule but these, which
Forager alone checks: the byte limits, the 8192 bytes of `details`, that no two subjects
have the same `type` and `ref`, a `url`'s syntax and host, that a `url` carries no user
name or password, and that no member name appears twice in `details`. The schema's
lengths count characters, so they are upper bounds of the byte limits. Forager holds
`about` to every rule here before it contacts the server: an `about` that breaks one is
no run.

Only `dev.qory.run.started` contains `about` among the events. Toward the server, the
run's registration contains it (§The server, The run endpoint); on the gateway's link
the run request contains it (§The gateway's link). It is for display: it never selects
or changes a security policy. An empty `about` is left out, and one whose every member
is left out for a secret is sent as `{}`.

## The policy

`policy.schema.json`. The document the command passes to Forager, from the machine's
configuration, never from inside the checkout, where the agent it constrains can write
it: for `qory`, the `gateway.egress` section of `~/.config/qory/forager.yaml`. The same
document a server's run configuration contains as `security_policy` (§The server), so
nothing is designed twice.

```yaml
version: 1
egress:
  mode: enforce                # or observe
  allow:
    - api.anthropic.com
    - github.com
    - "*.github.com"           # every host below github.com; not github.com itself
  deny:
    - gist.github.com          # denied in either mode, whatever allow contains
```

| Field | Meaning |
|---|---|
| `version` | `1`. Forager refuses a version it does not read, and the error contains that version |
| `egress.mode` | `observe`: every connection is recorded, and only a host `deny` covers is denied. `enforce`: a connection to a host outside `allow` is denied as well, and recorded |
| `egress.allow` | lower-case host names, or `*.` followed by a name for every host below it. No ports, no paths, no schemes. An entry that names a host, not a `*.` suffix, is a host name or an IPv4 address in canonical form, four decimal parts with no leading zero; a document with any other is refused as one the schema refuses. Absent is empty, and `enforce` with an empty list reaches nothing |
| `egress.deny` | hosts the session may not reach, in `allow`'s grammar, in either mode: a host an entry covers is denied before `allow` and the mode are consulted, whatever `allow` contains, and the entry is the rule reported. Absent is empty |
| `egress.paths` | by host, in `allow`'s grammar, the paths the session may request on it: a path matched whole, or up to a final `*` as a prefix. A host listed is terminated, which needs a wall; a host not listed is reached on every path. A host several entries cover is held to the most specific one: its name itself, else the `*.` entry with the longest suffix. An empty list is no path at all |
| `credentials` | the credentials of the machine's the run may use: `name`, and an `argument` for an adapter, such as a repository, of at most 4096 characters. A policy defines none (§Credentials) |
| `tools` | the tools of the machine's the run may reach: `name`, and an `argument` when the definition takes one, of at most 4096 characters. A policy defines none (§Tools) |
| `image` | the image the run starts in: the machine's name for one of its images, or a reference pinned by digest, `NAME@sha256:` and 64 lower-case hexadecimal digits, under one of the machine's `images.allow` prefixes; absent is the machine's default. A policy defines no image (§Images) |

**A node narrows a server's policy.** The server leads; the node only narrows. A node,
through an agent that writes its configuration for example, is easier to compromise
than the server, so on a node connected to a server what the node contributes can only
take away from the run. The node's policy is the policy document of the launch spec,
`Spec.Policy` in Go. A fetched `security_policy` and the node's policy combine by
narrowing. Without a server's `security_policy` the node's policy is the run's. One
exception: for a walled run behind a separate gateway with a selection of credentials,
the node policy's `credentials` member only caps that selection (the `credentials` row).
With a server's policy and no node policy, the server's applies as it is.

| Field | The run's |
|---|---|
| `egress.mode` | `enforce` when either side sets `enforce`, else `observe` |
| `egress.allow` | under `enforce`, a host passes only when the allow list of every side under `enforce` covers it; a side under `observe` allows every host its `deny` leaves open. Forager reports the entries of each side under `enforce` that every other such side's list covers, the server's first, each entry once, which is exactly the hosts both allow; with neither side under `enforce`, the server's entries |
| `egress.deny` | the union: a host either side's `deny` covers is denied, in either mode, and recorded with that entry as its rule |
| `egress.paths` | a host either side lists is terminated, and a request to it must match an entry of every side that lists its host. The run's mode decides what a miss does: under `enforce` it is denied; under `observe` it passes; either way it is recorded with an empty `path_rule`. A request every such side matches is recorded with the narrowest entry that matched |
| `tools` | the server's selection, narrowed by the node's `tools` member: absent, it leaves the selection as it is; present, each selected tool must be listed in it by name, and by argument when the node's entry has one, so `tools: []` allows none. A selected tool outside it is no run, `tool_unknown`, as a tool the node does not define |
| `credentials` | the server's selection, narrowed by the node's `credentials` member as `tools` is; a selected credential outside it is no run; behind a separate gateway, when the server's selects none, a walled run gets the gateway's selection: a credential that takes an argument takes it from the run's label the selection names, whose value must match whole the pattern it names, and only for a run whose `forge` label is the one it names |
| `image` | when both sides select one, it must be the same, else no run, `image_unknown`; when one does, that one; else the node's default |
| `variables` | the server's, over every source of the node's but the fixed names; the node's apply to the names the server leaves alone (§Variables) |

`image` selects one thing, so its narrowing is agreement: two different selections are
no run rather than a choice. The node's policy is fixed for the run: a reload replaces
the server's side, and the run applies the new `security_policy` narrowed by the same
node policy; the reload rules (§The server) hold for the result.
`dev.qory.run.policy_applied` reports the run's `mode`, `allow` and `deny` as the table
computes them, the server's `paths`, `source` `fetched` with the server's `url`,
`digest` and `run_configuration`, and the node's policy as `node_policy` (§The events).

**The harness's declared hosts.** The harness compose reports the hosts its modules
declare, the command passes that list to Forager, and `dev.qory.run.policy_applied`
reports it as `harness_hosts`; it decides nothing. The policy alone decides: `allow` is
the policy's list, a declared host the policy does not cover is denied under `enforce`
like any other, and one `deny` covers is denied in either mode. The grammar of a declared
host is that of `egress.allow`, defined here once; the harness contract copies it and
cites this document.

**Matching a connection.** The host of a `CONNECT` request is its authority; the host of
a plain request is the authority of its absolute-form target, never its `Host` header.
Host names are compared lower-case; an IP literal matches only an identical entry.
A host name is resolved as given, with no search domain added: a short name reaches
only a host of that exact name, from the hosts file or a name server.
A host that is neither a name of ASCII letters, digits, hyphens and dots nor an IP
address in canonical form is denied in either mode before either list, with the rule
`wall:host-form`. An IP address is in canonical form when it is an IPv4 address of four
decimal parts with no leading zero, or an IPv6 address in RFC 5952's form, in either
case, with no zone, and not in ::/96 (except ::1), ::ffff:0:0/96, ::ffff:0:0:0/96 or
64:ff9b::/96, ranges that each hold an IPv4 address in their last 32 bits. A host whose
last label is all digits, or 0x followed by hex digits or none, in either case, ends in
a number and is an address. `deny` is decided first: when an entry of it covers the host, the connection is denied
in either mode and that entry is the rule reported; only then `allow` and the mode
decide. `deny` beats `allow` whatever the shapes: `allow: ["*.example"]` with
`deny: ["tracker.example"]` denies `tracker.example` and reaches `api.example`, and a
host both lists cover is denied. A denied host is never reached, so its paths and a
credential for it never apply; the guard of a walled proxy (§The wall) decides before
either list. In each list the first entry that matches is the rule reported. A denial
is a `403 Forbidden` with a one-line text body containing the host and the mode; a tunnel
is never opened for it.

**Matching a path.** On a terminated host every request is decided, by the policy's
paths for the host and by the paths of the credential that is for it, and it passes
when every list that exists has an entry that matches. The comparison is exact, case
included: on a host that ignores case this denies a spelling the host accepts,
never the reverse, so whoever writes a path writes it as the host does. A path
that could be read two ways is denied in either mode, with the rule
`wall:ambiguous-path`: an encoded slash, backslash, dot or percent sign, a backslash, an
empty segment, a dot segment. On a host that gets a credential from the server, a
`TRACE` or `TRACK` is denied in either mode, with the rule `wall:echo-method`
(§Credentials, From the server). Under `observe` a path no entry matches is recorded as
allowed with an empty `path_rule` and passed on, as a host no entry matches is recorded
as allowed with an empty `rule`, but the credential is set only where the credential's
paths match: observe mode sends no secret to a path nobody configured. The host
requested upstream is the one the connection was opened to and decided on, whatever
`Host` a request contains. A denial is a `403` containing the method, the host and the path.
A plain request is decided by the same paths, and the proxy never sets a credential on it.

*Reading without writing.* Paths define what a run does on a host as well as where. git
over HTTPS requests three paths of a repository, on any host that serves it:
`/<repo>.git/info/refs`, then `/<repo>.git/git-upload-pack` for a fetch or
`/<repo>.git/git-receive-pack` for a push. A run allowed the first two and not the third
clones and fetches, with the credential set, and its push is refused before it leaves
the machine: git reports `HTTP 403` and fails, the record contains the denied `POST`, and
nothing reaches the repository, whatever the credential itself permits. Rules match the path
and never the query, so the `info/refs` a push requests first is allowed; it lists the
same refs a fetch reads.

*What a path rule does not read.* A rule reads the request's path and nothing else: not
its query, not its headers, not its body. What a request specifies there is outside the
rule: a subresource requested in the query, such as `?acl`; a listing whose prefix is a
query parameter, on a host that lists at `/`; a copy that sets its source in a header,
which writes under an allowed path what it reads from another; a GraphQL body that
selects any repository the credential reaches. A path rule limits a run to the paths it lists
and guarantees nothing about the rest. The rest is bounded by the credential's scope, or
by what serves the host, and whoever writes the policy for a host that accepts such
requests checks them there or leaves the host out.

## Credentials

A credential is a secret the gateway keeps outside the enclosure and sets on the
requests it applies to; the session's environment and files contain at most a
placeholder for it.
The machine defines credentials; the run's policy selects among them by name and
defines none, so whoever writes a policy chooses among the programs the machine's owner
installed and never specifies one. The gateway sets them for every run, with or without
a wall: the agent's environment contains only their placeholders. Without a wall a
program that ignores the proxy sends only the placeholder, and its connection is not
recorded (§Limits); a wall makes such a connection fail.

A definition defines where the secret comes from, exactly one of:

| Source | The secret is |
|---|---|
| `env` | a variable of Forager's environment, read once when the run starts |
| `file` | a file's content, read again whenever it is used, so whatever rotates it notifies no one |
| `adapter` | what a program of the machine's prints |

**An adapter** contains what one kind of host needs: a source code host, an artifact
store. Forager contains nothing specific to any host. The gateway starts the adapter
outside the enclosure, with Forager's environment without the access key's
variables, a minute to answer, and `${argument}`
in its arguments replaced by the policy's argument, which the definition's pattern must
match whole: one word of the command line, never a shell's. It prints one document,
`credential.schema.json`, and exits 0; anything else is no run, and the line it writes
to standard error is the reason reported.

```json
{"version": 1, "token": "…", "expires_at": "2026-09-19T14:00:00Z",
 "apply": [
   {"hosts": ["git.example.com"], "scheme": "basic", "username": "x-access-token",
    "paths": ["/acme/shop.git/*", "/acme/shop/*"]},
   {"hosts": ["api.git.example.com"], "scheme": "bearer",
    "paths": ["/repos/acme/shop", "/repos/acme/shop/*"]}],
 "placeholders": ["GIT_HOST_TOKEN"]}
```

The adapter's answer defines how its secret is used, because hosts differ in it: which
hosts, which scheme, and which paths make up what the run requests. The schemes are a
closed set, `bearer`, `basic` with a `username`, `header` with a header's name; an
adapter chooses among what the gateway implements and adds nothing to it. Of a host with
`paths` the run reaches those and no other, so one repository's credential does not open
another organization's on the same host; a path the adapter leaves out, such as the
host's GraphQL endpoint, is not reached. A definition may set `hosts` and `paths` for an
adapter: the most the adapter may claim. For `env` and `file`, which have no adapter to
define the use, the definition's `hosts`, scheme and `paths` are the use itself.

**Private hosts.** The proxy sets a credential on a private host only through a `hosts`
entry equal to the host, compared without regard to case, and never through a `*.`
pattern. A private host is an IP literal in `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16` or `fc00::/7`, a name of one label such as `litellm`, or a name that
ends in `.local`, `.internal` or `.home.arpa`. A credential whose `hosts` are
`["*.local"]` sets nothing on `litellm.local`; list `litellm.local` itself. A
credential's key is sent only over TLS whose certificate the gateway machine's system
trust store verifies.

Before the run starts every selected credential is resolved, and any of these is
no run: a name the machine does not define, an argument it does not provide for, a host
two credentials claim, a claim above the definition's, and under `enforce` a host the
run's allow list does not cover. The gateway runs an adapter again five minutes before
`expires_at`, and when a host returns 401 to a request it set the secret on, at most
once every thirty seconds. The new answer changes the secret and nothing else: one
that lists other hosts, schemes or paths is refused and reported, and the old secret
stays, because what a run reaches is fixed when it starts.

**Placeholders.** A program often needs a credential set to start. A
definition, or an adapter's answer, lists variables the agent's environment gets with the value
`qory-sets-the-credential-outside-the-enclosure`, which is no credential anywhere; the
proxy replaces what the program sends. A run that passes a value for such a variable
does not start.

**Termination.** For the hosts the credentials are for, and the hosts with path rules,
the proxy ends the session's TLS itself, answering as the host with a certificate of an
authority created for the run. The authority's key is in the gateway's memory and nowhere
else, and gone with the run; its certificate is what the wall adds to the enclosure's
trusted bundle (§The wall). Without a wall the session writes `ca-bundle.pem` into the
run directory: the first of `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem` and `/etc/ssl/cert.pem`
that is a regular file with a certificate in it, then the run's certificate. It points
the variables of `wall.ca_env`, `Spec.CAEnv` in Go, or the wall's default list
(§The wall), at that file. For programs that read those variables the bundle replaces
the machine's trust, so a root that exists only in another store, such as the macOS
Keychain, is not trusted. A machine with none of the four files does not start the run:
`install a CA bundle at /etc/ssl/cert.pem or /etc/ssl/certs/ca-certificates.crt: the
run's tools trust the gateway for the credentials' hosts only through a bundle, and this
machine has none of the files Forager reads`. The proxy verifies the real host against the machine's
roots. Every other host stays a tunnel the proxy does not read, and a run with no
credential and no path rule has no authority at all.

**The record.** `dev.qory.run.policy_applied` contains each use, `name`, `argument`,
`hosts`, `scheme` and `paths`, and the `terminated` hosts. Its `credential_variables` lists the
variables each credential's placeholder is in (§Variables, The record of the
variables). A credential's `*.` pattern
among the `terminated` hosts is for no private host under it, such as `x.home.arpa`
under `*.arpa`, and a pattern under which every name is a private host, such as
`*.local`, is not listed for the credential; it is listed when a tool serves it or it
has path rules. `argument` is the policy's
argument to the credential, the same on every use of one credential and absent when the
policy passes none, so the record shows what each secret is minted for, such as the
repositories of a source code host. On a terminated host `dev.qory.run.egress` is one
event per request, `method: HTTPS` with `request_method`, `path` without its query,
`path_rule`, and `credential`, the name of the one the proxy set. No event, no report
and no error contains a secret.

**From the server.** A run configuration may have `credentials`, the credentials whose
values the server stores for the run, at most 8 (`run-configuration.schema.json`):

```json
"credentials": [
  {"name": "model", "hosts": ["api.model.example"], "paths": ["/v1/*"],
   "auth": {"scheme": "header", "header": "x-api-key"},
   "key_variables": ["ANTHROPIC_API_KEY", "MODEL_API_KEY"]},
  {"name": "forge", "hosts": ["git.example", "api.git.example"],
   "auth": {"scheme": "basic", "username": "x-access-token"}}]
```

`name` is a credential's name, `^[a-z0-9][a-z0-9_.-]{0,63}$`, each once in the document.
Each of `hosts` is exact: a lower-case DNS name whose last label starts with a letter, an
IPv4 address of four decimal parts with no leading zero, or an IPv6 address of lower-case
hex groups with no leading zero, without brackets or a zone; never a `*.` pattern or a
port. The server writes an IPv6 address in RFC 5952's form, the form `policy.Host`
returns: the schema does not check which run of zero groups `::` replaces. `paths` are
in the policy's path grammar, absent meaning every path, `auth` is one of the closed set
of schemes, `auth.schema.json`. `key_variables`, optional, are the names of the
environment variables from which a runtime reads the credential's key, 1 to 16, each
`^[A-Z_][A-Z0-9_]{0,127}$` and none twice: the session gives the placeholder to the one
of them that the run's runtime declares (The variable of a model key, below).
`placeholders` are variables for the enclosure to get with the placeholder value. An entry
has no value and no member beside these six: the server seals each value to the access
key in the answer to the secrets request (§The server, Secrets). Forager checks a run
configuration's `credentials` against the schema, then refuses a name twice and an
`auth.header` that frames the request or that the proxy sets: `Host`, `Content-Length`,
`Transfer-Encoding`, `Connection`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`, `Expect`,
`Cookie`, and any name that starts with `Proxy-`, `X-Qory-` or `Qory-`, case ignored and
`_` read as `-`. It also refuses a placeholder that an entry of the built-in deny list,
`denied-variables.json`, covers, case ignored, such as `GIT_SSL_CAINFO`, `HTTPS_PROXY` or
one of Forager's `QORY_` names. Each is `run_configuration_invalid`, and a name that
contains an access key secret or a run key is shown as a phrase, in the text and in the
refusal's `names`.

The gateway sets these credentials for every run, with or without a wall. A run
configuration with `credentials` from a server whose discovery lists no `secrets` is
`run_configuration_invalid`. When the run
starts, the gateway sends the secrets request once, under the access key, for the
document's credentials in its order and the digest it computes of the document's bytes,
and opens the answer with `sealed.Open` under the pinned `apiary_public_key` and the
machine's clock. A pin or an access key that is a published fixture key is
`run_configuration_invalid`: the registration or the attach has been sent, and the
secrets request is not. A value with a control character other
than tab, or a space or tab at its start or end, is `run_configuration_invalid`, and so
is an answer `sealed.Open` refuses, but one whose envelope signature does not verify,
`answer_unsigned`. No message contains a value. A credential from the server replaces
each credential of the machine's whose hosts claim one of its hosts, or a host above or
below one: a key from `env` or `file`, such as forager.yaml's model key for that host, is
then not read; an adapter still runs, and its answer is dropped. The run answer, the
record and `placeholders` list the server's credential instead. The replaced credential
may have the same name: forager.yaml's `model` on `api.anthropic.com` and a run
configuration's `model` on `api.anthropic.com` give the run the server's `model`. A
credential of the machine's that stays, because its hosts claim none of the server's
credential's hosts, and that has the same name is no run, so the record lists each name
once. Without `credentials` the run gets the machine's credentials as before.

**The variable of a model key.** For a credential from the server with
`key_variables`, the session chooses one more variable for its placeholder. The run
answer's `credential_hosts` has the credential's `key_variables` and `auth` (§The
gateway's link), and the session takes the names among `key_variables` that the run's
runtime's descriptor declares (§The descriptor). Exactly one must match, and the
declaration's `auth` must equal the credential's: the same scheme and, for `header`, the
same header name, case ignored. The declaration's variable joins the credential's
`placeholders` and the run's. Claude Code sends the key in `ANTHROPIC_API_KEY` as the
header `x-api-key`, and the key in `ANTHROPIC_AUTH_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN` as
a bearer, so a credential for an API key sent as a bearer, such as OpenRouter's, lists
`ANTHROPIC_AUTH_TOKEN`. A name the runtime does not declare, such as another runtime's
variable, is passed over.

A credential of which the runtime declares none of the `key_variables`, or more than
one, or whose `auth` differs from the one declaration's, is `run_configuration_invalid`
with the credential's name. A credential's `placeholders` may also list the chosen
variable, which is set once, and variables the runtime does not declare, such as a
tool's `GITHUB_TOKEN`, which are set as well.

A placeholder goes only into a variable for a credential. A placeholder of a
credential from the server is `run_configuration_invalid`, with the credential's name,
when the runtime's descriptor lists it in `denies` or in its model `overrides`, when it
is the model `endpoint`'s variable, when the descriptor lists it in `reserves`, or when
the runtime declares it and the session did not choose it from the credential's
`key_variables`: a credential's key goes into one variable, and a key's variable gets a
placeholder only through `key_variables`. Two credentials with `key_variables`, on
different hosts, may each set one key's variable; each gets a placeholder. The session
checks the run answer's `placeholders` too, the machine's credentials and tools
included: one that the descriptor denies, lists in its
overrides or reads its endpoint from, or one the runtime declares or reserves that no
credential has among its `placeholders`, is `run_configuration_invalid` with the
placeholder's name. A credential of the machine's may have a declared variable among
its `placeholders`, such as forager.yaml's model key in `ANTHROPIC_API_KEY`. The chosen
variable is a
placeholder like any other: a value the run passes for it is `placeholder_conflict`, the
endpoint rule counts the credential as a model credential (§Variables), and Claude
Code's approval of the stand-in covers `ANTHROPIC_API_KEY` chosen this way (§The
runtime). A credential without `key_variables`, and every credential of the machine's,
gets the variables its `placeholders` list. The session chooses, since the gateway does
not know the run's runtime.

The credentials are fixed when the run starts: a reload whose `credentials` differ fails,
and the policy in force stays. A private host gets a value only through an exact entry,
as a credential of the machine's does, and the proxy verifies the host's certificate
against the gateway machine's trust store. A host on the gateway machine gets a value
only when the node's policy names it, as for every name on the machine. On a host that
gets a credential from the server, a `TRACE` or `TRACK` is denied with the rule
`wall:echo-method`, since its answer would send the value back. The values stay bytes
until the proxy sets the header, and are overwritten when the run ends.

## Tools

A tool is a program of the machine's that serves hosts, for what a run reaches that
needs more than a secret in a header: a request signed with a key that stays outside the
enclosure, a protocol with a custom exchange, a service that exists only on the machine,
such as an MCP server. Forager implements no protocol and a tool implements one, so no
protocol, cloud or provider enters Forager. The machine defines tools; the run's policy
selects among them by name, with an argument, as it selects credentials, and defines
none. Tools need a wall.

| Definition | Meaning |
|---|---|
| name | what a policy selects it by, in a credential's grammar |
| command | the program and its arguments; `${argument}` in an argument is replaced by the policy's argument |
| argument | a regular expression the policy's argument must match whole; none means a policy passes none |
| serves | the hosts whose requests go to the tool, in `egress.allow`'s grammar; at least one |
| placeholders | variables the enclosure gets with the placeholder value, as a credential's (§Credentials) |

```yaml
# the run's policy
egress:
  mode: enforce
  allow: [files.tools.internal]
  paths:
    files.tools.internal: [/media/acme/shop/*]
tools:
  - {name: files, argument: acme/shop}
```

**Starting.** Before the runtime starts, the gateway starts every selected tool outside
the enclosure: the command, with `${argument}` replaced by the argument, one word of the
command line and never a shell's; Forager's environment, without the variables the
machine's credentials are read from and without the access key's,
`QORY_ACCESS_KEY_SECRET`, `QORY_ACCESS_KEY_ID` and `QORY_APIARY_PUBLIC_KEY`, with
`QORY_TOOL_LISTEN`, the path of a Unix
socket in a private directory of Forager's, mode `0700`, and `QORY_RUN_ID`. The tool
listens there within a minute; one that exits first, or does not listen in time, is no
run, and the last line it writes to standard error is the reason reported. Once it
listens, what it writes to standard error is reported as Forager's lines and its
standard output is discarded. A tool that exits while the run goes on is reported and
not started again: a request to it is a failed dial. When the run ends, once the proxy
is closed, the gateway sends SIGTERM to the tool's process group, SIGKILL after five
seconds, and removes the socket.

**Reaching one.** For the hosts a tool serves, the proxy ends the session's TLS as for a
credential's host, decides the host and the path by the policy as for any host, and
sends the tool over the socket every request it allows, as HTTP/1.1, streamed both ways:
the request as the session sent it, its query, headers, body and trailers, placeholders
included, with the `Host` the connection was decided on. Under `observe` that includes a
request whose path no rule covers, which is recorded as allowed with an empty
`path_rule`. A plain request to
such a host goes the same way. The proxy never dials a host a tool serves, so the host
need not exist: a tool with no real host serves a name the machine's owner chooses, such
as one under `.internal`, a domain reserved for private use, and the session reaches it
like any host. The proxy sets two headers, after removing every header and trailer whose
name starts `Qory-` from the request, in any case and with an underscore for the dash,
so the values a tool reads are the proxy's, and a session that lists them in
`Connection` cannot remove them:

| Header | Value |
|---|---|
| `Qory-Request-Id` | the proxy's id of the request, 32 lower-case hex digits: the `request_id` of its `dev.qory.run.egress` |
| `Qory-Path-Rule` | the path rule that matched the path; `none` when the host has path rules and none covers the path, which happens only under `observe` and which a tool that enforces its rules refuses; absent when the host has no path rules |

The argument is not repeated per request: a tool started for the run has it on its
command line.

**What the tool decides.** A path rule reads the path and nothing else (§The policy), so
what a request specifies in its query, its headers or its body is the tool's to check,
against its argument and the path rule it receives. A tool refines inside what the
gateway allows and never widens it: a request the rules refuse never reaches it. What a
tool forwards, and where, leaves from the machine directly, not through the proxy; the
record contains only the request that reached the tool. A tool that forwards a request
unchanged sends the placeholder with it; replacing or dropping it is the tool's.

**Refused before the run starts:** a name the machine does not define, a tool selected
twice, an argument the definition does not provide for, a host two tools serve, a host a
tool serves and a credential is for, under `enforce` a host the run's allow list does not
cover, and a value the run passes for a tool's placeholder. The tools a run has are fixed
when it starts: a run configuration that selects other tools, or another argument, fails
the reload, and the policy in force stays.

**The record.** `dev.qory.run.policy_applied` lists the tools, `name`, `argument` and
`hosts`, and their hosts among `terminated`. `argument` is the policy's argument to the
tool, absent when the policy passes none, so the record shows what each tool is started
for, such as a repository. Every request to a tool's host is one
`dev.qory.run.egress`, a tool invocation: `method: HTTPS`, or `HTTP` for a plain
request, with `request_method`, `path` without its query, `path_rule`, `tool`, the
tool's name, `request_id`, and, once the tool answers, `status`. A request a path rule
refuses contains the tool it did not reach, with `decision: denied`; a connection the
policy refuses by its host, by the deny list, the guard or the allow list, contains
none. The gateway reads no body, so what an invocation does beyond its method and its
path is not read by the gateway, and the tool checks it; the runtime's hooks report the
MCP call an agent makes (`dev.qory.session.tool_started`), as the runtime reports it
from inside, which an image by reference can change (§Images).

## Variables

A run's variables reach the agent's process alone. The session adds them to the launch's
environment; the tools, the relay, the agent's Docker daemon and the wall's `docker`
command keep their environment.

**The order.** Several sources may set one name. For each name the run takes the value
of the highest source that sets it:

| Source, highest first | What it is | In the launch spec, Go |
|---|---|---|
| `fixed` | Forager's names, `QORY_RUN_ID`, `QORY_RUN_SOCKET` and `QORY_HARNESS_HOME`; the proxy's (§Sequence step 5); the names the wall sets (§The wall); the runtime's preparation (§The runtime); the placeholders (§Credentials, §Tools); and the values the harness computes itself | `Spec.HarnessHome`, `Spec.LaunchFixed` |
| `apiary` | the server's: the run configuration's `variables` | |
| `run` | the run's variables, `qory run --env` | `Spec.Variables.Run` |
| `machine` | the machine's variables, the `wall.env` of `forager.yaml` | `Spec.Variables.Machine` |
| `harness` | the harness's written defaults | `Spec.LaunchDefaults` |
| `shell` | the environment the run inherits | `Spec.Env` |

The server resolves its variables among its levels, a lock included, and sends the
resolved values alone, a name and a value each; Forager reads no level. So the server's
value of a name wins over the node's whenever the run applies it, and a node source
applies to the names the server leaves alone and to a name whose server value is left
out. Among the fixed names, Forager's, the proxy's, the wall's, the preparation's and
the placeholders win over the harness's computed values. Names are compared exactly
between sources; the deny list matches regardless of case. A value that loses is left
out, the record lists it with its source and the reason (§The record of the variables),
and the run starts.

**Refusals first.** Before it resolves anything, the session checks every value the node
passes: what the run inherits, the harness's computed values and defaults, and the run's
and the machine's variables. They keep the node's secrets and the stand-ins out of the
enclosure. A walled run that passes a `QORY_` variable, or a variable a value of the
machine's is read from, into the enclosure is no run, `variable_reserved`; `QORY_RUN_ID`
and `QORY_RUN_SOCKET` are exempt. So `--env QORY_X` or `wall.env: [QORY_X]` behind a wall
stops the run. A run that passes a value for a placeholder is no run,
`placeholder_conflict`, with or without a wall. Without a wall, a value of a placeholder
the run inherits is not passed: the placeholder wins over it. Without a wall, the
variables the machine's credentials are read from, the run answer's `reserved`, are
left out of what the run inherits. These are the only refusals before
the variables are resolved; after, a run without a model key is
`model_key_missing` (A model key, below). The server's values are never refused; its `QORY_` names are left out by
the deny list, apart from two (below). `QORY_HARNESS_HOME` is one of Forager's names
when the launch spec has a harness home, and the session sets it after the check. Behind a wall, a value any node
source passes for it is `variable_reserved`, as any `QORY_` name is. Without a wall, the
deny list leaves out a value of the server, the run, the machine or the harness for it,
and Forager's value wins over the one the run inherits: the record lists that one as
`shell`, lost as `fixed`, when another source set the name too.

**Denied names.** The deny list leaves out a value of the server, the run, the machine
or the harness's defaults whose name it matches: the built-in list
`denied-variables.json`, the run's runtime's `denies` (§The descriptor), and the names
the node's owner adds in the launch spec, `Spec.Variables.Deny` in Go, such as `[NAME,
PREFIX_*]`. The built-in entries apply to the harness's computed values as well, so a
computed `DOCKER_HOST` or `NODE_EXTRA_CA_CERTS` is left out too; the runtime's `denies`
and the node's entries leave them in, since the harness computes such values for the
runtime. Behind a wall, the names in the runtime's model `overrides` (§The descriptor)
are entries of the deny list too, and they leave out the harness's computed value of
such a name as well; without a wall they leave nothing out. What the run inherits is
matched against no entry: it is the developer's environment. A denied value is left
out, recorded as `denied`, and the next source's
value of the name applies. Where the endpoint rule applies, the runtime's `denies` leave
out no value of the variable of the runtime's model `endpoint`: the endpoint rule
decides (The model endpoint, below). Each built-in entry undermines the wall, the proxy or
Forager. An entry is a name or a pattern, `^[A-Za-z0-9_*]{1,128}$` with at least one
character other than `*`. It matches a whole name: `*` matches any run of characters,
the empty run included, anywhere in the entry. Matching ignores case, because programs
read `http_proxy` and `HTTP_PROXY` alike. `denied-variables.json`, `{"version": 1,
"names": [...], "patterns": [...]}`, is the built-in list for every source the deny list
covers, the harness's computed values included. It holds every row of the table but the
rows that depend on the node and the run: the names the wall sets for the run's bundle,
and the runtime's `denies` and `overrides`, which `runtimes.json` lists.

| Name | Why |
|---|---|
| `QORY_*`, apart from the server's values of `QORY_RUN_SYSTEM` and `QORY_RUN_REPOSITORIES` | Forager's names |
| `*_PROXY`, `NO_PROXY` included, in any case | the session sets the proxy variables (§Sequence step 5), and any other routes around the proxy |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE`, `GIT_SSL_CAINFO` | the wall points them at the run's bundle (§The wall), and another value would replace it |
| `SSL_CERT_DIR`, `GIT_SSL_CAPATH` | they point the same programs at another store beside the bundle the wall sets |
| every name the wall sets for the run's bundle | the node's names for the run's bundle |
| `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY` | they choose the daemon the agent's Docker client reaches under nested Docker (a Docker daemon inside the wall, separate from the machine's), and how |
| `DOCKER_CONFIG` | the wall sets it for nested Docker |
| `PATH` | the enclosure resolves the launch's program through it, and which program runs is the node's choice (§Images) |
| `NODE_OPTIONS`, `LD_PRELOAD`, `BASH_ENV` | they load code into node, into any dynamically linked program, or into bash before the launch's program starts |
| `HOME` | the image sets it to a writable place (§Images), and the agent and its tools read their configuration under it |
| the run's runtime's `denies` | they move the runtime's model credential or run its commands (§The descriptor) |
| behind a wall, the run's runtime's model `overrides` | they would override the model id or effort value a composer writes (§The descriptor) |

**The model endpoint.** Behind a wall, and without one for a run whose answer has
`credential_hosts`, the endpoint rule decides whether a value of the
variable of the runtime's model `endpoint` (§The descriptor), `ANTHROPIC_BASE_URL` for
Claude Code, applies. It checks each value of the server, the run, the machine, the
harness's defaults and the harness's computed values, after the other entries of the
deny list, and the other rules for the server's values (Also left out, below), that
apply to that source; it checks no value the run inherits. A model
credential is a credential of the run answer's `credential_hosts` whose `placeholders`,
with the variable the session chooses from its `key_variables` (§Credentials, The
variable of a model key), include a variable the runtime declares or reserves. A value applies only when
`policy.EndpointHost` reads a host from it, which needs an `https` URL without user
information, and that host is a host of a model credential by the rule the gateway's
proxy picks a request's credential by, `policy.CredentialFor`. When such a value
applies, the name's entry in the record, if the record lists the name, has `kept`
(The record of the variables, below). Any other value is
left out, recorded as `endpoint_unreadable` or `endpoint_uncovered`, and the next
source's value applies. When the rule leaves out one of the harness's computed values
of the name, it leaves out all of them; when it keeps all of them, the last one alone
applies. Behind a wall, an answer without `credential_hosts` has no model credential,
so every value is left out. Without a wall and without `credential_hosts` the rule does
not apply, and the deny list treats the name as any other.

**A model key.** A run whose answer has `credential_hosts`, with or without a wall, needs a model
key for its runtime when the runtime's descriptor has a `model` section and
declarations, its model keys (§The descriptor). After the variables are resolved,
the session refuses the run, `model_key_missing` with the model keys' variables, unless
one of these holds:

- A value of a model key's variable reaches the runtime: the run's, the machine's, the
  harness's, the runtime's preparation's or one the run inherits.
- A credential of `credential_hosts`, the machine's or the server's, has a model key's
  variable among its `placeholders`, the one chosen from its `key_variables` included,
  and a host
  of the runtime's model among its hosts, by `policy.CredentialFor`.

The runtime's model host is the host of the value of its endpoint variable that reaches
it, or, when none does, a host of a model key's declaration: `api.anthropic.com` for
Claude Code. A value that the endpoint rule leaves out does not reach the runtime: the
next value that reaches it counts, or, when none does, the declaration's host. When the
value that reaches it has no host `policy.EndpointHost` reads, such as an `http` URL or
one with a user name, no credential covers it, and the refusal says to set the endpoint
variable to an `https` URL, with no user name or password, whose host a model credential
covers. The refusal offers a value of a model key's variable only when the session, on
a trial with a value of that variable from the run, resolves the run's variables with no
refusal and the value is in the runtime's environment. A run whose answer has no
`credential_hosts` is not checked: its runtime may use a login the session does not see,
such as the developer's, one in a mount or one in the image. The refusal is posted on the link, as the session's
other refusals are.

**The run's system and repositories.** The server's variables may set two `QORY_`
names, `QORY_RUN_SYSTEM` and `QORY_RUN_REPOSITORIES`: the system and the repositories a
run's preparation may use (§The wall), as the server sets them. Forager reads nothing
into their values. The built-in `QORY_*` entry leaves the server's values of them in,
by these names exactly, in upper case: a name that only begins with one, such as
`QORY_RUN_SYSTEMX`, or one in lower case, is denied as any `QORY_` name. The runtime's
`denies` and the node's entries still apply to them, and an unwalled run takes them as
it takes any server variable. A value of either from any other source is held to the
rules of any `QORY_` name: `variable_reserved` behind a wall, denied without one.

**Also left out.** A value of any source below the fixed names for a fixed name is left
out and recorded as `fixed`: the fixed value applies. The server's value of a variable
the run's runtime declares or reserves, where the stand-in goes or which is unset, and of
one a value of the machine's is read from, such as a credential's `env` (§Credentials),
whose value stays outside the enclosure, is left out and recorded as `denied`. A value
the node passes for a variable the runtime declares or reserves reaches the runtime as
passed. Behind a wall, every variable the runtime declares or reserves that neither a
placeholder, a source, the runtime's preparation, Forager nor the wall sets is unset
inside the enclosure, so an image's `ENV` cannot set one, and the runtime never sees it
empty, which a program may read as set. So is every name the runtime `denies` or lists
in its model `overrides` or as its model `endpoint`, or the node's deny list removes, by
its exact name, that nothing sets: a pattern unsets none, and a name Forager, the wall or the preparation
sets keeps its value. One exception
limits this: with nested Docker, `DOCKER_CONFIG` is never unset, and a non-empty value
in the enclosure's environment, the image's included, takes the place of the wall's
docker configuration (§The wall, Nested Docker).

**Unwalled runs.** The launch spec decides whether an unwalled run receives the server's
variables, `Spec.Variables.Unwalled` in Go: `ignore`, the default, or `accept`. With
`ignore`, an unwalled run starts without them; each is recorded as `unwalled`, and the
node's sources apply. With `accept`, they apply as in a walled run, the deny list first.
The deny list protects the wall and Forager, not the developer, so `accept` opens the
developer's shell to the server. The run's variables, `qory run --env`, apply with or
without a wall.

**The record of the variables.** `dev.qory.run.policy_applied`'s `variables` lists the
run's variables by name, never a value, sorted by name: each `name`, `from`, the source
whose value the run applies, and `lost`, the values left out, the highest source first,
each with its source, `from`, and the reason, `why`: `overridden`, `denied`, `fixed`,
`unwalled`, `endpoint_uncovered`, the endpoint's host is none of the hosts of the run's
model credential, or `endpoint_unreadable`, the value is not an `https` URL with a host
Forager reads. An entry has `kept`, behind a wall, when the value that applies is one of
the model endpoint's variable whose host is a host of the run's model credential: `why`
`endpoint_covered` and the credential's name, `credential`.

```json
[{"name": "HARNESS_PROFILE", "from": "harness", "lost": []},
 {"name": "LOG_LEVEL", "from": "apiary", "lost": [{"from": "run", "why": "overridden"}]},
 {"name": "PATH", "lost": [{"from": "machine", "why": "denied"}]}]
```

- A name is listed when the server, the run, the machine or the harness's defaults set
  it, and when the built-in list or the endpoint rule leaves out a value the harness
  computed.
- A fixed name is listed only when it won over one of those sources, with `from:
  fixed`, so Forager's, the proxy's and the wall's names do not fill every record.
- A name the run inherits is listed only when one of those sources set it too, so the
  developer's whole shell does not fill the record of an unwalled run.
- A name no source's value applies to has no `from`: a value left out by the deny list
  with nothing below it, or a variable the runtime declares, which behind a wall goes in
  empty.
- The sources and the reasons are open lists: a receiver shows a word it does not know
  as it is.

The record is fixed when the run starts: every further `policy_applied` repeats it. The
launch spec's `OnVariables`, in Go, receives the same list once, before the agent
starts, so `qory` prints a line for an `--env` value that lost.

`credential_variables` lists the variables the agent gets a placeholder in, with or without a wall,
for a credential, never a value: one `{credential, name}` per credential and variable,
in the order of the run answer's `credential_hosts` and of each credential's
`placeholders`, the variable the session chooses from its `key_variables` after them
when the credential does not list it. A credential's name or a variable that contains
`qak_` or `qrk_` in any case is `(a name that contains an access key secret)` in its
place, or `(a name that contains a run key)` when it contains `qrk_` and no `qak_`, so
the record carries neither. `credential_variables` is absent when there is no entry,
and every further `dev.qory.run.policy_applied` repeats it.

```json
[{"credential": "forge", "name": "GITHUB_TOKEN"},
 {"credential": "model", "name": "ANTHROPIC_API_KEY"}]
```

**The document.** `variables` maps each name to an object with its `value`:
`{"LOG_LEVEL": {"value": "info"}}`. The object is open: Forager ignores a member beside
`value` it does not recognise; one it must honour needs a new revision.

**Limits.** At most 128 variables, each name `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, each
value a string of at most 4096 bytes of UTF-8 with no NUL, carriage return or line feed.
The schema's `maxLength` counts characters, so Forager counts the bytes beside it. A
document beyond them is `run_configuration_invalid`. The variables are fixed when the
run starts: a reload leaves them as they were. Events carry their names alone.

## The events

Every event is a [CloudEvents 1.0](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md)
event in the [JSON format](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/formats/json-format.md).
`event.schema.json` is the envelope: the published CloudEvents schema, vendored as
`cloudevents.schema.json`, plus what this contract fixes. Every type starts `dev.qory.`,
the reverse-DNS name of qory.dev, the domain that roots every identifier of the
contract, as it roots the schema URLs.

| Attribute | Value |
|---|---|
| `specversion` | `1.0` |
| `id` | a UUID, unique per event. A receiver deduplicates on it |
| `source` | `urn:qory:run:<run id>`. One run is one source, so `sequence` orders within it |
| `subject` | the run id. A receiver creates the run on the first event with an unknown subject |
| `type` | one of the types below, and nothing else. A breaking change to a type's data is a new type |
| `time` | Forager's clock, RFC 3339, UTC |
| `sequence` | the [sequence extension](https://github.com/cloudevents/spec/blob/main/cloudevents/extensions/sequence.md): the Forager-assigned order of the event within the run, a decimal zero-padded to ten digits, from `0000000001`, contiguous. A receiver orders by it, never by arrival |
| `dataschema` | `https://qory.dev/contracts/forager/v1/events/<type without dev.qory.>.schema.json`, the schema of `data` |
| `datacontenttype` | absent, which the JSON format reads as `application/json` |
| `data` | a JSON object validating against `dataschema` |

The types, one namespace. Forager's:

| Type | When | Data |
|---|---|---|
| `dev.qory.run.registered` | the server accepted the run's registration, or behind a separate gateway its attach: the gateway writes it as the first event of its record, sequence 1, before the runtime starts; in the record alone, never posted to the server, which has its values from the access key and the registration; absent when the run has no server | `workspace`, the one id discovery's `workspaces` lists, and `node_id`, discovery's; `instance_id`, the instance id the registration was signed with, as its `X-Qory-Instance-Id` contained it; `forager_version`, `events`, `contract_version`, `interval_seconds`, the registration's. Behind a separate gateway `workspace`, `node_id` and `instance_id` are the run key's, the other four the attach's, and `labels` and `about` the attach answer's, each absent when the starter's registration had none |
| `dev.qory.run.started` | the run is open: the runtime is about to start; `dev.qory.run.started` or `dev.qory.run.refused` is the first event after `dev.qory.run.registered`, heartbeats aside | `opened_by`, `forager_version`, `runtime`, `runtime_version`, `command`, `args`, `dir`, `interactive`, `host`, on a pseudo-terminal `terminal`, behind a wall `wall`, `image`, and when the machine's definition sets them `image_name`, `container_runtime` and `docker`, for an image by reference `image_fetch_ms`, and `preparation` when the run has one (§The wall); and `labels` when the caller passes any, and `about` when the caller passes one |
| `dev.qory.run.policy_applied` | right after, once; again at the sequence where a new run configuration takes effect | `mode`, `allow`, `deny`, `source`, `variables`, and with them set `url`, `digest`, `run_configuration`, `node_policy`, `harness_hosts`, `paths`, `credentials`, `tools`, `image`, `terminated` |
| `dev.qory.run.log` | one per chunk of output: on pipes one line or 4096 bytes, on a pseudo-terminal 4096 bytes or a quiet gap of 50 ms, whichever comes first | `stream`, `bytes` |
| `dev.qory.run.resized` | the pseudo-terminal was resized, at the sequence where the new size takes effect; never on pipes | `cols`, `rows` |
| `dev.qory.run.egress` | one per connection through the proxy, allowed or denied; on a terminated host one per request, and on a host a tool serves one per tool invocation | `host`, `port`, `method`, `decision`, `outcome`, `mode`, `rule`, and per request `request_id`, `status`, `request_method`, `path`, `path_rule`, `credential`, `tool` |
| `dev.qory.run.heartbeat` | every `interval_seconds` from the accepted registration until the final event, or from `dev.qory.run.started` when the run has no server; `elapsed_seconds` counts since the session's discovery of its gateway's link | `elapsed_seconds`, `interval_seconds` |
| `dev.qory.run.exited` | the run ended: the runtime exited, or the run ended without one; the result and the last event, as `dev.qory.run.refused` is the last of a refused run | `state`, `exit_code`, `signal`, `reason`, `duration_ms` |
| `dev.qory.run.refused` | the run was refused before it started; in place of `dev.qory.run.started`, the first event after `dev.qory.run.registered` where there is one, heartbeats aside, and the last. The session writes it: when a gateway refused the run request, with the code in its answer on the link, which opens no run at the gateway, recorded only in the session's record, and nothing reaches the server for it; when a gateway's `410` closed the run before the runtime started, with the `410`'s code, `session_lost`, `batch_refused`, `stopped` or `run_closed`, and `status` `410`, only in the session's record; when the session fails after the gateway's run answer and before its process starts, posted on the link too, and the gateway delivers it | `code`; for a gateway's `410` its code and `status`, `410`; for a gateway's refusal its code and, when it lists any, `names`; for a refusal of the server's its code and `status`. A code without `status` is one of the schema's list; a code of the server's, with its `status`, is kept as the server sent it, one the list does not hold yet included, and a receiver shows a code it does not know as it is |

The session's, produced by a descriptor from what the runtime reports:

| Type | When | Data |
|---|---|---|
| `dev.qory.session.started` | the runtime opened its session | `session_id`, `source`, `model`, `cwd` |
| `dev.qory.session.prompt_submitted` | a prompt reached the runtime | `session_id`, `prompt` |
| `dev.qory.session.tool_started` | the runtime is about to run a tool | `session_id`, `tool`, `tool_use_id`, `input` |
| `dev.qory.session.tool_finished` | a tool ran and returned | the same, `response`, `duration_ms` |
| `dev.qory.session.tool_failed` | a tool ran and failed | the same, `error`, `interrupted`, `duration_ms` |
| `dev.qory.session.turn_finished` | the runtime finished responding | `session_id`, `message`, `background_tasks` |
| `dev.qory.session.turn_failed` | a turn ended on an API error | `session_id`, `error`, `details`, `message` |
| `dev.qory.session.subagent_started` | a subagent was spawned | `session_id`, `agent_id`, `agent_type` |
| `dev.qory.session.subagent_finished` | a subagent finished | the same, `message`, `background_tasks` |
| `dev.qory.session.notification` | the runtime notified its user: waiting for a permission, idle | `session_id`, `kind`, `message`, `title` |
| `dev.qory.session.ended` | the runtime closed its session | `session_id`, `reason` |
| `dev.qory.session.result` | a non-interactive session printed its result | `session_id`, `outcome`, `is_error`, `turns`, `duration_ms`, `cost_usd`, `result` |

**Work in the background.** A runtime that starts a command or a subagent in the
background reports it where it reports everything else: the start is a tool call,
recorded as `dev.qory.session.tool_started` with the runtime's `input`,
`run_in_background` in Claude Code's, and as `dev.qory.session.tool_finished` with
whatever the tool returned; a subagent's start and end are the subagent events, with its
`agent_id` and `agent_type`. After that the runtime reports a list, not an event: what
is still running, each entry with the runtime's `id`, `type`, `status` and
`description`, and a shell's `command` or a subagent's `agent_type`. The descriptor
copies it as `background_tasks` onto `turn_finished` and `subagent_finished`, so a
receiver that wants a task's end takes the first list the task is missing from. Claude
Code reports no exit status and no duration for a background task, so the record has
neither; a descriptor copies what a runtime reports and computes nothing, and anything
more the runtime shows of a task is in its output stream, recorded as
`dev.qory.run.log`. What becomes of work in the background when a run ends is the
runtime's as well: it may end such work itself shortly after its last answer, wait for
it up to its ceiling, and read that ceiling from a variable. Forager adds no rule here.
Behind a wall only the variables a run lists go in, so such a variable is listed like
any other; and the run's stop signal and grace are what the runtime has to close such
work when the session stops it.

Every session event that comes from a hook may contain `agent_id` and `agent_type` when
it happened inside a subagent; `dev.qory.session.result`, read from the runtime's
output, contains neither. The schema of each type, under `events/`, defines which fields
are required and what each contains. Values are copied from the runtime unchanged:
`input` and `response` have the tool's shape, `error` is display text, and the
enumerations in `source`, `reason`, `kind`, `outcome` are the runtime's words.

**What opened the run.** `dev.qory.run.started` contains `opened_by`, `session`: a
Forager session around a runtime opened the run, and the event contains `runtime`,
`command`, `args`, `dir` and `interactive`, and the members the table lists with them.

**How a run ends.** Every `dev.qory.run.exited` contains `state`, how the run ended:
`succeeded`, the run ended well; `failed`, it ended badly; `cancelled`, it was stopped
before it said how it went. A session's runtime that exits by itself is `succeeded` on
exit status 0 and `failed` otherwise, a signal included. A run its starter ends with an
outcome has that outcome.

`reason` says why the run ended, when it ended other than by the runtime exiting by
itself, or gives the reason the run's starter gave. It is an open code: a lower-case
letter, then lower-case letters, digits and `_`, up to 64 characters,
`^[a-z][a-z0-9_]{0,63}$`. The pattern is anchored at both ends; a receiver in another
language anchors to the absolute end, such as `\z` (`\Z` in Python's `re`). Forager's
codes are reserved: `timeout`, `interrupted`, `stopped`, `session_lost`, `gateway_lost`,
`batch_refused` and `run_closed`; and so are seven old names, which Forager never
writes, kept so that records written before still validate: `quiet`,
`credential_expired`, `credential_check_unreachable`, `credential_check_invalid`,
`run_ended_at_issuer`, `issuer_unreachable` and `issuer_answer_invalid`. A
`dev.qory.run.exited` with the old `quiet` contains `quiet_seconds`, and no other does. Any other code
is the starter's, carried as given, and a receiver shows a code it does not know as it
is. A starter's reason that equals a reserved code is dropped, its outcome kept: the run
has no reason, but for a `cancelled` run, whose reason is then `stopped`, as when its
starter gave none (§The gateway's link, The end member). The session writes `timeout` and `interrupted`, the resend of
a record writes `gateway_lost` (§The server), and the gateway writes the others, on a
session's run on its link. The state of each of Forager's endings:

| Ending | `state` | `reason` |
|---|---|---|
| the run's starter ended the run with an outcome | that outcome | the starter's reason, or none |
| the run's starter ended the run with no outcome | `cancelled` | `stopped` |
| the run's time limit was reached, and the session stopped the runtime | `cancelled` | `timeout` |
| the run was stopped from where it was started (a Ctrl-C) before the session observed the runtime's exit; `exit_code` and `signal` are the runtime's | `cancelled` | `interrupted` |
| the gateway heard nothing from the session for 3 × its heartbeat interval | `failed` | `session_lost` |
| the gateway was lost before the run's exit was recorded, because Forager died; written when the record is sent again, `duration_ms` to the last event recorded | `failed` | `gateway_lost` |
| the gateway refused a batch from the run's session (§The gateway's link) | `failed` | `batch_refused` |

`stopped` is written only when the starter gave no outcome. On a session's run the
session records, only in the session's record, how the gateway's `410` says the run
ended: its `state` and `reason`; a `410` without a `state`, `run_closed` among them, the
gateway's `410` to a run that had already ended there, is recorded as `failed` with its
code as the reason (§The gateway's link, The end of a run at the gateway). `run_closed`
is in no record but the session's. A session's run always contains `exit_code`: the
runtime's exit status, and `-1` with `gateway_lost` and in every `dev.qory.run.exited`
the gateway writes for it, since no exit status was recorded; the session's record of
the gateway's `410` has the runtime's exit status. Records written before may hold a
`dev.qory.run.exited` with no `exit_code`, of a run with no process.

`dev.qory.run.policy_applied` records where the policy comes from: `source` is `none`,
`config` or `fetched`; `url` is the server's run endpoint, `run.url`, that answered the
run configuration, and
`run_configuration` the server's digest of it as its header contained it, with
`fetched`, and with `config` or `none` when the run configuration has no
`security_policy`; `digest` is Forager's hex sha256 of the policy document's canonical
JSON, with `config` and `fetched`; `allow` and `deny` are the policy's two lists as
written, `deny` the hosts denied by name in either mode, and when the node's policy
narrows a server's, the lists the narrowing computes (§The policy). Behind a separate
gateway, for a policy a session's `narrowing` narrows (§The gateway's link), `source` is
the source of the policy it narrows, `config` or `fetched`, with that policy's `url` and
`run_configuration`, and `digest` is the narrowed policy's; a narrowing of no policy has
`source` `config`, the narrowing coming from the session's configuration. `node_policy`,
present when the run has both a fetched policy and a policy the command passes, contains
its `digest`, `sha256=` and the lower-case hex SHA-256 of the RFC 8785 serialisation of
that `policy.schema.json` document, and its `paths`, when it has any, so the record
shows the path rules of the server's policy and of the node's; `ceiling_paths` lists
those of each ceiling a caller put the run's policy file under with
`gateway.Policy.Under`, by host, one object per ceiling that has any, fixed for the run.
`variables` lists the run's variables by name, never a value: each with the source whose
value the run applies and the values that lost, with their sources and why (§Variables,
the record of the variables).
`dev.qory.run.egress` records what becomes of the connection in `outcome`: `connected`,
the dial succeeded; `dial_failed`, allowed and the dial failed; `refused`, the policy or
the wall's guard denied it, or a reload closed it; no address the guard refuses is
dialled. An event that is one request, a plain one or one inside a terminated
connection, contains the proxy's `request_id` for it, and `status`, the status the host
or the tool returned, when one did.

The log is an event like the others. `bytes` is base64 of the chunk as the runtime
wrote it, terminal escapes included. On pipes the runtime's standard output and standard
error are chunked apart, `stream` is `stdout` or `stderr`, and a chunk is cut at a line
break or at 4096 bytes, whichever comes first, at a byte and not at a character: a
multibyte character may straddle two chunks, and the concatenation, not a chunk, is
text. On a pseudo-terminal `stream` is `terminal` and a line break cuts nothing: a
full-screen program redraws on every keypress, and cut at line breaks its record is
thousands of chunks of a few bytes. A terminal chunk is cut at 4096 bytes or once the
runtime has written nothing for 50 ms after its last write, whichever comes first, so
one redraw is one chunk, and never inside a multibyte character, so a chunk of UTF-8
output is text by itself. A stream that never pauses is cut at 4096 bytes; what is
buffered when the runtime exits is the last chunk.

A replay lays the redraws of a full-screen program over each other, which takes the
terminal's size, so the size is in the record. On a pseudo-terminal
`dev.qory.run.started` contains `terminal`, the columns and rows the runtime starts on:
Forager's terminal's when it has one, 80 by 24 otherwise. Every change after that is one
`dev.qory.run.resized` with the new size, at the sequence where it takes effect: what
the gap has buffered is cut before it, so the chunks before it were written to a terminal
of the old size and the chunks after it to one of the new. On pipes there is no
`terminal` and no resize.

## The record files

The run directory, `<id>/` in the runs directory (§Sequence step 2); in the checkout, the
compose keeps it out of git:

- `events.jsonl`: every event of the run, one per line, in sequence order,
  `dev.qory.run.registered` included when the server accepted the run's registration.
  The record of truth; the server's is a copy, without `dev.qory.run.registered`, which
  is never posted.
- `output.log`: the raw bytes of the session's output, the concatenation of the
  `dev.qory.run.log` chunks. Both files tail.
- `settings.json`: the runtime's settings with Forager's hooks added, when hooks
  are installed.
- `undelivered/`: the batches the server has not accepted, when there are any.
- `answered`: behind a separate gateway, an empty file the gateway writes before it
  answers a run request; a gateway that starts again keeps a record that holds it, and
  the run request that comes again is `409` `run_attached`.

The gateway writes `events.jsonl`, with its `delivered.log` and `undelivered/` (§The
server, After Forager stops unexpectedly); the session writes `session.jsonl`, its
record, numbered by its sequence (§The gateway's link), and `output.log`. On one machine
they share a run directory when the gateway writes its record in the session's runs
directory. Behind a separate gateway each machine has a separate run directory. The
gateway's machine holds `events.jsonl`, `delivered.log` and `undelivered/` toward the
server. The session's machine holds `session.jsonl`, `output.log` and `settings.json`,
its mark, and its delivery state toward the gateway:

- `separate-gateway`: an empty file, the mark of a session's record behind a separate
  gateway, which the session writes as it creates `session.jsonl` and no other writer of
  a run directory writes. A run directory holds a session's record behind a separate
  gateway exactly when it holds this name as a regular file, whatever else it holds and
  wherever the directory is.

- `delivered.log`: what the gateway accepted of `session.jsonl`, a line per batch as the
  gateway's answer comes, the delivery id and the session's sequence of each event in
  it, and the one word `stopped` when an answer of the gateway's ended the run. The
  session creates it once the gateway opened the run.
- `undelivered/`: the session's batches the gateway has not accepted, when there are
  any.

The run key of a run behind a separate gateway is in no file of either directory: a
resend of the session's record takes it from its caller (§The gateway's link, Resending a
session's record).

`fixtures/run/<id>/` are such directories, recorded. Qory Apiary's CI replays them.

## The server

`server.schema.json`. The document the command passes to Forager, from the machine's
configuration: for `qory`, the `gateway.server` section of
`~/.config/qory/forager.yaml`, with the access key secret from the file descriptor
`--access-key-secret-fd <n>` names, else `QORY_ACCESS_KEY_SECRET`, else the file
`access-key-secret`. Forager is a client of the server defined here, its session a
client of its gateway's link (§The gateway's link), and of nothing else: it fetches the
server's configuration, registers each run at the run endpoint it defines and takes
from the answer the run's run configuration, the server's policy for the run, which the
node's narrows, and the run's variables, and posts its events to the URL it defines. A
server is a control plane, or a plain receiver that implements this section: discovery,
the run endpoint and the events endpoint. The run endpoint is one small endpoint even
for a server with no policy, which answers every registration `{"version": 1}`.
Configuring one makes the run fail closed on the discovery fetch and on the
registration.

```yaml
version: 1
url: https://qory.example             # https, or http to a loopback address; scheme and host[:port] only
access_key_id: ak_f1xt0re000000000    # ak_ and 16 lower-case Crockford base32 characters
apiary_public_key:                    # the pin: the server's Ed25519 keys, one or more
  - {alg: ed25519, public_key: rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc}
```

`url` is the server's origin and nothing after it: no path, no query, no fragment.
Forager finds every endpoint through the configuration document under it.

**Via.** A keyed machine or a starter behind a gateway reaches the server through that
gateway's relay. Its server document then holds `via`, `server.schema.json`:

```yaml
via:
  url: https://gateway.example:8443     # https; scheme and host[:port] only
  ca_file: /etc/qory/gateway-ca.pem     # optional: the authorities, in place of the system's roots
  certificate_sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=   # optional: the pin
```

With `via` set, Forager sends every request to the server, the enrolment, discovery, the
registration and the outcome, to `via.url`'s origin with the target, the path and the
query, unchanged, discovery's absolute `run.url` rebased on it too. The gateway forwards
each to the server's origin and passes the answer back byte for byte, so the request's
signature and the answer's are the server's, as without `via`. `url` stays the server's,
so records and texts name the real server. A `via` connection is TLS 1.3 alone, and its
chain is always checked, for `via.url`'s host name, against the system's roots, or, when
`ca_file` is set, against the authorities of that file, which replace them;
`certificate_sha256`, optional, is the SHA-256 of the gateway certificate's DER
SubjectPublicKeyInfo in standard base64 with padding, 44 characters ending in `=`, and
with it only a certificate with that public key is accepted, its chain still checked.
The trust is never relaxed there, since a relayed registration's answer carries the run
key. The gateway a request is relayed through sees that run key, so `via` names a
gateway trusted at least as much as the run's gateway. `server.Via` holds the setting,
its `Transport` the trust, and `accesskey.EnrolmentRequest.PostVia` sends an enrolment
through it.

**The access key.** The access key authenticates Forager to the server. It is one
Ed25519 key, whose secret is one line: `qak_` and the 32-byte seed in base64url without
padding, 47 characters, from the system's random source; the prefix lets secret scanners
recognise it. The secret signs every request and is never sent, and the server stores
only the public key. The server assigns the access key its id, `ak_` and 16 lower-case
Crockford base32 characters, when the key enrols (Enrolment, below). The secret lives
outside this document and outside any repository, in the machine's configuration
directory, its environment or a file descriptor; it is never in a checkout and never in
an event. Forager leaves `QORY_ACCESS_KEY_SECRET`, `QORY_ACCESS_KEY_ID` and
`QORY_APIARY_PUBLIC_KEY` out of the environment of every program it starts: the
session, the tools, the credential adapters and the wall's `docker` commands, the one
that starts the agent's container included. The fixtures sign with the published fixture access key of
`fixtures/known-answers/keys.json`, under the id `ak_f1xt0re000000000`. `qory` refuses
its secret, and the fixture signing keys as a pin; a server refuses its public key at
enrolment, and the fixture signing keys as the server's key. A second fixture access
key, the seed being bytes 193 to 224, whose public key is
`dSnEVtk40rj-kPpsz5FtNGdwpkvLt7UyO2h6zeIM0Aw`, has its secret published in the
`accesskey` package's tests and in this repository's history, and every side refuses it
as it refuses the fixture access key. A fingerprint, of an access key's public key or
of the server's, is `base64url(SHA-256(raw public key)[:16])`, 22 characters. The
`accesskey` package decodes every base64url value it reads strictly: an access key
secret's seed, a public key, a fingerprint in an enrolment code, a signature and a
proof. A value with padding, a character of the standard alphabet (`+` or `/`), a line
break, non-zero bits after its last full byte, or the wrong length is refused.

**Nodes and instances.** An access key belongs to a node, `nd_`, a permanent machine
that runs one instance at a time, or to a node pool, `np_`, whose instances share the
access key, up to a limit the pool may set; each id is followed by 16 lower-case
Crockford base32 characters. A node or node pool belongs to one workspace, `ws_`
followed by 16 lower-case Crockford base32 characters, `^ws_[0-9a-hjkmnp-tv-z]{16}$`:
Qory Apiary's public id of the workspace, which is not the directory a run works in.
An instance is one running copy of `qory` with the access
key. Its instance id, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, is a signed line of every
request, for display, audit, per-instance events and the instance limit; authorisation
rests on the access key alone, and whoever holds the access key can claim any instance
id. `qory` generates `i_` and 16 bytes from the system's random source in lower-case
Crockford base32, 26 characters, and keeps the id in the file `instance-id`. It writes
two lines, each ended by a line feed: the id, and the lower-case hex HMAC-SHA256, keyed with `qory
instance-id v1`, of the machine's identity, `/etc/machine-id` on Linux, `IOPlatformUUID`
on macOS, else the host name, as machine-id(5) recommends, without the white space
around it. It reads the two lines with or without the final line feed. A file that is
not exactly two lines, whose first line is outside the pattern or contains an access
key secret, or whose second line is not this machine's hash, yields a new id, so a file
copied to another machine yields a new id there. The instance's
display name, the host name by default, is sent unsigned and serves display alone. A
registration from a new instance id beyond its node's limit is a signed `409`
`instance_limit`, and that run does not start; an instance counts while one of its runs
is live. For the server, a run is live from its accepted registration until its final
event, `dev.qory.run.exited`, or until it has no recent heartbeat: none within 3 × the
`interval_seconds` its registration announced. A heartbeat is as recent as its `time`,
corrected by the run's clock offset (the smallest arrival time less `time` over the
run's heartbeats), plus a tolerance of 300 seconds, and never more recent than its
arrival. So a backlog delivered late keeps no run live, and a clock that runs ahead
holds nothing live. A run behind a gateway counts from its attach (The attach, below):
its liveness follows the attach's `interval_seconds`, and before the attach the run is
lost at its run key's `attach_by`. The gateway's link judges a session by arrival alone (§The
gateway's link, Heartbeats and liveness): there, "the session lives" is not the
server's "live".

**The pin.** `apiary_public_key` lists the server's Ed25519 public keys, a list so the
server's key can rotate. Every answer of the server, to discovery, to the registration,
to a reload and to every delivery, is verified under the pin before its body or its
headers are read, and Forager takes keys from its pin alone. `qory` takes the pin
from `QORY_APIARY_PUBLIC_KEY`, the same list written as JSON, when the section has none,
and refuses to start when both are set; it takes `access_key_id` from
`QORY_ACCESS_KEY_ID` the same way. A run with a server and no pin is no run,
`apiary_public_key_missing`, decided before the first request.

**On every request** to the server:

| Header | Value |
|---|---|
| `User-Agent` | `qory-forager/<version>` |
| `X-Qory-Access-Key-Id` | the access key id |
| `X-Qory-Instance-Id` | the instance id |
| `X-Qory-Instance-Name` | the instance's display name, unsigned, for display alone |
| `X-Qory-Contract-Version` | the revision of this contract Forager implements, `1` |
| `X-Qory-Signature-Ed25519` | the Ed25519 signature of the request string under the access key secret, 64 bytes in base64url without padding |

**The request string** is lines joined by `\n`, with no newline after the last. It
starts with three lines: `qory-request-ed25519-v1`, the access key id and the instance
id, exactly as the headers contain them, an absent instance id as an empty line. Then:

- for a GET, the method in upper case; the request target exactly as sent, the path and
  then `?` and the query only when the query is non-empty, nothing decoded, reordered
  or normalised on either side; and the timestamp as sent in `X-Qory-Timestamp`, Unix
  seconds, UTC, a decimal integer. The server accepts the request when `|server now -
  timestamp| <= 300` seconds, in either direction.
- for a POST, `POST`; the request target exactly as sent; then the raw request body. A
  POST's signature covers its path and its body, so a body signed for one endpoint fails
  at every other. No timestamp line is signed on a POST: a replayed batch is a duplicate
  the receiver already discards by event id, and a registration, an attach and an
  outcome carry their `time` in the signed body, which the server holds to the same
  window as a GET's timestamp.

The signature covers the access key id, the instance id, and the method, the target and
the timestamp of a GET, or the method, the target and the body of a POST.
`User-Agent`, `Content-Type`, `X-Qory-Contract-Version`, `X-Qory-Instance-Name`,
`X-Qory-Delivery` and `X-Qory-Run-Configuration` are unsigned: the server takes every
authorisation decision from the signed lines and the body. Three known answers, under
the fixture access key secret and the instance id `i_gYKDhIWGh4iJiouMjY6PkA`, line by
line in `fixtures/known-answers/signatures.json`:

- the 115-byte message
  `qory-request-ed25519-v1\nak_f1xt0re000000000\ni_gYKDhIWGh4iJiouMjY6PkA\nGET\n/.well-known/qory-configuration\n1700000000`:
  `H9XeK0R-KWGvQNITRP01Fh9_62ATGKd7rTgehaIPjcYYM374LrKzswcmQRYO0m-2UHx6NJJxWT3rk0HL4sD_CQ`;
- the same with the target `/.well-known/qory-configuration?x=1`, 119 bytes:
  `XNhwjf5F3CaZENTcEE2J8U1eCk4dh0y0IdZdSMf6rJqdTZMN8lNq1a98GGIPiiVn3Mh0EPGEDFzRI12zMDMRBQ`;
- the registration of `fixtures/signed/register-valid.json`: `POST`, the target
  `/v1/runs` and, as the last line, the 274-byte body of
  `fixtures/known-answers/registration.json`, 357 bytes:
  `6IKFHBaK2bZgvqTdylVxM_G2Nueq2crrZ4PjVSE7LQ3MdkJt06YgxcIWBE9mEEwnThWwvMGKC130M1JhPJIqCQ`.

**A signed POST** is a batch, a run's registration, its attach, its outcome or a secrets
request. A batch, after [GitHub's model](https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers):
one `POST` per batch to the events URL, with the headers above and:

| Header | Value |
|---|---|
| `Content-Type` | `application/cloudevents-batch+json` |
| `X-Qory-Delivery` | a UUID per batch. A retry of the same batch contains the same id, and an id is never used for other events: a batch cut again, after a restart or a resend, has a new id |
| `X-Qory-Run-Configuration` | the server's digest of the run configuration the run uses, `sha256=<hex>`, as the registration's answer or the last reload carried it; absent otherwise |

A run's registration is one `POST` to `run.url`, with the headers above and
`Content-Type: application/json`, and neither `X-Qory-Delivery` nor `X-Qory-Timestamp`;
its body is a `run-registration.schema.json` document (The run endpoint, below).

**A signed GET**, for the configuration document and the reload of a run's
configuration by its id, contains `X-Qory-Timestamp` beside the headers above.

**Signed answers.** Every answer to a request that verified contains
`X-Qory-Signature-Ed25519`, the Ed25519 signature under the server's signing key, 64
bytes in base64url, of six lines joined by `\n`, with no newline after the last:

1. `qory-answer-ed25519-v1`, or for an answer to an enrolment
   `qory-enrol-answer-ed25519-v1`;
2. the status, three decimal digits;
3. the request's `X-Qory-Signature-Ed25519` exactly as sent, or for an enrolment the
   request's `proof`;
4. the lower-case hex SHA-256 of the body as the server produced it, before any content
   coding, which for an empty body is the SHA-256 of the empty string;
5. the answer's `X-Qory-Configuration`, or empty when the answer has none;
6. the answer's `X-Qory-Run-Configuration`, or empty when the answer has none.

The server signs every answer to a verified request, `202`, `404` and `503` included,
and every signed answer contains `Cache-Control: no-store, no-transform`. Every `401`
goes out unsigned, wherever it falls, and so does a `400`, `413` or `415` sent before
verification, and at enrolment every answer before the code is accepted, the key passes
the checks and the proof verifies under it. Line 3 binds the answer to its request, and
through the request's signature to the access key and the instance that sent it. An
enrolment answer has a separate domain line because its line 3 is a proof, which anyone
holding a live code chooses: its signature never verifies as the answer to a signed
request, nor the reverse. At run start Forager treats an answer without a valid
signature under the pin as no run, `answer_unsigned`; during the run a delivery's answer
without one is no answer, retried as any other with its headers unread, and a reload's
fetch without one fails the reload. Forager reads a body's code only from a signed
answer, and a refusal body over 64 KiB counts as unsigned. Three known answers under the
fixture signing key: to the GET of discovery above, `200` with the 290-byte body of
`fixtures/known-answers/discovery.json` and `X-Qory-Configuration: sha256=` and the hex
SHA-256 of that body, six lines of 251 bytes,
`bnG9MvDyG-EDbwP8bLCok0827-GbNkqD-8DPzVX4gCPOSndLhgknc7S6BIdZhGYlafju5Bmfo4R37UGQnHOECQ`,
and `404` with an empty body and no digest, 180 bytes,
`wtXEpqIYCRAH0I9P0wd1DxJxkury0OE566ADTu3bH2GWUP4-TAkNl3a5oKGP6ZVWsP8oPL-yJHuaOaxbNPU_Dg`;
and to the registration above, `200` with the 97-byte body of
`fixtures/known-answers/registration-answer.json`, no `X-Qory-Configuration` and
`X-Qory-Run-Configuration: sha256=` and the hex SHA-256 of that body, six lines of 251
bytes, `dH803Liu9KVYDlxZ12OQDx8JyZh4JRXRoKJY8yzNgO9wLRQSYm6zZbOvSjL2o9TT5wOubS7MF0Z6JZrjsmLxDg`.

**Coded refusals.** After verification, a `400`, `409`, `410`, `429` or `503` is
`application/json`, signed, with the body `{"error": "<code>", "names": ["…"]}`. The
order of refusals on discovery, the run endpoint and the events endpoint: `413`; `415`,
for a registration any type but `application/json` and for a batch any type but
`application/cloudevents-batch+json`; `400` `bad_request` for a header sent twice, of
`X-Qory-Access-Key-Id`, `X-Qory-Instance-Id`, `X-Qory-Signature-Ed25519` and
`X-Qory-Timestamp`, unsigned; `401`; `429`; `400` `bad_request` for an instance id
absent or outside its pattern, signed; `400` `unsupported_contract_version`; `400`
`invalid_request` for a body the contract refuses, a registration with
`interval_seconds` above 300 or a label value over 256 bytes, and a batch whose events
are not all of one run, included; `401` for a GET's timestamp, or a registration's
`time`, outside ±300 seconds; then each endpoint's checks. The events endpoint's checks,
in order: a signed `409` `run_id_used` comes before any other check of the run, for a
batch of a run id the server gave a dispatch, under a key that does not reach the run;
only a refusal of the key alone, which does not depend on the run, may come before it.
Until the run is handed to the node pool's job no key reaches it, since the server holds
no run for it while the dispatch is waiting, claimed, or ended before the handover. Once
the run is handed over, a key reaches it when it is the key of a node or node pool of
the run's workspace, of the gateway that attached the run, or of a gateway that serves
the run's workspace; such a key gets the checks that follow. Then, for a run the server
holds, a batch from a key outside the one node its batches are accepted from, a signed
`409` `wrong_gateway` or `wrong_node` (After the attach, below); for a run behind a
gateway, then the run's organisation and workspace, as a key of them would be: `401`
while either is out of use; then, for a run behind a gateway, a signed `410`
`workspace_not_served`, with no digest headers, when the gateway that attached it may no
longer serve the run's workspace, decided as at the attach; then `410` for an event of a
run the server wants nothing more of, a delivery already accepted included; then
deduplication, so a batch whose delivery id or event ids the server already accepted
gets the same `2xx` again.
The run endpoint's checks, for a registration, in order: a signed `409` `run_id_used`
comes first, before the stored answer and the limit, for a run id the server gave a
dispatch (a run the server starts itself and hands to a node pool's job), under any key;
then the same bytes under any active key of the node or node pool that registered the
run get the stored answer again, the same run key included, so a key replaced while the
run waits keeps working; `410`, signed, with any code or none: the server takes no run
here; `409` `gateway_key`, signed, for a gateway's key, which registers no run; `409`
`node_is_direct` or `node_uses_gateway`, signed, for a body whose shape does not match
the node's resolved choice (Through a gateway, below); `409` `no_default_gateway`, the
node's choice is the default and no default resolves for its workspace; `409`
`gateway_not_serving`, the named gateway may no longer serve the node's workspace; `409`
`gateway_without_key`, the resolved gateway has no active access key, so no run could
attach at it; `409` `instance_limit` for a new instance id beyond its node's limit; then
`409` `run_id_used` for a registration whose run id the server already accepted from
another node, even with the same bytes, or with other bytes: other labels or another
body; then a `409` code the server defines. A dispatched run keeps no stored
registration bytes, so the replay can never hand out its run key. The four codes of the
resolution come before the limit, so a run that can go nowhere never takes a slot. For a
reload, the server answers only for a run its node registered, under any of the node's
active keys, or, for a run behind a gateway, for the gateway node that attached it, and
anything else is `404`, so a run id cannot be probed.

**Failure.** Every authentication failure is `401` with the body
`{"error":"unauthorized"}` and nothing more, unsigned: a missing or empty
`X-Qory-Access-Key-Id` or `X-Qory-Signature-Ed25519`, an access key id of the wrong
shape, an access key the server does not recognise or has revoked, a timestamp that is
not an integer, a stale timestamp, a registration's `time` outside the window, a
signature that does not verify. The body never
indicates which, and Forager reports every `401` as `unauthorized`. The server
verifies the Ed25519 signature, cofactorless as RFC 8032 defines it, looks the access
key up only after its id's shape is checked, logs nothing about the signature header,
and records the instance id and name as display data. A redirect is not followed: a 3xx
is a status like any other.

**Enrolment.** A new access key gets its id by enrolment, `enrolment.schema.json`: a
`POST` to `<url>/.well-known/qory-enrolment`, beside discovery's path, with an enrolment
code an owner or administrator of the server created: a prefix, 26 Crockford base32
characters, then `.` and the fingerprint of the server's key, and during a rotation of
that key a second `.` and the next key's fingerprint. The prefix names the kind of key
the code enrols: `qecn_` a node's, `qecp_` a node pool's, `qecg_` a gateway's and
`qeci_` an integration's (node_kind `adapter`). A code whose prefix names another kind
than its node's is unknown to the server, which answers it `401` as any unknown code; a
code with any other prefix is malformed, and the server refuses it as an invalid
request, `400`. The body contains the code in its normalised form, the prefix in lower
case and the 26 characters in upper case with `I` and `L` read as `1`, `O` as `0` and hyphens
removed; a name for the access key; the raw public key; a timestamp; and
`proof`, the Ed25519 signature under the new key of five lines joined by `\n`:
`qory-enrol-ed25519-v1`, the code, the public key as in the body, the name, and the
timestamp in decimal. The request contains no `X-Qory-Access-Key-Id` and no request
signature: the code and the proof authenticate it. The server answers an enrolment in
this order, unsigned until the code is accepted, the key passes the checks and the proof
verifies under it: `413`; `415`; `400` `bad_request` for a header sent twice; `429` per
source address; `400` `unsupported_contract_version`; `400` `invalid_request`, a
malformed code among them; `401` for a code it did not issue or that is used, expired
or cancelled, for a code whose prefix names another kind than its node's, for a code
whose fingerprints are not its keys', and for a timestamp outside ±300 seconds; `409`
`key_invalid` for a key the checks refuse or a `proof` that does not verify under it,
the key checked first. Then, signed: `429` `rate_limited` per code; `409` `key_invalid`
for a key already enrolled, a revoked one included; `409` `key_limit`; and `201`. The
server signs an answer only to a proof that verifies under a key the checks pass, so a
proof no key made, such as one under a key of small order, which plain Ed25519
verification accepts for any message, gets no signed answer. The `201` answer contains
the access key id, `node_id` with `node_kind`, `node` for an `nd_` id, `pool` for an
`np_` id, `gateway` for an `ng_` id and `adapter` for an `na_` id, `stored_secrets`,
true for an access key allowed stored secrets, and the server's keys,
signed as Signed answers describes under `qory-enrol-answer-ed25519-v1` with the
request's `proof` as line 3; the machine verifies it under the listed key whose
fingerprint the code carries first, checks that `node_kind` is the kind the code's
prefix names, and pins only the keys whose fingerprints the code carries. A `201` means
the access key is active: the code's use activates it. A `401`
means the code was used, has expired or was cancelled; a signed `409` `key_invalid`
refuses the key, and `key_limit` a node that already holds two keys; a signed `429`
`rate_limited` means too many attempts with the code. Each signed refusal lists
`apiary_public_key`, the same list in the same order as a `201` at that moment, and the
machine verifies it exactly as the `201`; a refusal sent unsigned lists no key, and the
machine acts on none by its status, an unsigned `409` or `429` being `answer_unsigned`.
In place of a code, an owner or administrator may make a key for an existing node or node
pool in the server's console, which receives only its public key; the key is active at
once, and the machine takes its id, secret and pin as `QORY_ACCESS_KEY_ID`,
`QORY_ACCESS_KEY_SECRET` and `QORY_APIARY_PUBLIC_KEY`. The server checks every public
key it is given: a canonical encoding, a point on the curve, not of small order, of
prime order, and y ≠ 1; `fixtures/known-answers/small-order.json` lists keys it
refuses. The known answers are `fixtures/enrolment/` and the enrolment lines of
`signatures.json`.

**The configuration document.** `configuration.schema.json`. A signed
`GET <url>/.well-known/qory-configuration`, the path after OpenID Connect discovery, per
access key. The answer is a signed `200`, `application/json`, with the header
`X-Qory-Configuration: sha256=<hex>`, the server's digest of the document: opaque to
Forager, which compares it byte for byte and never recomputes it.

```json
{"version": 1,
 "node_id": "nd_f1xt0re000000000",
 "workspaces": ["ws_f1xt0re000000000"],
 "events": {"url": "https://qory.example/v1/events", "types": ["*"]},
 "run": {"url": "https://qory.example/v1/runs"},
 "apiary_public_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
```

`version`, `node_id`, `events`, `run` and `apiary_public_key` are required, and
`workspaces` for a node's or a node pool's key. `node_id` is the id of the access key's
node, node pool or gateway, `^n[dpg]_[0-9a-hjkmnp-tv-z]{16}$`, listed for display:
`qory` prints it. Discovery has no member that names the key's kind: the `ng_` prefix
alone says the key is a gateway's. `workspaces` holds ids of the form
`^ws_[0-9a-hjkmnp-tv-z]{16}$`: for a node's or a node pool's key exactly one, the
workspace the node or node pool belongs to. A gateway's key has no `workspaces`
(`fixtures/configuration/gateway.json`), and a document of a gateway's key with
`workspaces` is refused: a gateway is connected to the nodes and node pools whose choice
resolves to it (Through a gateway, below), and takes each run's workspace from the run's
run key. A direct node's gateway records its one entry as `workspace`, and `node_id`, in
a run's `dev.qory.run.registered`. `apiary_public_key` lists the server's current key,
and during a rotation the next one, for information: Forager verifies under its pin
alone. `secrets` is optional, `{url}` with `events.url`'s grammar: present for an access
key allowed stored secrets. Forager reads it only for a run whose run configuration has
`credentials`, with or without a wall (§Credentials, From the server). Its URL is the
secrets request's endpoint (§The server, Secrets).
Discovery lists no key endpoint: keys change through enrolment alone. A `401` is no run,
`unauthorized`. `events.url` is `https`, or `http` to a loopback address; `events.types`
is a non-empty list of full type names, or `*` for every type. `run.url` is the run
endpoint, `https`, or `http` to a loopback address, with no query, no fragment and no
trailing slash, since a reload appends a slash and the run's id to it: a run registers
there, and a reload fetches a run's configuration again there (The run endpoint, below).
A document without `run` is refused, as any document the schema refuses. A top-level member
Forager does not recognise is ignored, which is how a new revision adds a section.

**The run endpoint.** `run-registration.schema.json` and
`run-configuration.schema.json`. Before a run starts, the gateway registers it with a
signed `POST <run.url>`, `Content-Type: application/json`, whose body is a
`run-registration.schema.json` document:

```json
{"version": 1,
 "run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d",
 "labels": {"forge": "github.com", "issue": "77", "repository": "acme/shop"},
 "about": {"title": "Fix the failing build"},
 "forager_version": "0.7.0",
 "contract_version": 1,
 "interval_seconds": 30,
 "events": ["*"],
 "time": "2026-10-10T12:00:00Z"}
```

- `run_id`, required: the run's id, a UUID in the canonical lower-case form.
- `labels`: the run's labels, as `dev.qory.run.started` contains them; absent means none.
  At most 16, each key 1 to 64 of `a-z`, `0-9`, underscore, dot and dash, and each value
  at most 256 bytes of UTF-8. Each maxLength counts characters and is an upper bound of
  the byte limit: a body with a value over 256 bytes is a signed `400`
  `invalid_request`, though the schema passes it. They travel in the body, never in a
  URL. The server decides which labels identify what the run works on and returns the
  policy for that; Forager reads nothing into them, except that a separate gateway's
  selection of credentials can take a credential's argument from one.
- `about`: what the run is about (§What a run is about); absent means none. It is for
  display: it never selects or changes a security policy.
- `forager_version`, `contract_version`, `interval_seconds` and `events`, required: the
  Forager module version, the revision of this contract Forager implements, the
  heartbeat interval the run uses, from 1 to 300 seconds, and the event types the server
  receives, as its configuration lists them.
- `time`, required: when the gateway built the body, RFC 3339 in UTC with whole seconds.
  The server refuses a `time` more than 300 seconds from its clock, either way, with an
  unsigned `401`, as it refuses a GET's timestamp; the signature covers it with the body.

A member the schema does not define is refused, `invalid_request`. The gateway builds
the body once and sends the same bytes on every try, `time` included, so a server that
accepted them under the same access key answers the same again. The answer is a signed `200`, `application/json`,
whose body is a `run-configuration.schema.json` document, with the headers
`X-Qory-Run-Configuration: sha256=<hex>` and `ETag: "sha256=<hex>"`, the same string,
quoted the second time. The answer always carries `X-Qory-Run-Configuration`,
`{"version": 1}` included, so a policy the server sets later shows as another digest,
and Forager reloads (below). `{"version": 1}` is the answer of no policy: a server with
no policy answers every registration with it.

Forager reads a registration's answer as a document, up to one mebibyte, never as a
refusal's body, and a body's code only from a signed answer:

| Status | Meaning |
|---|---|
| 200, signed | the run is registered: the body is its run configuration |
| 409, signed, such as `instance_limit`, `run_id_used`, `node_uses_gateway` or `gateway_key`, or a code the server defines | no run, with its code |
| 410, with any code or none, signed or not | no run: the server takes no run here, and the registration is not accepted |
| anything else, an answer that does not verify, or no answer within ten seconds | asked again or final as §The gateway's link, Tries as a run opens, says; in the end no run, with the code of a signed answer when it carries one |

**The reload.** When an answer's `X-Qory-Run-Configuration` differs from the one in
force, Forager fetches the run's configuration again with a signed
`GET <run.url>/<run_id>`, `run.url` followed by a slash and the run's id, with
`X-Qory-Timestamp` as every GET. The answer is a signed `200`, `application/json`, a
`run-configuration.schema.json` document with the same headers as the registration's
answer. The server answers it only for a run its node registered, or for the gateway
node that attached it, under any of that node's active keys, and anything else is
`404`. For a run behind a gateway that may no longer serve the run's workspace, decided
as at the attach, the answer is a signed `410` `workspace_not_served`, with no digest
headers, never a run configuration. A reload that fails, a `404` among them, leaves the
policy in force; a signed `410` to it stops the deliveries, as to a batch (Delivery,
below).

```json
{"version": 1,
 "security_policy": {"version": 1, "egress": {"mode": "enforce", "allow": ["api.example"]}},
 "variables": {"NODE_ENV": {"value": "test"}, "APP_REGION": {"value": "eu-west-1"}}}
```

`version` is required; `security_policy`, `variables` and `image` are optional.
`security_policy` is a `policy.schema.json` document, and it is the server's policy; the policy the
command passes, when there is one, narrows it (§The policy, a node narrows). Without
`security_policy` the policy the command passes is the run's, else observe everything,
and `dev.qory.run.policy_applied` reports `url` and `run_configuration` beside `source`
`config` or `none`; a reload that brings a `security_policy` puts it in force, narrowed
by the command's, and one that drops it puts the command's back. `variables` are the
server's variables for the run, a name and an object with its string `value` each
(§Variables). `image` is the image the run starts in, a reference pinned by digest,
`NAME@sha256:` and 64 lower-case hexadecimal digits, which the machine runs only under
one of its `images.allow` prefixes. Absent, the run's policy selects the image, as
before (§Images). A member Forager does not recognise is ignored. The digest,
`X-Qory-Run-Configuration`, is `sha256=` and the lower-case hex SHA-256 of the exact bytes
of the document as the server sends it. For an attached run, it is the digest of the
document a reload of the run answers, without `labels` and `about`, and not of the attach
answer's body (§The server, The attach). A secrets request contains this digest for the
run configuration whose `credentials` it fetches (§The server, Secrets).
Forager keeps the digest and sends it back on every POST. Forager reads
the document with a decoder that refuses a member name that appears twice and invalid
UTF-8, then its `image`, then against the schema and the limits, and its error states
where in the document and which rule refused it, never a value but the image: an
`image` that is not a reference pinned by digest is refused before the schema reads it,
`run configuration <url>: the image <image> is not a reference pinned by digest`. A
registration answered with
anything but a signed `200`, or with a document Forager refuses, is no run,
`run_configuration_invalid` for the latter. On the gateway's link a run opens with a
`POST` of the session's run request instead, and its answer is the gateway's (§The
gateway's link).

**Secrets.** `secrets-request.schema.json`, `secrets-answer.schema.json` and
`sealed-plaintext.schema.json`. The secrets request fetches the values of a run
configuration's `credentials` (§Credentials), once per run: a signed `POST <secrets.url>`,
`Content-Type: application/json`, under the access key, signed as every POST is, with the
body as the request string's last line:

```json
{"version": 1,
 "run_id": "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a",
 "run_configuration": "sha256=<64 hex digits>",
 "credentials": ["model", "forge"],
 "timestamp": 1700000000}
```

`run_configuration` is the digest of the run configuration the credentials come from,
`credentials` the names of its entries in the document's order, each once, and
`timestamp` the sender's clock in Unix seconds. A member the schema does not define is
refused, and so is a member name twice in one object; the body is at most 32 KiB. After
the shared order of refusals (§The server, Coded refusals), in which a body the schema refuses
is `400` `invalid_request` and a `timestamp` more than 300 seconds from the server's
clock, either way, is `401`, the server refuses, in order: an access key not allowed
stored secrets, with a signed `409` `secrets_not_allowed`; a digest that is not the
digest of a run configuration it answered the run with, with a signed `410`
`run_configuration_superseded`; and a `credentials` list other than that run
configuration's names, with a signed `409` code it defines. Then it seals the value it
stores for each credential of that run configuration, to the public key of the access key
the request verified under, its X25519 u-coordinate (`accesskey.PublicKey.X25519`), with
a fresh ephemeral key, and sets `exp` to its clock plus 600 seconds. The answer is a
signed `200`, `application/json`, at most 5 MiB, whose body is the envelope:

```json
{"version": 1,
 "sealed": {"suite": "x25519-sha256-aes256gcm",
            "access_key_id": "ak_f1xt0re000000000",
            "run_id": "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a",
            "run_configuration": "sha256=<64 hex digits>",
            "exp": 1700000600,
            "enc": "<32 bytes, base64url>",
            "ct": "<ciphertext and tag, base64url>",
            "sig": "<64 bytes, base64url>"}}
```

`suite` is RFC 9180's base mode with DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256
`0x0001` and AES-256-GCM `0x0002`. `enc` is the ephemeral X25519 public key, `ct` the
ciphertext followed by the 16-byte tag, and `sig` an Ed25519 signature under the server's
key, each base64url without padding, decoded strictly. `exp` is a JSON integer with no
sign, fraction or exponent. With lp(x) the length of x as a u16 big-endian followed by x,
and lp32(x) the same with a u32:

| Input | Bytes |
|---|---|
| `info` | `qory secrets v1` ‖ `0x00` ‖ `0x0020` ‖ `0x0001` ‖ `0x0002` ‖ lp(access key id) |
| `aad` | lp(run id) ‖ lp(access key id) ‖ lp(digest) ‖ lp(`exp` in canonical decimal) |
| what `sig` signs | lp32(`qory envelope v1`) ‖ lp32(`suite`) ‖ lp32(`access_key_id`) ‖ lp32(`run_id`) ‖ lp32(`run_configuration`) ‖ lp32(`exp` in canonical decimal) ‖ lp32(`enc`, raw) ‖ lp32(`ct`, raw) |

The envelope opens to the sealed plaintext:

```json
{"version": 1,
 "run_configuration": "sha256=<64 hex digits>",
 "credentials": ["forge", "model"],
 "values": [{"credential": "forge", "value": "<the value>"},
            {"credential": "model", "value": "<the value>"}]}
```

`credentials` is the request's list, sorted, and `values` has one value for each,
sorted by credential: UTF-8 text of 1 to 16384 bytes with no NUL, and, for a value set in
a header, no control character other than tab and no leading or trailing space or tab.
Whoever opens the envelope checks, in order: the answer against its schema, with a suite
other than this one refused before the signature; `sig` under the pinned
`apiary_public_key`; `access_key_id`, `run_id` and `run_configuration` against the id of
its access key, the request's run id and the digest of the run configuration whose
`credentials` it applies, as §The server, The run endpoint, defines that digest; `exp`
against its clock, refusing an `exp` more than 300 seconds past or more than 900 seconds
ahead; the open, with `info` and `aad` built from those values, never the envelope's;
and the plaintext: against its schema, with a value of more than 16384 bytes refused
there too, then a credential with two values, its digest and its credentials against the
request, their order, a value for a credential the request did not ask for, and a value
missing.
The rule for a value set in a header is checked where the value is set.
`fixtures/sealed/` contains a sealed answer to the fixture access key, signed under the
fixture signing key, with its vectors and an envelope refused at each step
(§Fixtures). This revision defines the request, its answer and the plaintext. Package
`sealed` implements both sides: `sealed.Open` makes the checks of whoever opens the
envelope, in that order, all but the rule for a value set in a header, and returns the
values as bytes it can clear; `sealed.Seal` seals and signs an answer. The gateway sends
the secrets request and calls `sealed.Open` for a run whose run configuration has
`credentials` (§Credentials, From the server); for an attached run it takes the run
configuration and its digest from a reload, whose bytes the digest is of.

**Through a gateway.** Each node or node pool records one of three choices: `direct`,
`default`, or a named gateway, `ng_` followed by 16 lower-case Crockford base32
characters. The server resolves the choice at every registration, from the access key's
record and never from the body: `direct` means the run has no gateway, and the
registration answers as above; a named gateway is that gateway, if it may still serve
the node's workspace, checked again here; `default` resolves most specific first, the
workspace's default, else its organisation's, else its operator's. A change of choice
or of default applies to new registrations only: a run already registered attaches at
the gateway its run key names. The holder's role decides the body's shape, with no
member to say so: a direct node's gateway sends the direct shape above, and a starter,
or a keyed machine's `qory` behind a gateway, sends the gateway shape of
`run-registration.schema.json`:

```json
{"version": 1,
 "run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d",
 "labels": {"repository": "acme/shop"},
 "about": {"title": "Fix the failing build"},
 "attach_seconds": 600,
 "time": "2026-10-11T12:00:00Z"}
```

- `version`, `run_id` and `time`, required, as in the direct shape.
- `labels` and `about`, optional: the server gives them back in the attach's answer, and
  they select no policy; a separate gateway's selection of credentials can take a
  credential's argument from a label (the `credentials` row of the merge).
- `attach_seconds`, optional: the attach window the run asks for. Absent means the
  server's default, 600 seconds; one above its ceiling, 3600 seconds, is clamped to the
  ceiling, and the run key's `attach_by` states the window granted; below 1, or not an
  integer, is `invalid_request`.
- `forager_version`, `contract_version`, `interval_seconds` and `events` are absent: they
  move to the attach. A body with some of them and not all, or with them and
  `attach_seconds`, is `invalid_request`.

A body whose shape does not match what the access key's choice resolves to is a signed
`409` from the server: `node_is_direct` for the gateway shape from a key whose choice is
`direct`, and `node_uses_gateway` for the direct shape from a key whose choice resolves
to a gateway, a machine whose node was moved behind a gateway while it still starts its
gateway itself, say. The pool's instance slot is taken at `instance_limit` and frees
when the run ends, or at `attach_by` if the run never attached. The answer for a run
resolved to a gateway is a signed `200`, `application/json`,
`run-registration-answer.schema.json`:

```json
{"version": 1, "run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", "run_key": "qrk_…"}
```

It carries no run configuration, so the starter never receives the run's policy, and it
has no `X-Qory-Run-Configuration` and no `ETag`: line 6 of its signature is empty, and
line 5 carries `X-Qory-Configuration` as on every answer. Forager's client builds the
body with `server.GatewayRegistration`, whose `Body` sets `time` from the clock when it
is left empty, and posts it with `Client.RegisterThroughGateway`, which takes the answer
only when its `run_id` is the registration's and its `run_key` reads as one of that run;
a refusal reads `register <run.url>: <code> (status 409)`, and no error contains the run
key.

**The run key.** One string, `qrk_`, the payload in base64url without padding, `.`, and
the signature in base64url without padding, at most 2048 characters and no white
space. The payload is the exact JSON bytes Qory Apiary signed, `run-key.schema.json`, and
nobody re-serialises them. The signature is 64 bytes of Ed25519 under Qory Apiary's
server key, over the domain line, a line feed, then the payload bytes:

```
qory-run-key-ed25519-v1\n<payload bytes>
```

| Member | Type | Meaning |
|---|---|---|
| `version` | integer, `1` | the payload's version |
| `signer` | fingerprint | the server key that signed it, as an enrolment code names keys, so the server's key can rotate inside a live run |
| `run_id` | canonical lower-case UUID | the run |
| `workspace` | `^ws_…$` | the run's workspace, from the registering node's or node pool's record |
| `node_id` | `^n[dp]_…$` | the node or node pool that registered the run; any of its active keys may give the outcome |
| `gateway` | `^ng_…$` | the gateway the node's choice resolved to at this registration |
| `gateway_url` | `https://host[:port]`, the origin alone | where the edge reaches the gateway, the only address the run key is ever sent to |
| `gateway_public_key` | 1 or 2 of `{alg: "ed25519", public_key}` | the gateway's live keys, current then next |
| `instance_id` | the instance id's pattern | the registration's signed instance id; for a dispatched run, the run's `run_id`, so each dispatched run is a new instance |
| `issued` | RFC 3339 in UTC, whole seconds | when Qory Apiary made it |
| `attach_by` | RFC 3339 in UTC, whole seconds | the end of the attach window |

Every member is required, and a member the schema does not define is refused. A gateway
and Qory Apiary verify a run key in this order: split it on the last `.` after `qrk_`;
decode both parts strictly; find the pinned server key whose fingerprint equals
`signer`; verify the signature over the domain line, a line feed and the payload bytes
under it; then read the payload against the schema. A key that is not pinned, a
signature that fails or a payload that does not read is no run key. A runner pins no
server key, so it can only parse: the prefix, two parts of base64url and a payload that
passes the schema. From the parse it takes only `run_id`, `gateway_url` and
`gateway_public_key`; the parse grants nothing, and a runner never checks `issued` or
`attach_by`, since its clock decides nothing. The `runkey` package is both readings:
`Verify` under a pin, whose `Key` reports `Verified`, and `Parse`, whose `Key` never
does; `Key.Sign` makes one under a server key. Its errors name the part that is wrong,
`its signature does not verify` say, and never contain the run key.

**The attach.** The gateway the run key names takes the run on with a signed
`POST <run.url>/<run_id>/attach`, `Content-Type: application/json`, signed by the
gateway's access key under `qory-request-ed25519-v1`, whose body is a
`run-attach.schema.json` document, every member required:

```json
{"version": 1, "run_key": "qrk_…", "interval_seconds": 30, "events": ["*"],
 "forager_version": "v0.7.0-dev", "contract_version": 1, "time": "2026-10-11T12:00:05Z"}
```

The answer is a signed `200`, `run-attach-answer.schema.json`: the run's run
configuration document, as a direct registration's answer carries it, with
`X-Qory-Run-Configuration` and `ETag`, and two members more, `labels` and `about`, as the
starter's registration gave them, each absent when the registration had none; `about` is
information alone, and a separate gateway's selection of credentials can take a
credential's argument from a label. A reload's answer stays a plain run configuration.
The attach's refusals come after the shared order above, `time` among it. The
organisation of the gateway's key is checked as every key's is, and the run's
organisation once the run key verifies, each with the same refusal. Then the attach's
checks, in order:

| # | Status | Code | When |
|---|---|---|---|
| a | `409` signed | `not_a_gateway` | the signing key is not a gateway's |
| b | `400` signed | `run_key_invalid` | the run key does not verify, or its `run_id` is not the path's |
| 1 | `200` signed | — | the same gateway node, under any of its active keys and with the same signed `X-Qory-Instance-Id`, attaching the same live run again gets the stored answer, kept by gateway node, instance id and run id, not by the bytes, while the gateway still serves the run's workspace; once it may no longer serve it, row 5 answers instead |
| 2 | `410` signed | any or none | the run has ended: its `dev.qory.run.exited` arrived, an outcome ended it, or it was lost after the attach |
| 3 | `409` signed | `run_key_expired` | past `attach_by`, never attached |
| 4 | `409` signed | `wrong_gateway` | the run key names another gateway node |
| 5 | `409` signed | `workspace_not_served` | the gateway does not serve the run's workspace, whether or not it attached the run before (row 1) |
| 6 | `409` signed | `run_attached` | another gateway node, or another instance of the same node, has attached the run |

Forager's client builds the body with `server.Attach`, whose `Body` sets `time` from the
clock when it is left empty, and posts it with `Client.Attach`, which returns the run
configuration with its digest, the labels and `about`; a refusal reads
`attach <run.url>/<run_id>: <code> (status <status>)`, and a signed `410` is no run.

**After the attach.** A run's reloads, batches and heartbeats are accepted from the
active keys of one node alone, so replacing a key keeps working: for a run behind a
gateway, the gateway node that attached it, under any of its active keys: its reloads
from the attaching instance alone, and its batches and heartbeats from it too while the
run is live; a batch from any other key, the node pool's among them, or while the run is
live from another instance of that node, is a signed `409` `wrong_gateway`; for a direct
run, the node or node pool that registered it, under any of its active keys, and a batch
from another node's key is a signed `409` `wrong_node`. For a run the server gave a
dispatch, a batch from a key that does not reach the run is a signed `409` `run_id_used`
instead (the events endpoint's checks, above). A reload from any other key is `404` in
both cases, and so is one from another instance of the gateway node. The
organisation of the gateway's key is checked at batches, heartbeats and reloads, as
every key's is; the run's organisation and workspace are checked at batches once the
sender is (the events endpoint's checks, above), with the refusal a key of them would
get. A run's workspace, node and instance come from its registration, never from the
gateway's instance id. Once the run
is not live, its `dev.qory.run.exited` accepted, its heartbeats gone quiet or the run no
longer held, a batch from any instance of the attaching gateway node, under any of its
active keys, gets the answer the attaching instance would: a resend after a restart or a
loss. Until then, an outcome alone doesn't change who may send: a batch from another
instance is still refused. After a loss, only the attaching instance's heartbeat makes
the run live again. A run that never attached is never opened. Heartbeats are
`dev.qory.run.heartbeat` events in batches, as on a direct run. Whether the gateway may
serve the run's workspace is decided again at each batch, heartbeat and reload, by the
attach's test, never by the node's current choice: a change of choice or of default
leaves an attached run where it is (Through a gateway, above), and a gateway that may no
longer serve the workspace is answered a signed `410` `workspace_not_served`.

**The outcome.** The run's starter says how the run ended with a signed
`POST <run.url>/<run_id>/outcome`, `Content-Type: application/json`, signed by any active
key of the node or node pool that registered the run, under `qory-request-ed25519-v1`,
sent directly or through a gateway's relay. Its body is a `run-outcome.schema.json`
document:

```json
{"version": 1, "state": "succeeded", "reason": "all_checks_passed", "time": "2026-10-11T12:30:00Z"}
```

- `state`, optional: `succeeded`, `failed` or `cancelled`, `dev.qory.run.exited`'s
  vocabulary. With no `state`, the outcome is `cancelled` with the reason `stopped`.
- `reason`, optional: a code, a lower-case letter, then lower-case letters, digits and
  `_`, up to 64. One that is one of Forager's reserved codes, or that is not a code, is
  dropped, and the outcome is kept.
- `time`, required, held to the same window as a registration's.

The starter's outcome sets the run's state whenever it arrives while the run's record is
kept, before or after `dev.qory.run.exited`; the exit code, the signal and Forager's
reason stay on record beside it. Each run gets one outcome: the same one repeated is
accepted, and a different one is refused. The refusals, after the shared order: the
organisation of the signing key, as every key's; the same bytes under any active key of
the registering node get the stored answer; so does the same state and reason under any
of those keys, compared after the reason rules, no `state` counting as `cancelled` with
`stopped`, whatever its `time` or bytes; a signed `404` `not_found` for a run its node did
not register, or whose record is gone; and a different state or reason is a signed `409`
`outcome_given`.
The answer is a signed `200` with `{"version": 1}`, `run-outcome-answer.schema.json`.
Forager's client posts it with `Client.PostOutcome` and a `server.Outcome`: an empty
`State` sends neither `state` nor `reason`, so the zero outcome is `cancelled` with
`stopped`; a `Reason` without a `State` is refused before anything is sent; a `Time` left
empty is the clock's now; a refusal reads `outcome <run.url>/<run_id>: <code> (status
<status>)`.

**Known answers of a run through a gateway.** `fixtures/known-answers/through-gateway.json`
holds, under the fixture keys of `keys.json`: the run key of
`run-key-payload.json`, its signed message line by line and its signature under the
fixture signing key; the registration through a gateway, `registration-gateway.json`,
signed under the fixture access key, and its `200`, `registration-gateway-answer.json`,
which carries that run key; the attach, `attach.json`, signed under the fixture gateway
key, `ak_f1xt0re00000000g`, and its `200`, `attach-answer.json`, whose
`X-Qory-Configuration` is the digest of `discovery-gateway.json`, the fixture gateway
key's discovery, and whose `X-Qory-Run-Configuration` is the digest of
`attach-run-configuration.json`, the run configuration without the labels and about, as
a reload of the run answers it; and the outcome,
`outcome.json`, signed under the fixture access key, and its `200`,
`outcome-answer.json`; each request's six lines and each answer's, with their
signatures. It holds too, for a fixed exporter value in place of the one a connection
derives, the 32 bytes counting up from 129: the binding, the three lines the gateway
signs under the fixture gateway key, the signature and the `QORY-BOUND` line; and one
answer of the gateway on its link, a `202` with no body to a batch,
`fixtures/link/link-batch.json`, posted to `/qory-link/events`, with the four lines
whose SHA-256 is its third line, its six lines under `qory-link-answer-ed25519-v1` and
its signature under the fixture gateway key. `go generate ./runkey` writes them, and the
module's tests fail while they differ, or while the session's side and the gateway's
make other bytes of them.

**Delivery.** The body of a POST is a `batch.schema.json` document: a JSON array of
events of one run, in sequence order, never empty. Forager cuts a batch at one
hundred events, at one mebibyte, or after one second since its first event, whichever
comes first. A receiver verifies the Ed25519
signature over the request string before parsing, then deduplicates on each event's
`id`, since delivery is at least once.

Forager reads a body's code only from a signed answer:

| Status | Meaning |
|---|---|
| 2xx, signed | accepted; Forager forgets the batch, and reads the body's `end` when it has one (below) |
| 410, signed, with any code or none | stop: the server requests nothing more for this run. Forager sends no further batch and the run continues on the file sink |
| anything else, an answer that does not verify, or no answer within ten seconds | retried with exponential backoff, one second doubling to one minute, until the run ends |

Every answer may contain `X-Qory-Configuration` and `X-Qory-Run-Configuration`, the
digests in force: of the configuration document, and of the run configuration for the
run. Forager compares each to the one it keeps. A different run-configuration digest
means fetch the run's configuration again by its id (The reload, above) and apply it; a
different configuration digest means fetch the configuration document again and use
its sections for the batches that follow: the events URL and the filter. A
header absent means nothing, and so does a digest of an answer that does not verify.
This is how a control plane changes a run's policy while it runs, and the whole of it:
Forager reads a body's code only from a signed answer.

**The end member.** A signed `2xx` to a batch may carry a body, `application/json`,
`batch-answer.schema.json`, covered by line 4 of its signature, the body's hash:

```json
{"end": {"state": "succeeded", "reason": "all_checks_passed"}}
```

`state` is required, and `reason` is absent when the outcome has none. An empty body, or
one without `end`, means no end. Once the server has recorded the run's starter's outcome
(The outcome, above), it sends `end` on every `2xx` for the run until the run's
`dev.qory.run.exited` arrives; the answer to the batch that carries
`dev.qory.run.exited` holds no `end`. A signed `410` still stops the run's events, and
carries no `end`. Forager's client reads `end` only from a signed `2xx`, as
`Delivery.ServerEnd` (`server.ReadEnd`), and reads the body against
`batch-answer.schema.json` first: a body the schema refuses, an `end` whose `state` is
none of the three or whose `reason` is not a code among them, is no end. The server drops
a reason that is not a code at the outcome, so a valid `end` carries a code or none. A
`reason` that is one of Forager's reserved codes is dropped, and the state kept. The
gateway ends the run with the first `end` it reads (§The gateway's link, The end
member).

**Reload**, when a fetched run configuration replaces the one in force, three rules:

1. The new policy takes effect for new connections at once, and the record gets a
   second `dev.qory.run.policy_applied`, with the new digests, at the sequence where it
   takes effect.
2. A tunnel open to a host the new policy denies is closed by the proxy and recorded as
   a denied `dev.qory.run.egress` with `outcome: refused` and the rule that denied it.
3. A host the new policy terminates TLS for is terminated on its next connection.

What is still undelivered when the run ends is spooled to the run directory's
`undelivered/` as batch files with their delivery ids, and Forager reports the count
on its standard error. The file sink has every event regardless. The server never
delays the session: posting is asynchronous behind a bounded queue, and a queue that
fills spools to the same directory rather than blocking the runtime.

**After Forager stops unexpectedly.** The run directory records what the server is
still owed, without the Forager process that wrote it. `events.jsonl` is written as events
happen. `delivered.log` beside it begins `registered <seq>`, the sequence of the run's
`dev.qory.run.registered`, once the server accepts the run's registration; then it gets a
line as each batch is accepted, the delivery id and the sequence of every event in it,
and the one word `stopped` for a signed 410.
`lock` is held by the session for as long as it lives, by the kernel, so it is free once
the session is gone however it went. Sending a run again is the job's last step, whatever
happens before it: refused while the lock is held; then what the run's wall leaves
behind is removed, by the run's label; a record that has `dev.qory.run.started` and no
`dev.qory.run.exited` gets one, numbered on from the highest sequence of the record or
of `delivered.log`, with `state: failed` and `reason: gateway_lost`, and `exit_code: -1`
on a session's run, the gateway having been lost before the run's exit was recorded; and every event the
server's filter selects, `dev.qory.run.registered` never among them,
that no accepted batch contained is posted, in order, in batches cut the same way, until
the server accepts them or Forager stops retrying. A line of `events.jsonl` that holds
no whole event, a write Forager did not finish, on a full disk, is skipped, and every
event the gateway wrote after it is read and sent, one the next write put on the same
line included: the object that ends that line, when it is one whole event from where it
starts and numbered at least two after the event before it, never an object inside the
bytes before it. When those bytes, from the line's first, are themselves exactly one
whole event, numbered between the one before and the object, a write lost its newline
alone: both are kept, and the line is not counted as skipped. A whole event numbered at
or below the one before it is skipped too, and Forager reports on its standard error how
many lines it skipped. A last line without its newline is made a line before
`dev.qory.run.exited` follows it:
one that is a whole event, its newline alone lost, gets its newline, and any other is
cut off. Nothing else of the file is changed. The gateway writes
`dev.qory.run.registered` only once the server has accepted the run's registration, so
a record that holds it, or a `delivered.log`, is of a run that opened at the server.
Sent to a server, nothing is sent of a record that holds neither, and nothing is added
to it: it is of a run that never opened at that server, its registration refused or the
run having had no server, and Forager says so on its standard error, "the run never
opened at the server; nothing is sent", or "the run had no server; nothing is sent" for a
record that holds `dev.qory.run.started`. With no server to send to, every record is
completed as any other, without a word, and one that holds no event is left as it is.
The resend fetches the
configuration document first, as a run does, posts to the URL it defines, and verifies
every answer's signature under the pin. What is still not accepted is under
`undelivered/` again. A receiver sees some events twice when Forager dies between an
answer and its line, and discards them by `id` as any duplicate. Nothing of this
recovers a machine that dies: the record is lost with it, and a receiver detects that
from heartbeats that stop.

**The modes of a run:**

| Forager receives | Events go to | The policy comes from |
|---|---|---|
| nothing | files only | the machine's policy the command passes (`egress`), else observe everything |
| a server | the server's `events.url`, after a signed discovery fetch and the run's registration | the run configuration of the registration's answer: its policy, narrowed by the node's policy, else the node's policy |
| a server and `--local` | files only; the server is not contacted | the machine's policy |

A discovery fetch that fails, in transport, with a status other than `200`, with an
answer that does not verify or with a document the schema refuses, or a registration
not accepted: no run, and the error contains the URL, the status and the code when a
signed answer contains one.
The command's `--policy`, a run's policy file under the machine's local policy, keeps
its meaning without a server. With a fetched run configuration, the policy document of
the launch spec narrows the fetched policy (§The policy).

**The reference receiver** is the public package `receiver` of this module: a plain
receiver that serves discovery, the run endpoint, its registration, its reload by id,
its attach and its outcome, the events endpoint and the secrets endpoint, accepts the
public keys listed in its configuration, each with the node, node pool or gateway it
belongs to and whether it is allowed stored secrets, and skips enrolment, verifies each
request and answers in the order this section defines, signs every answer after
verification under the receiver's key, returns the digest headers, deduplicates and
appends to a file. Its discovery lists `version`, `node_id`, `workspaces`, `events`,
`run`, `apiary_public_key` and the `secrets` its configuration lists, which it leaves
out for a key not allowed stored secrets; for a key whose node or gateway its records
hold, `node_id` is that key's and `workspaces` a node's or node pool's one workspace,
and a gateway's key gets no `workspaces`. It resolves each registration's gateway from
the records of nodes and node pools, workspaces, organisations and gateways it is given,
as Through a gateway says, at the workspace and the organisation, and at no other
organisation; a key with no node is a separate node, which reports directly. It issues
each run through a gateway its run key, signed under the receiver's key, and holds no
organisation suspended. A hook of the server that embeds it is handed the run id, the
labels, `about` and the run's placement, its node, workspace and gateway, and returns
the run's run configuration, or refuses the run with a status and a code or with no
code; `about` is for display and never selects a policy. It asks the hook at the
registration, at the attach, at each reload and at each secrets request, and computes
the digest of the bytes it serves: the hook returns an empty digest or that one, and any
other digest is a signed `500`. Without a hook it answers every run `{"version": 1}`, no
policy. A second hook returns the values of a run's credentials for a secrets request it
accepted, which it seals to the access key the request verified under and then
overwrites with zeros. It answers a secrets request, after `secrets_not_allowed`, as a
reload of the run is answered: a signed `404` to a key that may not reload the run,
`410` `workspace_not_served`, and `410` for a run it wants nothing more of. A digest
that is not the one in force, or not one it answered the run with, is a signed `410`
`run_configuration_superseded`, and a `credentials` list other than that run
configuration's names in its order is a signed `409` `credentials_differ`. A hook
decides whether an instance may start a run, the instance limit. It keeps each
registration it accepted by its run id, with what became of the run: its attach, its
heartbeats, its `dev.qory.run.exited` and its outcome. The module's tests run Forager's
client against it. `fixtures/signed/` is
what any receiver is tested against: one request per file, `method`, `target`,
`headers`, a header sent twice being a list of its values, `body` (a string, or `null`
for a GET), the status a receiver returns as `expect`, the code of a coded refusal as
`expect_code`, and a `note` that explains why. A `POST` is a batch or a registration.
Every signature in them is real, under the fixture access key secret as the fixture
access key and instance; a receiver under test holds the fixture access key under
`ak_f1xt0re000000000`, sets its clock to `1700000000`, around which the timestamps and
the registrations' `time` are, counts the fixture instance as the one live instance the
fixture access key's node allows, and replays the files in the order of their names, so
a registration that repeats another's run id, and the reload of a run, come after that
run's registration. A receiver written by anyone else follows this section, replays
those files, and may read that code.

## The gateway's link

When the session and the gateway are two processes, the session runs the agent and the
gateway holds the proxy, the policy, the credentials and the access key, and is the
node toward the server (§The server). The session is the gateway's client by the
protocol Forager speaks toward the server, on the same paths: discovery, the run
endpoint, the events endpoint and the `410` close. Two transports carry it, and
the protocol is the same on both, but for how each end knows the other, the paths, and
what a run request and its answer carry.

| | The local link | A separate gateway |
|---|---|---|
| Where | one machine; `qory` starts the session and the gateway | the gateway the run's run key names by its `gateway_url`, on a separate machine |
| Transport | a Unix socket, `sock`, in a private directory of the gateway's, `qory-link-*` in the system's temporary directory, mode `0700`, the socket mode `0600`; the directory is one of Forager's files (§The wall) | TLS 1.3 alone, on the gateway's one address, the host and port of `gateway_url` |
| The session knows the gateway | the socket's peer is the session's user, by its uid | the certificate chain, for the host name of `gateway_url`, against the system's roots; and on every connection the binding, the gateway's proof that it holds a key the run key names, and every answer signed under one (below) |
| The gateway knows the session | the socket's peer is the gateway's user, by its uid; a batch names its run in `X-Qory-Run-Id` | the run key, sent only once the connection is bound: `Authorization: Bearer` on every request, and the relay's preamble of every proxy connection |
| The run's labels | the session's | the run's registration's; the run request carries none |
| Paths | `/.well-known/qory-configuration`, `/v1/run-configuration` and `/v1/events` | under `/qory-link/`: `/qory-link/configuration`, `/qory-link/run-configuration` and `/qory-link/events` |
| Answers | unsigned | signed under the gateway's access key, a key the run key names |
| The run answer's `labels` and `proxy_secret` | present | absent |
| `narrowing` | refused | accepted |

`gateway.tls.certificate` and `gateway.tls.key` are names of `qory`'s configuration,
and `QORY_RUN_KEY` is the variable that hands a session's command the run's run key;
Forager receives their values from the command, and the session reads no variable
itself. No access key is involved on the local link. Behind a separate gateway the
gateway's access key, a gateway's, `ng_` (§The server, Discovery), signs toward the
server, and on the one address it signs the binding of every connection and every answer
of the link: its public key is among those the run key names.

**The local link.** Before it sends anything, the session checks that the socket's peer
is the session's user, by the peer's uid; the gateway serves only a peer of the
gateway's user, by the same check, and closes any other connection unanswered before it
reads anything of it. A connection carries HTTP/1.1 from its first byte: there is no
preamble and no secret of the link. The directory, mode `0700`, and the socket, mode
`0600`, keep every other user out. Every URL the link's discovery lists is
`http://localhost` and a path, and the session sends every request over the link.

The socket's peer uid is the whole of the local link's trust. A process of the same
user that reaches the socket is served as a session is: knowing a local run's id, it can
post a batch into that run, fetch the run's configuration again, or end the run: with a
batch that carries its `dev.qory.run.exited`, or with any batch of that run the link
refuses with `400` `invalid_request` once its body has arrived whole, which ends the
run `failed` with `batch_refused` (Events, below).

**In one process.** When the session and the gateway share one process, as `qory` runs
them on one machine, the session reaches the gateway's link in memory and never dials
the socket's path, where another process of the same user could listen in the
gateway's place and pass the uid check. Each connection in memory carries the same
bytes as one over the socket, HTTP/1.1 from its first byte; its peer is the process
itself. The socket serves a session in another process. `gateway.Start` with
`NoLinkSocket`, as `qory run` starts the gateway, serves no socket: the link in memory
alone, which no other process reaches.

**A separate gateway.** The session is given the run's run key, the one Qory Apiary
answered the run's registration with (§The server, The run key), and reads it as a
runner reads one, unverified: its `gateway_url` is the one address the session ever
sends the run key to, and its `gateway_public_key` the keys the gateway must prove it
holds. A run key the session cannot read is no run, and the run's error is
"QORY_RUN_KEY is not a run key: " and the part that is wrong, never the run key. The
run's id is the run key's `run_id`; a run id the command names that is another is no
run either: "the run id <run id> is not the one QORY_RUN_KEY names, <its run id>".

TLS 1.3 alone: the gateway and the session each refuse an earlier version. The gateway
serves the operator's certificate and key, `gateway.tls.certificate` and
`gateway.tls.key`. The session verifies the full chain for the host name of
`gateway_url` against the system's roots.

**The binding.** Every connection to the gateway's one address, the link's and the
proxy's, opens with the binding, before anything else. The session writes `QORY-BIND`
and a newline. Each side derives the connection's exporter value: the TLS exporter
(RFC 8446 §7.5) with the label `EXPERIMENTAL-qory-link-binding`, an empty context and 32
bytes. The gateway answers `QORY-BOUND`, a space, the fingerprint of one of its keys
(§The server, The access key), a space, its Ed25519 signature under that key in
base64url without padding, and a newline, the line at most 256 bytes. The signature
covers three lines joined by `\n`, with no newline after the last:

```
qory-link-binding-ed25519-v1
<the exporter value in lower-case hex>
<the fingerprint>
```

The session verifies it under the key of `gateway_public_key` that has that
fingerprint, and only then sends the run key: on the link, `Authorization: Bearer` and
the run key on every request, HTTP/1.1 on the same connection; on a proxy connection,
`QORY-RELAY`, a space, the run key and a newline, then the agent's traffic (Agent
traffic, below). A gateway whose answer is missing, of another form, of a fingerprint
the run key does not name, or with a signature that does not verify, is sent nothing
more, and the connection is closed; the run does not start, and its error is "the
gateway at <gateway_url> could not prove it holds a key the run key names".

**Signed answers behind a separate gateway.** The gateway signs every answer on a bound
connection, a refusal and a `410` included, under a key the run key names:
`X-Qory-Signature-Ed25519`, exactly once, the Ed25519 signature in base64url without
padding over the six lines of a signed answer toward the server (§The server, Signed
answers), with `qory-link-answer-ed25519-v1` as the domain line and, as the third line,
the lower-case hex SHA-256 of

```
<the exporter value in lower-case hex>
<the method>
<the request target as sent>
<the body of a POST, empty for a GET>
```

the lines joined by `\n`, which binds the answer to its connection and its request,
since a request of the link carries no signature. An answer with no signature, with two,
or with one under a key the run key does not name is no answer: nothing of it is
applied, and the error is "the gateway at <gateway_url> answered under a key the run key
does not name".

Every path of a separate gateway's link begins with `/qory-link/`, so none is a path the
gateway relays to the server: its discovery is `GET /qory-link/configuration`, every URL
it lists has the origin of `gateway_url` and a path under `/qory-link/`, and its
`proxy.address` is the gateway's one address. The session refuses a discovery that
lists another, and sends no request to a URL off the link. A run request behind a
separate gateway carries no `labels` and no `about`, which are the run's registration's:
the session leaves them out, and its link refuses a request with either, "the run
request: a separate gateway takes no labels or about".

The one address is `gateway.Config.Listen`, served with ALPN `http/1.1`. It routes every
connection by its first bytes after the TLS handshake: a connection that opens with
`QORY-BIND` is an edge's, the session's or its forwarder's, and any other is the relay's
(The relay of the server's endpoints, below). The gateway answers the binding under its
access key, reads the edge's next line within the ten seconds of a preamble, each line
at most 8 KiB, and closes a connection that sends neither in time unanswered. Until a
connection's run key is admitted, on its first request of the link answered for its
live run (a run request, a reload or a batch answered `2xx`) or in its relay preamble
of a live run, it counts against three bounds: at most 4096 such connections at once, 64 of
one source, an IPv4 address or an IPv6 /64, and 256 of one IPv6 /48. One more closes the
oldest such connection whose run key has not verified, of its source when that is full,
else of its /48, else of all, and is taken; when none can be closed, it is closed as it
is accepted, unanswered. An admitted connection counts against none of them. On a bound connection a
request of the link arrives whole, its body included, within 60 seconds, and its
request line and fields within 16 KiB, the 4 KiB net/http allows past that aside: a
longer head is net/http's `431`, unsigned. The run request is
`POST /qory-link/run-configuration`, a reload
`GET /qory-link/run-configuration/<run_id>` and a batch `POST /qory-link/events`; the
discovery lists them on the origin the request names in its `Host`, the address the
edge reached, with that same `host:port` as `proxy.address`, and the gateway answers a
run request with `labels` or `about` `400` `invalid_request`.

**The run key on the one address.** Every request of the link there carries one
`Authorization: Bearer <run key>`, the run key of its run (§The server, Through a
gateway), and the gateway decides it first, before it reads the request's body, in
this order, from `gateway`:

| # | Status | Code | When |
|---|---|---|---|
| 1 | `400` | `run_key_invalid` | no single `Authorization` of the Bearer scheme, or a value that is not a run key that verifies under the server's pin |
| 2 | `409` | `run_key_expired` | past its `attach_by` plus a skew of 300 seconds, by the gateway's clock, for a run the gateway holds nothing of: not open, not opening, not kept after its end and not recorded; within the skew the request goes on as before `attach_by`, and the server decides the attach |
| 3 | `409` | `wrong_gateway` | the run key's `gateway` is not the `node_id` the gateway's discovery lists |

A request refused for its run key is answered once: the gateway reads its body, which
the refusal's signature covers, up to 64 KiB within 10 seconds, answers with
`Connection: close` and closes the connection. A body declared or sent longer than
64 KiB, or one that does not come whole within those 10 seconds, closes the connection
unanswered. No request without a run key the gateway takes keeps a connection open,
`OPTIONS *` among them. An answer other than a `2xx` to a request whose run key
passes, a `409` or a `410` among them, carries `Connection: close` too, and the gateway
closes the connection after it. A request answered other than `2xx` whose body does not
come whole within 10 seconds of the answer closes the connection unanswered.

Rows 2 and 3 are in the order the server decides an attach's refusals in. The message of
`run_key_invalid` is "the gateway refused the run: run_key_invalid". Each `409` is the
gateway's refusal of the attach, decided before it asks the server, and its message is
the line the server's refusal of the attach gives:
`attach <run.url>/<run_id>: <code> (status 409)`, `run.url` the server's. A run key
that passes names the request's run: a run request for another `run_id`, or a reload of
another, is `run_key_invalid`. The gateway verifies the run key under its pin on every
request of the run and on every proxy connection, not only the first, so once the
gateway restarts with a server key out of its pin, a run whose run key that key signed
gets `400` `run_key_invalid` on its next request, and its proxy connections are closed
unanswered.

**Attach.** Behind a separate gateway the gateway opens a run by attaching it at the
server (§The server, Through a gateway), not by registering it: on the run request it
posts the attach, `server.Client.Attach`, signed under the gateway's access key, with
the run key as it came, its heartbeat interval, the event types of its discovery and its
version, with the tries of a registration (Tries as a run opens, below). The attach's
answer is the run's run configuration. A refusal of the attach reaches the session as
any refusal of the server's, its code, its status and `from: apiary`, its message
`attach <run.url>/<run_id>: <code> (status <status>)`. The gateway then writes the
record's first event, `dev.qory.run.registered`: `workspace`, `node_id` and
`instance_id` of the run key, which name the starter's registration; `forager_version`,
`events`, `contract_version` and `interval_seconds` of the attach; and `labels` and
`about` as the attach's answer gives them back, each absent when it has none. It
delivers the run's events toward the server under the gateway's access key, and fetches
a reload of the run at the run endpoint, as a direct node's gateway does. An answer
whose `X-Qory-Configuration` differs from the one in force makes it read its discovery
again and put that document in force for every run, not only the one whose answer said
so. A gateway that stopped between the attach and marking the run's record `answered`
(The record files) leaves a record that holds the run's `dev.qory.run.registered` alone:
the run request that comes again removes it, and the gateway attaches the run again,
which the server answers the same; one that stopped after it keeps the record, and the
run request that comes again is `409` `run_attached`. An attach that fails, the server's
refusal or no answer, leaves nothing of the run at the gateway: the run request that
comes again, with the same run key, asks for the attach again. A run that was open at a
gateway that stopped is over: the gateway that starts again answers its reloads and
batches `410` `run_closed` and its run request `409` `run_attached`, and
`qory run resend` writes its `dev.qory.run.exited` with `gateway_lost` (§The server).

**No local sessions.** A separate gateway serves other machines alone: with `Listen`
it makes no local link, in memory or on a socket, and no proxy listener on loopback,
and a session on the gateway's machine that dials it gets "the gateway serves other
machines on its address, and runs no sessions". `Listen` needs `TLS`, and a server whose
access key is a gateway's: the gateway refuses to start with an access key whose
`node_id` is not `ng_`.

**The relay of the server's endpoints.** A connection to the one address that does not
open with the binding is the relay's: HTTP/1.1, for a keyed machine or a starter whose
server document holds `via` (§The server, Via). The relay forwards four endpoints alone
to the origin of the gateway's server document, with the target unchanged: the path it
matched, which holds no escaped byte, and a discovery's query as it came; in origin form
when it came in absolute form. They are the enrolment,
`POST /.well-known/qory-enrolment`; discovery, `GET /.well-known/qory-configuration`; a
registration, a `POST` to the path of the `run.url` of the gateway's discovery; and an
outcome, a `POST` to that path, a slash, a run's id and `/outcome`. It drops the fields
of one connection (RFC 9110 §7.6.1), those its `Connection` names among them, and the
fields that name a source, `X-Forwarded-For`, `Forwarded` and `X-Real-IP`, asks for no
compression, and passes the server's answer back byte for byte, its status and its
fields but those of one connection, so each request's signature and each answer's stay
the server's. It relays nothing else, the attach above all, and answers none of them
itself. Its limits, each answered by the relay itself with no body, in this order:

| Status | When |
|---|---|
| `429` | more than 60 requests a minute from one source, in bursts of at most 20, or more than 240 a minute from one IPv6 /48, in bursts of at most 80. The relay follows at most 65,536 sources; a new one past that lets go of the one idle longest. Of one IPv6 /48 it follows at most 256 sources; a new one past that lets go of that /48's source idle longest. |
| `404` | a path other than the four |
| `405` | one of the four paths, its escapes decoded, with another method |
| `404` | one of the four paths with its method, but a path with an escaped byte (`%2F` and the like) or a query on a `POST` |
| `413` | a request's body over 16 KiB for the enrolment, 64 KiB for a registration or 4 KiB for an outcome |
| `503` | 64 requests with the server already |
| `502` | the server not reached, or its answer over 1 MiB |
| `504` | no answer from the server within 10 seconds |

A source is the connection's address, an IPv4 address or an IPv6 /64, never a field the
request carries. The relay lets go of a source's count once it has been idle for the 20
seconds its burst takes to come back whole. A connection of the relay reads a request
whole, its body included, within 30 seconds, and writes its answer within 30 seconds of
the request's head; a connection that misses either is closed. A request's line and
fields are within 16 KiB, the 4 KiB net/http allows past that aside: a longer head is
net/http's `431`, which counts toward no rate.

**On the wire.** A request on the link contains `User-Agent` and
`X-Qory-Contract-Version`, as toward the server, and a batch its `Content-Type` and
`X-Qory-Delivery`; there is no access key id, instance id, timestamp or signature.
Behind a separate gateway every request also carries the run key, `Authorization:
Bearer`. Answers on the local link are unsigned: the socket's peer authenticates them.
Behind a separate gateway every answer is signed under a key the run key names (Signed
answers behind a separate gateway, above). Signing under the access key stays toward
the server. A coded refusal is
a `link-refusal.schema.json` document, the body of one toward the server with `from`,
who refused, required, and `message`:
`{"error": "<code>", "names": ["…"], "message": "…", "from": "gateway"}`. `from` is
`gateway` for the gateway's refusal, and `apiary` for the server's, which the gateway
passes on with its code and status; `names` is absent when the refusal concerns none.
Every refusal on the link, the `403`, `409`, `400` and `410`, the server's passed on and
the `500` `internal`, carries `message`: the text the session gives the user as the
run's error, today's text word for word. For a refusal of the server's it names Qory
Apiary's URL, such as
`register https://apiary.example/v1/runs: instance_limit (status 409)`, the signed `409`
to the registration, whose URL is the server's `run.url`. `message` is optional in the schema, and a session that reads none uses the
code. The gateway refuses a run's start with a code of `refusal.Decides`, such as
`image_unknown`, `placeholder_conflict`, `tool_unknown` or `run_configuration_invalid`,
or with `wall_required`, each a `403` from `gateway`, and so a reload behind a separate
gateway. A run that fails to open for a reason without a code is a `500` from `gateway`
with the code `internal`: `{"error": "internal", "message": "…", "from": "gateway"}`.
`message` is up to 8192 characters and may span lines: tab and newline are its only
control characters, and every other C0 control character, DEL and every C1 control
character, U+0080 to U+009F, is refused. It holds no secret and no image reference. Every `410` on the link has this body (The end of a run at the gateway,
below). A redirect is not followed.

**Discovery.** `GET /.well-known/qory-configuration` on the local link, and
`GET /qory-link/configuration` behind a separate gateway, answered with a
`link-discovery.schema.json` document: `version`, `events`, `run` and `proxy`, each
required, `run` since a run on the link opens with its run request. `events` has `url`
and `types` as `configuration.schema.json` defines them, and `interval_seconds`,
required: the gateway's heartbeat interval, the member that carries it in the
registration toward the server. The session sends its heartbeats every `interval_seconds`. `proxy`
has `address`, `host:port`: the gateway's proxy, the one address the run's agent traffic
goes to (Agent traffic, below), on loopback on one machine, and the gateway's one
address behind a separate gateway. The discovery contains no
`node_id`, no `workspaces`, no `apiary_public_key` and no `secrets`: the node, the
workspace, the server's keys and the run's stored secrets are the gateway's, toward the
server. A member Forager does not recognise is ignored.

```json
{"version": 1,
 "events": {"url": "https://gateway.example:8443/qory-link/events", "types": ["*"], "interval_seconds": 30},
 "run": {"url": "https://gateway.example:8443/qory-link/run-configuration"},
 "proxy": {"address": "gateway.example:8443"}}
```

**Opening a run.** The session opens a run with a `POST` to `run.url`,
`Content-Type: application/json`, whose body is a `link-run-request.schema.json`
document. Toward the server the gateway then registers the run with a separate `POST`,
the labels and `about` in its body (§The server, The run endpoint); on the local link
the session opens the run with this `POST`, and it contains `about` too. Behind a
separate gateway the gateway attaches the run instead (Attach, above): the run's labels
and `about` are the starter's registration's, and the run request carries neither; the gateway refuses one with either, `400`
`invalid_request`.

```json
{"version": 1,
 "run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d",
 "wall": true,
 "labels": {"forge": "example-forge", "repository": "example-namespace/project", "run_key": "rk-0001"},
 "about": {"title": "Fix the failing build", "details": {"requester": "requester"}},
 "passes": ["HOME", "NODE_ENV", "PATH"],
 "images": {"default": "base",
            "definitions": [{"name": "base", "ref": "registry.example/agents/base@sha256:…", "runtime": "sysbox-runc"}]},
 "narrowing": {"egress": {"allow": ["api.example", "git.example"], "deny": ["tracker.example"]}}}
```

- `run_id`, required: the run's id. The session chooses it on both transports (§Sequence),
  a UUID in the canonical lower-case form.
- `wall`, required: whether the session runs the agent behind a wall.
- `labels`, on the local link alone: the run's labels, as `dev.qory.run.started`
  contains them.
- `about`, on the local link alone: what the run is about (§What a run is about). It
  selects no policy.
- `passes`: the names of the variables the run passes a value for, in what it inherits,
  what the harness sets and its variables: names alone, never a value, each in the
  grammar of a variable's name (§Variables): the session leaves out a name outside it,
  which can match no placeholder. The gateway refuses the run with
  `placeholder_conflict` when a placeholder of a credential or a tool it holds is among
  them. Absent means none.
- `images`: the session's images, which the gateway resolves the policy's selection
  against (§Images): `default`, the machine's default, the name of one of `definitions`
  or a reference; and `definitions`, the images the machine defines, each with `name`,
  `ref`, its reference, `runtime` when the definition sets one, and `docker: true` for
  nested Docker; and `allow`, the machine's `images.allow`, the prefixes of the
  references a policy may name. A reference is not secret, but it may carry a registry's credentials in
  its user information: the gateway never logs or reports one. Absent means none.
- `narrowing`, behind a separate gateway alone: the session's narrowing of the policy,
  `egress` with `allow`, `deny` or both, each in the grammar of the policy's
  `egress.allow`, and no other member. It only narrows: it can only remove what the
  policy allows. It combines with the policy the gateway holds for the run as a node's
  policy narrows a server's (§The policy): a side under `enforce` when it lists `allow`,
  so a host its `allow` does not cover is removed, and under `observe` otherwise; its
  `deny` adds to the hosts denied. A narrowing `allow` that puts an `observe` policy
  under `enforce` narrows too.

A member the schema does not define is refused, so a narrowing is never dropped
unread. Every run request opens a separate run, with a separate run id, and on the local
link a separate proxy secret. Behind a separate gateway the run key is decided before
the body is read (The run key on the one address, above), so no body is parsed for a
request without a run key that passes. The gateway then refuses a run request in this
order:

| Status | Code | When |
|---|---|---|
| `400` | `invalid_request` | a body the schema refuses: a `run_id` not in the canonical lower-case form, labels or `about` outside their rules, a member the schema does not define; and a `narrowing` on the local link |
| `400` | `run_key_invalid` | behind a separate gateway, a `run_id` that is not the run key's |
| `400` | `invalid_request` | behind a separate gateway, `labels` or `about` in the request |
| `409` | `run_attached` | behind a separate gateway, a run the gateway holds or is opening, live or ended, or holds a record of; its message `attach <run.url>/<run_id>: run_attached (status 409)` |
| `409` | `run_id_used` | on the local link, a `run_id` that already names a run at this gateway, live or ended; no names. Behind a separate gateway the gateway answers `run_attached` instead (above) |
| `403` | `wall_required` | a run without a wall whose policy selects what needs one, below; the link's code alone |
| `403` | a code of `refusal.Decides` | the gateway's decision of the run with `passes` and `images`, below: `run_configuration_invalid`, `image_unknown`, `tool_unknown`, `placeholder_conflict` and the like |

A session waits ten seconds for its run answer, as for any answer on the link. A run
request whose session gives up opens no run: once its connection goes, the gateway asks
the server nothing more for it, the registration among it, opens no run, and removes
what it recorded of the run, so the same `run_id` sent again is a new run request, not
`run_id_used` at the gateway. A registration the server accepted before then stays the
server's. The gateway keeps the bytes it built for a `run_id` for 150 seconds of their
`time`, by the wall clock, half the server's window: when the same `run_id` comes again within them,
with every member but `time` the same, its labels and `about` among them, it sends the
same bytes, `time` included, which a server that accepted them under the same access key
answers the same again. After them, or when another member differs, it builds the
registration anew, with another `time`, and the server answers `409` `run_id_used`.
A session that goes in the moment between the gateway's last look and the answer's
arrival may leave a run open, which ends `session_lost` as any run whose session sends
nothing does.

**Tries as a run opens.** The gateway tries the server's registration up to 3 times,
the second try 1 second after the first ends and the third 2 seconds
after the second, and starts a try again only within 6 seconds of the run request's
arrival, so the last answer comes inside the ten seconds the session waits. It asks
again after no answer, a transport failure or a timeout, a `5xx`, signed or not, and a
signed `429` `rate_limited`; it ignores `Retry-After`. Every other answer is final: a
`401`, any other coded refusal, `not_found` among them, a signed answer other than a
`5xx` with no code, and a document Forager refuses. The gateway builds the
registration's body once, and each try sends the same bytes, `time` included, which a
server that accepted them under the same access key answers the same again; the run's record holds
`dev.qory.run.registered` once. Once the tries are spent the last answer is the
session's, as without them: its code and status passed on from `apiary`, or a `500`
`internal`.

With `passes` and `images`, the gateway then decides the run as the session decides it
on one machine today, in the same order, and before it sets anything: the policy in
force, from the node's policy and the run configuration, `run_configuration_invalid` for
a run configuration it refuses; what needs a wall, refused without one with
`wall_required`; the run's image among `images`, `image_unknown` for a name the machine
does not define and `image_not_allowed` for a reference under none of `allow`; the
credentials it resolves, `placeholder_conflict` for a credential's
placeholder in `passes`; and the tools it chooses beside the credentials (§Tools),
`placeholder_conflict` for a tool's placeholder in `passes`. A refusal with a code of
`refusal.Decides` is a `403` with that code and its names, `from: gateway`, as the
session gives them today; a refusal of the server's passes through with its status and
`from: apiary`. The checks of the session's image table and runtime, an image defined
twice, a daemon without a runtime or an `allow` that cannot be one, have no code: the session makes them before it
sends the request, as today. A refused run opens nothing: the gateway holds no
credential, starts no tool and makes no proxy secret for it. A run that fails to open
for a reason without a code is a `500` with `error: internal` and `from: gateway`. Every
refusal carries `message`, the text the session gives the user as the run's error, word
for word as today, so the user sees the line they see today. The session applies what
the answer gives and decides none of it again.

`wall_required` is a code of the link alone: a `403` from `gateway` to a run request
whose `wall` is false and whose policy in force selects what needs a wall. Its names are
`tools` and `paths`, each one the policy selects, or `image=<name>` for an image the
policy selects. A credential needs no wall: the gateway sets it for every run. The
message for tools and path rules is `run it with a wall: the policy selects tools or has
path rules, and without a wall a program that ignores the proxy is bound by neither`.
The session turns it back into the error it gives today,
word for word, and writes no `dev.qory.run.refused` for it, as today: the code is not
one of `refusal.Decides`, not in the enum of `events/run.refused.schema.json`, and never
appears in an event.

A run request the gateway refuses opens no run at the gateway. The session records the
`dev.qory.run.refused` it received, for every code but `wall_required` and `internal`,
only in the session's record, as with the server's `410` before `dev.qory.run.started`,
and nothing reaches the server for it. A session that fails after the run answer and
before its process starts posts its `dev.qory.run.refused` on the link: the gateway
holds that run, and delivers it.

The answer is a `200`, `application/json`, whose body is a `link-run-answer.schema.json`
document:

```json
{"version": 1,
 "run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d",
 "labels": {"forge": "example-forge", "repository": "example-namespace/project", "run_key": "rk-0001"},
 "policy": {"version": 1,
            "egress": {"mode": "enforce", "allow": ["api.example", "git.example"], "deny": ["tracker.example"]}},
 "digest": "<hex sha256 of the policy as canonical JSON>",
 "variables": {"NODE_ENV": {"value": "test"}},
 "placeholders": ["GIT_SECRET"],
 "reserved": ["EXAMPLE_SOURCE_KEY"],
 "image": {"name": "base", "ref": "registry.example/agents/base@sha256:…", "runtime": "sysbox-runc"},
 "applied": {"mode": "enforce", "allow": ["api.example", "git.example"], "deny": ["tracker.example"],
             "source": "fetched", "url": "https://apiary.example/v1/run-configuration",
             "digest": "<hex sha256 of the policy as canonical JSON>", "run_configuration": "sha256=<hex>"},
 "proxy_secret": "<the run's proxy secret>",
 "certificate_authority": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"}
```

- `run_id`, required: the request's, echoed.
- `labels`, on the local link: the run's labels as the gateway holds them, the run
  request's. The session's `dev.qory.run.started` contains exactly these labels. Behind
  a separate gateway the answer has none: the run's labels are its registration's, and
  the session's `dev.qory.run.started` has none.
- `policy`: the policy in force for the run, the one the gateway holds for it narrowed by
  the request's `narrowing`, and `digest`, the hex SHA-256 of its canonical JSON, which
  `dev.qory.run.policy_applied` reports. Each is present with the other; with neither,
  the gateway observes everything.
- `variables`: the run's variables, as a run configuration contains them (§Variables).
- `placeholders`: the variables the agent sees in place of a credential or a tool's
  secret the gateway holds, names alone: the session sets each to a value that is no
  credential, as it sets a credential's placeholder (§Credentials). Absent means none.
- `reserved`: the names of the variables the machine's credentials are read from: a
  walled run that passes one is refused with `variable_reserved`, and an unwalled run has
  its value left out, as today. Absent means none.
- `credential_hosts`: the hosts and placeholders of each credential the gateway holds
  for the run, so the session can tell which hosts the run's credentials cover. One
  entry per credential, in the order the policy selects them, each closed: `name`, the
  credential's name; `hosts`, 1 or more, the credential's hosts as the proxy matches
  them, which are the hosts `applied.credentials` lists for it, in its order; and
  `placeholders`, the variables the session sets to a placeholder for this credential,
  each also in `placeholders` and each once, empty when it sets none. A credential from
  the server also has `auth`, its run configuration entry's, and `key_variables` when
  the entry has them. The variable the session chooses from them (§Credentials, The
  variable of a model key) may
  be in both `placeholders`, when the server's entry lists it; when it is not, the
  session adds it. Names and hosts alone, never a secret. Absent means none.
- `image`: the image the run gets, as a definition of `images` has it, `ref` required:
  the one the policy in force selects, or the machine's default, `name` absent when the
  default is a reference. For a reference the policy names, `ref` is that reference,
  `runtime` the default's, `name` absent and `reference: true`. Present when the
  request's `wall` is true. The session's `dev.qory.run.started` reports it (§Images).
- `relay_image`: the reference of the machine's default image, which the relay starts
  from whatever image the run gets. Present when the request's `wall` is true and the
  machine has a default image; without one the relay starts from the run's image, one
  the machine defines, since an image by reference needs a default.
- `applied`, required: the members of `dev.qory.run.policy_applied` the gateway decides
  for the policy in force, every member but `variables`, `credential_variables` and
  `harness_hosts`, each present exactly when the gateway's is, under the rules of
  `events/run.policy_applied.schema.json`. The session's `dev.qory.run.policy_applied`
  is this object with the session's `variables`, `credential_variables` and
  `harness_hosts` added (Events, below).
- `proxy_secret`, on the local link: the run's proxy secret (Agent traffic, below), 22
  to 256 characters of `A-Z`, `a-z`, `0-9`, `_` and `-`, which the relay's preamble
  carries as they are; the session refuses a run answer on the local link
  without one. Behind a separate gateway the answer has none: the run key opens the
  proxy's connections.
- `certificate_authority`: the certificate of the run's certificate authority, PEM,
  present, with or without a wall, when the gateway reads inside HTTPS for the run: for
  a credential it holds, a tool it starts or a path rule, the policy's or the node's,
  and with a server always, since a reload may bring credentials or path rules and the
  agent's tools trust only what they were given at the start. Absent otherwise. Never
  its key, which stays with the gateway.

**Events.** The session posts its events to `events.url`, in batches cut as toward the
server (§The server, Delivery), with `Content-Type: application/cloudevents-batch+json`.
The body is a `link-batch.schema.json` document: events of the run as
`event.schema.json` defines them, with their ids and without `sequence`, in the
session's order. The gateway numbers the run's stream: one `sequence` per run, from
`0000000001` and contiguous, as §The events requires. Into a session's run it merges its
`dev.qory.run.egress` and, when it ends the run, its `dev.qory.run.exited`, with the
reason it ended the run with (The end of a run at the gateway, below), or `gateway_lost`
when it sends its record again. It numbers an event once, by its id, so a batch the
session sends again is not numbered twice, and it delivers the stream to the server under
its access key. The gateway is the node toward the server, so it registers the run, or
behind a separate gateway attaches it, and writes `dev.qory.run.registered`; the session
registers nothing on the link, and a link batch holds no `dev.qory.run.registered`.
`dev.qory.run.policy_applied` is the session's: the session writes it from the run
answer's `applied`, and again from the `applied` of a reload answer whose digest
changed, at the sequence where the new configuration takes effect, adding `variables`,
`credential_variables` and `harness_hosts`, since only the session has the run's
resolved variables, the variables it chose and the harness's hosts. From the moment a reload puts a new policy in force on the run's
proxy, the gateway holds every `dev.qory.run.egress` of the run, those of the tunnels the
policy closed first, then each connection decided after, and numbers them right after
the session's `dev.qory.run.policy_applied` of that policy, so no connection under a
policy precedes its event (§The server, Reload, rule 1); a connection the gateway saw
before the switch keeps its place, and when the run ends before the session writes the
event, what is held comes right before the run's final event. The session keeps a
separate file record of its events, numbered as today (§The record files): that record
is the session's, not the run's stream. The gateway keeps the record of what it sent,
which `qory run resend` sends again through `gateway.Resend` (§The server, After Forager
stops unexpectedly). The gateway answers a batch as the server does: a `2xx` is
accepted. A batch is of the run it names, checked before its body is read: on the local
link the one value of its `X-Qory-Run-Id`, which the session sets to the run's id on
every batch, and behind a separate gateway the run of the run key it carries. On the
local link a batch with no `X-Qory-Run-Id`, with two, or with the id of no run of this
gateway's is `400` `invalid_request`, which ends no run, so no run can be probed. Behind
a separate gateway a batch of a run the gateway does not hold is a `410`, of the run's
end while the gateway keeps it, 15 minutes after its record is flushed, and `run_closed`
after, or for a run that never opened there. Once the run key's `attach_by` plus a skew
of 300 seconds has passed, by the gateway's clock, a batch of a run the gateway holds
nothing of, its record included, is `409` `run_key_expired` instead (The run key on the
one address, above). A batch whose body does not arrive whole, its client gone before
the end, is `400` `invalid_request` too, and ends no run. Any other `400`
`invalid_request` to a batch, one over the size limit or one that does not decode among
them, ends its run at the gateway: the gateway writes `dev.qory.run.exited`, `failed`
with `reason: batch_refused`, since it no longer accepts the session's stream, refuses
the run's proxy secret, or behind a separate gateway its run key on a bound connection's
`QORY-RELAY`, and answers the session's further requests with a `410` `batch_refused`
(The end of a run at the gateway, below). The session stops the runtime as after a `410`
and records `dev.qory.run.exited`, `failed` with `reason: batch_refused`, only in the
session's record. Anything else but a `2xx`, that `400` or a `410` is retried.

A session writes no event the gateway decides. The gateway
refuses a batch with a `400` `invalid_request`, and numbers nothing of it, when any of
its events:

- has a `subject` that is not the batch's run, the one its `X-Qory-Run-Id` names on the
  local link, or its run key's behind a separate gateway;
- has a type the gateway writes, `dev.qory.run.registered` or `dev.qory.run.egress`;
- is a `dev.qory.run.started` whose `opened_by` is not `session`, or whose `labels`
  differ from the run's labels as the gateway holds them, none behind a separate
  gateway;
  or is a `dev.qory.run.started` when the run already has one with another id: a run
  has at most one;
- is an event, by an id the gateway has not numbered, after the run's
  `dev.qory.run.exited` or `dev.qory.run.refused`: nothing follows either; or is a
  `dev.qory.run.refused` after the run's `dev.qory.run.started`, whose place it takes;
- is a `dev.qory.run.exited` other than the session's: one that is not `succeeded` with
  `exit_code` 0 and no `reason`, `failed` with any other exit status or a signal and no
  `reason`, or `cancelled` with `reason` `timeout` or `interrupted` and any exit status
  or signal. A session's batch carries only the session's `dev.qory.run.exited`, the
  runtime's exit, its time limit or its stop from where it was started, and the gateway
  writes the event of every other reason itself (The end of a run at the gateway,
  below);
- is a `dev.qory.run.policy_applied` that is not `applied` from an answer of this run,
  the run answer's or a reload answer's, with the session's members added: every
  member the gateway decides, `mode`, `allow`, `deny`, `source`, `url`, `digest`,
  `run_configuration`, `node_policy`, `paths`, `credentials`, `tools`, `image` and
  `terminated`, present exactly when that `applied` holds it and equal to it. Only
  `harness_hosts`, `variables`, the variables' names and their sources, and
  `credential_variables` are the session's. The gateway accepts one that matches any policy it has put in force for the
  run, so a batch in flight during a reload is not refused;
- is a `dev.qory.run.refused` whose `code` is not one the session decides itself, the
  codes of `refusal.Decides`: `run_configuration_invalid`, `tool_unknown`,
  `image_unknown`, `image_not_allowed`, `image_user_root`, `variable_reserved`,
  `placeholder_conflict`, `model_key_missing`,
  `mount_contains_forager_files`, `mount_mode_conflict`, `mount_shared_with_run`,
  `mount_through_link` and `engine_unreachable`. So a gateway's code `run_id_used`, the
  old codes `run_credential_refused`, `target_differs_from_credential` and
  `differs_from_credential`, the gateway's `run_closed` and every code of the server's
  are refused; and so is a `dev.qory.run.refused` with a name of the form
  `<member>=<value>`, a member being `labels.<key>` or `about.details.<key>`, the form
  only those old refusals carried.

`link-batch.schema.json` states what a schema can: neither type the gateway writes, an
`opened_by` of `session`, `timeout` and `interrupted` as the only ones of Forager's
reasons of a `dev.qory.run.exited`, and `cancelled` as their state, a
`dev.qory.run.refused` code among the session's, and no name of the form
`<member>=<value>`. The gateway checks the rest.

**Heartbeats and liveness.** A run has one source of heartbeats. For a session's run,
the session's `dev.qory.run.heartbeat` events on the link, every `interval_seconds` of
the link's discovery, are the run's heartbeats: the gateway numbers and forwards them
like any other event of the session's, and they are its sign that the session lives,
judged by their arrival, not by the server's rule (§The server). When the
session sends nothing for 3 × `interval_seconds`, counted from the run answer and again
from each request of the session's, the gateway ends the run with
`dev.qory.run.exited`, `reason: session_lost`, and answers the session's later requests
with a `410` `session_lost` (The end of a run at the gateway, below). When the gateway
stops, the server receives no events from it; when `qory run resend` sends the run's
record again, through `gateway.Resend`, the resend writes `dev.qory.run.exited` with
`reason: gateway_lost`.

**The end of a run at the gateway.** When the gateway ends a session's run, with
`session_lost`, `batch_refused`, `stopped` or the starter's outcome, it writes the run's
`dev.qory.run.exited` itself, with the state and the reason of that ending (§The events,
How a run ends) and `exit_code: -1`, as with `session_lost`: it holds no exit status of
the runtime's. It numbers that event into the run's stream and delivers it toward the
server. It answers the session's next request on the link, and every one after it, with
a `410`. Every `410` on the link is a `link-refusal.schema.json` document, its `from`
what ended the run, and its `message` the text the session gives the user; a `410` that
ends a run carries the `state` and the `reason` of the gateway's `dev.qory.run.exited`
of it, the reason absent when that event has none:
`{"error": "<code>", "message": "…", "from": "gateway", "state": "cancelled", "reason": "stopped"}`.
`from` is `gateway` on every `410`, since only the gateway ends a run there, and the
code says why:

| Code | From | Cause |
|---|---|---|
| `stopped` | `gateway` | the run's starter ended the run; `state` and `reason` are the starter's outcome and reason, or `cancelled` and `stopped` when it gave no outcome |
| `session_lost` | `gateway` | the session was silent for 3 × the heartbeat interval (Heartbeats and liveness, above); `failed` and `session_lost` |
| `batch_refused` | `gateway` | the gateway refused a batch from the run's session (Events, above); `failed` and `batch_refused` |
| `run_closed` | `gateway` | the run had already ended otherwise: after the session's final event, or when the gateway stops; no `state` |

**The end member.** When the server's signed `2xx` to a batch of the run carries `end`,
the outcome the run's starter gave (§The server, The end member), the gateway ends the run
with it, a direct node's gateway and a separate gateway alike: code `stopped`, from
`gateway`, and the gateway's `dev.qory.run.exited` of it has the outcome's `state` and
`reason`, and `exit_code: -1`. An `end` `cancelled` with no reason gives the reason
`stopped`, the starter ending the run with no outcome. The gateway still numbers the
run's last events and its `dev.qory.run.exited` and delivers them, and ignores any
later `end`, the first having ended the run. The session's next request is the `410`
`stopped` with that state and reason, its message "the run has ended: <state>, <words>":
the reason's words, `no outcome given` for `stopped`, and any other reason with spaces
for its underscores, "the run has ended: failed, checks failed" for `checks_failed`;
with no reason, "the run has ended: <state>", "the run has ended: succeeded".

The session stops the runtime as at its time limit, records its `dev.qory.run.exited`
with the `410`'s state and reason, and its code as the reason after a `410` without a
state, only in the session's record (§The events, How a run ends), and posts nothing
more on the link. A `410` with another code, or none, is `run_closed`.

**A session's run behind a separate gateway whose session is lost.** Such a run ends at
the gateway with `session_lost` once the gateway has heard nothing from the session for
3 × `interval_seconds` (Heartbeats and liveness, above). When the gateway
itself stops, `qory run resend` sending the run's record again, through
`gateway.Resend`, writes its `dev.qory.run.exited` with `gateway_lost` (§The server).
While the session lives, the run normally ends with its runtime exiting by itself; the
gateway can also end it, with `stopped`, or `batch_refused` after it refused a batch from
the run's session, and the session records that end (The end of a run at the gateway,
above).

**Resending a session's record.** Behind a separate gateway the session's machine holds
the session's record, `session.jsonl`, and what the gateway accepted of it,
`delivered.log` (§The record files). `session.Resend` sends the gateway every event of
that record the link takes that no accepted batch contained, in order and in batches
cut as the session cuts them, over the link as the run spoke to it, with the run's run
key, which its caller passes from `QORY_RUN_KEY`: the run key is never written to the run
directory, which a walled agent sees. A record that owes nothing is sent nothing and
needs no run key, and one with no `delivered.log` is of a run that never opened at the
gateway and is sent nothing. A record that owes something is refused, before any
request, without a run key, "resend <dir>: the run key is needed to send to its gateway;
set QORY_RUN_KEY", with a run key the resend cannot read, "QORY_RUN_KEY is not a run
key: " and the part that is wrong, and with the run key of another run, "resend <dir>:
QORY_RUN_KEY names the run <run id>, not this one". The record is never completed: the
gateway writes the end of a run whose session was lost. The gateway's `410`, after
`session_lost` or any other end, closes the resend, and the events stay in the
directory: a batch of a run the gateway no longer holds is that `410`, the run's end
while the gateway keeps it and `run_closed` after (Events, above), as long as the
gateway still has the run's record. Once the run key's `attach_by` plus a skew of 300
seconds has passed, by the gateway's clock, a batch of a run the gateway holds nothing
of, its record included, is `409` `run_key_expired` instead (The run key on the one
address, above), which stops the resend as every refusal of the run key does. A refusal of the run
key the gateway passes on, `400` `run_key_invalid`, or `409` `wrong_gateway`,
`run_key_expired` or `run_attached`, stops it with that refusal, its code, status and
message the gateway's, and what was not accepted is under `undelivered/` again; so does
a `401` `unauthorized`, which the gateway does not send, so a resend never sends again
into one. Any other refusal of a batch is sent again.

**Reload.** The run request is one-shot per `run_id`: sent again, it is `run_id_used` on
the local link, and behind a separate gateway the gateway answers `run_attached`, unless
its session gave up before the run opened (above), or, behind a separate gateway, its
attach failed, and the gateway asks for the attach again (Attach, above). A
reload is a `GET` of the run's configuration by its run id instead,
`<run.url>/<run_id>`: the path of `run.url`, a slash and the `run_id`, with no query.
The gateway's answers on the link, the run answer and the reload's among them, contain
the digest headers `X-Qory-Configuration` and `X-Qory-Run-Configuration`, unsigned on
the local link and covered by the answer's signature behind a separate gateway, and
the session follows the rule it follows toward the server (§The server, Delivery and
Reload): a different run-configuration digest means it fetches the run's configuration
again and applies it, and the same digest means the policy in force is unchanged. The
answer is a `200`, `application/json`, with `X-Qory-Run-Configuration` and `ETag`, whose
body is a `link-reload-answer.schema.json` document: `version`, the policy in force with
its `digest`, `variables`, `placeholders`, `reserved`, `image` and `applied`, required,
as the run answer has them. It never contains `proxy_secret` or `certificate_authority`, which the run answer
alone gives, once. The gateway decides a reload with the run request's `passes` and
`images`, as the session decides one today and in the same order, before it sets
anything. A run configuration it refuses fails the reload, and the policy in force
stays: one it cannot read, `run_configuration_invalid`; one that selects an image or
tools other than the run started with; a name the machine does not define,
`image_unknown`; an image or path rules, which need a wall the run does not have,
decided by the run request's `wall` as at the start; and a
credential's placeholder in `passes`, `placeholder_conflict`. On the local link the
gateway applies a reload itself, and every reload that fails, with a code or without
one, stays off the link: the gateway reports it to the user with the text the session
reports today, and the session's reload `GET` is answered with the policy in force, its
digest unchanged. Behind a separate gateway, to a refusal with a code of
`refusal.Decides` the reload's answer is a `403` with that code and its names,
`from: gateway`; a refusal of the server's passes through with its status and
`from: apiary`.

```json
{"version": 1,
 "policy": {"version": 1, "egress": {"mode": "enforce", "allow": ["api.example"]}},
 "digest": "<hex sha256 of the policy as canonical JSON>",
 "variables": {"NODE_ENV": {"value": "test"}},
 "placeholders": ["GIT_SECRET"],
 "reserved": ["EXAMPLE_SOURCE_KEY"],
 "image": {"name": "base", "ref": "registry.example/agents/base@sha256:…", "runtime": "sysbox-runc"},
 "applied": {"mode": "enforce", "allow": ["api.example"], "source": "fetched",
             "url": "https://apiary.example/v1/run-configuration",
             "digest": "<hex sha256 of the policy as canonical JSON>", "run_configuration": "sha256=<hex>"}}
```

Behind a separate gateway, the reload carries the run key, whose run the `run_id` must
be, and any other is `400` `run_key_invalid`, so no run id can be probed. On the local
link the reload names its run by its path alone, and the socket's peer, the gateway's
user, is what lets it in. A walled agent never reaches the socket; an unwalled one runs
as the session's user and can, so without a wall enforcement is cooperative
([the wall](../../../docs/wall.md)). A `run_id` of a run that has ended is a `410`, with
the code and the `from` of its end at the gateway (above) when it ended there, else
`run_closed` from `gateway`; behind a separate gateway the gateway keeps the end of a
run it let go of for 15 minutes after its record is flushed, and a run it does not hold
is `run_closed` after, unless the run key's `attach_by` plus a skew of 300 seconds has
passed, by the gateway's clock, and the gateway holds nothing of the run, its record
included, which is `409` `run_key_expired` (The run key on the one address, above); on the local link an unknown `run_id` is `400`
`invalid_request`. Toward the server
the reload names the run the same way, a signed `GET <run.url>/<run_id>` (§The server,
The run endpoint).

**Agent traffic.** On one machine the run's agent traffic goes to the gateway's proxy,
the discovery's `proxy.address` on loopback: inside a wall the relay opens every
connection with `QORY-RELAY`, a space, the run's proxy secret and a newline (§Limits),
and without a wall the session's forwarder does.
Behind a separate gateway the session's forwarder opens every connection to the
gateway's one address over TLS 1.3, with the link's trust, bound as every connection of
the link is (The binding, above), and with `QORY-RELAY`, a space, the run key and a
newline. Behind a wall the forwarder takes the relay's connection, which opens with
`QORY-RELAY` and a value the session makes for the run's forwarder alone, and takes that
line off before anything reaches the gateway. Without a wall, on one machine as behind a
separate gateway, the agent's proxy URL is the forwarder's address on loopback with a
password, `http://qory:<password>@127.0.0.1:<port>`, the password a secret the session
makes for the run's forwarder alone, 32 bytes from the system's random source in
base64url, which lives as long as the run and is never logged or recorded. A connection
to the forwarder carries one request, a `CONNECT` and its tunnel or one plain HTTP
request and its reply, so every request is checked: it must carry the password in its
one `Proxy-Authorization`, Basic, the user name ignored, compared in constant time. The
forwarder takes the header off, passes the request on with `Connection: close`, passes
on nothing the agent sends after a plain request, and closes the connection at the end
of its reply; a plain request that asks for an upgrade goes on with
`Connection: Upgrade` instead, and a `101` reply makes the connection a tunnel. It reads
the proxy's reply head to an upgrade up to 64 KiB. It closes the connection at the first
byte the agent sends before the reply to an upgrade. It closes a connection without the
password unanswered before anything reaches the gateway. At most 128 connections at once
wait to show the password or the hop line; one more closes the one that has waited
longest. A process of the agent's user can read the agent's environment, and the
password in its proxy URL with it, so the password keeps out the machine's other users,
not the agent's user: the same user is trusted, as on the local link. The run key
reaches neither the agent's environment, from which the session takes `QORY_RUN_KEY` out
whatever the agent inherits, nor any file, and the agent's view is the same as on one
machine. The gateway takes the bytes after that line as the run's proxy's, as a
connection the proxy secret opens on one machine, with at most 2048 characters of run
key; a run key it refuses (The run key on the one address, above), or one of a run not
live there, closes the connection unanswered. The run's proxy secret, on one machine, is
at least 128 bits from the system's random source, made by the gateway for the run; the
gateway compares it in constant time, never logs it, and refuses it once its run ends,
and it never leaves the machine.

## The runtime

The session starts a program, records it and stops it, and contains nothing specific to
one. What is
particular to one is behind an interface, `runtimes.Runtime` in the Go module, as an
enclosure is behind `wall.Wall`, and Claude Code is one implementation of it. A runtime
defines seven things: its name and the version of the program it was written against,
reported in `dev.qory.run.started`; how a launch is prepared so the program reports to
the session and runs with the run's placeholders, which may change the command and
arguments, add variables and write into the run directory, and nothing else (a script it
writes there may record an approval where the program reads it, then start the program);
whether the program's standard output is records to read; what event, if any, one record
is; how the program is stopped, a signal and a grace; whether the arguments it is
started with mean it runs without an interface, so the session is on pipes whatever the
caller has; and the secrets it declares, a descriptor's `secrets` (below), which a
runtime in Go defines through the optional interface `runtimes.Secrets`, checked by type
assertion: a runtime without it declares nothing. Behind a wall, the preparation
receives the variables the enclosure gets the placeholder value in.

There are three ways to a runtime, and a name resolves to the first that applies:

1. **A descriptor**, a runtime written as data (below): `<name>.yaml` in a directory
   the command sets, `~/.config/qory/runtimes/` for `qory`, then the one this contract
   ships under `runtimes/<name>/`. Nothing of a descriptor runs, so a machine adds a
   runtime or corrects one without a new binary.
2. **A bare runtime**, for a name nothing describes. Nothing is prepared and no record
   is read: the run's events, its log and its egress record are all there, the session's
   are not. Any program runs behind a wall this way, with no descriptor.
3. **An implementation in Go**, for a caller that embeds Forager and whose program
   needs what a descriptor cannot express. It is set in `session.Spec.Runtime` like any
   other.

`session/runtimes/runtimetest` is what any of them is tested against: `Conforms`, that a
runtime leaves alone what doesn't belong to it, and `Replays`, that its records produce
exactly the recorded events and that each passes this contract's schema.

### The descriptor

`descriptor.schema.json`. One YAML file per runtime. It has seven parts, beside
`runtime`, the name, a lower-case letter and then up to 63 lower-case letters, digits
and dashes, and an optional `title`, the name a person reads: `Claude Code`.

**Sources**: how the session attaches. The terminal bytes always, with nothing to match
in them and so no source. `output`: JSON lines on the runtime's standard output, when
the session runs on pipes; a line that is not a JSON object is not a record. `hooks`:
the runtime's hook events, for each of which the session installs its forwarder as a
command hook, the way `install` selects among the installers the binary has: a
descriptor selects an installer and never contains one, so a program that takes hooks
another way needs an installer in Forager before a descriptor can select it.
`claude-settings` adds a group per event under `hooks` in the JSON settings the launch
passes with its first `--settings`, leaving the groups already there; a launch that
passes `--settings` more than once is handled as §Sequence step 6 says. The forwarder
writes the JSON it reads on its standard input to the local socket, as one record. A
forwarder exits 0 and prints nothing, which every hook interface reads as no decision,
so an installed hook observes and never changes what the runtime does.

**Rules**: for each source, a match and a target. `match` is a map of dotted paths into
the record to values: equality with a string, number or boolean, or `{present: true}`.
Every entry must match. `data` is a map of the event's fields to dotted paths whose
values are copied unchanged; a path that does not exist leaves the field out, which is
how optional fields work. Rules run in order and the first that matches produces one
event; a record no rule matches produces nothing. No patterns, no expressions, no
defaults, no concatenation. A mapping that needs more than equality and presence is a
Forager change.

**Stop**, optional: `signal`, one of the six above, and `grace`, a duration. It is how a
runtime that closes its session on one signal and drops it on another defines which.

**Headless**, optional: `args`, the arguments that mean the runtime runs without an
interface. When one of them is among the arguments the runtime is started with, the
session runs on pipes even at a terminal, exactly as when the caller selects pipes: the
runtime is recorded as not interactive, and the descriptor's `output` source is read. A
short argument matches the whole token (`-p`); a long one matches the token or its
`--name=value` form (`--print`, `--print=…`). Nothing else is inferred: a runtime
started without an interface in another way, such as one that takes its prompt on
standard input, has no argument to list, and its caller sets headless itself. Absent,
the caller alone decides. Runtimes differ in how they are started without an interface,
which is why the descriptor defines the inference and not the
command.

**Secrets**, optional: what the runtime needs of a run's secrets. `declares` lists the
secrets it reads, each `{id, title, name, hosts, paths, auth}`: an id, unique
among the declarations; a title for a person choosing one; the variable the
runtime reads it from; the hosts its value is set on, exact DNS names; optionally the
paths of those hosts, in the policy's path grammar; how it is set,
`auth.schema.json`, a scheme of the closed set, `bearer`, `header` with its `header`, or
`basic` with its `username`. The session gives a declaration's variable the placeholder
of a credential from the server whose `key_variables` list it and whose `auth` is the
declaration's (§Credentials, The variable of a model key). When the descriptor also has
a `model` section, its declarations are its model keys, and a walled run whose run
answer has `credential_hosts` needs one (§Variables, A model key). `one_of` lists groups `{id, required, of}`, `of` being
declared ids, each in one group at most: groups of declarations of which the runtime
needs at most one, and exactly one of a `required` group. `reserves` lists variables
the runtime reads a credential from beside the declared ones; `denies`, variables the
session leaves out of the server's set for the runtime, apart from the variable of the
model `endpoint` behind a wall (Model, below); `credential_files`, files
in which the runtime keeps its credential, `~` being the home of the user Forager runs
as. Behind a wall, a declared or reserved variable that neither a placeholder, the run
nor the runtime's preparation sets is unset inside (§Variables). The session checks
`secrets` when it reads the descriptor: the schema, that ids are distinct, that every id
of a group is declared and in one group at most.

**Model**, optional: the model API formats the runtime sends its requests in, and where
a composer, such as qory, writes a run's model id, effort value and model endpoint.
`formats` lists one or more formats of `api-format.schema.json`. `model` is the place
of the model id. A place is exactly one of `flag`, an argument the runtime is started
with, which takes the value; `setting`, a dotted key in the JSON settings file the
launch passes; or `variable`, an environment variable. `effort`, optional, has `run`,
the place of the run's effort value with `values`, the 1 to 16 values the runtime
accepts there, and optionally `agent`, `{frontmatter, values}`: the key of an agent
file's frontmatter that takes an agent's effort value, and the values the runtime
accepts there. A value is a lower-case letter, then up to 31 lower-case letters, digits
and dashes. `endpoint` is `{variable}`, the variable the runtime reads the base URL of
its model API from, and is always a variable. `overrides`, optional, lists 1 to 64
distinct variables that would override the model id or effort value a composer writes.
Behind a wall the session treats each as a name of `denies`, and also leaves out the
harness's computed value of it (§Variables); without a wall `overrides` changes
nothing. Every object of the section is closed. The session uses `overrides` and
`endpoint` of the section, and the gateway uses none of it. Behind a wall, and without
one for a run whose answer has `credential_hosts`, the endpoint rule decides whether a
value of the endpoint's variable reaches the runtime, in place of `denies` (§Variables,
The model endpoint); otherwise `denies` decides.

**Fixtures**: `fixtures/<case>/records.jsonl`, records as the runtime produced them, in
the shape of `record.schema.json`, beside `expected/events.jsonl`, one `{type, data}`
per event the rules produce from them, in order. A descriptor without fixtures is not
accepted. The tests validate every record and every expected event against the schemas;
`runtimetest.Replays` replays the records through the runtime and compares.

`runtimes/claude/descriptor.yaml` is the Claude Code descriptor, written against version
2.1.273 as installed and its published hooks reference. Its hooks are the canonical
source in both modes; its standard output adds the result line, which only the output
reports. A descriptor records the version it was written against; Forager
reports that version and does not check the installed one. Its `secrets` declare the
model credential, each on `api.anthropic.com` under `/v1/`: `api_key`,
`ANTHROPIC_API_KEY`, an API key set as `x-api-key`; `oauth_token`,
`CLAUDE_CODE_OAUTH_TOKEN`, a subscription login's key set as a bearer; and `auth_token`,
`ANTHROPIC_AUTH_TOKEN`, an API key set as a bearer. It reserves no variable, and has no `one_of` group. The descriptor requires
neither, because a server's model key reaches the run only as a sealed credential that
the run configuration names (§Credentials, From the server), and otherwise the run's
model key is a credential the machine defines. Its `model` lists
`anthropic-messages`; it places the model id as `--model`, the run's effort value as
`--effort` and an agent's effort value in the `effort` frontmatter, each of the two
taking `low`, `medium`, `high`, `xhigh` and `max`; it places the endpoint in
`ANTHROPIC_BASE_URL`; and its `overrides` are `ANTHROPIC_MODEL`,
`ANTHROPIC_DEFAULT_MODEL`, `ANTHROPIC_DEFAULT_OPUS_MODEL`,
`ANTHROPIC_DEFAULT_SONNET_MODEL`, `ANTHROPIC_DEFAULT_HAIKU_MODEL`,
`ANTHROPIC_DEFAULT_FABLE_MODEL`, `ANTHROPIC_SMALL_FAST_MODEL`,
`CLAUDE_CODE_SUBAGENT_MODEL`, `CLAUDE_CODE_SUBAGENT_MODEL_FORCE`,
`CLAUDE_CODE_AUTO_MODE_MODEL`, `CLAUDE_CODE_EFFORT_LEVEL` and `CLAUDE_CODE_EXTRA_BODY`.

On a pseudo-terminal, Claude Code with `ANTHROPIC_API_KEY` set waits for a person to
approve the key, unless the configuration it reads lists the key's last 20 characters,
after trimming the space around it, under `customApiKeyResponses.approved`. That
configuration is `.config.json` in `CLAUDE_CONFIG_DIR`, else in `~/.claude`, when the
file exists, and otherwise `.claude.json` in `CLAUDE_CONFIG_DIR`, else in `~`. When the
session is interactive, the run has a wall and `ANTHROPIC_API_KEY` is a placeholder of
the run, `claude-settings` writes `approve-key.sh` into the run directory and starts Claude Code
through it with `/bin/sh`, so an image for such a run contains `/bin/sh`. The script
adds the placeholder value's entry, `utside-the-enclosure`, to that configuration inside
the enclosure, then starts Claude Code with its arguments. A missing file becomes one
with the entry alone, mode 0600; an empty one gets the entry and keeps its mode. A JSON
object without `customApiKeyResponses` gets the entry as its first member, and keeps
every member and the bytes before and after its opening brace, ending in one newline. A
file with `customApiKeyResponses`, one that is no object, and a path that is neither a
regular file nor missing stay as they are; Claude Code then shows its approval prompt
unless that list approves the placeholder value already. The script writes the new
content to a temporary file beside the configuration, copies it over the configuration,
through a link when it is one, and removes the temporary file; whatever fails, the
configuration keeps its content and Claude Code starts. The entry is always the
placeholder value's. A headless session, and an OAuth credential in either mode, need no
approval, and Claude Code starts as it is. A run without a wall starts Claude Code as it
is too: the script would write into the developer's configuration, so Claude Code shows
its approval prompt for the placeholder value, and the approval the person gives stays
in that configuration for later runs. A run's preparation (§The wall) is started
the same way, through a script the session writes into the run directory,
`preparation.sh`, which then starts the launch as the runtime prepared it, through
`approve-key.sh` when the runtime prepared that.

**`runtimes.json`** lists, for a server to vendor, every descriptor this contract ships,
in name order: `version`, 1, and `runtimes`, each with its `name`, `title`, `reserves`,
`denies`, `credential_files`, `declares` with `id`, `title`, `name`, `hosts`, `auth`
(`scheme`, and `header` for the `header` scheme and `username` for the `basic` scheme),
`paths` when the declaration has some, `one_of` with `id`, `required` and `of`, and
`model`, the descriptor's model section in the same shape, when it has one. Every list
is present, empty when the descriptor has none; `model` is absent when the descriptor
has none, and so is `overrides` in a `model` that has none. `go generate ./contracts`
writes it from the descriptors, and a test fails while the file differs from what that
writes.

**`api-format.schema.json`** is the fixed list of the formats a model API uses for its
requests and answers: `anthropic-messages`, Anthropic's Messages API;
`openai-responses`, OpenAI's Responses API; `openai-chat`, OpenAI's Chat Completions
API; and `gemini`, Google's Gemini API. The file has no `$defs`: a schema that uses the
list, in this contract or in another, refers to the whole file with `$ref`.

## The local socket

`QORY_RUN_SOCKET` is an address, not a path to open: a path, or `unix:` and a path, is
the local socket, and any other scheme selects a transport, which a forwarder without it
refuses with an error that contains the scheme. The local socket is the only transport.
It is not the gateway's link, whose socket is the gateway's (§The gateway's link).
It is a Unix domain socket the session creates before the runtime starts, in a separate
private directory under the system's temporary directory, mode `0700`, because a socket
path has a short limit on some systems and a run directory in a deep checkout can exceed
it. A client connects, writes one record per line in the shape of `record.schema.json`,
and closes; the session reads until end of file, one connection at a time in the order
they arrive, so two hook calls in a row keep their order. There is no answer and no
framing beyond the newline. The forwarder the session installs as a hook is one such
client; a harness that reports something itself writes the same shape with
`source: hooks`. Nothing on the socket reaches a receiver except through the
descriptor's rules. The socket is removed when the run ends.

## Images

The agent's image is the machine's to choose, and a run's to select among. The machine
defines images by name, and a run's policy selects one by that name, as it selects
credentials and tools, or names one by its reference pinned by digest, which the machine
runs only when the reference starts with one of its allowed prefixes, `images.allow`. A
policy defines no image, so a repository chooses what it runs under only among what the
machine allows. A run whose policy selects none starts in the machine's default. Images
need a wall: without one the runtime is a process on the machine.

| Definition | Meaning |
|---|---|
| name | what a policy, or the machine's default, selects it by, in a credential's grammar |
| reference | the image, pinned by digest where the machine requires the same image every time |
| runtime | the container runtime the wall starts it under, one the machine's engine has: `sysbox-runc`. Absent is the engine's default |
| docker | the agent gets nested Docker (§The wall). It needs a runtime that runs a Docker daemon without privileges. Experimental |

```yaml
version: 1
egress:
  mode: enforce
  allow: [api.anthropic.com, registry-1.docker.io]
image: with-docker
```

```yaml
version: 1
egress:
  mode: enforce
  allow: [api.anthropic.com]
image: registry.example/agents/app@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
```

The machine's default is the name of one of its images, or a reference, which starts
under the engine's default runtime with no daemon. A name the machine defines is read
as that image first.

**An image by reference** starts as the machine's default does: under the default's
runtime, with no daemon, as the wall's user, which for such an image is a uid and a gid
in numbers, neither 0, so that no name or group of the image's `/etc/passwd` or
`/etc/group` chooses who the agent is: a wall user given by name, or as a uid alone, is
refused before anything is made. Before the run starts, the wall fetches it unless the
engine holds it by that digest, and refuses one whose user is root. The relay always
starts from the machine's default image, never from the run's. The run sees its
workspace at `/workspace`, not at its path on the machine (below).

Against an image by reference, which a repository may have built, what holds is what
Forager enforces outside the enclosure: the wall, the egress policy, the credentials the
proxy sets, the tools the gateway starts and the `dev.qory.run.*` records. The runtime's
settings, its hooks and its prompts, and the `dev.qory.session.*` records, which the
runtime reports from inside, are not that boundary: the image can change or forge them.

A run configuration may name the image too, by reference only, beside its
`security_policy`. The run configuration, the server's policy and the node's policy must
name the same image wherever two of them name one; otherwise the run is refused,
`image_unknown`. The image is fixed when the run starts: a run configuration that names
another is refused, and the one in force stays.

**`images.allow`** lists the prefixes of the references the machine runs. An entry is
the start of a reference pinned by digest, in lower case, up to a whole part of it: a
registry, a name or a path, which may end in `/`, or a name and its `@`. An entry
covers a reference that starts with it when the entry ends in `/` or `@`, or the
reference's next character is one of them: `registry.example/agents` covers
`registry.example/agents/app@sha256:…` and `registry.example/agents@sha256:…`, and
neither `registry.example/agents-other/app@sha256:…` nor
`registry.example:5000/agents/app@sha256:…`. Nothing is normalised: an entry covers the
references written under it alone. No list allows no reference.

**Refused before the run starts:** a name the machine does not define, a selection
without a wall, an image defined twice, a daemon without a runtime; an empty entry of
`images.allow`, `*`, an entry that is not the start of a reference, and `images.allow`
on a machine with no default image, whose runtime an image by reference starts under. A
reference that is not pinned by digest, one with a tag, without a digest or in upper
case, is `run_configuration_invalid`, in a node's policy file and in a run configuration
alike. A reference under none of the machine's prefixes is `image_not_allowed`, with the
reference as its name: "the image <ref> is under none of the machine's allowed prefixes
(images.allow)". The image a run starts in is fixed when it starts: a run configuration
that selects another is refused, and the policy in force stays.

**The user of an image by reference.** The wall fetches the image with the engine's
pull, before it makes anything else for the run, unless the engine holds it by that
digest, and reads the image's user. No user, `root`, and a uid of 0 in any spelling,
with or without a group, are root, and so is a name the image's `/etc/passwd` maps to
uid 0. A user given by a name the image's `/etc/passwd` does not map, or in an image
with no `/etc/passwd`, cannot be checked and is refused the same way: such an image
gives its user as a uid. Root is
`image_user_root`, with the reference as its name: "the image <ref> runs as root; a
run's image runs as the wall's user". The image's user decides nothing else: the agent
runs as the wall's numeric uid:gid. A fetch that fails is no run, and leaves no
container or network of the run's; an image the engine pulled stays in its store.

**The workspace at `/workspace`.** A run whose policy names its image by reference sees
the bind that holds its workspace, the outermost, at `/workspace`, and the working
directory under it where it lies in that bind. Another bind whose path inside is
`/workspace`, holds it or lies under it is refused before the wall is asked. Forager
names the workspace at `/workspace`, by whole path components, in what it puts inside:
the working directory, the runtime's command, arguments and variables, the preparation's
words, `QORY_HARNESS_HOME`, the harness's fixed and default values, and the settings the
runtime copies; `dir` of `dev.qory.run.started` is the working directory inside. A value
of the server's, of `--env` or of the machine passes as it is. The working folder must
be a full repository: a git worktree's `.git` file names the main checkout by its path
on the machine, which is not inside. An image that brings a tree for the run keeps it at
`/qory/seed`, and `qory` copies it into the workspace; Forager copies none of it.
`/qory/hooks` works as in every walled run, and what reaches it is what the runtime
reports from inside, which such an image can change or forge (§Images). Every other run
sees its workspace at the same path as on the machine.

**The record.** `dev.qory.run.started` contains `image`, the reference, and when the image
is one the machine defines `image_name`, `container_runtime` when the definition sets
one, and `docker: true` when the enclosure has nested Docker; for an image by reference,
`image_fetch_ms`, how long the wall took to find the image, in milliseconds, its fetch
included when the engine does not hold it by that digest.
`dev.qory.run.policy_applied` contains `image` when the policy or the run configuration
selects or names one.

**What an image provides.** The wall builds no image and changes none. An image runs:

- under any user id the machine assigns it, with no home directory: `HOME` points at a
  writable place;
- with its authorities in a bundle where the wall looks for one, so the run's
  certificate goes after them (§The wall);
- with the runtime at the path the launch sets;
- with no setuid program or capability needed for its work;
- for nested Docker, with `dockerd`, and what it starts, `containerd`, `runc` and
  `iptables` among them, in `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`,
  `/usr/bin`, `/sbin` or `/bin`: the daemon's `PATH` is these directories alone. The
  users and groups the wall passes to the image by name are in the image's `/etc/passwd`
  and `/etc/group`.

## The wall

A wall is what makes a connection around the proxy fail. It is optional: with none, the
runtime is a process of the machine and enforcement is cooperative (§Limits). With one,
the runtime runs in an **enclosure** and the session stays outside it with the
proxy, the policy and the access key secret; the record is written from outside, and the
enclosure sees the run directory read-only. A wall is built by an adapter, one per
container interface; the contract's rules refer to no specific tool and define one list
for all of them.

**What every wall guarantees:**

- no route out of the enclosure except to the gateway;
- a resolver that resolves nothing outside the enclosure;
- no cloud metadata address, which is a network path to credentials;
- no file of the host beyond the mounts the run lists, and no environment beyond what
  the run passes;
- a user that is not root, no added capabilities, no privileged mode, no host
  namespaces;
- no credential the run's policy selects: a placeholder where a program requires one set
  and the certificate of the run's authority, never a secret and never the authority's
  key;
- never the container runtime's socket: a process that can request a container on the
  host's network from the daemon has left the wall. A mount that is a socket, or a
  directory containing a runtime's, is refused.

**Names unset inside.** When a walled run has names to unset, its launch starts through
Forager's helper, the caller's binary, at the front of everything the launch starts, the
run's preparation and Claude Code's approval of its key included, and after the wall's
programs: `exec --unset NAME … -- program args…`, which removes the names from its
environment and executes the program, found in `PATH`. A program found only through `.`
or an empty entry of `PATH` is not run, and ends the run with 127. The names are those a
source does not set and win with (§Variables); a name Forager, the wall or the
preparation sets for the run is never one of them; a name the wall sets only for a run
with an authority, such as a CA bundle's, counts as set only when the run has one. So an
image's `ENV` cannot set a name that is unset, with one exception: with nested Docker,
`DOCKER_CONFIG` is never unset, and a non-empty value in the environment, the image's
included, takes the place of the wall's docker configuration (Nested Docker, below).
Only an image the machine defines has nested Docker; an image by reference never does. A
name outside a variable's grammar is refused, and a program it does not find or cannot
execute ends the run with 127 or 126, as a shell's would. A run with no names to unset
starts its launch as it is. `dev.qory.run.started` reports the launch without the
helper.

**Forager's files.** A walled run, one without a server included, refuses a mount,
or the workspace, that is, contains or lies inside one of Forager's files: no run,
`mount_contains_forager_files`, with the mount and Forager's file as its names, in
that order. The session checks before it contacts the server and before anything starts,
so no event records that refusal, and checks again just before the enclosure binds the
mounts. Both paths are
resolved through symbolic links, a part that does not exist yet through its nearest
parent that does and a link whose target does not exist yet through that target, and
compared by whole components; a path that cannot be resolved is no run. The filesystem
judges what exists: two directories are the same when they are one file, by device and
inode, so a path written in another case on a disk that ignores case is the directory
it names. A part that does not exist yet is compared by name, regardless of case.
Forager's files are:

- the paths the caller lists as Forager's files: for `qory`, the directory of
  `forager.yaml`, with the access key secret;
- the directory of every credential program and every tool program the machine defines,
  and of the file a link to one leads to, the directory and not only the file, so an
  interpreter, a module or a configuration beside a program is covered too;
- the file a credential is read from;
- the private directories of the tools' sockets, made in the system's temporary
  directory, every run's on the machine, whether or not the run has tools;
- the private directories in the system's temporary directory where every run on the
  machine makes its record socket, `qory-run-*`, and where the `docker` wall writes a
  run's environment files, `qory-wall-*`, the relay's with the proxy's secret among
  them;
- the private directories in the system's temporary directory where every gateway on the
  machine makes its link's socket, `qory-link-*` (§The gateway's link);
- the wall's files: for `docker`, the directory of the `docker` command and of the
  helper, and the command's configuration directory, `DOCKER_CONFIG` or `~/.docker`,
  whose context and credential helpers start programs;
- the runs directory, where the session makes the run directories;
- the session's registry of walled runs (below).

An agent that can change a program Forager starts outside the wall, or read a file a
credential is read from, has left the wall.

**No bind from a place a walled agent can change.** An engine looks up every name of a
bind's source path again when it binds it, links included, so a check of the path
before cannot hold if a name is looked up in a directory an agent can write. So no name
on the way to a walled run's bind source is looked up in a writable bind, the run's or
another walled run's still going, or in a directory inside one. A bind's root is looked
up in its parent, so two binds of one root are allowed:

- the enclosure binds the outermost of the places the run lists, the mounts and the
  workspace, each once, and the run directory, read-only. The workspace is writable and
  is the working directory inside, through the bind that holds it, or bound at the same
  path as on the machine when no mount holds it; a run whose policy names its image by
  reference sees the bind that holds it at `/workspace` (§Images), and a wall binds a
  mount at the path the session gives it inside, never one that overlaps `/qory`. The
  session passes the wall every bind,
  each path clean, and the working directory lies in one of them by its names, or the
  run fails; a wall binds nothing of the caller's the launch does not list;
- a place inside another one, or the same, of the same mode is reached through the
  outer one, which alone is bound. Of the other mode it is no run,
  `mount_mode_conflict`, with the inner place and the outer one as its names, in that
  order: a read-only part of a writable bind is one the agent replaces, and a writable
  part of a read-only one writes what the run shows read-only;
- a place, of either mode, whose path goes through a link inside a writable place of
  the run's and that does not resolve into it is no run, `mount_through_link`: the
  agent that writes the link would choose what is bound. Its names are the place as
  passed, the link, absolute and clean, the last one inside the writable place on the
  way, and the writable place as passed. The same holds of a link inside a place the
  caller records as written by walled runs (`Spec.Written`), whether or not a run that
  wrote it is still going: the names are the place, the link and the written place;
- the runs directory is one of Forager's files, so the run directory lies in no
  place the run lists, and a writable place that holds a directory a name on the way
  to one of Forager's files is looked up in is `mount_contains_forager_files`;
- the session keeps a registry of the walled runs still going on the machine, per user,
  with each run's binds: the places, the run directory and the wall's extra binds, for
  `docker` its helper, the hook socket's directory and the private directory that holds
  the run's environment files and, with a CA, the bundle the enclosure binds. The wall's
  are listed when the run starts, those it makes later as their patterns, which never
  conflict with another session's. A run is no run, `mount_shared_with_run`, when one of
  its binds lies inside a writable bind of another run's or is reached through one, when
  one of its writable binds holds a bind of another run's or a directory a name on the
  way to one is looked up in, or when one of its binds is, holds or lies inside another
  run's run directory, whatever the modes: a run directory is its run's alone. Two binds
  of the same root never conflict otherwise, and neither do two read-only ones. Its
  names are the path of this run's, the other run's id and the other run's path. A place
  that lies inside a writable directory among another run's extra binds is refused too.
  A run whose helper, or another directory of Forager's its wall binds, lies inside a
  writable bind of another run's, or is reached through one, does not start. The session
  checks and lists the run in one step, before it contacts the server, and the run
  leaves the registry when it ends, however it ends, unless its wall could not be
  removed. A run is still going while its session holds its entry, or, once its session
  is gone, while the container engine its entry records, pinned by its selection and by
  its id when it gave one, holds a container labelled `dev.qory.run=<id>`, in any state.
  The selection is pinned by the variables the command reads: for the command named
  podman, `CONTAINER_HOST` or `CONTAINER_CONNECTION` set and recorded; for any other
  command, `DOCKER_HOST` or `DOCKER_CONTEXT` set and recorded, or the context the
  command shows. A variable of the other kind never pins. A command other than podman is
  asked by its id, through its pinned selection; podman is asked by its pinned selection
  when it gave no id. A run that cannot ask that engine, reaches another, or finds an
  entry whose engine is a command other than podman with no id, or podman with neither a
  pinned selection nor an id, is no run, `engine_unreachable`, whose names are the
  earlier run's id and then the absolute path of its entry in the registry.

Each of these refusals lists its names in the order given with it. A place of this run's,
a mount or the workspace, is named by its path as the caller passed it, and its run
directory by the runs directory the caller passed; a bind of another run's is named as
that run passed it, a file of Forager's, a link and a registry entry by their paths, and an
earlier or another run by its id. The first name of each `mount_` refusal is one of this
run's places, or for `mount_shared_with_run` also its run directory; the first name of
`engine_unreachable` is the earlier run's id. The session checks again just before the
enclosure binds, with the wall's extra binds, and a place that resolves otherwise, or
whose names are looked up in other directories, than at the start does not start. So no
name on the way to a bind source is looked up in a place a walled agent of this user's
can write. A process outside every wall, the user's or another user's, can still change
a path between the session's last check and the bind.

When the run has a separate authority (§Credentials), a wall sets the enclosure's trust
to one bundle, the image's authorities with the run's certificate after them, and points
the variables programs read a bundle's path from at it: `SSL_CERT_FILE`,
`GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and
`AWS_CA_BUNDLE` unless the caller sets others. The bundle is the image's and one more,
never the run's alone, because those variables replace a program's trust and do not add
to it; an image that keeps a bundle in no place the wall reads gets the run's alone and
reaches only the terminated hosts over TLS, which is the image's to mend. The
authority's key never crosses.

A run may set limits on what the agent uses, processors, memory, processes and the
size of `/dev/shm`; an adapter passes them to its engine and a run that sets none gets
the engine's defaults. They are no guarantee of the wall's: they keep one run from
starving a machine, not an agent inside.

The proxy is part of the list, because it dials from outside on behalf of what is
inside: behind a wall it is **guarded**, and what is on Forager's machine is not
reached by default. Two rules, in either mode, observe included:

- The link-local range, where a cloud keeps its metadata service, is refused whatever
  the allow list contains.
- Forager's machine, loopback and every address it has, is refused unless an
  `egress.allow` entry of the node's policy lists the host itself and the run's policy
  allows the host. A `*.` suffix over it does not count, and neither does a name a
  harness declares under such a suffix, an entry of a server's `security_policy` or a
  session's narrowing: the machine's owner decides what is opened on the machine, a
  repository or a server cannot. A local MCP server or model endpoint is reached
  through the proxy like everything else, decided and recorded, when the node's policy
  lists it and the run's policy allows it, and the rule that lists it applies under
  observe as well. A session's narrowing of a policy that observes opens nothing, the
  node's policy's entries included. The session addresses such a server by the
  machine's host name or an alias of it, as the hosts file or a name server gives it,
  with no search domain added, not by `localhost`, which `NO_PROXY` keeps inside the
  enclosure.

An address is judged as itself, an IPv6 address without its zone, and one that does not
read is refused. An address in `::/96` (other than `::1` and `::`), `::ffff:0:0:0/96`
or `64:ff9b::/96` is also judged by the IPv4 address in its last 32 bits, and refused
where that address would be.

A refusal the proxy can make without resolving, a literal address or `localhost`, is a
`denied` `dev.qory.run.egress` with the rule `wall:own-address` and a `403`; a name that
resolves to such an address is never dialled at it: a name's addresses are tried in
order, past any the guard refuses, and when none connects, the first one tried decides
the answer, the same refusal if the guard refused it and a `502` if it failed. Without
the guard the way around a wall is through the proxy.

**What crosses**, all three the session's, none containing a credential of the
gateway's: the proxy, as a network address; the pseudo-terminal or the pipes, through
the adapter's command; the hook socket, as a mounted file where a file can cross.

**The relay.** The agent reaches the proxy by a name, through a relay: a process of
Forager's on the enclosure's network and on an ordinary one, listening on a fixed port and
copying every byte to one address fixed when it starts, the proxy's. It reads nothing,
decides nothing and takes no instruction from the agent; the policy stays in the
gateway. It exists because the host is not always where a container expects it: with
the engine in a virtual machine the network's gateway is the virtual machine's, not the
host's. It forwards no packet between its two networks: IP forwarding is off in its
namespace, so what it passes on is the connections it copies and nothing routed
through it.

**A run's preparation.** A walled run may have a preparation: a program and its
arguments, which the session runs inside the enclosure before the runtime, after the
runtime's preparation (§The runtime), as the runtime's user, in its working directory,
with its environment, through the relay and the proxy: it reaches what the policy
allows, with the run's placeholders where the gateway sets the run's credentials.
Forager reads nothing into what it does. The session writes `preparation.sh` into the
run directory, each word of the preparation in single quotes, and starts the runtime
through it with `/bin/sh`, so an image for such a run contains `/bin/sh`. The script
runs the preparation with no input and its output where the runtime's goes, and starts
the runtime, as the runtime prepared it, once the preparation exits 0. A preparation
that exits otherwise is the run's exit status, and the runtime never starts;
`dev.qory.run.exited` records it as it records a runtime's exit. The run's time limit
counts the preparation. A stop during the preparation, by any of the run's stop
signals, asks it to leave with `SIGTERM`, and the runtime never starts; a preparation
that does not leave within the stop grace is killed as a runtime is.
`dev.qory.run.started` contains it as `preparation`, as given, with the script as
`command` and `args`. A run without a wall has no preparation.

**Nested Docker.** *Experimental.* Under the nested runtime the enclosure has a root,
and whether that root reaches the mounts the run lists as the machine's root is
unverified, so the option is experimental: it may change, and a run that uses it mounts
nothing the machine's root must protect.

An image the machine defines with a daemon (§Images) provides the agent a Docker daemon
inside the enclosure, never the machine's. It needs a runtime that runs a daemon in a
container without privileges: `sysbox-runc`, whose container has a separate root, in a
user namespace, mapped to a user of the machine's that is not root. The helper refuses
to start the daemon where the enclosure's root is the machine's, which it reads from
`/proc/self/uid_map`, so a runtime without a user namespace is no run. The enclosure
starts as that root, with no privileged mode and `no-new-privileges`, and with the whole
set of capabilities the runtime grants it inside its user namespace, which the daemon
needs; the wall's helper, not the image, starts it: `dockerd` on its Unix socket alone,
never a port of the enclosure's network, the socket in the agent's group, the daemon's
output in a separate file. The daemon and what it starts run with the system directories
§Images lists as their `PATH` and, of the run's environment, only the proxy and the
run's bundle; the rest of the run's environment, such as a `PATH` into the workspace or
`LD_PRELOAD`, reaches the agent alone. Once the daemon answers, the helper drops every
capability, the bounding set included, becomes the agent's user, and clears the
inheritable and ambient sets. The daemon's store is a volume of the run's, removed with
the enclosure, with no size limit of the run's: the run's limits do not bound it. A
daemon that exits during the run is not started again, and its output is root's inside
the enclosure, not the agent's to read. Three guarantees read differently under it, and
every other stands as written:

- *no added capabilities*: the agent has none, and none to gain. The enclosure's root has
  every capability inside its user namespace, and nothing of the machine's;
- *not root*: the agent runs as a user that is not root. The enclosure has a root, a
  user of the machine's that is not root, and whoever reaches the daemon's socket is
  that root, inside the enclosure and nowhere else;
- *no file of the host beyond the mounts the run lists*: beyond those, and the runtime's
  files. Sysbox adds the machine's kernel modules, read-only, and its scratch
  directories, and shows emulated parts of `/proc` and `/sys`; `/proc/partitions` lists
  the machine's disks, none of which opens.

The containers the agent starts are inside the enclosure's network namespace, a
container on the host's network or a privileged one included, so they reach the relay
and nothing else, and what they reach is decided and recorded as the agent's traffic.
The daemon pulls through the proxy, so a registry is a host the policy allows. Those
containers do not resolve the relay's name: the agent's docker configuration,
`DOCKER_CONFIG` at `/run/qory/docker` unless the enclosure's environment has a non-empty
`DOCKER_CONFIG`, the image's included, sets the proxy for them by its address. The
directory and its `config.json` belong to the agent's user, mode 0700 and 0600, inside
`/run/qory`, which belongs to root with mode 0755: the agent's user passes through it
and cannot write in it. The helper sets these owners and modes whatever the umask, and
on a `/run/qory` already in the image, and refuses a link in either place. The
containers the agent starts get the run's bundle only when the agent mounts it into
them, and they inherit `no-new-privileges`, so a setuid program in them gains nothing.
Docker in Docker with `--privileged`, and the machine's socket, stay refused. gVisor
breaks the list: its daemon inside starts only with every capability added.

**One conformance suite**, the `e2e` package, checks the list from inside the
enclosure with a real session behind the adapter, and an adapter ships when the suite
passes for it. The suite needs Linux and the tool, so it runs in Forager's CI on a
Linux machine; the ordinary tests compare the commands an adapter generates with golden
files and need neither.

**What ships:** `docker`, through the `docker` command and no library, serving whatever
engine that command reaches. It is supported where the suite passes. An engine in a
virtual machine on a Mac is where a wall is developed, not a target: the suite passes
there without the hook check (§Limits). The agent's image is the caller's; the wall
builds none. Nested Docker is experimental, under `sysbox-runc` on Docker Engine 28 or
later through the `docker` command, where the suite passes with it: Forager's CI
installs Sysbox on a Linux machine and runs the suite in an enclosure with a daemon. The
suite checks the list as the agent's user; what
the enclosure's root reaches of the mounts the run lists is the open question that keeps
the option experimental.

## Files of secrets and variables

| File | Defines |
|---|---|
| `enrolment.schema.json` | the enrolment request's body and its answer |
| `events/run.refused.schema.json` | the data of `dev.qory.run.refused`, a run a gateway refused or closed before it started, with its refusal code |
| `denied-variables.json` | the built-in deny list of variables, `names` and `patterns`, each matching a whole name regardless of case, `*` matching any run of characters |

## Fixtures

| Directory | Contains | Validated against |
|---|---|---|
| `fixtures/policy/` | policy documents that are accepted: observe, enforce, enforce with nothing, observe with a deny list, enforce with a tool, a credential and a tool each with an argument of 4096 characters, the most one may have, and enforce with an image named by its reference pinned by digest | `policy.schema.json` |
| `fixtures/server/` | server documents that are accepted, with the fixture access key id and the fixture signing key as the pin, one of them with `via`, its `ca_file` and its pin | `server.schema.json` |
| `fixtures/configuration/` | configuration documents a server returns: with its events and run endpoints, with a section this revision does not define, with `secrets` and two keys of a rotation, a gateway key's, with no `workspaces` | `configuration.schema.json` |
| `fixtures/run-registration/` | registration bodies: one without labels or `about`, and one with labels and an `about` of every member; and in the gateway shape, one with labels, `about` and `attach_seconds`, and one with `version`, `run_id` and `time` alone | `run-registration.schema.json` |
| `fixtures/run-attach-answer/` | attach answers: a run configuration of no policy, and one with variables and labels | `run-attach-answer.schema.json` |
| `fixtures/run-outcome/` | outcomes: with no state, with a state alone, and with a reason that is no code, which the server drops | `run-outcome.schema.json` |
| `fixtures/batch-answer/` | bodies of a signed `2xx` to a batch: an `end` with a reason, one without, and none | `batch-answer.schema.json` |
| `fixtures/api-format/` | each API format of the list, one per file | `api-format.schema.json` |
| `fixtures/descriptor/` | descriptors that are accepted: one whose `model` places the model id in a setting, the run's effort in a variable and an agent's in the frontmatter, with two formats and two `overrides`, and one whose `model` has no `effort` | `descriptor.schema.json` |
| `fixtures/run-configuration/` | run configuration documents a server returns: with a policy of each mode, with variables, with neither, which leaves the node's policy in force, and with an image named by its reference pinned by digest and no policy; `credentials.json`, with a model credential on a name, an IPv4 and an IPv6 host; `credentials-forge.json`, with a model credential and a forge credential that has no `key_variables` | `run-configuration.schema.json` |
| `fixtures/batch/` | delivery bodies: a first batch, the `dev.qory.run.refused` of a run whose run configuration was refused, `run_configuration_invalid`; the gateway's `dev.qory.run.exited` of a session's run whose starter gave no outcome, `cancelled` with `stopped` and `exit_code` `-1`, `session-stopped.json`; and the `dev.qory.run.refused` of the server's `not_found` with its `status` `404`, `refused-not-found.json`, and of a code of the server's the schema's list does not hold, with its `status`, `refused-unlisted-server-code.json`; and the `dev.qory.run.policy_applied` of a walled run whose policy file was put under a ceiling with path rules, with its `ceiling_paths`, `policy-applied-ceiling-paths.json` | `batch.schema.json` |
| `fixtures/signed/` | signed requests, one per file, under the fixture access key secret, with the status a receiver returns and the code of a coded refusal: discovery, batches, registrations and a reload | the receiver, replaying each in the order of their names with its clock at `1700000000` and checking each answer's signature |
| `fixtures/run/<id>/` | recorded runs, `events.jsonl` and `output.log` each: one on a developer machine, one behind a wall that reaches a tool started with an argument, with a credential an adapter mints, and one behind a wall in an image its policy names by reference, with its workspace at `/workspace` and the fetch's time | `event.schema.json` per line, plus the sequence, source and concatenation rules, and that every `dev.qory.run.exited` contains `state` and `exit_code` |
| `fixtures/run/about-*.json` | the `about` of `dev.qory.run.started` (§What a run is about): accepted ones, with a title alone, with every member and `details` 4 levels deep, with a `type` of two words and one of a dotted name; and refused ones, `about-refused-<reason>.json`, one per bound. A refused one named `about-refused-beyond-schema-<reason>.json` breaks a rule only Forager checks, and passes the schema: a `kind` of 64 characters and 128 bytes, two subjects with the same `type` and `ref`, a `url` with no host, a `url` with a user name and password, `details` over 8192 bytes as the event contains it, and `details` with a member name twice | the `about` of `events/run.started.schema.json`, expecting a failure for each refused one the name does not mark beyond the schema; the session's check, `session.CheckAbout`, expecting a failure for every refused one |
| `fixtures/link/` | documents of the gateway's link, each named after its schema: the discovery of the local link and of a separate gateway, each with its `proxy`, a run request without a wall with its `passes`, one with a wall, its `passes` and `images`, and one with a narrowing as well, one with `images.allow` and a policy that names its image by reference, a run answer with a wall, its labels, `placeholders`, `reserved`, `credential_hosts`, `image`, `applied` and `certificate_authority`, one with a wall and an `image` whose default is a reference but no `certificate_authority`, one with an image by reference, its `reference` and `relay_image`, one whose `credential_hosts` has a credential from the server with its `auth` and `key_variables`, one without a wall and one without a policy, each with its `applied`, one without a wall whose gateway holds a credential, with its `placeholders`, `credential_hosts` and `certificate_authority` and no `image`, one behind a separate gateway, without labels and `proxy_secret`, a reload answer with and without a policy, each with its `applied`, and one whose `applied` has `ceiling_paths`, a batch of a session's events without `sequence`, its `dev.qory.run.started` first, a batch of the `dev.qory.run.refused` of a session's code, a batch of a session's `dev.qory.run.exited` with `timeout`, `cancelled`, two with `interrupted`, `cancelled`, one with the runtime's exit status and one with its signal, and refusals: `run_closed`, `session_lost` with its `state` and `reason`, `stopped` with `cancelled` and `stopped` and with the starter's `failed` and `checks_failed`, `batch_refused` with its `state` and `reason`, `placeholder_conflict`, `image_unknown`, `image_not_allowed`, `tool_unknown`, `wall_required` and `internal`, once with a `message` of one line and once with one that spans lines, `run_key_invalid` and `run_attached`, from `gateway`, each with today's text as its `message` but `run_closed`, which shows it optional, and the signed `409` `instance_limit` to the registration and `run_key_expired` to the attach from `apiary` with Qory Apiary's `run.url` in its `message`, each the body alone | the `link-*.schema.json` its name starts with |
| `fixtures/invalid/` | documents each schema refuses, whose name is `<schema>-<reason>`, a session's `dev.qory.run.exited` with `timeout` and `succeeded`, and one with `interrupted` and `failed`, and a run configuration whose `image` has a tag and one whose `image` is the machine's name for one, among them; and, named `<schema>-beyond-schema-<reason>`, documents that break a rule only the gateway checks and pass the schema: a session's `dev.qory.run.exited`, `cancelled` with no reason, and `succeeded` with exit status 1 | the schema the name starts with, expecting a failure, and a pass for each one the name marks beyond the schema |
| `fixtures/enrolment/` | enrolment requests with a node's code, `qecn_`, one carrying one fingerprint and one carrying two, and a gateway's request with a gateway's code, `qecg_`, under the fixture gateway key, the answer, the answer to the gateway's request, the answer for an adapter's key, `answer-adapter.json`, unsigned, the signed refusals `key_limit` and `key_invalid`, each with one key and during a rotation with two, and the signed `429` `rate_limited` with one key | `enrolment.schema.json`; each proof under the fixture access key, the gateway's under the fixture gateway key, each answer's and refusal's signature under the fixture signing key, `answer-adapter.json` being checked against the schema alone |
| `fixtures/known-answers/` | `keys.json`, the fixture access key with its secret, instance id and X25519 keys, and the fixture signing keys, current and next; `signatures.json`, the request, enrolment and answer strings line by line with their signatures, a registration among the requests, and its answer and the signed enrolment refusals among the answers; `discovery.json`, the body an answer signature covers; `registration.json` and `registration-answer.json`, the registration's body and its answer's; `small-order.json`, the public keys enrolment refuses; `keys.json`'s fixture gateway key, the seed being bytes 97 to 128, with its id `ak_f1xt0re00000000g`; `through-gateway.json`, the run key of `run-key-payload.json` and the requests and answers of a run through a gateway, line by line with their signatures, over `registration-gateway.json`, `registration-gateway-answer.json`, `attach.json`, `attach-answer.json`, `attach-run-configuration.json`, `discovery-gateway.json`, `outcome.json` and `outcome-answer.json`, and, for a fixed exporter value, a binding and an answer of the gateway on its link, signed under the fixture gateway key (Known answers of a run through a gateway, §The server) | `configuration.schema.json` for `discovery.json`, `run-registration.schema.json` for `registration.json` and `run-configuration.schema.json` for `registration-answer.json`, and each file of a run through a gateway against its schema, `run-key.schema.json` for the payload; each key recomputed from its seed, the files of a run through a gateway written again by `go generate ./runkey` and compared, each signature verified and signed again, each point checked with integer arithmetic |
| `fixtures/sealed/` | the secrets request's fixture: `run-configuration.json`, a run configuration with two credentials; `secrets-request.json`, the request for them; `secrets-answer.json`, its envelope, sealed to the fixture access key with a fixed ephemeral key, bytes 33 to 64, and signed under the fixture signing key; `sealed-plaintext.json`, what it opens to; `vectors.json`, its `info`, `aad`, lengths and hashes and the refused cases; and under `invalid/` envelopes each refused at one step, a wrong `aad`, a wrong `info`, a bad signature, an `exp` past the window, an `exp` too far ahead, another digest, another run id, an unknown suite and a value for a credential not requested, and `plaintext-other-digest.json` and `plaintext-not-requested.json`, the plaintexts the cases of another digest and of a value not requested were sealed from | each file against its schema, and `invalid/` against `secrets-answer.schema.json`, which refuses only the unknown suite; each envelope sealed again with the standard library, its signature verified and signed again, and opened with `crypto/hpke`; each refused one at its step and at no step before |
| `runtimes/<name>/fixtures/<case>/` | descriptor fixtures | `record.schema.json` and the data schema of each expected type |

After a change to the body of a `POST`, a batch's or a registration's, Forager's module
signs the `POST`s under `fixtures/signed/` again, under the fixture access key secret, with
`go test ./contracts -run TestSignedFixtures -update-signed`; the same test without the
flag checks them.

Every fixture is synthetic. No host name of anyone's infrastructure, no real secret, no
recorded session of anyone's work.

## Sources

Public sources this contract was written from, and nothing else:

- CloudEvents 1.0.2: the [core specification](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md),
  the [JSON event format](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/formats/json-format.md)
  with its batch format, the [HTTP protocol binding](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md),
  the [sequence extension](https://github.com/cloudevents/spec/blob/main/cloudevents/extensions/sequence.md)
  in its current form, without the retired `sequencetype`, and the published
  [JSON schema](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/formats/cloudevents.json),
  vendored unchanged as `cloudevents.schema.json` under its Apache License, Version 2.0.
- HTTP: [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) §9.3.6 for `CONNECT`,
  §15.5.4 for 403 and §15.5.8 for why not 407, §10.1.5 for `User-Agent`, §8.8.3 for
  `ETag`, §15.3.3, §15.5.2 and §15.5.11 for 202, 401 and 410;
  [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)
  §3.2 for the absolute-form target a proxy receives;
  [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) §2.1 for the
  `Authorization: Bearer` that carries the run key on a separate gateway's one address,
  and §7.6.1 of RFC 9110 for the fields of one connection the relay drops. UUID version 7 from
  [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html). The JSON Canonicalization
  Scheme of [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) for the digest of a
  node's policy, `node_policy`.
- The proxy variables: [curl's environment](https://curl.se/docs/manpage.html#ENVIRONMENT),
  which reads `http_proxy` in lower case only; [Go's httpproxy](https://pkg.go.dev/golang.org/x/net/http/httpproxy),
  which reads both cases and exempts loopback; [Node's built-in proxy support](https://nodejs.org/api/http.html#built-in-proxy-support);
  [Claude Code's proxy configuration](https://code.claude.com/docs/en/network-config);
  [git's http.proxy](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpproxy);
  the [npm](https://docs.npmjs.com/cli/v11/using-npm/config#proxy), [pip](https://pip.pypa.io/en/stable/user_guide/#using-a-proxy-server),
  [uv](https://docs.astral.sh/uv/reference/environment/) and [cargo](https://doc.rust-lang.org/cargo/reference/config.html#httpproxy)
  configuration pages. Setting both cases and listing loopback in `NO_PROXY` is what the
  union of them requires.
- The wall: Docker's [`network create
  --internal`](https://docs.docker.com/reference/cli/docker/network/create/), which
  creates a network with no route out; the [`docker run`
  reference](https://docs.docker.com/reference/cli/docker/container/run/) for
  `--cap-drop`, `--security-opt no-new-privileges`, `--user`, `--env-file`, `--mount`
  and `--add-host` with `host-gateway`; Docker's [note on the daemon
  socket](https://docs.docker.com/engine/security/#docker-daemon-attack-surface), which
  is why the socket never crosses; the instance metadata service of
  [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html),
  the address the list contains; Kubernetes' [network
  policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/),
  the picture the relay matches: one named peer and nothing else.
- Claude Code 2.1.273: the [hooks reference](https://code.claude.com/docs/en/hooks) for
  the event names, the input on standard input and the rule that exit 0 with no output
  is no decision; the [CLI reference](https://code.claude.com/docs/en/cli-reference) and
  [settings](https://code.claude.com/docs/en/settings) for `--settings` and
  `--setting-sources`; the [headless page](https://code.claude.com/docs/en/headless) and
  the [Agent SDK types](https://code.claude.com/docs/en/agent-sdk/typescript) for the
  JSON lines of `--output-format stream-json`; the [sessions page](https://code.claude.com/docs/en/sessions)
  for the statement that the transcript format is internal, which is why no descriptor
  reads it.
- The gateway's link: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), TLS 1.3,
  the only version a separate gateway speaks, and §7.5 for the exporter the binding
  signs;
  [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) §4.1.2.7 for the
  SubjectPublicKeyInfo the certificate pin is the SHA-256 of;
  [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html) §4 for the standard base64,
  with padding, the pin is written in.
- The server: [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), Ed25519, for the
  access key, the request and answer signatures and the proof of enrolment; Thormarker,
  "On using the same key pair for Ed25519 and an X25519 based KEM", IACR ePrint
  2021/509, for the X25519 key of the same seed;
  [machine-id(5)](https://www.freedesktop.org/software/systemd/man/latest/machine-id.html),
  for the keyed hash of the machine's identity beside the instance id;
  [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
  §4, the model for a configuration document under `/.well-known/`; GitHub's
  [delivery headers](https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers)
  and [best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks),
  the model for the delivery headers and the ten-second answer.
