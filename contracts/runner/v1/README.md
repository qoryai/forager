# Runner contract, v1

What the runner reads, and what it emits. The runner is the security boundary around one
coding agent session: the only thing between the agent and the world. This directory is
its contract: the documents, one JSON schema per document, and the fixtures a reader or
a receiver is tested against.

## Versions

Every document here contains `version: 1`, an integer, and its schema is addressed by
URL under `https://qory.dev/contracts/runner/v1/`. The harness contract of `qory`
spells its version differently, `apiVersion: qory.dev/v1alpha1`, and the difference is
the rule, not an accident. A document a person writes and commits, the stack and the
module manifest, contains the group and the version together, the way a Kubernetes
object does, because the file is read on its own and its format evolves with the
product. A document addressed by a schema URL, read or written by a program, contains an
integer that guards its reader, because the URL already contains the group and the
generation. The policy, the server document, the documents a server returns and the
descriptor are on this side: the objects the command passes to the runner and the ones a
control plane sends over the wire, and the compose report `qory` writes is versioned
the same way. CloudEvents adds its own `specversion: 1.0`, which is not ours to change.

**Revisions.** This is `v1`, revision 1. The runner sends the revision as one integer:
the header `X-Qory-Contract-Version: 1` on every request to the server, and
`contract_version: 1` in the ping's data. A runner on revision N reads every section
defined up to N and ignores any other section, and a server may rely on the sections up
to N and no more. An addition is a new revision; a breaking change is `v2`. An addition
made while no released runner is in use goes into the revision the runner sends; the
revision is raised only when a released runner is in use. Revision 1 is everything this
document describes: the server (§The server), a run's variables (§Variables), tools
(§Tools) and images (§Images), where `container_runtime` and `docker` belong to an
option that is experimental (§The wall), and nodes, access keys, instances and
enrolment (§The server).

`v1` is the first generation of this namespace, not a stability promise. The runner
module is at `v0`, which under Go's rules promises no compatibility: while the module is
at `v0`, a document or an event here may change in a way that breaks a reader, and the
changelog lists each such change. With the module at `v1`, a breaking change is a new
event type or a new directory, `v2`, never a change in place.

## The boundary

The runner's duties, in the order that matters when they conflict:

1. **Policy.** The runner reads one policy document, pinned for the run, that can only
   narrow what the binary allows: the egress mode, the allow list, the deny list, the
   paths of a host, and which of the machine's credentials the run may use. A policy
   that cannot be read means no run. No policy means observe everything, with no
   list to deny by. Nothing in a policy grants; a stale or failed policy degrades toward more
   restrictive, never toward more permissive.
2. **Egress.** The runner runs an HTTP proxy, on loopback or, behind a wall, on the one
   address the enclosure reaches (§The wall), and starts the session behind it.
   Every connection the session opens through the proxy is observed and recorded as one
   event: the host, the port, whether it was a `CONNECT` tunnel or a plain request, the
   decision, and the rule that made it. A connection to a host the deny list covers is
   denied in either mode; in enforce mode a connection to a host outside the allow
   list is denied as well. A denied attempt is recorded and the session continues; a
   denial never ends a run.
3. **Credentials.** The session's environment and files contain none of the runner's. On
   a developer machine the session runs with the developer's own environment, and the
   server's variables only when the launch spec accepts them (§Variables). Behind a
   wall the runner keeps the credentials the run's policy selects in memory, outside the
   enclosure, and its proxy sets each on the requests to the hosts it is for
   (§Credentials): the session reaches a code host and a model endpoint as itself, and
   its environment and files contain at most a placeholder for the credential. The tools
   the policy selects run outside as well, and the proxy sends them the requests to the
   hosts they serve (§Tools).
4. **Liveness.** A heartbeat while the session runs; the exit as the result.
5. **Reporting.** The session's terminal bytes as log chunks, the runner's observations
   as events, the runtime's own output mapped to session events by a descriptor. Every
   event goes to files. When a server is configured, every event its configuration lists
   goes there too. When the caller passes a stream, such as standard output, every event
   goes there as well, as the line `events.jsonl` contains; that is how a run with no
   receiver is followed.
6. **The harness reports over a local socket**, never over a network. A hook the
   runtime calls forwards what it received to the runner's socket; the runner is the
   only thing that sends to a receiver.

## Limits

Stated so a receiver reads the record for what it is.

- The proxy sees host names and ports, never the content of a TLS connection: a
  `CONNECT` tunnel is a blind relay once established. The exception is stated in the
  run's record: behind a wall, for a host the run has a credential or path rules for, or
  a tool serves, the proxy ends the session's TLS itself and reads each request's method
  and path. `dev.qory.run.policy_applied` lists those hosts as `terminated`, and no
  other host is read.
- On a terminated host the session's side of the connection is HTTP/1.1, so a protocol
  that needs HTTP/2 end to end, such as gRPC, does not work there, and a program that pins
  the host's own certificate refuses the run's. A host that sends a request's headers
  back, an echo service, returns to the session the credential the proxy set. A path rule
  reads a path and nothing else: where a host, such as a GraphQL endpoint, takes every
  request on one path, the path is reachable or it is not, and what the request may
  touch behind it is bounded by the credential's own scope, not by the runner.
- Only proxy-aware programs are seen. The agent CLIs, git over HTTPS, curl, the package
  managers and the language runtimes read the proxy variables; SSH, and any program that
  ignores the variables, is not seen. Without a wall, enforce mode is
  advisory against such a program. Enforcement against bypass belongs to the wall (§The
  wall): the session runner runs outside and the agent in an enclosure whose only route
  out leads to the proxy. The three outcomes: a connection through the proxy is decided
  by the policy and recorded, on any machine; a connection around the proxy succeeds
  unseen without a wall, and fails unseen behind one. The runner records what passes
  through it and nothing else; a record of attempts a wall refuses is the container
  layer's own logging, or the network's.
- A wall decides which process may connect, not where the machine may connect. A packet
  filter in front of a node cannot distinguish the agent from the runner, so its list is
  the union of both; the run's policy can only be enforced at the proxy. Neither
  distinguishes two accounts on one allowed host: a code host, an object store and a
  model endpoint each deliver data to whoever owns the account the request specifies.
- A credential the run passes into the enclosure's environment is the agent's; one the
  policy selects stays outside (§Credentials). What is passed in is the agent's: a
  checkout that keeps a token in the repository's configuration passes the token in with
  the workspace. The run directory is shown read-only, so the agent cannot change
  `events.jsonl`; when it lies inside the workspace the agent can still rename the
  directory above it, which moves the record and does not alter it. The server's copy is
  out of reach either way.
- Behind a wall the exit status is the adapter's command's. With Docker that is the
  runtime's status, except that `125` is the engine failing to start the container,
  `126` and `127` the program not being startable in the image, and a runtime killed by
  a signal arrives as `128` plus the signal's number, with `signal` absent.
- The proxy behind a wall listens where the enclosure reaches it, which other
  containers of the same engine, or other processes of the machine, reach too. It
  serves none of them: the run has a token that only its relay receives, every connection
  the relay forwards opens with `QORY-RELAY`, a space, the token and a newline before
  the first byte of HTTP, and a connection that opens otherwise is closed unanswered
  and reported once. The token is never inside the enclosure.
- On an engine inside a virtual machine, such as a Mac's, the hook socket does not cross the
  file share, so a walled run there has no session events from hooks; the log, the
  egress record and the structured output are unaffected. The forwarder's only
  transport is the local socket (§The local socket).
- The runtime's session events are what the runtime reports through its hooks and its
  structured output. A runtime that reports nothing produces no session events; the log
  and the egress record are the runner's own and are always there.
- A descriptor matches and copies. It never computes, so a mapping that needs a program
  is a runner change, never a configuration change.
- The server is trusted with what it is sent. The access key authenticates the runner to
  the server. Every answer is signed under the key the runner pins, so the runner
  authenticates the server over `https` and over loopback `http` alike.

## Sequence

One run, on a developer machine, with a server configured:

1. The runner receives a launch spec: the program, its arguments, its environment and
   directory, whether the session is interactive, the policy document, the server
   document with the access key secret and the instance id and name, the egress the
   harness declared, the node's variables, and the runtime name. The spec comes from
   the `qory` command, which reads the policy and the server from its own
   configuration; the runner receives nothing about what composed it or where it was
   read.
2. The runner creates a run id, a UUID version 7, and the run directory
   `.qory/runs/<id>/` in the checkout.
3. It validates the server document once, when one is passed; without a pinned
   `apiary_public_key` the run does not start, `apiary_public_key_missing`, before any
   request. It fetches the server's configuration document with a signed `GET` (§The
   server), and verifies every answer's signature under the pin before it reads the
   body or the headers. It posts one `dev.qory.ping` to the events URL the document
   defines and waits for a signed 2xx; heartbeats start once the ping is accepted. A
   fetch that fails, a document the schema refuses, an answer that does not verify, or a
   ping not accepted means the run does not start: a run configured to be observed never
   runs unobserved by accident.
   The `--local` flag of the command runs with the file sink alone and contacts no
   server. With no server configured there is no fetch and no ping, and the run starts
   at once, files only.
4. It determines the policy. When the server's configuration contains a `run` section, it
   fetches the run configuration, with every label of the run as the query, and its
   `security_policy`, narrowed by the policy the command passes, is the policy, and its
   `variables` are the server's (§Variables); anything but `200` is no run.
   Otherwise, or when the run configuration has no `security_policy`, the policy is the
   one the command passes. It validates the policy once.
   Refused by the schema: the run does not start. Absent: mode `observe`, everything
   allowed and recorded. Present: pinned, with the digest of its canonical JSON as its
   stamp. The allow list and the deny list are the policy's entries; the hosts the
   harness declared are reported and decide nothing (§The policy).
5. It starts the proxy on a loopback port and sets `HTTP_PROXY`, `HTTPS_PROXY` and
   `NO_PROXY` in the session's environment, in upper and lower case, with
   `NO_PROXY=localhost,127.0.0.1,::1` so a local MCP server or model endpoint still
   answers. It opens the local socket and sets `QORY_RUN_SOCKET` to its path and
   `QORY_RUN_ID` to the run id. Nothing else of the runner's enters the environment but
   the variables (§Variables), the placeholders and, in a walled run, the runtime's
   declared and reserved variables nothing else sets, as empty.
6. It has the runtime prepare the launch (§The runtime): for a runtime that takes hooks,
   the runner's forwarder as a command hook for each event the runtime lists. For Claude
   Code that is a copy of the settings file the launch passes, written as
   `settings.json` in the run directory and passed in its place, and, for an
   interactive session whose API key is a placeholder, a script that pre-approves the
   placeholder value in Claude Code's configuration before it starts (§The descriptor).
   What is prepared goes into the run directory; the composed home is not modified.
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
   ping with a server and from step 7 without one, until the final event.
9. The program exits. The runner drains the socket, so a hook on the runtime's last
   event is still read, emits `dev.qory.run.exited`, waits up to fifteen seconds for the
   sinks to flush, reports what the server has not accepted, and returns the program's exit
   status. A runtime killed by a signal exits as `-1` with `signal` set.

A run may have a time limit. When the runtime still runs at the limit the runner stops
it, and `dev.qory.run.exited` contains `reason: timeout` with the state `failed`; step 9
is otherwise the same. A denied connection never ends a run; the limit is the one thing
of the runner's that does. A server ends a run by closing it: a signed `410` with
`run_closed` to a delivery stops the runtime as at the limit, and
`dev.qory.run.exited` contains `reason: run_closed` (§The server).

The runner stops a runtime the same way at the limit and when its own context ends: a
signal that requests the runtime's exit, then SIGKILL after a grace. The signal is one of
SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2, since runtimes differ in what
each means: one closes its session on SIGINT and drops it on SIGTERM, another the other
way round. So the runtime defines which and how long (§The runtime), the run may set
others over it, and with neither it is SIGTERM and ten seconds. Behind a wall the
enclosure passes the same signal on to the runtime inside.

The run id is the runner's own, a UUID version 7, unless the caller already has one: a
caller's id is a UUID in the canonical lower-case form, since it is every event's
`subject` and the run directory's name, and anything else is no run. What else the caller
identifies the run by, a key in its queue, a repository, an issue, goes in `labels` on
`dev.qory.run.started`: at most 16, a key of 1 to 64 of `a-z`, `0-9`, `_`, `.` and `-`, a
value of at most 256 bytes. The runner reads nothing into them. It copies them into
`dev.qory.run.started`, and no other event repeats them: a receiver joins on `subject`.
It sends them, all of them, on the run configuration request (§The server), and the
server decides which labels identify what the run works on. The `qory` command, for one,
labels a run in a git checkout with `forge` and `repository` from its origin remote, and
a server that keys its policies on those finds them there.

Behind a wall, three steps differ and no event does. Before step 5 the runner starts the
tools the policy selects and waits until each listens (§Tools), then has the wall
prepare the enclosure and listens on the address the wall returns, not on loopback.
After step 6 it passes the wall the launch, the proxy's address, the socket and the
run directory, read-only, and starts the command the wall returns, on the same pseudo-terminal or
pipes; the proxy and socket variables inside contain the addresses the enclosure reaches
them on. After step 9 it closes the wall, which removes everything it created, and stops
the tools.
`dev.qory.run.started` contains `wall` and `image`, and `image_name`, `container_runtime`
and `docker` when the image is one the machine defines (§Images).

Under a node runner, step 1 is the node runner passing the same spec down through the
environment, with the run id it already has; everything after is one code path.

## The policy

`policy.schema.json`. The document the command passes to the runner, from the machine's
own configuration, never from inside the checkout, where the agent it constrains can
write it: for `qory`, the `egress` section of `~/.config/qory/runner.yaml`. The same
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
| `version` | `1`. A runner refuses a version it does not read, and the error contains that version |
| `egress.mode` | `observe`: every connection is recorded, and only a host `deny` covers is denied. `enforce`: a connection to a host outside `allow` is denied as well, and recorded |
| `egress.allow` | lower-case host names, or `*.` followed by a name for every host below it. No ports, no paths, no schemes. Absent is empty, and `enforce` with an empty list reaches nothing |
| `egress.deny` | hosts the session may not reach, in `allow`'s grammar, in either mode: a host an entry covers is denied before `allow` and the mode are consulted, whatever `allow` contains, and the entry is the rule reported. Absent is empty |
| `egress.paths` | by host, in `allow`'s grammar, the paths the session may request on it: a path matched whole, or up to a final `*` as a prefix. A host listed is terminated, which needs a wall; a host not listed is reached on every path. An empty list is no path at all |
| `credentials` | the credentials of the machine's the run may use: `name`, and an `argument` for an adapter, such as a repository, of at most 4096 characters. A policy defines none (§Credentials) |
| `tools` | the tools of the machine's the run may reach: `name`, and an `argument` when the definition takes one, of at most 4096 characters. A policy defines none (§Tools) |
| `image` | the image of the machine's the run starts in, by the machine's name for it; absent is the machine's default. A policy contains no reference and defines no image (§Images) |

**A node narrows a server's policy.** The server leads; the node only narrows. A node,
through an agent that writes its configuration for example, is easier to compromise
than the server, so on a node connected to a server what the node contributes can only
take away from the run. The node's policy is the policy document of the launch spec,
`Spec.Policy` in Go. A fetched `security_policy` and the node's policy combine by
narrowing. Without a server's `security_policy` the node's policy is the run's; with a
server's policy and no node policy, the server's applies as it is.

| Field | The run's |
|---|---|
| `egress.mode` | `enforce` when either side sets `enforce`, else `observe` |
| `egress.allow` | under `enforce`, a host passes only when the allow list of every side under `enforce` covers it; a side under `observe` allows every host its `deny` leaves open. The runner reports the entries of each side under `enforce` that every other such side's list covers, the server's first, each entry once, which is exactly the hosts both allow; with neither side under `enforce`, the server's entries |
| `egress.deny` | the union: a host either side's `deny` covers is denied, in either mode, and recorded with that entry as its rule |
| `egress.paths` | a host either side lists is terminated, and a request to it must match an entry of every side that lists its host. The run's mode decides what a miss does: under `enforce` it is denied; under `observe` it passes; either way it is recorded with an empty `path_rule`. A request every such side matches is recorded with the narrowest entry that matched |
| `tools` | the server's selection, narrowed by the node's `tools` member: absent, it leaves the selection as it is; present, each selected tool must be listed in it by name, and by argument when the node's entry has one, so `tools: []` allows none. A selected tool outside it is no run, `tool_unknown`, as a tool the node does not define |
| `credentials` | the server's selection, narrowed by the node's `credentials` member as `tools` is; a selected credential outside it is no run |
| `image` | when both sides select one, it must be the same, else no run, `image_unknown`; when one does, that one; else the node's default |
| `variables` | the server's; the node adds only names whose server value the run does not apply (§Variables) |

`image` selects one thing, so its narrowing is agreement: two different selections are
no run rather than a choice. The node's policy is fixed for the run: a reload replaces
the server's side, and the run applies the new `security_policy` narrowed by the same
node policy; the reload rules (§The server) hold for the result.
`dev.qory.run.policy_applied` reports the run's `mode`, `allow` and `deny` as the table
computes them, the server's `paths`, `source` `fetched` with the server's `url`,
`digest` and `run_configuration`, and the node's policy as `node_policy` (§The events).

**The harness's declared hosts.** The harness compose reports the hosts its modules
declare, the command passes that list to the runner, and `dev.qory.run.policy_applied`
reports it as `harness_hosts`; it decides nothing. The policy alone decides: `allow` is
the policy's list, a declared host the policy does not cover is denied under `enforce`
like any other, and one `deny` covers is denied in either mode. The grammar of a declared
host is that of `egress.allow`, defined here once; the harness contract copies it and
cites this document.

**Matching a connection.** The host of a `CONNECT` request is its authority; the host of
a plain request is the authority of its absolute-form target, never its `Host` header.
Host names are compared lower-case; an IP literal matches only an identical entry.
`deny` is decided first: when an entry of it covers the host, the connection is denied
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
empty segment, a dot segment. Under `observe` a path no entry matches is recorded as
allowed with an empty `path_rule` and passed on, as a host no entry matches is recorded
as allowed with an empty `rule`, but the credential is set only where its own paths
match: observe mode sends no token to a path nobody configured. The host
requested upstream is the one the connection was opened to and decided on, whatever
`Host` a request contains. A denial is a `403` containing the method, the host and the path.
A plain request is decided by the same paths, and the proxy never sets a credential on it.

*Reading without writing.* Paths define what a run does on a host as well as where. git
over HTTPS requests three paths of a repository, on any host that serves it:
`/<repo>.git/info/refs`, then `/<repo>.git/git-upload-pack` for a fetch or
`/<repo>.git/git-receive-pack` for a push. A run allowed the first two and not the third
clones and fetches, with the credential set, and its push is refused before it leaves
the machine: git reports `HTTP 403` and fails, the record contains the denied `POST`, and
nothing reaches the repository, whatever the token itself permits. Rules match the path
and never the query, so the `info/refs` a push requests first is allowed; it lists the
same refs a fetch reads.

*What a path rule does not read.* A rule reads the request's path and nothing else: not
its query, not its headers, not its body. What a request specifies there is outside the
rule: a subresource requested in the query, such as `?acl`; a listing whose prefix is a
query parameter, on a host that lists at `/`; a copy that sets its source in a header,
which writes under an allowed path what it reads from another; a GraphQL body that
selects any repository the token reaches. A path rule limits a run to the paths it lists
and guarantees nothing about the rest. The rest is bounded by the credential's own
scope, or by what serves the host, and whoever writes the policy for a host that accepts
such requests checks them there or leaves the host out.

## Credentials

A credential is a token the runner keeps outside the enclosure and the proxy sets on the
requests it applies to; the session's environment and files contain at most a
placeholder for it.
The machine defines credentials; the run's policy selects among them by name and
defines none, so whoever writes a policy chooses among the programs the machine's owner
installed and never specifies one. They need a wall: without one a program that ignores the
proxy is bound by nothing here.

A definition defines where the token comes from, exactly one of:

| Source | The token is |
|---|---|
| `env` | a variable of the runner's own environment, read once when the run starts |
| `file` | a file's content, read again whenever it is used, so whatever rotates it notifies no one |
| `adapter` | what a program of the machine's prints |

**An adapter** contains what one kind of host needs: a source code host, an artifact
store. The runner contains nothing specific to any host. The runner starts the adapter
outside the enclosure, with its own environment, a minute to answer, and `${argument}`
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

The adapter's answer defines how its token is used, because hosts differ in it: which
hosts, which scheme, and which paths make up what the run requests. The schemes are a
closed set, `bearer`, `basic` with a `username`, `header` with a header's name; an
adapter chooses among what the runner implements and adds nothing to it. Of a host with
`paths` the run reaches those and no other, so one repository's credential does not open
another organization's on the same host; a path the adapter leaves out, such as the
host's GraphQL endpoint, is not reached. A definition may set `hosts` and `paths` of its
own for an adapter: the most the adapter may claim. For `env` and `file`, which have no
adapter to define the use, the definition's `hosts`, scheme and `paths` are the use
itself.

Before the run starts every selected credential is resolved, and any of these is
no run: a name the machine does not define, an argument it does not provide for, a host
two credentials claim, a claim above the definition's, and under `enforce` a host the
run's allow list does not cover. The runner runs an adapter again five minutes before
`expires_at`, and when a host returns 401 to a request it set the token on, at most
once every thirty seconds. The new answer changes the token and nothing else: one
that lists other hosts, schemes or paths is refused and reported, and the old token
stays, because what a run reaches is fixed when it starts.

**Placeholders.** A program often needs a credential set to start. A
definition, or an adapter's answer, lists variables the enclosure gets with the value
`qory-sets-the-credential-outside-the-enclosure`, which is no credential anywhere; the
proxy replaces what the program sends. A run that passes a value of its own for such a
variable does not start.

**Termination.** For the hosts the credentials are for, and the hosts with path rules,
the proxy ends the session's TLS itself, answering as the host with a certificate of an
authority created for the run. The authority's key is in the runner's memory and nowhere
else, and gone with the run; its certificate is what the wall adds to the enclosure's
trusted bundle (§The wall). The proxy verifies the real host against the machine's own
roots. Every other host stays a tunnel the proxy does not read, and a run with no
credential and no path rule has no authority at all.

**The record.** `dev.qory.run.policy_applied` contains each use, `name`, `argument`,
`hosts`, `scheme` and `paths`, and the `terminated` hosts. `argument` is the policy's
argument to the credential, the same on every use of one credential and absent when the
policy passes none, so the record shows what each token is minted for, such as the
repositories of a source code host. On a terminated host `dev.qory.run.egress` is one
event per request, `method: HTTPS` with `request_method`, `path` without its query,
`path_rule`, and `credential`, the name of the one the proxy set. No event, no report
and no error contains a token.

## Tools

A tool is a program of the machine's that serves hosts, for what a run reaches that
needs more than a token in a header: a request signed with a key that stays outside the
enclosure, a protocol with an exchange of its own, a service that exists only on the
machine, such as an MCP server. The runner implements no protocol and a tool implements
one, so no protocol, cloud or provider enters the runner. The machine defines tools; the
run's policy selects among them by name, with an argument, as it selects credentials,
and defines none. Tools need a wall, as credentials do.

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

**Starting.** Before the runtime starts, the runner starts every selected tool outside
the enclosure: the command, with `${argument}` replaced by the argument, one word of the
command line and never a shell's; the runner's own environment, without the variables
the machine's credentials are read from, with `QORY_TOOL_LISTEN`, the path of a Unix
socket in a private directory of the runner's, mode `0700`, and `QORY_RUN_ID`. The tool
listens there within a minute; one that exits first, or does not listen in time, is no
run, and the last line it writes to standard error is the reason reported. Once it
listens, what it writes to standard error is reported as the runner's own lines and its
standard output is discarded. A tool that exits while the run goes on is reported and
not started again: a request to it is a failed dial. When the run ends, once the proxy
is closed, the runner sends SIGTERM to the tool's process group, SIGKILL after five
seconds, and removes the socket.

**Reaching one.** For the hosts a tool serves, the proxy ends the session's TLS as for a
credential's host, decides the host and the path by the policy as for any host, and
sends the tool over the socket every request it allows, as HTTP/1.1, streamed both ways:
the request as the session sent it, its query, headers, body and trailers, placeholders
included, with the `Host` the connection was decided on. Under `observe` that includes a
request whose path no rule covers, which is recorded as allowed with an empty
`path_rule`. A plain request to
such a host goes the same way. The proxy never dials a host a tool serves, so the host
need not exist: a tool with no host of its own serves a name the machine's owner
chooses, such as one under `.internal`, a domain reserved for private use, and the session
reaches it like any host. The proxy sets two headers of its own, after removing every
header and trailer whose name starts `Qory-` from the request, in any case and with an
underscore for the dash, so the values a tool reads are the proxy's, and a session that
lists them in `Connection` cannot remove them:

| Header | Value |
|---|---|
| `Qory-Request-Id` | the proxy's id of the request, 32 lower-case hex digits: the `request_id` of its `dev.qory.run.egress` |
| `Qory-Path-Rule` | the path rule that matched the path; `none` when the host has path rules and none covers the path, which happens only under `observe` and which a tool that enforces its rules refuses; absent when the host has no path rules |

The argument is not repeated per request: a tool started for the run has it on its
command line.

**What the tool decides.** A path rule reads the path and nothing else (§The policy), so
what a request specifies in its query, its headers or its body is the tool's to check,
against its argument and the path rule it receives. A tool refines inside what the
runner allows and never widens it: a request the rules refuse never reaches it. What a
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
none. The runner reads no body, so what an invocation does beyond its method and its
path is not read by the runner, and the tool checks it; the runtime's hooks report the MCP call an agent makes
(`dev.qory.session.tool_started`).

## Variables

A run's variables reach the agent's process alone. The runner adds them to the launch's
environment; the tools, the relay, the agent's Docker daemon and the wall's `docker`
command keep their own environment.

**The server leads.** On a node connected to a server, the server's variables, the run
configuration's `variables`, are the run's. The server resolves them among its own
levels and sends the resolved values alone, a name and a value each. The node adds only
names: its own variables, the ones the launch spec lists as the node's,
`Spec.Variables.Own` in Go, apply for every name whose server value the run does not
apply. A node value for a name whose server value the run applies, a name in `names`, is
left out and reported in `policy_applied`'s `variables.node_ignored`, and the run
starts. A server value the deny list leaves out, or one an unwalled run leaves out under
`ignore`, leaves the node's own value in place, as without a server. Names are compared
exactly between the node and the server; the deny list matches regardless of case. A
node, through an agent that writes its configuration for example, is easier to
compromise than the server, so the node only adds. Without a server, the node's own
variables are the run's.

The runtime's preparation (§The runtime) and the harness's composed launch,
`Spec.LaunchEnv` in Go, set names that are the runner's own, not the node's. Such a name
wins over the server's variable, which is left out and reported in `denied`, because the
runtime needs it.

**Unwalled runs.** The launch spec decides whether an unwalled run receives the server's
variables, `Spec.Variables.Unwalled` in Go: `ignore`, the default, or `accept`. With
`ignore`, an unwalled run starts without them; they are left out and reported by name in
`policy_applied`'s `variables.unwalled`. With `accept`, the deny list below applies, as
in a walled run. The deny list protects the wall and the runner, not the developer, so
`accept` opens the developer's shell to the server.

**Denied names.** The runner leaves out of every walled run, and of an unwalled run with
`accept`, a server variable whose name is on the deny list: the built-in list
`denied-variables.json`, the run's runtime's `denies` (§The descriptor), and the names
the node's owner adds in the launch spec, `Spec.Variables.Deny` in Go, such as `[NAME,
PREFIX_*]`. Each built-in entry undermines the wall, the proxy or the runner. A denied
variable is left out and reported by name in `variables.denied`, and the run starts. An
entry is a name or a pattern, `^[A-Za-z0-9_*]{1,128}$` with at least one character other
than `*`. It matches a whole name: `*` matches any run of characters, the empty run
included, anywhere in the entry. Matching ignores case, because programs read
`http_proxy` and `HTTP_PROXY` alike. `denied-variables.json`, `{"version": 1, "names":
[...], "patterns": [...]}`, holds every row of the table but the two that depend on the
node and the run: the names the wall sets for the run's bundle, and the runtime's
`denies`, which `runtimes.json` lists.

| Name | Why |
|---|---|
| `QORY_*` | the runner's own |
| `*_PROXY`, `NO_PROXY` included, in any case | the runner sets the proxy variables (§Sequence step 5), and any other routes around the proxy |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE`, `GIT_SSL_CAINFO` | the wall points them at the run's bundle (§The wall), and a server value would replace it |
| `SSL_CERT_DIR`, `GIT_SSL_CAPATH` | they point the same programs at another store beside the bundle the wall sets |
| every name the wall sets for the run's bundle | the node's own names for the run's bundle |
| `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY` | they choose the daemon a Docker of the agent's own reaches, and how |
| `DOCKER_CONFIG` | the wall sets it for a Docker of the agent's own |
| `PATH` | the enclosure resolves the launch's program through it, and which program runs is the node's choice (§Images) |
| the run's runtime's `denies` | they move the runtime's model credential or run its commands (§The descriptor) |

**Also left out, the same way:** a server variable with the name of a placeholder of
this run, where the placeholder wins; one the run's runtime declares or reserves, where
the stand-in or an empty value goes; one a value of the machine's is read from, such as
a credential's `env` (§Credentials), whose value stays outside the enclosure; and one
the runtime's preparation, the harness or the wall sets.

**The node's own environment** keeps two refusals, because they keep the node's secrets
and the stand-ins out of the enclosure. A walled run whose environment, what it
inherits, what the harness sets and the node's variables, passes a `QORY_` variable, or
a variable a value of the machine's is read from, into the enclosure is no run,
`variable_reserved`; `QORY_RUN_ID` and `QORY_RUN_SOCKET`, which the runner itself sets
for the session, are exempt. A run that passes a value for a placeholder is no run,
`placeholder_conflict`. A variable the run's runtime declares or reserves that the run
passes as a node variable reaches the runtime as passed. Behind a wall, every variable
the runtime declares or reserves that neither a placeholder, the run nor the runtime's
preparation sets goes into the enclosure as an empty value, so an image's own `ENV`
cannot set one.

**Limits.** At most 128 variables, each name `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, each
value a string of at most 4096 bytes of UTF-8 with no NUL, carriage return or line feed.
The schema's `maxLength` counts characters, so the runner counts the bytes beside it. A
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
| `time` | the runner's clock, RFC 3339, UTC |
| `sequence` | the [sequence extension](https://github.com/cloudevents/spec/blob/main/cloudevents/extensions/sequence.md): the runner-assigned order of the event within the run, a decimal zero-padded to ten digits, from `0000000001`, contiguous. A receiver orders by it, never by arrival |
| `dataschema` | `https://qory.dev/contracts/runner/v1/events/<type without dev.qory.>.schema.json`, the schema of `data` |
| `datacontenttype` | absent, which the JSON format reads as `application/json` |
| `data` | a JSON object validating against `dataschema` |

The types, one namespace. The runner's own:

| Type | When | Data |
|---|---|---|
| `dev.qory.ping` | before the runtime starts, to the server's events endpoint only, when a server is configured | `runner_version`, `events`, `contract_version`, `interval_seconds` |
| `dev.qory.run.started` | the runtime is about to start; `dev.qory.run.started` or `dev.qory.run.refused` is the first event after the ping, heartbeats aside | `runtime`, `runtime_version`, `command`, `args`, `dir`, `interactive`, `runner_version`, `host`, on a pseudo-terminal `terminal`, behind a wall `wall`, `image`, and when the machine's definition sets them `image_name`, `container_runtime` and `docker`, and `labels` when the caller passes any |
| `dev.qory.run.policy_applied` | right after, once; again at the sequence where a new run configuration takes effect | `mode`, `allow`, `deny`, `source`, `variables`, and with them set `url`, `digest`, `run_configuration`, `node_policy`, `harness_hosts`, `paths`, `credentials`, `tools`, `image`, `terminated` |
| `dev.qory.run.log` | one per chunk of output: on pipes one line or 4096 bytes, on a pseudo-terminal 4096 bytes or a quiet gap of 50 ms, whichever comes first | `stream`, `bytes` |
| `dev.qory.run.resized` | the pseudo-terminal was resized, at the sequence where the new size takes effect; never on pipes | `cols`, `rows` |
| `dev.qory.run.egress` | one per connection through the proxy, allowed or denied; on a terminated host one per request, and on a host a tool serves one per tool invocation | `host`, `port`, `method`, `decision`, `outcome`, `mode`, `rule`, and per request `request_id`, `status`, `request_method`, `path`, `path_rule`, `credential`, `tool` |
| `dev.qory.run.heartbeat` | every `interval_seconds` from the accepted ping until the final event, or from `dev.qory.run.started` when the run has no server; `elapsed_seconds` counts since the ping, or since `dev.qory.run.started` when the run has no server | `elapsed_seconds`, `interval_seconds` |
| `dev.qory.run.exited` | the runtime exited; the result and the last event, as `dev.qory.run.refused` is the last of a refused run | `state`, `exit_code`, `signal`, `reason`, `duration_ms` |
| `dev.qory.run.refused` | the run did not start after the ping; in place of `dev.qory.run.started`, the first event after the ping, heartbeats aside, and the last | `code`, and when they apply `connection`, `names`, `providers`, `status` |

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
recorded as `dev.qory.session.tool_started` with the runtime's own `input`,
`run_in_background` in Claude Code's, and as `dev.qory.session.tool_finished` with
whatever the tool returned; a subagent's start and end are the subagent events, with its
`agent_id` and `agent_type`. After that the runtime reports a list, not an event: what
is still running, each entry with the runtime's `id`, `type`, `status` and
`description`, and a shell's `command` or a subagent's `agent_type`. The descriptor
copies it as `background_tasks` onto `turn_finished` and `subagent_finished`, so a
receiver that wants a task's end takes the first list the task is missing from. Claude
Code reports no exit status and no duration for a background task, so the record has
neither; a descriptor copies what a runtime reports and computes nothing, and anything
more the runtime shows of a task is in its own output stream, recorded as
`dev.qory.run.log`. What becomes of work in the background
when a run ends is the runtime's as well: it may end such work itself shortly after its
last answer, wait for it up to a ceiling of its own, and read that ceiling from a variable.
The runner adds no rule of its own here. Behind a wall only the variables a run lists go
in, so such a variable is listed like any other; and the run's stop signal and grace are
what the runtime has to close such work when the runner stops it.

Every session event that comes from a hook may contain `agent_id` and `agent_type` when
it happened inside a subagent; `dev.qory.session.result`, read from the runtime's
output, contains neither. The schema of each type, under `events/`, defines which fields
are required and what each contains. Values are copied from the runtime unchanged:
`input` and `response` have the tool's own shape, `error` is display text, and the
enumerations in `source`, `reason`, `kind`, `outcome` are the runtime's words.

`dev.qory.run.policy_applied` records where the policy comes from: `source` is `none`,
`config` or `fetched`; `url` is where the run configuration was fetched from, and
`run_configuration` the server's digest of it as its header contained it, with
`fetched`, and with `config` or `none` when the run configuration has no
`security_policy`; `digest` is the runner's own hex sha256 of the policy document's
canonical JSON, with `config` and `fetched`; `allow` and `deny` are the policy's two
lists as written, `deny` the hosts denied by name in either mode, and when the node's
policy narrows a server's, the lists the narrowing computes (§The policy).
`node_policy`, present when the run has both a fetched policy and a policy the command
passes, contains its `digest`, `sha256=` and the lower-case hex SHA-256 of the RFC 8785
serialisation of that `policy.schema.json` document, and its `paths`, when it has any,
so the record shows both sides of every path rule. `variables` reports the run's
variables by name, never a value: `names`, the variables the run applies, the server's
and the names the node adds; `denied`, the server's variables left out by the deny list
or because the run sets that name otherwise; `unwalled`, the server's variables an
unwalled run left out under `ignore`, then every one of them; `node_ignored`, the node's
variables left out because the run applies the server's value for that name. Each list
is sorted and may be empty, and each server variable is in exactly one of `names`,
`denied` and `unwalled` (§Variables). `dev.qory.run.egress` records what becomes of the
connection in `outcome`: `connected`, the dial succeeded; `dial_failed`, allowed and the
dial failed; `refused`, not dialled, because the policy or the wall's guard denied it,
or closed by a reload. An event that is one request, a plain one or one inside a
terminated connection, contains the proxy's `request_id` for it, and `status`, the
status the host or the tool returned, when one did.

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
output is text on its own. A stream that never pauses is cut at 4096 bytes; what is buffered
when the runtime exits is the last chunk.

A replay lays the redraws of a full-screen program over each other, which takes the
terminal's size, so the size is in the record. On a pseudo-terminal
`dev.qory.run.started` contains `terminal`, the columns and rows the runtime starts on:
the runner's own terminal's when it has one, 80 by 24 otherwise. Every change after that is
one `dev.qory.run.resized` with the new size, at the sequence where it takes effect: what
the gap has buffered is cut before it, so the chunks before it were written to a terminal
of the old size and the chunks after it to one of the new. On pipes there is no
`terminal` and no resize.

## The record files

`.qory/runs/<id>/` in the checkout, kept out of git by the compose:

- `events.jsonl`: every event of the run, one per line, in sequence order, the ping
  included when one is sent. The record of truth; the server's is a copy.
- `output.log`: the raw bytes of the session's output, the concatenation of the
  `dev.qory.run.log` chunks. Both files tail.
- `settings.json`: the runtime's settings with the runner's hooks added, when hooks
  are installed.
- `undelivered/`: the batches the server has not accepted, when there are any.

`fixtures/run/<id>/` are such directories, recorded. The control plane's CI replays them.

## The server

`server.schema.json`. The document the command passes to the runner, from the machine's
own configuration: for `qory`, the `server` section of `~/.config/qory/runner.yaml`,
with the access key secret from the file descriptor `--access-key-secret-fd <n>` names,
else `QORY_ACCESS_KEY_SECRET`, else the file `access-key-secret`. The runner is a client of the server defined here and of
nothing else: it fetches the server's configuration, posts its events to the URL it
defines, and takes the server's policy for the run, which the node's narrows, and the
run's variables from the server when the server offers them. A server is a control
plane, or a plain receiver that implements this section: discovery and the events
endpoint are enough. Configuring one makes the run fail closed on the discovery fetch
and on the ping.

```yaml
version: 1
url: https://qory.example             # https, or http to a loopback address; scheme and host[:port] only
access_key_id: ak_f1xt0re000000000    # ak_ and 16 lower-case Crockford base32 characters
apiary_public_key:                    # the pin: the server's Ed25519 keys, one or more
  - {alg: ed25519, public_key: rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc}
```

`url` is the server's origin and nothing after it: no path, no query, no fragment. The
runner finds every endpoint through the configuration document under it.

**The access key.** The access key authenticates the runner to the server. It is one
Ed25519 key, whose secret is one line: `qak_` and the 32-byte seed in base64url without
padding, 47 characters, from the system's random source; the prefix lets secret scanners
recognise it. The secret signs every request and is never sent, and the server stores
only the public key. The server assigns the access key its id, `ak_` and 16 lower-case
Crockford base32 characters, when the key enrols (Enrolment, below). The secret lives
outside this document and outside any repository, in the machine's configuration
directory, its environment or a file descriptor; it is never in a checkout and never in
an event. The fixtures sign with the published fixture access key of
`fixtures/known-answers/keys.json`, under the id `ak_f1xt0re000000000`. `qory` refuses
its secret, and the fixture signing keys as a pin; a server refuses its public key at
enrolment, and the fixture signing keys as its own key. A second fixture access key,
the seed being bytes 193 to 224, whose public key is
`dSnEVtk40rj-kPpsz5FtNGdwpkvLt7UyO2h6zeIM0Aw`, has its secret published in the
`accesskey` package's tests and in this repository's history, and every side refuses it
as it refuses the fixture access key. A fingerprint, of an access key's public key or
of the server's, is `base64url(SHA-256(raw public key)[:16])`, 22 characters.

**Nodes and instances.** An access key belongs to a node, `nd_`, a permanent machine
that runs one instance at a time, or to a node pool, `np_`, whose instances share the
access key, up to a limit the pool may set; each id is followed by 16 lower-case
Crockford base32 characters. An instance is one running copy of `qory` with the access
key. Its instance id, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, is a signed line of every
request, for display, audit, per-instance events and the instance limit; authorisation
rests on the access key alone, and whoever holds the access key can claim any instance
id. `qory` generates `i_` and 16 random bytes in base64url and keeps the id in the file
`instance-id` with the HMAC-SHA256, keyed with `qory instance-id v1`, of the machine's
identity, so a file copied to another machine yields a new id there. The instance's
display name, the host name by default, is sent unsigned and serves display alone. A
ping from a new instance id beyond its node's limit
is a signed `409` `instance_limit`, and that run does not start; an instance counts
while one of its runs is live. A run is live from its accepted ping until its final
event, `dev.qory.run.exited` or `dev.qory.run.refused`, or until no accepted event of
the run has arrived for 3 × the `interval_seconds` its ping announced.

**The pin.** `apiary_public_key` lists the server's Ed25519 public keys, a list so the
server's key can rotate. Every answer of the server, to discovery, to the run
configuration and to every delivery, is verified under the pin before its body or its
headers are read, and the runner takes keys from its pin alone. `qory` takes the pin
from `QORY_APIARY_PUBLIC_KEY`, the same list written as JSON, when the section has none,
and refuses to start when both are set; it takes `access_key_id` from
`QORY_ACCESS_KEY_ID` the same way. A runner with a server and no pin is no run,
`apiary_public_key_missing`, decided before the first request.

**On every request** to the server:

| Header | Value |
|---|---|
| `User-Agent` | `qory-runner/<version>` |
| `X-Qory-Access-Key-Id` | the access key id |
| `X-Qory-Instance-Id` | the instance id |
| `X-Qory-Instance-Name` | the instance's display name, unsigned, for display alone |
| `X-Qory-Contract-Version` | the revision of this contract the runner implements, `1` |
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
  at every other. No timestamp is signed on a POST and no replay window is checked: a
  replayed batch is a duplicate the receiver already discards by event id.

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
- a POST to `/v1/secrets` of the 297-byte body of
  `fixtures/sealed/secrets-request.json`, a signed message of 383 bytes:
  `evE_tMJMYuStWh8E3xfWNnozoq-zMznRZ4KuFpz0h_e1GUeap3diwAG01KWTZ2mxvU0Cl62LiK_u7nw6UV67Cw`.

**A signed POST**, after [GitHub's model](https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers).
One `POST` per batch to the events URL, with the headers above and:

| Header | Value |
|---|---|
| `Content-Type` | `application/cloudevents-batch+json` |
| `X-Qory-Delivery` | a UUID per batch. A retry of the same batch contains the same id |
| `X-Qory-Run-Configuration` | the server's digest of the run configuration the run uses, `sha256=<hex>`, when it uses a fetched one; absent otherwise |

**A signed GET**, for the configuration document and the run configuration, contains
`X-Qory-Timestamp` beside the headers above.

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
enrolment answer has its own domain line because its line 3 is a proof, which anyone
holding a live code chooses: its signature never verifies as the answer to a signed
request, nor the reverse. At run start the runner treats an answer without a valid
signature under the pin as no run, `answer_unsigned`; during the run a delivery's answer
without one is no answer, retried as any other with its headers unread, and a reload's
fetch without one fails the reload. The runner reads a body's code only from a signed
answer, and a refusal body over 64 KiB counts as unsigned. Two known answers under the
fixture signing key, to the GET of discovery above: `200` with the 208-byte body of
`fixtures/known-answers/discovery.json` and `X-Qory-Configuration: sha256=` and the hex
SHA-256 of that body, six lines of 251 bytes,
`KR8RzAb1z5MnEj2SPYFrghfXqVdU7Da2Yu0qU1-VQhmuObVUiKLywh8FoTawEfg9u0VgOgFQJhutD3-w4a55Bg`;
and `404` with an empty body and no digest, 180 bytes,
`wtXEpqIYCRAH0I9P0wd1DxJxkury0OE566ADTu3bH2GWUP4-TAkNl3a5oKGP6ZVWsP8oPL-yJHuaOaxbNPU_Dg`.

**Coded refusals.** After verification, a `400`, `409`, `410`, `429` or `503` is
`application/json`, signed, with the body `{"error": "<code>", "names": ["…"]}`. The
order of refusals on discovery, the run configuration and the events endpoint: `413`;
`415`; `400` `bad_request` for a header sent twice, of `X-Qory-Access-Key-Id`,
`X-Qory-Instance-Id`, `X-Qory-Signature-Ed25519` and `X-Qory-Timestamp`, unsigned;
`401`; `429`; `400` `bad_request` for an instance id absent or outside its pattern,
signed; `400` `unsupported_contract_version`; `400`
`invalid_request` for a body or labels the contract refuses, a ping with
`interval_seconds` above 300 included; `401` for a timestamp outside ±300 seconds;
then each endpoint's own.
The events endpoint's own, in order: deduplication, so a batch whose delivery id or
event ids the server already accepted gets the same `2xx` again; `410` `run_closed` for
an event of a run the server has closed; then, for a ping alone, `409`
`instance_limit`.

**Failure.** Every authentication failure is `401` with the body
`{"error":"unauthorized"}` and nothing more, unsigned: a missing or empty
`X-Qory-Access-Key-Id` or `X-Qory-Signature-Ed25519`, an access key id of the wrong
shape, an access key the server does not recognise or has revoked, a timestamp that is
not an integer, a stale timestamp, a signature that does not verify. The body never
indicates which, and the runner reports every `401` as `unauthorized`. The server
verifies the Ed25519 signature, cofactorless as RFC 8032 defines it, looks the access
key up only after its id's shape is checked, logs nothing about the signature header,
and records the instance id and name as display data. A redirect is not followed: a 3xx
is a status like any other.

**Enrolment.** A new access key gets its id by enrolment, `enrolment.schema.json`: a
`POST` to `<url>/.well-known/qory-enrolment`, beside discovery's path, with an enrolment
code an owner or administrator of the server created: `qec_`, 26 Crockford base32
characters, then `.` and the fingerprint of the server's key, and during a rotation of
that key a second `.` and the next key's fingerprint. The body contains the code in its
normalised form, the 26 characters in upper case with `I` and `L` read as `1`, `O` as
`0` and hyphens removed; a name for the access key; the raw public key; a timestamp; and
`proof`, the Ed25519 signature under the new key of five lines joined by `\n`:
`qory-enrol-ed25519-v1`, the code, the public key as in the body, the name, and the
timestamp in decimal. The request contains no `X-Qory-Access-Key-Id` and no request
signature: the code and the proof authenticate it. The server answers an enrolment in
its own order, unsigned until the code is accepted, the key passes the checks and the
proof verifies under it: `413`; `415`; `400` `bad_request` for a header sent twice;
`429` per source address; `400` `unsupported_contract_version`; `400` `invalid_request`;
`401` for a code it did not issue or that is used, expired or cancelled, for a code
whose fingerprints are not its keys', and for a timestamp outside ±300 seconds; `409`
`key_invalid` for a key the checks refuse or a `proof` that does not verify under it,
the key checked first. Then, signed: `429` per code; `409` `key_invalid` for a key
already enrolled, a revoked one included; `409` `key_limit`; and `201`. The server signs
an answer only to a proof that verifies under a key the checks pass, so a proof no key
made, such as one under a key of small order, which plain Ed25519 verification accepts
for any message, gets no signed answer. The `201` answer contains the access key id,
`node_id` with `node_kind`, `stored_secrets` and the server's keys, signed as Signed
answers describes under `qory-enrol-answer-ed25519-v1` with the request's `proof` as
line 3; the machine verifies it under the listed key whose fingerprint the code carries
first, and pins only the keys whose fingerprints the code carries. A `201` means the
access key is active: the code's use activates it. A `401` means the code was used, has
expired or was cancelled; a signed `409` `key_invalid` refuses the key, and `key_limit`
a node that already holds two keys. Each signed refusal lists `apiary_public_key`, the
same list in the same order as a `201` at that moment, and the machine verifies it
exactly as the `201`; a refusal sent unsigned lists no key, and the machine acts on none
by its status, an unsigned `409` being `answer_unsigned`. In place of a code, an owner
or administrator may paste a public key the machine printed into an existing node or
node pool, where it is active at once. The server checks every public key it is given:
a canonical encoding, a point on the curve, not of small order, of prime order, and
y ≠ 1; `fixtures/known-answers/small-order.json` lists keys it refuses. The known
answers are `fixtures/enrolment/` and the enrolment lines of `signatures.json`.

**The configuration document.** `configuration.schema.json`. A signed
`GET <url>/.well-known/qory-configuration`, the path after OpenID Connect discovery, per
access key. The answer is a signed `200`, `application/json`, with the header
`X-Qory-Configuration: sha256=<hex>`, the server's digest of the document: opaque to the
runner, which compares it byte for byte and never recomputes it.

```json
{"version": 1,
 "node_id": "nd_f1xt0re000000000",
 "events": {"url": "https://qory.example/v1/events", "types": ["*"]},
 "run": {"url": "https://qory.example/v1/run-configuration"},
 "apiary_public_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
```

`version`, `node_id`, `events` and `apiary_public_key` are required. `node_id` is the id
of the access key's node or node pool, `^n[dp]_[0-9a-hjkmnp-tv-z]{16}$`, listed for
display: `qory` prints it. `apiary_public_key` lists the server's current key, and
during a rotation the next one, for information: a runner verifies under its pin alone.
`secrets` is optional, `{url}` with `run.url`'s grammar, listed only for an access key
allowed to receive stored secrets. Discovery lists no key endpoint: keys change through
enrolment alone. A `401` is no run, `unauthorized`. `events.url` is `https`, or `http` to a loopback
address; `events.types` is a non-empty list of full type names, or `*` for every type,
and the ping is always sent. `run` is optional: a server whose document has no `run` section
offers no run configuration, and the policy is the machine's. A top-level member the
runner does not recognise is ignored, which is how a new revision adds a section.

**The run configuration document.** `run-configuration.schema.json`. A signed `GET
<run.url>?<the run's labels>`: one query parameter per label, the label's key as the
name and its value as the value, a label with an empty value as `key=`, and no query
when the run has no label. The parameters are sorted by key and percent-encoded as a
form is, a space as `+`, so a run labelled `forge: github.com`, `issue: "77"` and
`repository: acme/shop` fetches
`<run.url>?forge=github.com&issue=77&repository=acme%2Fshop`. When `run.url` has a query
of its own, the labels are added to it, and a label replaces a parameter of the same
name. The server decides which labels identify what the run works on and returns the
policy for that; the runner reads nothing into them. The labels are bounded, at most 16,
a key of at most 64 bytes that needs no encoding and a value of at most 256 bytes, which
is at most 768 once encoded, so the query the labels make is at most 13,343 bytes; a
server whose front end limits a request line to less refuses the longest of them. The
reference receiver, once the request verifies, returns `400` to a query that is not
labels by these rules: a key sent twice, a key outside the grammar, a value too long or
not UTF-8, more than 16. The answer is `200`, `application/json`, with the headers
`X-Qory-Run-Configuration: sha256=<hex>` and `ETag: "sha256=<hex>"`, the same string,
quoted the second time.

```json
{"version": 1,
 "security_policy": {"version": 1, "egress": {"mode": "enforce", "allow": ["api.example"]}},
 "variables": {"NODE_ENV": "test", "APP_REGION": "eu-west-1"}}
```

`version` is required; `security_policy` and `variables` are optional. `security_policy`
is a `policy.schema.json` document, and it is the server's policy; the policy the
command passes, when there is one, narrows it (§The policy, a node narrows). Without
`security_policy` the policy the command passes is the run's, else observe everything,
and `dev.qory.run.policy_applied` reports `url` and `run_configuration` beside `source`
`config` or `none`; a reload that brings a `security_policy` puts it in force, narrowed
by the command's, and one that drops it puts the command's back. `variables` are the
server's variables for the run, a name and a string value each (§Variables). A member
the runner does not recognise is ignored. The digest is the server's and opaque; the
runner keeps it, sends it back on every POST, and never recomputes it. The runner reads
the document with a decoder that refuses a member name that appears twice and invalid
UTF-8, then against the schema and the limits, and its error states where in the
document and which rule refused it, never a value. Anything but `200`, or a document the
runner refuses, is no run, `run_configuration_invalid` for the latter.

**Delivery.** The body of a POST is a `batch.schema.json` document: a JSON array of
events of one run, in sequence order, never empty. The runner cuts a batch at one
hundred events, at one mebibyte, or after one second since its first event, whichever
comes first; the ping is a batch of one, sent before anything else, with the heartbeat
interval the run uses, `interval_seconds`, at most 300. A receiver verifies the Ed25519
signature over the request string before parsing, then deduplicates on each event's
`id`, since delivery is at least once.

The runner reads a body's code only from a signed answer:

| Status | Meaning |
|---|---|
| 2xx, signed | accepted; the runner forgets the batch |
| 409 to the ping, signed, such as `instance_limit` | no run, with its code |
| 410, signed, with `run_closed` | the run ends: the runner stops the runtime as at its time limit, records `dev.qory.run.exited` with `reason: run_closed` in the file sink, and sends nothing further. Before `dev.qory.run.started`, it stops the start and records `dev.qory.run.refused` with the code `run_closed` instead |
| 410, signed, without that code | stop: the server requests nothing more for this run. The runner sends no further batch and the run continues on the file sink |
| anything else, an answer that does not verify, or no answer within ten seconds | retried with exponential backoff, one second doubling to one minute, until the run ends |

Every answer may contain `X-Qory-Configuration` and `X-Qory-Run-Configuration`, the
digests in force: of the configuration document, and of the run configuration for the
run's labels. The runner compares each to the one it keeps. A different
run-configuration digest means fetch the run configuration again and apply it; a
different configuration digest means fetch the configuration document again and use
its sections for the batches that follow: the events URL and the filter. A
header absent means nothing, and so does a digest of an answer that does not verify.
This is how a control plane changes a run's policy while it runs, and the whole of it:
the runner reads a body's code only from a signed answer.

**Reload**, when a fetched run configuration replaces the one in force, three rules:

1. The new policy takes effect for new connections at once, and the record gets a
   second `dev.qory.run.policy_applied`, with the new digests, at the sequence where it
   takes effect.
2. A tunnel open to a host the new policy denies is closed by the proxy and recorded as
   a denied `dev.qory.run.egress` with `outcome: refused` and the rule that denied it.
3. A host the new policy terminates TLS for is terminated on its next connection.

What is still undelivered when the run ends is spooled to `.qory/runs/<id>/undelivered/`
as batch files with their delivery ids, and the runner reports the count on its standard
error. The file sink has every event regardless. The server never delays the session:
posting is asynchronous behind a bounded queue, and a queue that fills spools to the
same directory rather than blocking the runtime.

**After a runner stops unexpectedly.** The run directory records what the server is
still owed, without the runner that wrote it. `events.jsonl` is written as events
happen. `delivered.log` beside it gets a line as each batch is accepted, the delivery id
and the sequence of every event in it, and the one word `stopped` for a signed 410.
`lock` is held by the runner for as long as it lives, by the kernel, so it is free once
the runner is gone however it went. Sending a run again is the job's last step, whatever
happens before it: refused while the lock is held; then what the run's wall leaves
behind is removed, by the run's label; a record that has `dev.qory.run.started` and no
`dev.qory.run.exited` gets one, numbered on from the last event, with `state: failed`,
`exit_code: -1` and `reason: runner_lost`; and every event the server's filter selects
that no accepted batch contained is posted, in order, in batches cut the same way, until
the server accepts them or the runner stops retrying. The resend fetches the
configuration document first, as a run does, posts to the URL it defines, and verifies
every answer's signature under the pin. What is still not accepted is under
`undelivered/` again. A receiver sees some events twice when the runner dies between an
answer and its line, and discards them by `id` as any duplicate. Nothing of this
recovers a machine that dies: the record is lost with it, and a receiver detects that
from heartbeats that stop.

**The modes of a run:**

| The runner receives | Events go to | The policy comes from |
|---|---|---|
| nothing | files only | the machine's policy the command passes (`egress`), else observe everything |
| a server | the server's `events.url`, after a signed discovery fetch and a ping | the server's run configuration when it offers one, narrowed by the node's policy, else the node's policy |
| a server and `--local` | files only; the server is not contacted | the machine's policy |

A discovery fetch that fails, in transport, with a status other than `200`, with an
answer that does not verify or with a document the schema refuses, or a ping not
accepted: no run, and the error contains the URL, the status and the code when a signed
answer contains one. A `run` section present and its fetch not returning `200`: no run.
The command's `--policy`, a run's own policy under the machine's, keeps its meaning
without a server. With a fetched run configuration, the policy document of the launch
spec narrows the fetched policy (§The policy).

**The reference receiver** is the public package `receiver` of this module: a plain
receiver that serves discovery, the events endpoint and the run configuration, accepts
the public keys pasted into its own configuration and skips enrolment, verifies each
request and answers in the order this section defines, signs every answer after
verification under its own key, returns the digest headers, deduplicates and appends to
a file. Its discovery lists `version`, `node_id`, `events` and `apiary_public_key`, and
no `secrets`. The module's own tests run the runner's client against it.
`fixtures/signed/` is what any receiver is tested against: one request per file,
`method`, `target`, `headers`, a header sent twice being a list of its values, `body`
(a string, or `null` for a GET), the status a receiver returns as `expect`, the code of
a coded refusal as `expect_code`, and a `note` that explains why. Every signature in
them is real, under the fixture access key secret as the fixture access key and
instance; a receiver under test holds the fixture access key under
`ak_f1xt0re000000000` and sets its clock to `1700000000`, around which the timestamps
are. A receiver written by anyone else follows this section, replays those files, and
may read that code.

## The runtime

The runner starts a program, records it and stops it, and contains nothing specific to
one. What is
particular to one is behind an interface, `runtimes.Runtime` in the Go module, as an
enclosure is behind `wall.Wall`, and Claude Code is one implementation of it. A runtime
defines seven things: its name and the version of the program it was written against,
reported in `dev.qory.run.started`; how a launch is prepared so the program reports to
the runner and runs with the run's placeholders, which may change the command and
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
   is read: the run's own events, its log and its egress record are all there, the
   session's are not. Any program runs behind a wall this way, with no descriptor.
3. **An implementation in Go**, for a caller that embeds the runner and whose program
   needs what a descriptor cannot express. It is set in `session.Spec.Runtime` like any
   other.

`runtimes/runtimetest` is what any of them is tested against: `Conforms`, that a runtime
leaves alone what is not its own, and `Replays`, that its records produce exactly the
recorded events and that each passes this contract's schema.

### The descriptor

`descriptor.schema.json`. One YAML file per runtime. It has six parts, beside
`runtime`, the name, a lower-case letter and then up to 63 lower-case letters, digits
and dashes, and an optional `title`, the name a person reads: `Claude Code`.

**Sources**: how the runner attaches. The terminal bytes always, with nothing to match
in them and so no source. `output`: JSON lines on the runtime's standard output, when
the session runs on pipes; a line that is not a JSON object is not a record. `hooks`:
the runtime's hook events, for each of which the runner installs its forwarder as a
command hook, the way `install` selects among the installers the binary has: a
descriptor selects an installer and never contains one, so a program that takes hooks
another way needs an installer in the runner before a descriptor can select it.
`claude-settings` adds a group per event under `hooks` in the JSON settings the launch
passes with `--settings`, leaving the groups already there. The forwarder writes the
JSON it reads on its standard input to the local socket, as one record. A forwarder
exits 0 and prints nothing, which every hook interface reads as no decision, so an
installed hook observes and never changes what the runtime does.

**Rules**: for each source, a match and a target. `match` is a map of dotted paths into
the record to values: equality with a string, number or boolean, or `{present: true}`.
Every entry must match. `data` is a map of the event's fields to dotted paths whose
values are copied unchanged; a path that does not exist leaves the field out, which is
how optional fields work. Rules run in order and the first that matches produces one
event; a record no rule matches produces nothing. No patterns, no expressions, no
defaults, no concatenation. A mapping that needs more than equality and presence is a
runner change.

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
secrets it reads, each `{id, title, name, hosts, paths, auth}`: an id, the key a runtime
connection supplies it under; a title for a person choosing one; the variable the
runtime reads it from; the hosts its value is set on, exact DNS names; optionally the
paths of those hosts, in the policy's path grammar; and how it is set,
`auth.schema.json`, a scheme of the closed set, `bearer`, `header` with its `header`, or
`basic`, with neither `secret` nor `username_secret`. `one_of` lists groups
`{id, required, of}`, `of` being declared ids, each in one group at most: a runtime
connection supplies at most one declaration of a group, and one of a `required` group.
`reserves` lists variables the runtime reads a credential from beside the declared ones;
`denies`, variables the runner always leaves out of the server's set for the runtime;
`credential_files`, files in which the runtime keeps a credential of its own, `~` being
the home of the user the runner runs as. The runner checks `secrets` when it reads the
descriptor: the schema, that ids are distinct, and that every id of a group is declared
and in one group at most.

**Fixtures**: `fixtures/<case>/records.jsonl`, records as the runtime produced them, in
the shape of `record.schema.json`, beside `expected/events.jsonl`, one `{type, data}`
per event the rules produce from them, in order. A descriptor without fixtures is not
accepted. The tests validate every record and every expected event against the schemas;
`runtimetest.Replays` replays the records through the runtime and compares.

`runtimes/claude/descriptor.yaml` is the Claude Code descriptor, written against version
2.1.273 as installed and its published hooks reference. Its hooks are the canonical
source in both modes; its standard output adds the result line, which only the output
reports. A descriptor records the version it was written against; the runner
reports that version and does not check the installed one. Its `secrets` declare the
model credential, an API key set as `x-api-key` or an OAuth credential set as a bearer,
on `api.anthropic.com` under `/v1/`, one of the two required.

On a pseudo-terminal, Claude Code with `ANTHROPIC_API_KEY` set waits for a person to
approve the key, unless the configuration it reads lists the key's last 20 characters,
after trimming the space around it, under `customApiKeyResponses.approved`. That
configuration is `.config.json` in `CLAUDE_CONFIG_DIR`, else in `~/.claude`, when the
file exists, and otherwise `.claude.json` in `CLAUDE_CONFIG_DIR`, else in `~`. When the
session is interactive and `ANTHROPIC_API_KEY` is a placeholder of the run,
`claude-settings` writes `approve-key.sh` into the run directory and starts Claude Code
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
approval, and Claude Code starts as it is.

**`runtimes.json`** lists, for a server to vendor, every descriptor this contract ships,
in name order: `version`, 1, and `runtimes`, each with its `name`, `title`, `reserves`,
`denies`, `credential_files`, `declares` with `id`, `title`, `name`, `hosts`, `auth`
(`scheme`, and `header` for the `header` scheme and `username` for the `basic` scheme)
and `paths` when the declaration has some, and `one_of` with `id`, `required` and `of`.
Every list is present, empty when the descriptor has none. `go generate ./contracts`
writes it from the descriptors, and a test fails while the file differs from what that
writes.

## The local socket

`QORY_RUN_SOCKET` is an address, not a path to open: a path, or `unix:` and a path, is
the local socket, and any other scheme selects a transport, which a forwarder without it
refuses with an error that contains the scheme. The local socket is the only transport.
It is a Unix domain socket the runner creates before the runtime starts, in a private
directory of its own under the system's temporary directory, mode `0700`, because a
socket path has a short limit on some systems and a run directory in a deep checkout can
exceed it. A client connects, writes one record per line in the shape of
`record.schema.json`, and closes; the runner reads until end of file, one connection at
a time in the order they arrive, so two hook calls in a row keep their order. There is
no answer and no framing beyond the newline. The forwarder the runner installs as a hook
is one such client; a harness that reports something of its own writes the same shape
with `source: hooks`. Nothing on the socket reaches a receiver except through the
descriptor's rules. The socket is removed when the run ends.

## Images

The agent's image is the machine's to choose, and a run's to select among. The machine
defines images by name, and a run's policy selects one by that name, as it selects
credentials and tools; it contains no reference and defines no image, so a repository never
chooses what it runs under. A run whose policy selects none starts in the machine's
default. Images need a wall: without one the runtime is the machine's own process.

| Definition | Meaning |
|---|---|
| name | what a policy, or the machine's default, selects it by, in a credential's grammar |
| reference | the image, pinned by digest where the machine requires the same image every time |
| runtime | the container runtime the wall starts it under, one the machine's engine has: `sysbox-runc`. Absent is the engine's default |
| docker | the agent gets a Docker daemon of its own inside the enclosure (§The wall). It needs a runtime that runs one without privileges. Experimental |

```yaml
version: 1
egress:
  mode: enforce
  allow: [api.anthropic.com, registry-1.docker.io]
image: with-docker
```

The machine's default is the name of one of its images, or a reference, which starts
under the engine's default runtime with no daemon. A name the machine defines is read
as that image first.

**Refused before the run starts:** a name the machine does not define, a selection
without a wall, an image defined twice, a daemon without a runtime. The image a run
starts in is fixed when it starts: a run configuration that selects another is refused,
and the policy in force stays.

**The record.** `dev.qory.run.started` contains `image`, the reference, and when the image
is one the machine defines `image_name`, `container_runtime` when the definition sets
one, and `docker: true` when the enclosure has a daemon of its own.
`dev.qory.run.policy_applied` contains `image` when the policy selects one.

**What an image provides.** The wall builds no image and changes none. An image runs:

- under any user id the machine assigns it, with no home of its own: `HOME` points at a
  writable place;
- with its authorities in a bundle where the wall looks for one, so the run's
  certificate goes after them (§The wall);
- with the runtime at the path the launch sets;
- with no setuid program or capability needed for its work;
- for a Docker of the agent's own, with `dockerd`, and what it starts, `containerd`,
  `runc` and `iptables` among them, in `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`,
  `/usr/bin`, `/sbin` or `/bin`: the daemon's `PATH` is these directories alone. The
  users and groups the wall passes to the image by name are in the image's own
  `/etc/passwd` and `/etc/group`.

## The wall

A wall is what makes a connection around the proxy fail. It is optional: with none, the
runtime is a process of the machine and enforcement is cooperative (§Limits). With one,
the runtime runs in an **enclosure** and the session runner stays outside it with the
proxy, the policy and the access key secret; the record is written from outside, and the
enclosure sees the run directory read-only. A wall is built by an adapter, one per
container interface; the contract's rules refer to no specific tool and define one list
for all of them.

**What every wall guarantees:**

- no route out of the enclosure except to the session runner's proxy;
- a resolver that resolves nothing outside the enclosure;
- no cloud metadata address, which is a network path to credentials;
- no file of the host beyond the mounts the run lists, and no environment beyond what
  the run passes;
- a user that is not root, no added capabilities, no privileged mode, no host
  namespaces;
- no credential the run's policy selects: a placeholder where a program requires one set
  and the certificate of the run's authority, never a token and never the authority's
  key;
- never the container runtime's own socket: a process that can request a
  container on the host's network from the daemon has left the wall. A mount that is a
  socket, or a directory containing a runtime's, is refused.

When the run has an authority of its own (§Credentials), a wall sets the enclosure's
trust to one bundle, the image's own authorities with the run's certificate after them,
and points the variables programs read a bundle's path from at it: `SSL_CERT_FILE`,
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
inside: behind a wall it is **guarded**, and what is on the runner's machine is not
reached by default. Two rules, in either mode, observe included:

- The link-local range, where a cloud keeps its metadata service, is refused whatever
  the allow list contains.
- The runner's own machine, loopback and every address it has, is refused unless an
  `egress.allow` entry of the policy lists the host itself. A `*.` suffix over it does
  not count, and neither does a name a harness declares under such a suffix: the
  machine's owner decides what is opened on the machine, a repository cannot. A
  local MCP server or model endpoint is reached through the proxy like everything else,
  decided and recorded, when the policy lists it, and the rule that lists it applies
  under observe as well. The session addresses such a server by the machine's host name or
  an alias of it, not by `localhost`, which `NO_PROXY` keeps inside the enclosure.

A refusal the proxy can make without resolving, a literal address or `localhost`, is a
`denied` `dev.qory.run.egress` with the rule `wall:own-address` and a `403`; a name that
resolves to such an address passes the decision, is refused when dialled, and the
runtime gets a `502`. Without the guard the way around a wall is through the proxy.

**What crosses**, all three the session runner's, none containing a credential of the
runner's: the proxy, as a network address; the pseudo-terminal or the pipes, through the
adapter's own command; the hook socket, as a mounted file where a file can cross.

**The relay.** The agent reaches the proxy by a name, through a relay: a process of the
runner's on the enclosure's network and on an ordinary one, listening on a fixed port and
copying every byte to one address fixed when it starts, the proxy's. It reads nothing,
decides nothing and takes no instruction from the agent; the policy stays in the session
runner. It exists because the host is not always where a container expects it: with
the engine in a virtual machine the network's gateway is the virtual machine's, not the
host's. It forwards no packet between its two networks: IP forwarding is off in its
namespace, so what it passes on is the connections it copies and nothing routed
through it.

**A Docker of the agent's own.** *Experimental.* Under the nested runtime the enclosure
has a root, and whether that root reaches the mounts the run lists as the machine's root
is unverified, so the option is experimental: it may change or be
withdrawn in a minor release, and a run that uses it mounts nothing the machine's root
must protect.

An image the machine defines with a daemon (§Images) provides the agent a Docker daemon
inside the enclosure, never the machine's. It needs a runtime that runs a daemon in a
container without privileges: `sysbox-runc`, whose container has a root of its own, in a
user namespace, mapped to a user of the machine's that is not root. The helper refuses
to start the daemon where the enclosure's root is the machine's, which it reads from
`/proc/self/uid_map`, so a runtime without a user namespace is no run. The enclosure
starts as that root, with no privileged mode and `no-new-privileges`, and with the whole
set of capabilities the runtime grants it inside its user namespace, which the daemon
needs; the wall's helper, not the image, starts it: `dockerd` on its Unix socket alone,
never a port of the enclosure's network, the socket in the agent's group, the daemon's
output in a file of its own. The daemon and what it starts run with the system
directories §Images lists as their `PATH` and, of the run's environment, only the proxy
and the run's bundle; the rest of the run's environment, such as a `PATH` into the
workspace or `LD_PRELOAD`, reaches the agent alone. Once the daemon answers, the helper
drops every capability, the bounding set included, becomes the agent's user, and clears
the inheritable and ambient sets. The daemon's store is a volume of the run's, removed
with the enclosure, with no size limit of the run's: the run's limits do not bound it. A
daemon that exits during the run is not started again, and its output is root's inside
the enclosure, not the agent's to read. Three guarantees read differently under it, and
every other stands as written:

- *no added capabilities*: the agent has none, and none to gain. The enclosure's root has
  every capability inside its user namespace, and nothing of the machine's;
- *not root*: the agent runs as a user that is not root. The enclosure has a root, a
  user of the machine's that is not root, and whoever reaches the daemon's socket is
  that root, inside the enclosure and nowhere else;
- *no file of the host beyond the mounts the run lists*: beyond those, and the
  runtime's own. Sysbox adds the machine's kernel modules, read-only, and scratch
  directories of its own, and shows emulated parts of `/proc` and `/sys`;
  `/proc/partitions` lists the machine's disks, none of which opens.

The containers the agent starts are inside the enclosure's network namespace, a
container on the host's network or a privileged one included, so they reach the relay
and nothing else, and what they reach is decided and recorded as the agent's own
traffic. The daemon pulls through the proxy, so a registry is a host the policy allows.
Those containers do not resolve the relay's name: the agent's docker configuration,
`DOCKER_CONFIG` at `/run/qory/docker` unless the run sets a non-empty one, sets the
proxy for them by its address. The directory and its `config.json` belong to the agent's
user, mode 0700 and 0600, inside `/run/qory`, which belongs to root with mode 0755: the
agent's user passes through it and cannot write in it. The helper sets these owners and
modes whatever the umask, and on a `/run/qory` already in the image, and refuses a link
in either place. The containers the agent starts get the run's bundle only when the
agent mounts it into them, and they inherit `no-new-privileges`, so a setuid program in
them gains nothing. Docker in Docker with `--privileged`, and the machine's own socket,
stay refused. gVisor breaks the list: its daemon inside starts only with every
capability added.

**One conformance suite**, the `wall/walltest` package, checks the list from inside the
enclosure with a real session behind the adapter, and an adapter ships when the suite
passes for it. The suite needs Linux and the tool, so it runs in the runner's CI on a
Linux machine; the ordinary tests compare the commands an adapter generates with golden
files and need neither.

**What ships:** `docker`, through the `docker` command and no library, serving whatever
engine that command reaches. It is supported where the suite passes. An engine in a
virtual machine on a Mac is where a wall is developed, not a target: the suite passes
there without the hook check (§Limits). The agent's image is the caller's; the wall
builds none. A Docker of the agent's own is experimental, under `sysbox-runc`, where the
suite passes with it: the runner's CI installs Sysbox on a Linux machine and runs the
suite in an enclosure with a daemon. The suite checks the list as the agent's user; what
the enclosure's root reaches of the mounts the run lists is the open question that keeps
the option experimental.

## Files of secrets and variables

| File | Defines |
|---|---|
| `secrets-request.schema.json` | the body of the signed POST to the configuration's `secrets.url` |
| `secrets-answer.schema.json` | its answer, the envelope: the stored values sealed with HPKE to the access key, signed under the server's key |
| `sealed-plaintext.schema.json` | the plaintext the envelope opens to |
| `enrolment.schema.json` | the enrolment request's body and its answer |
| `events/run.refused.schema.json` | the data of `dev.qory.run.refused`, a run that does not start after the ping, with its refusal code |
| `denied-variables.json` | the built-in deny list of variables, `names` and `patterns`, each matching a whole name regardless of case, `*` matching any run of characters |
| `headers.json` | the header names, `refused`, and prefixes, `refused_prefixes`, refused for a connection's header, in lower case: every field of the IANA HTTP Field Name Registry as updated on 2026-08-28; the Fetch standard's forbidden request headers as of 2026-10-06; `origin`, `content-type`, `x-request-id`, `x-correlation-id`, `forwarded`, `via`, `range`, `user-agent`, `referer`, `host`, `content-length`, `transfer-encoding`, `connection`, `keep-alive`, `te`, `trailer`, `upgrade`, `cookie` and `authorization`; and the prefixes `accept`, `if-`, `x-forwarded-`, `proxy-`, `sec-`, `x-qory-` and `qory-` |

## Fixtures

| Directory | Contains | Validated against |
|---|---|---|
| `fixtures/policy/` | policy documents that are accepted: observe, enforce, enforce with nothing, observe with a deny list, enforce with a tool, a credential and a tool each with an argument of 4096 characters, the most one may have | `policy.schema.json` |
| `fixtures/server/` | server documents that are accepted, with the fixture access key id and the fixture signing key as the pin | `server.schema.json` |
| `fixtures/configuration/` | configuration documents a server returns: events only, with a run section, with a section this revision does not define, with `secrets` and two keys of a rotation | `configuration.schema.json` |
| `fixtures/run-configuration/` | run configuration documents a server returns: with a policy of each mode, with variables, and with neither, which leaves the node's policy in force | `run-configuration.schema.json` |
| `fixtures/batch/` | delivery bodies: the ping, a first batch, the `dev.qory.run.refused` of a run that does not start | `batch.schema.json` |
| `fixtures/signed/` | signed requests, one per file, under the fixture access key secret, with the status a receiver returns and the code of a coded refusal | the receiver, replaying each with its clock at `1700000000` and checking each answer's signature |
| `fixtures/run/<id>/` | recorded runs, `events.jsonl` and `output.log` each: one on a developer machine, one behind a wall that reaches a tool started with an argument, with a credential an adapter mints | `event.schema.json` per line, plus the sequence, source and concatenation rules |
| `fixtures/invalid/` | documents each schema refuses, whose name is `<schema>-<reason>` | the schema the name starts with, expecting a failure |
| `fixtures/sealed/` | the sealed fixture: a run configuration, the secrets request that lists its digest, the envelope sealed to the fixture access key with a fixed ephemeral key, the plaintext it opens to, and `vectors.json` with `info`, `aad`, the ephemeral key and the lengths and SHA-256 of the ciphertext and of the envelope's signed message | `secrets-request.schema.json`, `secrets-answer.schema.json`, `sealed-plaintext.schema.json` and `run-configuration.schema.json`; the open with Go's `crypto/hpke`, and the envelope's signature under the fixture signing key |
| `fixtures/enrolment/` | enrolment requests, with a code that carries one fingerprint and with one that carries two, the answer, and the signed refusals `key_limit` and `key_invalid`, each with one key and during a rotation with two | `enrolment.schema.json`; each proof under the fixture access key, each answer's and refusal's signature under the fixture signing key |
| `fixtures/known-answers/` | `keys.json`, the fixture access key with its secret, instance id and X25519 keys, and the fixture signing keys, current and next; `signatures.json`, the request, enrolment and answer strings line by line with their signatures, the signed enrolment refusals among the answers; `discovery.json`, the body an answer signature covers; `small-order.json`, the public keys enrolment refuses | `configuration.schema.json` for `discovery.json`; each key recomputed from its seed, each signature verified and signed again, each point checked with integer arithmetic |
| `runtimes/<name>/fixtures/<case>/` | descriptor fixtures | `record.schema.json` and the data schema of each expected type |

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
  §3.2 for the absolute-form target a proxy receives. UUID version 7 from
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
