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
object does, because the file is read on its own and its format evolves with the
product. A document addressed by a schema URL, read or written by a program, contains an
integer that guards its reader, because the URL already contains the group and the
generation. The policy, the server document, the documents a server returns and the
descriptor are on this side: the objects the command passes to Forager and the ones a
control plane sends over the wire, and the compose report `qory` writes is versioned
the same way. CloudEvents adds its own `specversion: 1.0`, which is not ours to change.

**Revisions.** This is `v1`, revision 1. Forager sends the revision as one integer:
the header `X-Qory-Contract-Version: 1` on every request to the server, and
`contract_version: 1` in the ping's data. Forager on revision N reads every section
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
3. **Credentials.** The session's environment and files contain none of Forager's. On
   a developer machine the session runs with the developer's own environment, and the
   server's variables only when the launch spec accepts them (§Variables). Behind a
   wall the gateway keeps the credentials the run's policy selects in memory, outside the
   enclosure, and sets each on the requests to the hosts it is for
   (§Credentials): the session reaches a code host and a model endpoint as itself, and
   its environment and files contain at most a placeholder for the credential. The tools
   the policy selects run outside as well, and the proxy sends them the requests to the
   hosts they serve (§Tools).
4. **Liveness.** A heartbeat while the session runs; the exit as the result.
5. **Reporting.** The session's terminal bytes as log chunks, Forager's observations
   as events, the runtime's own output mapped to session events by a descriptor. Every
   event goes to files. When a server is configured, every event its configuration lists
   goes there too. When the caller passes a stream, such as standard output, every event
   goes there as well, as the line `events.jsonl` contains; that is how a run with no
   receiver is followed.
6. **The harness reports over a local socket**, never over a network. A hook the
   runtime calls forwards what it received to the session's socket; the gateway is the
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
  touch behind it is bounded by the credential's own scope, not by the gateway.
- Only proxy-aware programs are seen. The agent CLIs, git over HTTPS, curl, the package
  managers and the language runtimes read the proxy variables; SSH, and any program that
  ignores the variables, is not seen. Without a wall, enforce mode is
  advisory against such a program. Enforcement against bypass belongs to the wall (§The
  wall): the session runs outside and the agent in an enclosure whose only route
  out leads to the proxy. The three outcomes: a connection through the proxy is decided
  by the policy and recorded, on any machine; a connection around the proxy succeeds
  unseen without a wall, and fails unseen behind one. The gateway records what passes
  through it and nothing else; a record of attempts a wall refuses is the container
  layer's own logging, or the network's.
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
  and the egress record are Forager's own and are always there.
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
   values and defaults, and the runtime name. The spec comes from
   the `qory` command, which reads the policy and the server from its own
   configuration; Forager receives nothing about what composed it or where it was
   read.
2. The session creates a run id, a UUID version 7, and the run directory `<id>/` in the
   runs directory the caller passes, else in `.qory/runs/` in the checkout. A walled
   run's runs directory lies outside every place the run binds (§The wall).
3. It validates the server document once, when one is passed; without a pinned
   `apiary_public_key` the run does not start, `apiary_public_key_missing`, before any
   request. It fetches the server's configuration document with a signed `GET` (§The
   server), and verifies every answer's signature under the pin before it reads the
   body or the headers. It posts one `dev.qory.ping` to the events URL the document
   defines and waits for a signed 2xx; heartbeats start once the ping is accepted. A
   fetch that fails, a document the schema refuses, an answer that does not verify, or a
   ping not accepted means the run does not start: a run configured to be observed never
   runs unobserved by accident. The gateway tries the ping and the run configuration up
   to 3 times each as a run opens (§The gateway's link, Tries as a run opens).
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
   answers. It opens the local socket and sets `QORY_RUN_SOCKET` to its path,
   `QORY_RUN_ID` to the run id, and `QORY_HARNESS_HOME` to the harness's home when the
   launch spec has one. Nothing else of Forager's enters the environment but
   the variables (§Variables), the placeholders and, in a walled run, the runtime's
   declared and reserved variables nothing else sets, as empty.
6. It has the runtime prepare the launch (§The runtime): for a runtime that takes hooks,
   Forager's forwarder as a command hook for each event the runtime lists. For Claude
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
9. The program exits. The session drains the socket, so a hook on the runtime's last
   event is still read, emits `dev.qory.run.exited`, waits up to fifteen seconds for the
   sinks to flush, reports what the server has not accepted, and returns the program's exit
   status. A runtime killed by a signal exits as `-1` with `signal` set.

A run may have a time limit. When the runtime still runs at the limit the session stops
it, and `dev.qory.run.exited` contains `reason: timeout` with the state `cancelled`; step 9
is otherwise the same. A denied connection never ends a run; the limit is the one thing
of Forager's that does. A server's `410` never ends a run: Qory Apiary records what a
run reports and never ends a run it did not start, so its signed `410` stops the
deliveries alone, and the run goes on (§The server).

The session stops a runtime the same way at the limit and when its own context ends: a
signal that requests the runtime's exit, then SIGKILL after a grace. The signal is one of
SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2, since runtimes differ in what
each means: one closes its session on SIGINT and drops it on SIGTERM, another the other
way round. So the runtime defines which and how long (§The runtime), the run may set
others over it, and with neither it is SIGTERM and ten seconds. Behind a wall the
enclosure passes the same signal on to the runtime inside.

The run id is Forager's own, a UUID version 7, unless the caller already has one: a
caller's id is a UUID in the canonical lower-case form, since it is every event's
`subject` and the run directory's name, and anything else is no run. What else the caller
identifies the run by, a key in its queue, a repository, an issue, goes in `labels` on
`dev.qory.run.started`: at most 16, a key of 1 to 64 of `a-z`, `0-9`, `_`, `.` and `-`, a
value of at most 256 bytes. Forager reads nothing into them. It copies them into
`dev.qory.run.started`, and no other event repeats them: a receiver joins on `subject`.
It sends them, all of them, on the run configuration request (§The server), and the
server decides which labels identify what the run works on. The `qory` command, for one,
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
and `docker` when the image is one the machine defines (§Images).

When the session and the gateway are two processes, the requests of steps 3, 4 and 8
go to the gateway over its link, unsigned, and the gateway is the node toward the
server (§The gateway's link): the session fetches the link's discovery, opens the run
with a `POST` of its run request, and posts its events without `sequence`; the gateway
sends the ping. No access key and no server key pin are on the link.

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

Only `dev.qory.run.started` contains `about` among the events. Toward the server,
`about` is never sent on the run configuration request; on the gateway's link the run
request contains it (§The gateway's link). It never selects a policy. An empty `about`
is left out.

## The policy

`policy.schema.json`. The document the command passes to Forager, from the machine's
own configuration, never from inside the checkout, where the agent it constrains can
write it: for `qory`, the `gateway.egress` section of `~/.config/qory/forager.yaml`.
The same document a server's run configuration contains as `security_policy` (§The
server), so nothing is designed twice.

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
| `egress.allow` | under `enforce`, a host passes only when the allow list of every side under `enforce` covers it; a side under `observe` allows every host its `deny` leaves open. Forager reports the entries of each side under `enforce` that every other such side's list covers, the server's first, each entry once, which is exactly the hosts both allow; with neither side under `enforce`, the server's entries |
| `egress.deny` | the union: a host either side's `deny` covers is denied, in either mode, and recorded with that entry as its rule |
| `egress.paths` | a host either side lists is terminated, and a request to it must match an entry of every side that lists its host. The run's mode decides what a miss does: under `enforce` it is denied; under `observe` it passes; either way it is recorded with an empty `path_rule`. A request every such side matches is recorded with the narrowest entry that matched |
| `tools` | the server's selection, narrowed by the node's `tools` member: absent, it leaves the selection as it is; present, each selected tool must be listed in it by name, and by argument when the node's entry has one, so `tools: []` allows none. A selected tool outside it is no run, `tool_unknown`, as a tool the node does not define |
| `credentials` | the server's selection, narrowed by the node's `credentials` member as `tools` is; a selected credential outside it is no run |
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
match: observe mode sends no secret to a path nobody configured. The host
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
and guarantees nothing about the rest. The rest is bounded by the credential's own
scope, or by what serves the host, and whoever writes the policy for a host that accepts
such requests checks them there or leaves the host out.

## Credentials

A credential is a secret the gateway keeps outside the enclosure and sets on the
requests it applies to; the session's environment and files contain at most a
placeholder for it.
The machine defines credentials; the run's policy selects among them by name and
defines none, so whoever writes a policy chooses among the programs the machine's owner
installed and never specifies one. They need a wall: without one a program that ignores the
proxy is bound by nothing here.

A definition defines where the secret comes from, exactly one of:

| Source | The secret is |
|---|---|
| `env` | a variable of Forager's own environment, read once when the run starts |
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
host's GraphQL endpoint, is not reached. A definition may set `hosts` and `paths` of its
own for an adapter: the most the adapter may claim. For `env` and `file`, which have no
adapter to define the use, the definition's `hosts`, scheme and `paths` are the use
itself.

Before the run starts every selected credential is resolved, and any of these is
no run: a name the machine does not define, an argument it does not provide for, a host
two credentials claim, a claim above the definition's, and under `enforce` a host the
run's allow list does not cover. The gateway runs an adapter again five minutes before
`expires_at`, and when a host returns 401 to a request it set the secret on, at most
once every thirty seconds. The new answer changes the secret and nothing else: one
that lists other hosts, schemes or paths is refused and reported, and the old secret
stays, because what a run reaches is fixed when it starts.

**Placeholders.** A program often needs a credential set to start. A
definition, or an adapter's answer, lists variables the enclosure gets with the value
`qory-sets-the-credential-outside-the-enclosure`, which is no credential anywhere; the
proxy replaces what the program sends. A run that passes a value of its own for such a
variable does not start.

**Termination.** For the hosts the credentials are for, and the hosts with path rules,
the proxy ends the session's TLS itself, answering as the host with a certificate of an
authority created for the run. The authority's key is in the gateway's memory and nowhere
else, and gone with the run; its certificate is what the wall adds to the enclosure's
trusted bundle (§The wall). The proxy verifies the real host against the machine's own
roots. Every other host stays a tunnel the proxy does not read, and a run with no
credential and no path rule has no authority at all.

**The record.** `dev.qory.run.policy_applied` contains each use, `name`, `argument`,
`hosts`, `scheme` and `paths`, and the `terminated` hosts. `argument` is the policy's
argument to the credential, the same on every use of one credential and absent when the
policy passes none, so the record shows what each secret is minted for, such as the
repositories of a source code host. On a terminated host `dev.qory.run.egress` is one
event per request, `method: HTTPS` with `request_method`, `path` without its query,
`path_rule`, and `credential`, the name of the one the proxy set. No event, no report
and no error contains a secret.

## Tools

A tool is a program of the machine's that serves hosts, for what a run reaches that
needs more than a secret in a header: a request signed with a key that stays outside the
enclosure, a protocol with an exchange of its own, a service that exists only on the
machine, such as an MCP server. Forager implements no protocol and a tool implements
one, so no protocol, cloud or provider enters Forager. The machine defines tools; the
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

**Starting.** Before the runtime starts, the gateway starts every selected tool outside
the enclosure: the command, with `${argument}` replaced by the argument, one word of the
command line and never a shell's; Forager's own environment, without the variables
the machine's credentials are read from and without the access key's,
`QORY_ACCESS_KEY_SECRET`, `QORY_ACCESS_KEY_ID` and `QORY_APIARY_PUBLIC_KEY`, with
`QORY_TOOL_LISTEN`, the path of a Unix
socket in a private directory of Forager's, mode `0700`, and `QORY_RUN_ID`. The tool
listens there within a minute; one that exits first, or does not listen in time, is no
run, and the last line it writes to standard error is the reason reported. Once it
listens, what it writes to standard error is reported as Forager's own lines and its
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
path is not read by the gateway, and the tool checks it; the runtime's hooks report the MCP call an agent makes
(`dev.qory.session.tool_started`).

## Variables

A run's variables reach the agent's process alone. The session adds them to the launch's
environment; the tools, the relay, the agent's Docker daemon and the wall's `docker`
command keep their own environment.

**The order.** Several sources may set one name. For each name the run takes the value
of the highest source that sets it:

| Source, highest first | What it is | In the launch spec, Go |
|---|---|---|
| `fixed` | Forager's own names, `QORY_RUN_ID`, `QORY_RUN_SOCKET` and `QORY_HARNESS_HOME`; the proxy's (§Sequence step 5); the names the wall sets (§The wall); the runtime's preparation (§The runtime); the placeholders (§Credentials, §Tools); and the values the harness computes itself | `Spec.HarnessHome`, `Spec.LaunchFixed` |
| `apiary` | the server's: the run configuration's `variables` | |
| `run` | the run's own variables, `qory run --env` | `Spec.Variables.Run` |
| `machine` | the machine's variables, the `wall.env` of `forager.yaml` | `Spec.Variables.Machine` |
| `harness` | the harness's written defaults | `Spec.LaunchDefaults` |
| `shell` | the environment the run inherits | `Spec.Env` |

The server resolves its variables among its own levels, a lock included, and sends the
resolved values alone, a name and a value each; Forager reads no level. So the
server's value of a name wins over the node's whenever the run applies it, and a node
source applies to the names the server leaves alone and to a name whose server value is
left out.
Among the fixed names, Forager's, the proxy's, the wall's, the preparation's and the
placeholders win over the harness's computed values. Names are compared exactly between
sources; the deny list matches regardless of case. A value that loses is left out, the
record lists it with its source and the reason (§The record of the variables), and the
run starts.

**Refusals first.** Before it resolves anything, the session checks every value the node
passes: what the run inherits, the harness's computed values and defaults, and the run's
and the machine's variables. They keep the node's secrets and the stand-ins out of the
enclosure. A walled run that passes a `QORY_` variable, or a variable a value of the
machine's is read from, into the enclosure is no run, `variable_reserved`; `QORY_RUN_ID`
and `QORY_RUN_SOCKET` are exempt. So `--env QORY_X` or `wall.env: [QORY_X]` behind a wall
stops the run. A run that passes a value for a placeholder is no run,
`placeholder_conflict`, with or without a wall. These are the only refusals of the
variables. `QORY_HARNESS_HOME` is Forager's own when the launch spec has a harness
home, and the session sets it after the check. Behind a wall, a value any node source
passes for it is `variable_reserved`, as any `QORY_` name is. Without a wall, the deny
list leaves out a value of the server, the run, the machine or the harness for it, and
Forager's value wins over the one the run inherits: the record lists that one as
`shell`, lost as `fixed`, when another source set the name too.

**Denied names.** The deny list leaves out a value of the server, the run, the machine
or the harness's defaults whose name it matches: the built-in list
`denied-variables.json`, the run's runtime's `denies` (§The descriptor), and the names
the node's owner adds in the launch spec, `Spec.Variables.Deny` in Go, such as `[NAME,
PREFIX_*]`. The built-in entries apply to the harness's computed values as well, so a
computed `DOCKER_HOST` or `NODE_EXTRA_CA_CERTS` is left out too; the runtime's `denies`
and the node's entries leave them in, since the harness computes such values for the
runtime. What the run inherits is matched against no entry: it is the developer's own
environment. A denied value is left out, recorded as `denied`, and the next source's
value of the name applies. Each built-in entry undermines the wall, the proxy or
Forager. An entry is a name or a pattern, `^[A-Za-z0-9_*]{1,128}$` with at least one
character other than `*`. It matches a whole name: `*` matches any run of characters,
the empty run included, anywhere in the entry. Matching ignores case, because programs
read `http_proxy` and `HTTP_PROXY` alike. `denied-variables.json`, `{"version": 1,
"names": [...], "patterns": [...]}`, is the built-in list for every source the deny list
covers, the harness's computed values included. It holds every row of the table but the
two that depend on the node and the run: the names the wall sets for the run's bundle,
and the runtime's `denies`, which `runtimes.json` lists.

| Name | Why |
|---|---|
| `QORY_*` | Forager's own |
| `*_PROXY`, `NO_PROXY` included, in any case | the session sets the proxy variables (§Sequence step 5), and any other routes around the proxy |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE`, `GIT_SSL_CAINFO` | the wall points them at the run's bundle (§The wall), and another value would replace it |
| `SSL_CERT_DIR`, `GIT_SSL_CAPATH` | they point the same programs at another store beside the bundle the wall sets |
| every name the wall sets for the run's bundle | the node's own names for the run's bundle |
| `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY` | they choose the daemon a Docker of the agent's own reaches, and how |
| `DOCKER_CONFIG` | the wall sets it for a Docker of the agent's own |
| `PATH` | the enclosure resolves the launch's program through it, and which program runs is the node's choice (§Images) |
| the run's runtime's `denies` | they move the runtime's model credential or run its commands (§The descriptor) |

**Also left out.** A value of any source below the fixed names for a fixed name is left
out and recorded as `fixed`: the fixed value applies. The server's value of a variable
the run's runtime declares or reserves, where the stand-in or an empty value goes, and of
one a value of the machine's is read from, such as a credential's `env` (§Credentials),
whose value stays outside the enclosure, is left out and recorded as `denied`. A value
the node passes for a variable the runtime declares or reserves reaches the runtime as
passed. Behind a wall, every variable the runtime declares or reserves that neither a
placeholder, a source nor the runtime's preparation sets goes into the enclosure as an
empty value, so an image's own `ENV` cannot set one.

**Unwalled runs.** The launch spec decides whether an unwalled run receives the server's
variables, `Spec.Variables.Unwalled` in Go: `ignore`, the default, or `accept`. With
`ignore`, an unwalled run starts without them; each is recorded as `unwalled`, and the
node's sources apply. With `accept`, they apply as in a walled run, the deny list first.
The deny list protects the wall and Forager, not the developer, so `accept` opens the
developer's shell to the server. The run's own variables apply with or without a wall.

**The record of the variables.** `dev.qory.run.policy_applied`'s `variables` lists the
run's variables by name, never a value, sorted by name: each `name`, `from`, the source
whose value the run applies, and `lost`, the values left out, the highest source first,
each with its source, `from`, and the reason, `why`: `overridden`, `denied`, `fixed` or
`unwalled`.

```json
[{"name": "HARNESS_PROFILE", "from": "harness", "lost": []},
 {"name": "LOG_LEVEL", "from": "apiary", "lost": [{"from": "run", "why": "overridden"}]},
 {"name": "PATH", "lost": [{"from": "machine", "why": "denied"}]}]
```

- A name is listed when the server, the run, the machine or the harness's defaults set
  it, and when the built-in list leaves out a value the harness computed.
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

The types, one namespace. Forager's own:

| Type | When | Data |
|---|---|---|
| `dev.qory.ping` | before the runtime starts, to the server's events endpoint only, when a server is configured | `forager_version`, `events`, `contract_version`, `interval_seconds` |
| `dev.qory.run.started` | the run is open: the runtime is about to start, or a gateway opened the run; `dev.qory.run.started` or `dev.qory.run.refused` is the first event after the ping, heartbeats aside | `opened_by`, `credential`, `forager_version`; opened by a session `runtime`, `runtime_version`, `command`, `args`, `dir`, `interactive`, `host`, on a pseudo-terminal `terminal`, behind a wall `wall`, `image`, and when the machine's definition sets them `image_name`, `container_runtime` and `docker`; and `labels` when the caller passes any, and `about` when the caller passes one |
| `dev.qory.run.policy_applied` | right after, once; again at the sequence where a new run configuration takes effect | `mode`, `allow`, `deny`, `source`, `variables`, and with them set `url`, `digest`, `run_configuration`, `node_policy`, `harness_hosts`, `paths`, `credentials`, `tools`, `image`, `terminated` |
| `dev.qory.run.log` | one per chunk of output: on pipes one line or 4096 bytes, on a pseudo-terminal 4096 bytes or a quiet gap of 50 ms, whichever comes first | `stream`, `bytes` |
| `dev.qory.run.resized` | the pseudo-terminal was resized, at the sequence where the new size takes effect; never on pipes | `cols`, `rows` |
| `dev.qory.run.egress` | one per connection through the proxy, allowed or denied; on a terminated host one per request, and on a host a tool serves one per tool invocation | `host`, `port`, `method`, `decision`, `outcome`, `mode`, `rule`, and per request `request_id`, `status`, `request_method`, `path`, `path_rule`, `credential`, `tool` |
| `dev.qory.run.heartbeat` | every `interval_seconds` from the accepted ping until the final event, or from `dev.qory.run.started` when the run has no server; `elapsed_seconds` counts since the ping, or since `dev.qory.run.started` when the run has no server | `elapsed_seconds`, `interval_seconds` |
| `dev.qory.run.exited` | the run ended: the runtime exited, or the run ended without one; the result and the last event, as `dev.qory.run.refused` is the last of a refused run | `state`, `exit_code` on a session's run, `signal`, `reason`, `quiet_seconds` when `reason` is `quiet`, `duration_ms` |
| `dev.qory.run.refused` | the run was refused before it started; in place of `dev.qory.run.started`, the first event after the ping where there is one, heartbeats aside, and the last. The session writes it: when a gateway refused the run request, with the code in its answer on the link, which opens no run at the gateway, recorded in the session's own record alone, and nothing reaches the server for it; when a gateway's `410` closed the run before the runtime started, with the `410`'s code, `session_lost`, `batch_refused`, `credential_expired`, `stopped`, `credential_check_unreachable`, `credential_check_invalid` or `run_closed`, and `status` `410`, in the session's own record alone; when the session fails after the gateway's run answer and before its process starts, posted on the link too, and the gateway delivers it | `code`; for a gateway's `410` its code and `status`, `410`; for a gateway's refusal its code and, when it lists any, `names`, `credential_check_unreachable` for its `503` and `credential_check_invalid` for its `502` among them; for a refusal of the server's its code and `status`. A code without `status` is one of the schema's list; a code of the server's, with its `status`, is kept as the server sent it, one the list does not hold yet included, and a receiver shows a code it does not know as it is |

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
Forager adds no rule of its own here. Behind a wall only the variables a run lists go
in, so such a variable is listed like any other; and the run's stop signal and grace are
what the runtime has to close such work when the session stops it.

Every session event that comes from a hook may contain `agent_id` and `agent_type` when
it happened inside a subagent; `dev.qory.session.result`, read from the runtime's
output, contains neither. The schema of each type, under `events/`, defines which fields
are required and what each contains. Values are copied from the runtime unchanged:
`input` and `response` have the tool's own shape, `error` is display text, and the
enumerations in `source`, `reason`, `kind`, `outcome` are the runtime's words.

**What opened the run.** `dev.qory.run.started` contains `opened_by`. `session`: a
Forager session around a runtime opened the run, and the event contains `runtime`,
`command`, `args`, `dir` and `interactive`, and the members the table lists with them.
`gateway`: a gateway opened the run, on a run credential a client presented through its
proxy, with no session. The run has no process, so the event contains none of
`runtime`, `runtime_version`, `command`, `args`, `dir`, `interactive`, `terminal`,
`host`, `wall` and `image`, and the run's `dev.qory.run.exited` contains no `exit_code`,
only its `state`. `forager_version` is the version of what opened the run: the gateway's
for a run a gateway opened. Such a run's `labels`, `run_key` among them, and
`about.details` come from the run credential's mapping. It gets the credentials, the
tools and the path rules its policy selects, as a session's run does; the gateway's
proxy reads inside HTTPS for them with the gateway's own certificate authority, which
the clients' machines trust.

**Where the run's credential came from.** `dev.qory.run.started` contains `credential`,
which the gateway decides: `starter`, the run's starter gave the run its run credential,
for a session's run behind a separate gateway and every run a gateway opened; `none`,
the run has no run credential, for a run on the local link. A session copies it from the
run answer. Nothing else of the run's starter is reported: no name, claim, key or
lifetime.

**How a run ends.** Every `dev.qory.run.exited` contains `state`, how the run ended:
`succeeded`, the run ended well; `failed`, it ended badly; `cancelled`, it was stopped
before it said how it went. It is the same for a session's run and for a run a gateway
opened. A session's runtime that exits by itself is `succeeded` on exit status 0 and
`failed` otherwise, a signal included, unless the run's starter gives an outcome at the
exit (§The gateway's link, The outcome at the exit). A run its starter ends with an
outcome has that outcome (§Run credentials, How a run's starter says how it ended).

`reason` says why the run ended, when it ended other than by the runtime's own exit, or
gives the reason the run's starter gave. It is an open code: a lower-case letter, then
lower-case letters, digits and `_`, up to 64 characters, `^[a-z][a-z0-9_]{0,63}$`.
Forager's own codes are reserved: `timeout`, `quiet`, `credential_expired`, `stopped`,
`session_lost`, `gateway_lost`, `batch_refused`, `credential_check_unreachable` and
`credential_check_invalid`; and so are three old names, which Forager never writes:
`run_ended_at_issuer`, `issuer_unreachable` and `issuer_answer_invalid`. Any other code
is the starter's, carried as given, and a receiver shows a code it does not know as it
is. A starter's reason that equals a reserved code is dropped, and the run has no
reason, its outcome kept. The session writes `timeout`, the resend of a record writes
`gateway_lost` (§The server), and the gateway writes the others, on a run with no
session and on a session's run on its link alike. The state of each of Forager's own
endings:

| Ending | `state` | `reason` |
|---|---|---|
| the run's starter answered that the run credential is no longer active, with an outcome | that outcome | the starter's reason, or none |
| the starter answered so with no outcome, or ended so another run of the same run key, which the gateway then holds (§Run credentials) | `cancelled` | `stopped` |
| the run's time limit was reached, and the session stopped the runtime | `cancelled` | `timeout` |
| a run with no session had no connection for the gateway's quiet period, which `quiet_seconds` contains | `cancelled` | `quiet` |
| the run credential's `exp` passed with no fresh credential for the same run key | `cancelled` | `credential_expired` |
| the gateway heard nothing from the session for 3 × its heartbeat interval | `failed` | `session_lost` |
| the gateway was lost before the run's exit was recorded, because Forager died; written when the record is sent again, `duration_ms` to the last event recorded | `failed` | `gateway_lost` |
| the gateway refused a batch of the session's (§The gateway's link) | `failed` | `session_lost` in the gateway's record, `batch_refused` in the session's own |
| the run credential could not be checked: the introspection endpoint could not be reached after the gateway's tries | `failed` | `credential_check_unreachable` |
| the run credential could not be checked: the introspection endpoint gave no valid answer | `failed` | `credential_check_invalid` |

`stopped` is written only when the starter gave no outcome. Neither check of the run
credential holds the run key. On a session's run the session records, in its own record
alone, how the gateway's `410` says the run ended: its `state` and `reason`, but
`batch_refused`, its code, after a refused batch; a `410` without a `state`, `run_closed`
among them, the gateway's `410` to a run that had already ended there, is recorded as
`failed` with its code as the reason (§The gateway's link, The end of a run at the
gateway). `batch_refused` and `run_closed` are in no record but the session's. A
session's run always contains `exit_code`: the runtime's exit status, and `-1` with
`gateway_lost` and in every `dev.qory.run.exited` the gateway writes for it, since no
exit status was recorded; the session's own record of the gateway's `410` has the
runtime's exit status. A run a gateway opened contains no `exit_code`, `gateway_lost`
included.

`dev.qory.run.policy_applied` records where the policy comes from: `source` is `none`,
`config` or `fetched`; `url` is where the run configuration was fetched from, and
`run_configuration` the server's digest of it as its header contained it, with
`fetched`, and with `config` or `none` when the run configuration has no
`security_policy`; `digest` is Forager's own hex sha256 of the policy document's
canonical JSON, with `config` and `fetched`; `allow` and `deny` are the policy's two
lists as written, `deny` the hosts denied by name in either mode, and when the node's
policy narrows a server's, the lists the narrowing computes (§The policy). Behind a
separate gateway, for a policy a session's `narrowing` narrows (§The gateway's link),
`source` is the source of the policy it narrows, `config` or `fetched`, with that
policy's `url` and `run_configuration`, and `digest` is the narrowed policy's own; a
narrowing of no policy has `source` `config`, the narrowing coming from the session's
configuration.
`node_policy`, present when the run has both a fetched policy and a policy the command
passes, contains its `digest`, `sha256=` and the lower-case hex SHA-256 of the RFC 8785
serialisation of that `policy.schema.json` document, and its `paths`, when it has any,
so the record shows both sides of every path rule. `variables` lists the run's
variables by name, never a value: each with the source whose value the run applies and
the values that lost, with their sources and why (§Variables, the record of the
variables). `dev.qory.run.egress` records what becomes of the
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
Forager's own terminal's when it has one, 80 by 24 otherwise. Every change after that is
one `dev.qory.run.resized` with the new size, at the sequence where it takes effect: what
the gap has buffered is cut before it, so the chunks before it were written to a terminal
of the old size and the chunks after it to one of the new. On pipes there is no
`terminal` and no resize.

## The record files

The run directory, `<id>/` in the runs directory (§Sequence step 2); in the checkout, the
compose keeps it out of git:

- `events.jsonl`: every event of the run, one per line, in sequence order, the ping
  included when one is sent. The record of truth; the server's is a copy.
- `output.log`: the raw bytes of the session's output, the concatenation of the
  `dev.qory.run.log` chunks. Both files tail.
- `settings.json`: the runtime's settings with Forager's hooks added, when hooks
  are installed.
- `undelivered/`: the batches the server has not accepted, when there are any.

The gateway writes `events.jsonl`, with its `delivered.log` and `undelivered/` (§The
server, After Forager stops unexpectedly); the session writes `session.jsonl`, its own
record, numbered by its own sequence (§The gateway's link), and `output.log`. On one
machine they share a run directory when the gateway writes its record in the session's
runs directory. Behind a separate gateway each machine has a run directory of its own. The gateway's machine holds `events.jsonl`, `delivered.log`
and `undelivered/` toward the server. The session's machine holds `session.jsonl`,
`output.log` and `settings.json`, and its delivery state toward the gateway:

- `delivered.log`: what the gateway accepted of `session.jsonl`, a line per batch as the
  gateway's answer comes, the delivery id and the session's sequence of each event in
  it, and the one word `stopped` when an answer of the gateway's ended the run. The
  session creates it once the gateway opened the run.
- `undelivered/`: the session's batches the gateway has not accepted, when there are
  any.

Neither holds the run credential. `run-secret`: behind a separate gateway, the run's
`run_secret`, mode 0600, written when the run opens; it is removed once nothing is owed.

`fixtures/run/<id>/` are such directories, recorded. Qory Apiary's CI replays them.

## The server

`server.schema.json`. The document the command passes to Forager, from the machine's
own configuration: for `qory`, the `gateway.server` section of
`~/.config/qory/forager.yaml`, with the access key secret from the file descriptor
`--access-key-secret-fd <n>` names, else `QORY_ACCESS_KEY_SECRET`, else the file
`access-key-secret`. Forager is a client of the server defined here, its session a
client of its gateway's link (§The gateway's link), and of nothing else: it fetches the
server's configuration, posts its events to the URL it defines, and takes the server's
policy for the run, which the node's narrows, and the run's variables from the server
when the server offers them. A server is a control plane, or a plain receiver that
implements this section: discovery and the events endpoint are enough. Configuring one
makes the run fail closed on the discovery fetch and on the ping.

```yaml
version: 1
url: https://qory.example             # https, or http to a loopback address; scheme and host[:port] only
access_key_id: ak_f1xt0re000000000    # ak_ and 16 lower-case Crockford base32 characters
apiary_public_key:                    # the pin: the server's Ed25519 keys, one or more
  - {alg: ed25519, public_key: rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc}
```

`url` is the server's origin and nothing after it: no path, no query, no fragment.
Forager finds every endpoint through the configuration document under it.

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
enrolment, and the fixture signing keys as its own key. A second fixture access key,
the seed being bytes 193 to 224, whose public key is
`dSnEVtk40rj-kPpsz5FtNGdwpkvLt7UyO2h6zeIM0Aw`, has its secret published in the
`accesskey` package's tests and in this repository's history, and every side refuses it
as it refuses the fixture access key. A fingerprint, of an access key's public key or
of the server's, is `base64url(SHA-256(raw public key)[:16])`, 22 characters. The
`accesskey` package decodes every base64url value it reads strictly: an access key
secret's seed, a public key, a fingerprint in an enrolment code, a signature and a
proof. A value with padding, a character of the standard alphabet (`+` or `/`), a line
break, non-zero bits after its last full byte, or a length other than its own is
refused.

**Nodes and instances.** An access key belongs to a node, `nd_`, a permanent machine
that runs one instance at a time, or to a node pool, `np_`, whose instances share the
access key, up to a limit the pool may set; each id is followed by 16 lower-case
Crockford base32 characters. An instance is one running copy of `qory` with the access
key. Its instance id, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, is a signed line of every
request, for display, audit, per-instance events and the instance limit; authorisation
rests on the access key alone, and whoever holds the access key can claim any instance
id. `qory` generates `i_` and 16 bytes from the system's random source in base64url, 24
characters, and keeps the id in the file `instance-id`. It writes two lines, each ended
by a line feed: the id, and the lower-case hex HMAC-SHA256, keyed with `qory
instance-id v1`, of the machine's identity, `/etc/machine-id` on Linux, `IOPlatformUUID`
on macOS, else the host name, as machine-id(5) recommends, without the white space
around it. It reads the two lines with or without the final line feed. A file that is
not exactly two lines, whose first line is outside the pattern or contains an access
key secret, or whose second line is not this machine's hash, yields a new id, so a file
copied to another machine yields a new id there. The instance's
display name, the host name by default, is sent unsigned and serves display alone. A
ping from a new instance id beyond its node's limit is a signed `409` `instance_limit`,
and that run does not start; an instance counts while one of its runs is live. For the
server, a run is live from its accepted ping until its final event,
`dev.qory.run.exited`, or until it has no recent heartbeat: none within 3 × the
`interval_seconds` its ping announced. A heartbeat is as recent as its own `time`,
corrected by the run's clock offset (the smallest arrival time less `time` over the
run's heartbeats), plus a tolerance of 300 seconds, and never more recent than its
arrival. So a backlog delivered late keeps no run live, and a clock that runs ahead
holds nothing live. The gateway's link judges a session by arrival alone (§The
gateway's link, Heartbeats and liveness): there, "the session lives" is not the
server's "live".

**The pin.** `apiary_public_key` lists the server's Ed25519 public keys, a list so the
server's key can rotate. Every answer of the server, to discovery, to the run
configuration and to every delivery, is verified under the pin before its body or its
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
  at every other. No timestamp is signed on a POST and no replay window is checked: a
  replayed batch is a duplicate the receiver already discards by event id.

The signature covers the access key id, the instance id, and the method, the target and
the timestamp of a GET, or the method, the target and the body of a POST.
`User-Agent`, `Content-Type`, `X-Qory-Contract-Version`, `X-Qory-Instance-Name`,
`X-Qory-Delivery` and `X-Qory-Run-Configuration` are unsigned: the server takes every
authorisation decision from the signed lines and the body. Two known answers, under
the fixture access key secret and the instance id `i_gYKDhIWGh4iJiouMjY6PkA`, line by
line in `fixtures/known-answers/signatures.json`:

- the 115-byte message
  `qory-request-ed25519-v1\nak_f1xt0re000000000\ni_gYKDhIWGh4iJiouMjY6PkA\nGET\n/.well-known/qory-configuration\n1700000000`:
  `H9XeK0R-KWGvQNITRP01Fh9_62ATGKd7rTgehaIPjcYYM374LrKzswcmQRYO0m-2UHx6NJJxWT3rk0HL4sD_CQ`;
- the same with the target `/.well-known/qory-configuration?x=1`, 119 bytes:
  `XNhwjf5F3CaZENTcEE2J8U1eCk4dh0y0IdZdSMf6rJqdTZMN8lNq1a98GGIPiiVn3Mh0EPGEDFzRI12zMDMRBQ`.

**A signed POST**, after [GitHub's model](https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers).
One `POST` per batch to the events URL, with the headers above and:

| Header | Value |
|---|---|
| `Content-Type` | `application/cloudevents-batch+json` |
| `X-Qory-Delivery` | a UUID per batch. A retry of the same batch contains the same id, and an id is never used for other events: a batch cut again, after a restart or a resend, has a new id |
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
request, nor the reverse. At run start Forager treats an answer without a valid
signature under the pin as no run, `answer_unsigned`; during the run a delivery's answer
without one is no answer, retried as any other with its headers unread, and a reload's
fetch without one fails the reload. Forager reads a body's code only from a signed
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
event ids the server already accepted gets the same `2xx` again; `410` for an event of a
run the server wants nothing more of; then, for a ping alone, `409`
`instance_limit`.

**Failure.** Every authentication failure is `401` with the body
`{"error":"unauthorized"}` and nothing more, unsigned: a missing or empty
`X-Qory-Access-Key-Id` or `X-Qory-Signature-Ed25519`, an access key id of the wrong
shape, an access key the server does not recognise or has revoked, a timestamp that is
not an integer, a stale timestamp, a signature that does not verify. The body never
indicates which, and Forager reports every `401` as `unauthorized`. The server
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
the key checked first. Then, signed: `429` `rate_limited` per code; `409` `key_invalid`
for a key already enrolled, a revoked one included; `409` `key_limit`; and `201`. The
server signs an answer only to a proof that verifies under a key the checks pass, so a
proof no key made, such as one under a key of small order, which plain Ed25519
verification accepts for any message, gets no signed answer. The `201` answer contains
the access key id, `node_id` with `node_kind`, `stored_secrets`, true for an access key
allowed stored secrets, and the server's keys,
signed as Signed answers describes under `qory-enrol-answer-ed25519-v1` with the
request's `proof` as line 3; the machine verifies it under the listed key whose
fingerprint the code carries first, and pins only the keys whose fingerprints the code
carries. A `201` means the access key is active: the code's use activates it. A `401`
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
 "events": {"url": "https://qory.example/v1/events", "types": ["*"]},
 "run": {"url": "https://qory.example/v1/run-configuration"},
 "apiary_public_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
```

`version`, `node_id`, `events` and `apiary_public_key` are required. `node_id` is the id
of the access key's node or node pool, `^n[dp]_[0-9a-hjkmnp-tv-z]{16}$`, listed for
display: `qory` prints it. `apiary_public_key` lists the server's current key, and
during a rotation the next one, for information: Forager verifies under its pin alone.
`secrets` is optional, `{url}` with `run.url`'s grammar: present for an access key
allowed stored secrets, and a server that lists it requires a wall for every run. Discovery lists no key endpoint: keys change through
enrolment alone. A `401` is no run, `unauthorized`. `events.url` is `https`, or `http` to a loopback
address; `events.types` is a non-empty list of full type names, or `*` for every type,
and the ping is always sent. `run` is optional: a server whose document has no `run` section
offers no run configuration, and the policy is the machine's. A top-level member
Forager does not recognise is ignored, which is how a new revision adds a section.

**The run configuration document.** `run-configuration.schema.json`. A signed `GET
<run.url>?<the run's labels>`: one query parameter per label, the label's key as the
name and its value as the value, a label with an empty value as `key=`, and no query
when the run has no label. The parameters are sorted by key and percent-encoded as a
form is, a space as `+`, so a run labelled `forge: github.com`, `issue: "77"` and
`repository: acme/shop` fetches
`<run.url>?forge=github.com&issue=77&repository=acme%2Fshop`. When `run.url` has a query
of its own, the labels are added to it, and a label replaces a parameter of the same
name. The server decides which labels identify what the run works on and returns the
policy for that; Forager reads nothing into them. The labels are bounded, at most 16,
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
 "variables": {"NODE_ENV": {"value": "test"}, "APP_REGION": {"value": "eu-west-1"}}}
```

`version` is required; `security_policy` and `variables` are optional. `security_policy`
is a `policy.schema.json` document, and it is the server's policy; the policy the
command passes, when there is one, narrows it (§The policy, a node narrows). Without
`security_policy` the policy the command passes is the run's, else observe everything,
and `dev.qory.run.policy_applied` reports `url` and `run_configuration` beside `source`
`config` or `none`; a reload that brings a `security_policy` puts it in force, narrowed
by the command's, and one that drops it puts the command's back. `variables` are the
server's variables for the run, a name and an object with its string `value` each
(§Variables). A member
Forager does not recognise is ignored. The digest is the server's and opaque;
Forager keeps it, sends it back on every POST, and never recomputes it. Forager reads
the document with a decoder that refuses a member name that appears twice and invalid
UTF-8, then against the schema and the limits, and its error states where in the
document and which rule refused it, never a value. Anything but `200`, or a document
Forager refuses, is no run, `run_configuration_invalid` for the latter. On the gateway's
link the run configuration is a `POST` of the session's run request, and its answer is
the gateway's (§The gateway's link).

**Delivery.** The body of a POST is a `batch.schema.json` document: a JSON array of
events of one run, in sequence order, never empty. Forager cuts a batch at one
hundred events, at one mebibyte, or after one second since its first event, whichever
comes first; the ping is a batch of one, sent before anything else, with the heartbeat
interval the run uses, `interval_seconds`, at most 300. A receiver verifies the Ed25519
signature over the request string before parsing, then deduplicates on each event's
`id`, since delivery is at least once.

Forager reads a body's code only from a signed answer:

| Status | Meaning |
|---|---|
| 2xx, signed | accepted; Forager forgets the batch |
| 409 to the ping, signed, such as `instance_limit` | no run, with its code |
| 410, signed, with any code or none | stop: the server requests nothing more for this run. Forager sends no further batch and the run continues on the file sink. A `410` to the ping, signed or not, is no run: the ping was not accepted; to the run configuration as the run opens, signed or not, it is a failure without a code |
| anything else, an answer that does not verify, or no answer within ten seconds | retried with exponential backoff, one second doubling to one minute, until the run ends |

Every answer may contain `X-Qory-Configuration` and `X-Qory-Run-Configuration`, the
digests in force: of the configuration document, and of the run configuration for the
run's labels. Forager compares each to the one it keeps. A different
run-configuration digest means fetch the run configuration again and apply it; a
different configuration digest means fetch the configuration document again and use
its sections for the batches that follow: the events URL and the filter. A
header absent means nothing, and so does a digest of an answer that does not verify.
This is how a control plane changes a run's policy while it runs, and the whole of it:
Forager reads a body's code only from a signed answer.

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
happen. `delivered.log` beside it gets a line as each batch is accepted, the delivery id
and the sequence of every event in it, and the one word `stopped` for a signed 410.
`lock` is held by the session for as long as it lives, by the kernel, so it is free once
the session is gone however it went. Sending a run again is the job's last step, whatever
happens before it: refused while the lock is held; then what the run's wall leaves
behind is removed, by the run's label; a record that has `dev.qory.run.started` and no
`dev.qory.run.exited` gets one, numbered on from the highest sequence of the record or
of `delivered.log`, with `state: failed` and `reason: gateway_lost`, and `exit_code: -1`
on a session's run, the gateway having been lost before the run's exit was recorded; and every event the
server's filter selects
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
cut off. Nothing else of the file is changed. `delivered.log` is
made once the server accepts the ping, its first line the ping's: a record that holds a
ping and no `delivered.log` is of a run whose ping was never accepted, which never
opened, and nothing of it is sent or added to it. Neither is anything of a record with
no ping and no `delivered.log`, of a run that had no server, which never opened at the
server it is sent to. Forager says on its standard error which of the two it is. A
`delivered.log` says the run opened, even when its ping's line was not finished.
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
the public keys listed in its own configuration and skips enrolment, verifies each
request and answers in the order this section defines, signs every answer after
verification under its own key, returns the digest headers, deduplicates and appends to
a file. Its discovery lists `version`, `node_id`, `events` and `apiary_public_key`, and
no `secrets`. The module's own tests run Forager's client against it.
`fixtures/signed/` is what any receiver is tested against: one request per file,
`method`, `target`, `headers`, a header sent twice being a list of its values, `body`
(a string, or `null` for a GET), the status a receiver returns as `expect`, the code of
a coded refusal as `expect_code`, and a `note` that explains why. Every signature in
them is real, under the fixture access key secret as the fixture access key and
instance; a receiver under test holds the fixture access key under
`ak_f1xt0re000000000` and sets its clock to `1700000000`, around which the timestamps
are. A receiver written by anyone else follows this section, replays those files, and
may read that code.

## The gateway's link

When the session and the gateway are two processes, the session runs the agent and the
gateway holds the proxy, the policy, the credentials and the access key, and is the
node toward the server (§The server). The session is the gateway's client by the
protocol Forager speaks toward the server, on the same paths: discovery, the run
configuration, the events endpoint and the `410` close. Two transports carry it, and
the protocol is the same on both.

| | The local link | A separate gateway |
|---|---|---|
| Where | one machine; `qory` starts the session and the gateway | the gateway `session.gateway.url` names, on a machine of its own |
| Transport | a Unix socket, `sock`, in a private directory of the gateway's, `qory-link-*` in the system's temporary directory, mode `0700`, the socket mode `0600`; the directory is one of Forager's files (§The wall) | TLS 1.3 alone, on the gateway's one address |
| The session knows the gateway | the socket's peer is the session's own user, by its uid | the certificate chain, for the host name of `session.gateway.url`, and the pin when one is set |
| The gateway knows the session | `QORY-LINK`, a space, the link secret and a newline, before the first byte of every connection; and `X-Qory-Run-Secret`, the run answer's `run_secret`, on every reload and batch | `Authorization: Bearer <run credential>` on every request; and `X-Qory-Run-Secret`, the run answer's `run_secret`, on every reload and batch |
| The run's labels | the session's | the run credential's |
| `narrowing` | refused | accepted |

`session.gateway.url`, `session.gateway.ca_file`, `session.gateway.certificate_sha256`,
`gateway.tls.certificate` and `gateway.tls.key` are names of `qory`'s configuration;
Forager receives their values from the command. No access key is involved on the
link: the gateway's access key keeps its one role, signing toward the server.

**The local link.** The link secret is at least 128 bits from the system's random
source, made each time the gateway starts, and `qory`, which starts both, hands it to
the session. Before it writes the secret, the session checks that the socket's peer is
its own user, by the peer's uid. The gateway compares the secret in constant time,
never logs it, and closes a connection that opens otherwise unanswered, as the proxy
closes one without `QORY-RELAY` (§Limits). Every URL the link's discovery lists is
`http://localhost` and a path, and the session sends every request over the link.

**In one process.** When the session and the gateway share one process, as `qory` runs
them on one machine, the session reaches the gateway's link in memory and never dials
the socket's path, where another process of the same user could listen in the
gateway's place, pass the uid check and read the secret. Each connection in memory
carries the same bytes as one over the socket: `QORY-LINK`, a space, the link secret
and a newline, then HTTP/1.1, and the gateway checks the preamble as on the socket; its
peer is the process itself. The socket serves a session in another process; a gateway
started without one, as `qory run` starts it, serves its link in memory alone.

**A separate gateway.** TLS 1.3 alone: the gateway and the session each refuse an
earlier version. The gateway serves the operator's certificate and key,
`gateway.tls.certificate` and `gateway.tls.key`. The session verifies the full chain for
the host name of `session.gateway.url` against the system's roots, or, when
`session.gateway.ca_file` is set, against the authorities of that file, which replace
the system's roots for this link. `session.gateway.certificate_sha256` is optional: the
SHA-256 of the gateway certificate's public key, base64. With it, `qory` accepts only a
certificate with that key, and still checks its chain. The value is the SHA-256 over the
DER SubjectPublicKeyInfo, in standard base64 with padding, 44 characters ending in `=`,
which this computes from the certificate:

```sh
openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

Every request carries the run credential as `Authorization: Bearer <run credential>`,
in the header syntax of RFC 6750 §2.1. Every URL the link's discovery lists has the
origin of `session.gateway.url`, and the session refuses a discovery that lists
another, so the run credential goes to the gateway alone. The run credential is never
logged, recorded or contained in an event, on the session or on the gateway.

**On the wire.** A request on the link contains `User-Agent` and
`X-Qory-Contract-Version`, as toward the server, and a batch its `Content-Type` and
`X-Qory-Delivery`; there is no access key id, instance id, timestamp or signature.
Answers on the link are unsigned: the transport authenticates them, the socket's peer on
one machine and TLS on two. Ed25519 signing stays toward the server. A coded refusal is
a `link-refusal.schema.json` document, the body of one toward the server with `from`,
who refused, required, and `message`:
`{"error": "<code>", "names": ["…"], "message": "…", "from": "gateway"}`. `from` is
`gateway` for the gateway's own refusal, and `apiary` for the server's, which the
gateway passes on with its code and status; `names` is absent when the refusal concerns
none. Every refusal on the link, the `403`, `409`, `400` and `410`, the server's passed
on and the `500` `internal`, carries `message`: the text the session gives the user as
the run's error, today's text word for word. For a refusal of the server's it names Qory
Apiary's URL as today, such as
`ping https://apiary.example/v1/events: instance_limit (status 409)`, the signed `409`
to the ping. `message` is optional in the schema, and a session that reads none uses the
code. The gateway refuses a run's start with a code of `refusal.Decides`, such as
`image_unknown`, `placeholder_conflict`, `tool_unknown` or `run_configuration_invalid`,
or with `wall_required`, each a `403` from `gateway`, and so a reload behind a separate
gateway. A run that fails to open for a reason without a code is a `500` from `gateway`
with the code `internal`: `{"error": "internal", "message": "…", "from": "gateway"}`.
`message` is up to 8192 characters and may span lines: tab and newline are its only
control characters, and every other C0 control character, DEL and every C1 control
character, U+0080 to U+009F, is refused. It holds no secret, no run credential and no
image reference. Every `410` on the link has this body (The end of a run at the gateway,
below). A redirect is not followed.

**Discovery.** `GET /.well-known/qory-configuration`, answered with a
`link-discovery.schema.json` document: `version`, `events`, `run` and `proxy`, each
required, `run` since a run on the link opens with its run request. `events` has `url`
and `types` as `configuration.schema.json` defines them, and `interval_seconds`,
required: the gateway's heartbeat interval, the member that carries it in the ping
toward the server. The session sends its heartbeats every `interval_seconds`. `proxy`
has `address`, `host:port`: the gateway's proxy, the one address the run's agent traffic
goes to (Agent traffic, below), on loopback on one machine, and the gateway's one
address behind a separate gateway. The discovery contains no
`node_id`, no `apiary_public_key` and no `secrets`: the node, the server's keys and the
run's stored secrets are the gateway's, toward the server. A member Forager does not
recognise is ignored.

```json
{"version": 1,
 "events": {"url": "https://gateway.example:8443/v1/events", "types": ["*"], "interval_seconds": 30},
 "run": {"url": "https://gateway.example:8443/v1/run-configuration"},
 "proxy": {"address": "gateway.example:8443"}}
```

**Opening a run.** The session opens a run with a `POST` to `run.url`,
`Content-Type: application/json`, whose body is a `link-run-request.schema.json`
document. Toward the server the run configuration request is a `GET` with the labels as
its query and no `about` (§The server); on the link it is this `POST`, and it contains
`about`.

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
- `labels`: the run's labels, as `dev.qory.run.started` contains them.
- `about`: what the run is about (§What a run is about). It selects no policy.
- `passes`: the names of the variables the run passes a value for, in what it inherits,
  what the harness sets and its variables: names alone, never a value, each in the
  grammar of a variable's name (§Variables): the session leaves out a name outside it,
  which can match no placeholder. The gateway refuses the run with
  `placeholder_conflict` when a placeholder of a credential or a tool it holds is among
  them. Absent means none.
- `images`: the session's images, which the gateway resolves the policy's selection
  against (§Images): `default`, the machine's default, the name of one of `definitions`
  or a reference; and `definitions`, the images the machine defines, each with `name`,
  `ref`, its reference, `runtime` when the definition sets one, and `docker: true` for a
  Docker of the agent's own. A reference is not secret, but it may carry a registry's
  credentials in its user information: the gateway never logs or reports one. Absent
  means none.
- `narrowing`, behind a separate gateway alone: the session's narrowing of the policy,
  `egress` with `allow`, `deny` or both, each in the grammar of the policy's
  `egress.allow`, and no other member. It only narrows: it can only remove what the
  policy allows. It combines with the policy the gateway holds for the run as a node's
  policy narrows a server's (§The policy): a side under `enforce` when it lists `allow`,
  so a host its `allow` does not cover is removed, and under `observe` otherwise; its
  `deny` adds to the hosts denied. A narrowing `allow` that puts an `observe` policy
  under `enforce` narrows too.

A member the schema does not define is refused, so a narrowing is never dropped
unread. Behind a separate gateway, the gateway verifies the run credential and makes
the run's labels from it through the operator's mapping. The session's `forge` and
`repository`, when the session sends them, must equal the credential's. Any other label
the mapping sets, and any key of `about.details` it sets, must equal the credential's
value when the session sends it. A label the session leaves out is the credential's, and
a label the mapping does not set is ignored: a run's labels come only from the
credential. The gateway tracks run keys and does not require them to be unique; each
period of activity is a run, and every run request opens a run of its own, of its own
run id and proxy secret (§Run credentials). Every request to a separate gateway,
the run request and every batch, carries a run credential whose `sub` is the run's run
key, and so does every reload (below); any other is `run_credential_refused`. Behind a
separate gateway, the gateway decides the run credential first: a run request without
one, or with one the verifier refuses, is `401` `run_credential_refused` before its body
is read, so no body is parsed for a request that is not authenticated. It then refuses
a run request in this order:

| Status | Code | When |
|---|---|---|
| `400` | `invalid_request` | a body the schema refuses: a `run_id` not in the canonical lower-case form, labels or `about` outside their rules, a member the schema does not define; and a `narrowing` on the local link |
| `401` | `run_credential_refused` | behind a separate gateway, a run key the gateway refuses after the issuer's end (§Run credentials), and a run credential the issuer's introspection does not hold active. One opaque code, with no names, and `WWW-Authenticate: Bearer`, as for every failure of the run credential |
| `503` | `credential_check_unreachable` | behind a separate gateway, the run credential could not be checked: the introspection endpoint could not be reached after the gateway's tries (§Run credentials); the message is "the gateway could not open the run: the issuer's introspection endpoint could not be reached; try again" |
| `502` | `credential_check_invalid` | behind a separate gateway, the run credential could not be checked: the introspection endpoint gave no valid answer (§Run credentials); the message is "the gateway could not open the run: the issuer's introspection endpoint gave no valid answer" |
| `409` | `run_id_used` | a `run_id` that already names a run at this gateway, live or ended; no names |
| `403` | `target_differs_from_credential` | behind a separate gateway, a `forge` or `repository` that differs from the credential's |
| `403` | `differs_from_credential` | behind a separate gateway, another label or key of `about.details` the mapping sets, sent with another value |
| `403` | `wall_required` | a run without a wall whose policy selects what needs one, below; the link's code alone |
| `403` | a code of `refusal.Decides` | the gateway's decision of the run with `passes` and `images`, below: `run_configuration_invalid`, `image_unknown`, `tool_unknown`, `placeholder_conflict` and the like |

The names of `target_differs_from_credential` and of `differs_from_credential` are
`<member>=<the run credential's value>`, one for each member that differs and for no
other, the member being `labels.<key>` or `about.details.<key>`:
`labels.repository=example-namespace/project`, for one.

A session waits ten seconds for its run answer, as for any answer on the link. A run
request whose session gives up opens no run: once its connection goes, the gateway asks
the server nothing more for it, the ping and the run configuration among it, opens no
run, and removes what it recorded of the run, so the same `run_id` sent again is a new
run request, not `run_id_used`. A ping the server took before then stays the server's.
A session that goes in the moment between the gateway's last look and the answer's
arrival may leave a run open, which ends `session_lost` as any run whose session sends
nothing does.

**Tries as a run opens.** The gateway tries the server's ping and run configuration up
to 3 times each, the second try 1 second after the first ends and the third 2 seconds
after the second, and starts a try again only within 6 seconds of the run request's
arrival, or of a client's proxy login's start, the time the issuer's introspection took
included, so the last answer comes inside the ten seconds the session waits. It asks
again after no answer, a transport failure or a timeout, a `5xx`, signed or not, and a
signed `429` `rate_limited`; it ignores `Retry-After`. Every other answer is final: a
`401`, any other coded refusal, `not_found` among them, a signed answer other than a
`5xx` with no code, and a document Forager refuses. Each try of the ping sends the same delivery id and body,
which the server deduplicates, and the run's record holds the ping once; each try of the
run configuration is signed anew. Once the tries are spent the last answer is the
session's, as without them: its code and status passed on from `apiary`, or a `500`
`internal`. A `404` of the run configuration does not fetch the configuration document
again.

With `passes` and `images`, the gateway then decides the run as the session decides it
on one machine today, in the same order, and before it sets anything: the policy in
force, from the node's policy and the run configuration, `run_configuration_invalid` for
a run configuration it refuses; what needs a wall, refused without one with
`wall_required`; the run's image among `images`, `image_unknown` for a name the machine
does not define; the credentials it resolves, `placeholder_conflict` for a credential's
placeholder in `passes`; and the tools it chooses beside the credentials (§Tools),
`placeholder_conflict` for a tool's placeholder in `passes`. A refusal with a code of
`refusal.Decides` is a `403` with that code and its names, `from: gateway`, as the
session gives them today; a refusal of the server's passes through with its own status
and `from: apiary`. The checks of the session's own image table and runtime, an image
defined twice or a daemon without a runtime, have no code: the session makes them before
it sends the request, as today. A refused run opens nothing: the gateway holds no
credential, starts no tool and makes no proxy secret for it. A run that fails to open
for a reason without a code is a `500` with `error: internal` and `from: gateway`. Every
refusal carries `message`, the text the session gives the user as the run's error, word
for word as today, so the user sees the line they see today. The session applies what
the answer gives and decides none of it again.

`wall_required` is a code of the link alone: a `403` from `gateway` to a run request
whose `wall` is false and whose policy in force selects what needs a wall. Its names are
`credentials`, `tools` and `paths`, each one the policy selects, or `image=<name>` for
an image the policy selects. The session turns it back into the error it gives today,
word for word, and writes no `dev.qory.run.refused` for it, as today: the code is not
one of `refusal.Decides`, not in the enum of `events/run.refused.schema.json`, and never
appears in an event.

A run request the gateway refuses opens no run at the gateway. The session records the
`dev.qory.run.refused` it received, for every code but `wall_required` and `internal`,
in its own record alone, as with the server's `410` before `dev.qory.run.started`, and
nothing reaches the server for it. A session that fails after the run answer and before
its process starts posts its `dev.qory.run.refused` on the link: the gateway holds that
run, and delivers it.

The answer is a `200`, `application/json`, whose body is a `link-run-answer.schema.json`
document:

```json
{"version": 1,
 "run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d",
 "credential": "starter",
 "labels": {"forge": "example-forge", "repository": "example-namespace/project", "run_key": "rk-0001"},
 "details": {"requester": "requester"},
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
 "run_secret": "<the run's secret>",
 "certificate_authority": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"}
```

- `run_id`, required: the request's, echoed.
- `credential`, required: where the run's credential came from, as the gateway decides
  it: `starter` behind a separate gateway, where the run's starter gave the run its run
  credential, and `none` on the local link. The session's `dev.qory.run.started`
  contains exactly this.
- `labels`, required: the run's labels as the gateway holds them: behind a separate
  gateway the run credential's, through the operator's mapping; on the local link the
  run request's. The session's `dev.qory.run.started` contains exactly these labels.
- `details`: the `about.details` keys the run credential decides, those whose claims it
  carries, with the run credential's values; absent when it decides none, and on the
  local link. The session's `dev.qory.run.started` contains each of these keys in
  `about.details` with this value.
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
- `image`: the image the run gets, as a definition of `images` has it, `ref` required:
  the one the policy in force selects, or the machine's default, `name` absent when the
  default is a reference. Present when the request's `wall` is true. The session's
  `dev.qory.run.started` reports it (§Images).
- `applied`, required: the members of `dev.qory.run.policy_applied` the gateway decides
  for the policy in force, every member but `variables` and `harness_hosts`, each
  present exactly when the gateway's is, under the rules of
  `events/run.policy_applied.schema.json`. The session's `dev.qory.run.policy_applied`
  is this object with its own `variables` and `harness_hosts` added (Events, below).
- `proxy_secret`, required: the run's proxy secret (Agent traffic, below), 22 to 256
  characters of `A-Z`, `a-z`, `0-9`, `_` and `-`, which a URL's password and the relay's
  preamble carry as they are.
- `run_secret`, required: the run's secret: at least 128 bits from the system's random
  source, made by the gateway for this run and given once, 22 to 256 characters of
  `A-Z`, `a-z`, `0-9`, `_` and `-`. The session sends it in `X-Qory-Run-Secret` on every
  reload and batch. Compared in constant time, never logged.
- `certificate_authority`: the certificate of the run's own certificate authority, PEM,
  present when the request's `wall` is true and the gateway reads inside HTTPS for the
  run: for a credential it holds, a tool it starts or a path rule, the policy's or the
  node's, and behind a wall with a server always, since a reload may bring path rules or
  credentials and the enclosure trusts only what it was given at the start. Absent
  otherwise. Never its key, which stays with the gateway.

**Events.** The session posts its events to `events.url`, in batches cut as toward the
server (§The server, Delivery), with `Content-Type: application/cloudevents-batch+json`.
The body is a `link-batch.schema.json` document: events of the run as
`event.schema.json` defines them, with their ids and without `sequence`, in the
session's own order. The gateway numbers the run's stream: one `sequence` per run, from
`0000000001` and contiguous, as §The events requires. Into a session's run it merges its
own `dev.qory.run.egress` and, when it ends the run, its `dev.qory.run.exited`, with the
reason it ended the run with (The end of a run at the gateway, below), or `gateway_lost`
when it sends its record again. It numbers an event once, by its id, so a batch the
session sends again is not numbered twice, and it delivers the stream to the server under
its access key. The gateway is the node toward the server, so it sends the ping; the
session sends no ping on the link, and a link batch holds none.
`dev.qory.run.policy_applied` is the session's: the session writes it from the run
answer's `applied`, and again from the `applied` of a reload answer whose digest
changed, at the sequence where the new configuration takes effect, adding `variables`
and `harness_hosts`, since only the session has the run's resolved variables and the
harness's hosts. From the moment a reload puts a new policy in force on the run's
proxy, the gateway holds every `dev.qory.run.egress` of the run, those of the tunnels the
policy closed first, then each connection decided after, and numbers them right after
the session's `dev.qory.run.policy_applied` of that policy, so no connection under a
policy precedes its event (§The server, Reload, rule 1); a connection the gateway saw
before the switch keeps its place, and when the run ends before the session writes the
event, what is held comes right before the run's final event. For a run with no session
the gateway writes `dev.qory.run.policy_applied` itself. The session
keeps its own file record of its own events, numbered as today (§The record files): that
record is the session's, not the run's stream. The gateway keeps the record of what it
sent, which `qory run resend` sends again through `gateway.Resend` (§The server, After
Forager stops unexpectedly). The
gateway answers a batch as the server does, unsigned: a `2xx` is accepted. A batch is of
the run whose `run_secret` it carries, checked before its body is read; behind a
separate gateway that run must be of the run credential's run key. A batch without it,
or with one of no such run, is `401` `run_credential_refused` behind a separate gateway
and `400` `invalid_request` on the local link, and ends no run, so no run can be probed.
A batch whose body does not arrive whole, its client gone before the end, is `400`
`invalid_request` too, and ends no run. Any other `400` `invalid_request` to a batch, one over the size limit or one that does
not decode among them, ends its run at the gateway: the
gateway writes `dev.qory.run.exited` with `reason: session_lost`, since it no longer
accepts the session's stream, refuses the run's proxy secret, and answers the session's
further requests with a `410` `batch_refused` (The end of a run at the gateway, below).
The session stops the runtime as after a `410` and records `dev.qory.run.exited` with
`reason: batch_refused` in its own record alone. Anything else but a `2xx`, that `400` or a
`410` is retried.

A session writes no event the gateway or the run credential decides. The gateway
refuses a batch with a `400` `invalid_request`, and numbers nothing of it, when any of
its events:

- has a `subject` that is not the batch's run, the one whose `run_secret` it carries;
- has a type the gateway writes, `dev.qory.ping` or `dev.qory.run.egress`;
- is a `dev.qory.run.started` whose `opened_by` is not `session`, whose `credential` is
  not the run's, `starter` behind a separate gateway and `none` on the local link, whose
  `labels` differ from the run's labels as the gateway holds them, the run credential's
  behind a separate gateway, or whose `about.details` differ in a key the run credential
  decides;
  or is a `dev.qory.run.started` when the run already has one with another id: a run
  has at most one;
- is an event, by an id the gateway has not numbered, after the run's
  `dev.qory.run.exited` or `dev.qory.run.refused`: nothing follows either; or is a
  `dev.qory.run.refused` after the run's `dev.qory.run.started`, whose place it takes;
- is a `dev.qory.run.exited` whose `reason` is neither `timeout` nor the `reason` of the
  gateway's outcome answer to the run, or whose `state` is not that answer's `state`
  when the answer had one: a session's batch carries only its own
  `dev.qory.run.exited`, the runtime's exit, its time limit or the starter's outcome at
  the exit (The outcome at the exit, below), and the gateway writes the event of every
  other reason itself (The end of a run at the gateway, below);
- is a `dev.qory.run.policy_applied` that is not `applied` from an answer of this run,
  the run answer's or a reload answer's, with the session's own two members added:
  every member the gateway decides, `mode`, `allow`, `deny`, `source`, `url`,
  `digest`, `run_configuration`, `node_policy`, `paths`, `credentials`, `tools`,
  `image` and `terminated`, present exactly when that `applied` holds it and equal to
  it. Only `harness_hosts` and `variables`, the variables' names and their sources, are
  the session's. The gateway accepts one that matches any policy it has put in force
  for the run, so a batch in flight during a reload is not refused;
- is a `dev.qory.run.refused` whose `code` is not one the session decides itself, the
  codes of `refusal.Decides`: `run_configuration_invalid`, `tool_unknown`,
  `image_unknown`, `variable_reserved`, `placeholder_conflict`,
  `mount_contains_forager_files`, `mount_mode_conflict`, `mount_shared_with_run`,
  `mount_through_link` and `engine_unreachable`. So a gateway's codes,
  `run_credential_refused`, `target_differs_from_credential`, `differs_from_credential`
  and `run_id_used`, and the gateway's `run_closed` and every code of the server's are refused;
  and so is a `dev.qory.run.refused` with a name of the form `<member>=<value>`, a
  member being `labels.<key>` or `about.details.<key>`, the form only a gateway's
  refusal carries.

`link-batch.schema.json` states what a schema can: neither type the gateway writes, an
`opened_by` of `session`, `timeout` as the only one of Forager's reasons of a
`dev.qory.run.exited`, a
`dev.qory.run.refused` code among the session's own, and no name of the form
`<member>=<value>`. The gateway checks the rest.

**Heartbeats and liveness.** A run has one source of heartbeats. For a session's run,
the session's `dev.qory.run.heartbeat` events on the link, every `interval_seconds` of
the link's discovery, are the run's heartbeats: the gateway numbers and forwards them
like any other event of the session's, and they are its sign that the session lives,
judged by their arrival, not by the server's rule (§The server).
The gateway writes `dev.qory.run.heartbeat` only for a run with no session. When the
session sends nothing for 3 × `interval_seconds`, counted from the run answer and again
from each request of the session's, the gateway ends the run with
`dev.qory.run.exited`, `reason: session_lost`, and answers the session's later requests
with a `410` `session_lost` (The end of a run at the gateway, below). When the gateway
stops, the server receives no events from it; when `qory run resend` sends the run's
record again, through `gateway.Resend`, the resend writes `dev.qory.run.exited` with
`reason: gateway_lost`.

**The end of a run at the gateway.** When the gateway ends a session's run, with
`session_lost`, `credential_expired`, `stopped`, the starter's outcome,
`credential_check_unreachable` or `credential_check_invalid`, it writes the run's
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
| `credential_expired` | `gateway` | the run credential expired with no fresh one |
| `stopped` | `gateway` | the run's starter reports the run credential no longer active, or ended another run of the same run key so, which the gateway holds (§Run credentials); `state` and `reason` are the starter's outcome and reason, or `cancelled` and `stopped` when it gave no outcome |
| `credential_check_unreachable` | `gateway` | the run credential could not be checked: the introspection endpoint could not be reached after the gateway's tries |
| `credential_check_invalid` | `gateway` | the run credential could not be checked: the introspection endpoint gave no valid answer |
| `session_lost` | `gateway` | the session was silent for 3 × the heartbeat interval (Heartbeats and liveness, above); the gateway's record says `session_lost` |
| `batch_refused` | `gateway` | the gateway refused a batch of the session's (Events, above); the gateway's record says `session_lost` |
| `run_closed` | `gateway` | the run had already ended otherwise: after the session's own final event, or when the gateway stops; no `state` |

The session stops the runtime as at its time limit, records its own
`dev.qory.run.exited` with the `410`'s state and reason, and its code as the reason after
`batch_refused` or a `410` without a state, in its own record alone (§The events, How a
run ends), and posts nothing more on the link. A `410` with another code, or none, is
`run_closed`.

**A session's run behind a separate gateway whose session is lost.** Such a run,
`credential` `starter`, ends at the gateway: with `session_lost` once the gateway has heard
nothing from the session for 3 × `interval_seconds` (Heartbeats and liveness, above);
earlier, with `credential_expired`, when the latest `exp` of a run credential presented
for it passes first. The gateway asks the starter's introspection endpoint at the
session's requests, so `stopped`, `credential_check_unreachable` or
`credential_check_invalid` ends the run while they reach it. When the gateway
itself stops, `qory run resend` sending the run's record again, through
`gateway.Resend`, writes its `dev.qory.run.exited` with `gateway_lost` (§The server).
While the session lives, the run normally ends with its runtime's own exit; the gateway
can also end it, with `credential_expired`, `stopped`, `credential_check_unreachable`,
`credential_check_invalid`, or `batch_refused` after it refused a batch of the
session's, its record saying `session_lost`, and the session records that end (The end
of a run at the gateway, above).

**Reload.** The run request is one-shot per `run_id`: sent again, it is `run_id_used`,
unless its session gave up before the run opened (above). A
reload is a `GET` of the run's configuration by its run id instead,
`<run.url>/<run_id>`: the path of `run.url`, a slash and the `run_id`, with no query.
The gateway's answers on the link, the run answer and the reload's among them, contain
the digest headers `X-Qory-Configuration` and `X-Qory-Run-Configuration`, unsigned, and
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
`image_unknown`; an image or credentials that need a wall the run does not have; and a
credential's placeholder in `passes`, `placeholder_conflict`. On the local link the
gateway applies a reload itself, and every reload that fails, with a code or without
one, stays off the link: the gateway reports it to the user with the text the session
reports today, and the session's reload `GET` is answered with the policy in force, its
digest unchanged. Behind a separate gateway, to a refusal with a code of
`refusal.Decides` the reload's answer is a `403` with that code and its names,
`from: gateway`; a refusal of the server's passes through with its own status and
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

Behind a separate gateway, the reload carries a run credential whose `sub` is the run's
run key, and the run's `run_secret`, whose run the `run_id` must be, and any other is
`401` `run_credential_refused`; the credential is checked first, so a `run_id` that is
not a run of its run key, unknown or another run key's, is `run_credential_refused` too,
and no run id can be probed. On the local link the link secret and the run's
`run_secret` authorise it: `qory` hands the secret to the session alone, of the same
user, and the reload re-sends no secret of the run but its `run_secret`. A walled agent never reaches the socket, and an
unwalled one is never given the link secret: `qory` hands the session the secret in
memory, never in an environment or a file, so a program the agent starts does not inherit
it. Without a wall, enforcement is cooperative ([the wall](../../../docs/wall.md)). A
`run_id` of a run that has ended is a `410`, with the code and the `from` of its end at
the gateway (above) when it ended there, else `run_closed` from `gateway`; on the local
link an unknown `run_id` or a missing secret is `400` `invalid_request`. Toward the server
no reload request names a run: the run configuration is fetched by the run's labels.

**The outcome at the exit.** Behind a separate gateway, when the runtime exits by
itself, the session asks the gateway once, before it writes `dev.qory.run.exited`, how
the run's starter says the run ended: a `GET` of `<run.url>/<run_id>/outcome`, the
reload's path followed by `/outcome`, with no query. It carries what a reload carries,
`Authorization: Bearer <run credential>` and the run's `X-Qory-Run-Secret`, and is
decided as a reload is (Reload, above): a `run_id` that is not a run of the run
credential's run key is `401` `run_credential_refused`, and a run that has ended at the
gateway is its `410`. The gateway asks the starter's introspection endpoint once, not
from its cache, and answers within a few seconds: a `200`, `application/json`, whose body
is a `link-outcome-answer.schema.json` document. It holds the outcome and the reason the
starter gave, when the endpoint answers that the run credential is no longer active with
`qory_outcome` (§Run credentials):

```json
{"state": "succeeded", "reason": "all_checks_passed"}
```

and is `{}` otherwise: the run credential still active, an answer with no outcome, no
answer within those seconds, or one that is not valid. `reason` is absent when the
starter gave none, or gave a reserved code, which is dropped. The session writes a
non-empty answer's `state` and `reason` into its `dev.qory.run.exited`, beside the
runtime's own `exit_code`; with `{}`, a refusal or no answer, the runtime's exit decides
the state, as without the ask, and nothing is added to the record. Once the session has
written its `dev.qory.run.exited`, no later word of the starter's changes it. An answer
that the run credential is no longer active holds the run key, as on any request of the
run's (§Run credentials). On the local link there is no starter to ask: the session never
asks it there, so a run on one machine never waits at its exit.

**Agent traffic.** Inside a wall, the relay connects to the gateway's proxy, the
discovery's `proxy.address`, on loopback on one machine, and between two machines over
TLS 1.3 with the same trust as the link: the system's roots or `session.gateway.ca_file`,
and the pin when `session.gateway.certificate_sha256` is set. It opens every connection
with `QORY-RELAY`, a space, the run's proxy secret and a newline, as it does on one
machine (§Limits). Behind a wall and a separate gateway, the session's forwarder takes
the relay's connection, which opens with `QORY-RELAY` and a token the session makes for
the run, and opens the gateway's one address over TLS with `QORY-RELAY`, a space, the
run's proxy secret and a newline; the agent's view is the same. Without a wall, behind a separate gateway, the agent's proxy URL carries the
run's proxy secret as its password, never the run credential; the URL's user name is
ignored. The run's proxy secret is at least 128 bits from the system's random source,
made by the gateway for the run; the gateway compares it in constant time, never logs
it, and refuses it once its run ends, and it is sent between machines only inside TLS.
`qory` takes the run credential out of the agent's environment, as it does the access
key's variables, so the agent never holds it.

## Run credentials

A gateway that serves other machines opens a run only for a run credential: a JWT (RFC
7519) signed as a JWS (RFC 7515) with an asymmetric key, which an issuer the operator
trusts gives a run. Its `sub` is the run key, the `run_key` label of each run it opens;
its `aud` contains the gateway's own audience; and the claims the operator names make
the run's labels and `about.details`. `run-credentials.schema.json` defines the issuers a gateway
accepts, the list under `gateway.run_credentials` of the operator's `forager.yaml`: per
issuer, `issuer`, `audience`, `algorithms` among `RS256`, `ES256` and `EdDSA`, the pinned
`keys`, `leeway` (60 s by default, at most 5 minutes), `max_lifetime`, the scope `allow`, the mapping
`labels` and `details`, and `introspection` (RFC 7662).

The public package `runcredential` holds the rules beyond the schema:

- `Issuers.Check` and `Issuer.Check`: no two issuers are the same; every key's `alg` is
  among the issuer's algorithms; with more than one key, every key has a `kid`, and no
  two the same; each `public_key_file` is one PEM block of type `PUBLIC KEY`, with
  nothing but white space around it, of the key its `alg` needs: RSA of at least 2048
  bits for `RS256`, P-256 for `ES256`, Ed25519 for `EdDSA`, which passes the checks of an
  Ed25519 public key; no key is one of the published fixture keys of the known answers,
  whose private keys anyone can derive; the `leeway` is at most 5 minutes; and no
  `details` key holds `=`, since a refusal names a key as `about.details.<key>=<value>`.
- `NewVerifier` and `Verifier.Verify`, the whole verification, in order: the JWS compact
  serialisation, at most 16384 bytes, exactly three parts of base64url without padding,
  white space or another byte, the header and the payload not empty; the header, one
  JSON object with each member name once, through `Issuer.SelectKey`; the signature
  under each key selected, over the exact bytes received: `RS256` by RSASSA-PKCS1-v1_5
  with SHA-256, `ES256` exactly 64 bytes with `R` and `S` each in [1, n-1], `EdDSA` by
  Ed25519; then the payload, one JSON object with each member name once, read only after
  the signature verified, and among the issuers whose key verified it the one whose
  issuer equals `iss`; then the claims, the scope and the mapping below.
  `Verifier.VerifyExpired`, the same verification of a run credential that `Verify`
  refuses only because its `exp` passed, less than 5 minutes before, the time checks
  made as just before `exp`: the gateway uses it to answer a reload or a batch of a run
  that has ended with its `410`, and for nothing else.
- `Issuer.SelectKey`, the header: `alg` is among the issuer's algorithms, never `none` or
  an HMAC algorithm, and equals the selected key's; the key is selected by `kid`, and a
  run credential without one is accepted only while one key is pinned; `crit` is
  refused; `typ`, when present, is `JWT`, compared without regard to case.
- `Issuer.CheckClaims`, the claims of a run credential whose signature is verified:
  `exp` required and after now less the leeway; `iat` and `nbf`, when present, no later
  than now plus the leeway; `exp - iat` at most `max_lifetime` when it is set, which then
  requires `iat`; `iss` the issuer, which is never empty; `aud`, a string or an array,
  containing the audience, which is never empty; `sub` present.
- `Issuer.Allowed`, the scope; `Issuer.Labels`, the labels `forge`, `repository` and
  `run_key`, which come from the run credential alone; `Issuer.Details`, the
  `about.details` keys it decides, those whose claims it carries; each claim either
  reads is a string with no control character; and `Compare`, which refuses a session
  that sends `forge` or `repository` with another value with
  `target_differs_from_credential`, and any other key the mapping sets with
  `differs_from_credential`.
- `NewIntrospector` and `Introspector.Active`, the issuer's RFC 7662 endpoint: a `POST`
  over TLS of the form `token` and `token_type_hint=access_token`, with HTTP Basic as the
  client, following no redirect; active only on status 200 with one JSON object, each
  member name once, of at most 65536 bytes, whose `active` is the JSON `true`; any other
  answer, or a failure, is not active. A try that gets no answer, a transport, TLS or
  timeout failure, a failed read, a `5xx` or a `429`, is tried again: up to 3 tries,
  2 seconds each, 1 second and then 2 seconds apart, a try starting only within 4
  seconds of the first, and then `ErrIssuerUnreachable`. Any other answer that is not a
  valid one, a status other than 200 or a 200 that is too long, not one JSON object
  with each member name once or without a boolean `active`, is tried once and is
  `ErrAnswerInvalid`, its status named. An answer the endpoint gives is kept for `cache`
  by the SHA-256 of the run credential, at most 4096 of them; a failure is not kept.
- `OpenEnded` and `Ended`, the run keys a gateway refuses after the issuer's end, by
  issuer, in a file of the gateway's state directory, each kept until the latest `exp`
  added for it plus 5 minutes, so a restart refuses them too. `OpenEnded` refuses a
  state directory it cannot create a file in, so the gateway does not start on one;
  `Ended.Written` reports whether the file, as last read or written, refuses a run key.

**The runs of a run key.** The gateway tracks run keys and does not require them to be
unique; each period of activity is a run, of its own run id, with the run key as its
`run_key` label. Each run request of a session opens a run of its own, so one run key
may have several runs at once, and one after another; every later request of a
session's run carries a run credential of that run's run key, and a refreshed run
credential continues only its own run, with that run's `run_secret`. A refreshed run credential's labels and
`about.details` are the run's: one whose `forge` or `repository` differs is `403`
`target_differs_from_credential`, and one whose other label or key of `about.details`
differs, or is left out, `403` `differs_from_credential`, each named with the run
credential's value, and the run goes on; to a client's connection it is `407`. A reload or a batch of a session's run that
has ended is answered with its `410` for a run credential of its run key whose `exp`
has passed, less than 5 minutes before, its signature and every other claim verified as
always, so the session learns the run's end, `credential_expired` under an issuer with
no leeway among them; such a run credential is `401` `run_credential_refused` to every
other request, and serves none. A client with no session presents its run
credential as the password of its proxy login. While the client's run of its run key is
open, the connection joins it, its run credential extending the run to its `exp`;
otherwise the connection opens a new run, and a run that ended is never opened again. A
client has at most one open run per run key. A client never joins a session's run: a
session's run is reached only by its proxy secret, and decided under that session's wall
and narrowing, so a client of a run key whose sessions' runs are open opens or joins its
own run beside them. A run with no session ends with `quiet`, `credential_expired`,
`stopped` or the starter's outcome, `credential_check_unreachable` or
`credential_check_invalid`, or
`gateway_lost` when `qory run resend` sends its record again, through `gateway.Resend`
(§The events, How a run ends). A client's run that fails to open for a reason that may
pass is answered `503 Service Unavailable`, `Content-Type: text/plain; charset=utf-8`,
with the body "the gateway could not open the run; try again": the issuer's
introspection endpoint could not be reached, Qory Apiary's `5xx`, signed or not, with
any code or none, or its signed `429` `rate_limited`, once the tries are spent, its
`410` to the ping or the run configuration, signed or not, with any code or none, at
once, or a
failure with neither a code nor a status of Qory Apiary's. One refused for a reason that does not pass is
answered `403 Forbidden`, `Content-Type: text/plain; charset=utf-8`, with one line:
"the gateway could not open the run: Qory Apiary refused it, \<code\>" for a code of
Qory Apiary's answer, `answer_unsigned` among them; "the gateway could not open the run:
the gateway refused it, \<code\>" for a code the gateway decides of the run
configuration, `run_configuration_invalid`, `tool_unknown` or `image_unknown`; "the
gateway could not open the run: Qory Apiary refused it, status \<n\>" for a signed
answer of Qory Apiary's, other than a `5xx` or a `410`, with no code, a `404` with an empty body or
a `200` without its digest header; and "the gateway could not open the run: the issuer's introspection
endpoint gave no valid answer" when the issuer's endpoint gave no valid answer, at its
login or a later connection's. A run refused with a code gets the gateway's
`dev.qory.run.refused` with that code, after its ping, and its status for a code read
from Qory Apiary's answer, `unauthorized` among them; `answer_unsigned`, which the
client reads as Qory Apiary's, carries no status. A connection that would join a run whose issuer's endpoint could not be
reached, or gave no valid answer, ends the run, `credential_check_unreachable` or
`credential_check_invalid`, and gets the `503` or the `403` above.

**How a run's starter says how it ended.** When the run's starter's run is over, its
introspection endpoint answers `active: false`, and may add two members of its own to
that answer, both optional:

```json
{"active": false, "qory_outcome": "succeeded", "qory_reason": "all_checks_passed"}
```

- `qory_outcome`: how the run ended, `succeeded`, `failed` or `cancelled`: the `state`
  of the run's `dev.qory.run.exited`.
- `qory_reason`: why, a code of the pattern of `reason`, `^[a-z][a-z0-9_]{0,63}$`: the
  `reason` of the run's `dev.qory.run.exited`, carried as given, such as
  `all_checks_passed`, `checks_failed` or `no_longer_needed`.

They are extension members of the answer, which RFC 7662 §2.2 lets a server add, and
their `qory_` prefix keeps them clear of other servers' names, as §3.1 asks of a name
used across domains. One deviation from the standard is documented: §2.2 says an
endpoint SHOULD NOT say why a credential is inactive. That guards against an asker the
endpoint does not trust; this gateway is the operator's own, configured to trust this
endpoint, and authenticates to it as its client. The gateway reads the two members only
when `active` is `false`:

- with no `qory_outcome`, the run ends `cancelled` with the reason `stopped`, as with
  `{"active": false}` alone;
- with a `qory_outcome` and no `qory_reason`, the run ends with that outcome, and its
  reason is empty;
- a `qory_reason` that is one of Forager's reserved codes (§The events, How a run ends)
  is dropped, and the reason is empty; the outcome is kept.

An answer is about a run credential, so about its run key: the outcome and the reason
apply to every live run of that run key when the answer arrives, as the end of the run
key always has. The starter knows its run keys and never Forager's run ids, so a starter
that wants one outcome per run gives each run its own run key. The gateway asks on each
of a session's requests, its heartbeats among them, so a session's run learns the end
within one heartbeat interval and the answer's `cache`; on a client run's connections; and
once at a session's runtime's own exit (§The gateway's link, The outcome at
the exit).

After the starter's end, `stopped` or its outcome, the gateway holds the run key, refusing
every request of a run of it, until the latest `exp` of the run credentials of the key
the gateway still holds, and of any presented during the hold, plus 5 minutes, the
longest leeway. The run credentials it still holds are those of the run key's runs that
are live, and of those that ended whose record is not yet flushed; it keeps no `exp` of
a run once its record is flushed. During the hold, a session's run request is `401`
`run_credential_refused`; a reload or a batch of a session's run of the run key that is
still live is the run's `410` `stopped`, and the run ends with the end the starter gave; and a client's
connection is `407`, and the client's run of the run key it would join ends,
with the end the starter gave. The discovery is answered to a run credential of the run key as
to any, and opens nothing. A run credential for a refused run key presented during the
hold, its signature and claims verified, is refused and extends the hold to its own
`exp`; a request whose run credential fails verification extends nothing. The gateway
keeps the refused run keys in its state directory, so a restart refuses them too. When
that write fails, the gateway reports it once and holds the run key all the same while
it runs; it writes them again on each refused request of the run key, every 5 seconds,
and once more at Close, until a write succeeds. It reports the write that succeeds
again, and at Close, when the write still fails, how many run keys a restart would not
refuse.

Neither `credential_check_unreachable` nor `credential_check_invalid` holds the run key: the next
request opens a run as soon as the issuer answers active. Each comes only after the run
credential's signature and claims verified, so it tells a caller that is not
authenticated nothing. Every failure of a run credential is one opaque answer,
`run_credential_refused` to a session and `407` to a client with no session, and names
no claim value. The run
credential never appears in an event, a record or a log. The proxy login over TLS, and
when the gateway asks the endpoint and refuses an ended run, are the gateway's. How an
issuer integrates: [docs/gateway-run-credentials.md](../../../docs/gateway-run-credentials.md).

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
   is read: the run's own events, its log and its egress record are all there, the
   session's are not. Any program runs behind a wall this way, with no descriptor.
3. **An implementation in Go**, for a caller that embeds Forager and whose program
   needs what a descriptor cannot express. It is set in `session.Spec.Runtime` like any
   other.

`session/runtimes/runtimetest` is what any of them is tested against: `Conforms`, that a runtime
leaves alone what is not its own, and `Replays`, that its records produce exactly the
recorded events and that each passes this contract's schema.

### The descriptor

`descriptor.schema.json`. One YAML file per runtime. It has six parts, beside
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
secrets it reads, each `{id, title, name, hosts, paths, auth}`: an id, unique among the
declarations; a title for a person choosing one; the variable the
runtime reads it from; the hosts its value is set on, exact DNS names; optionally the
paths of those hosts, in the policy's path grammar; and how it is set,
`auth.schema.json`, a scheme of the closed set, `bearer`, `header` with its `header`, or
`basic` with its `username`. `one_of` lists groups `{id, required, of}`, `of` being
declared ids, each in one group at most: groups of declarations of which the runtime
needs at most one, and exactly one of a `required` group. `reserves` lists variables
the runtime reads a credential from beside the declared ones; `denies`, variables the
session always leaves out of the server's set for the runtime; `credential_files`, files
in which the runtime keeps a credential of its own, `~` being the home of the user
Forager runs as. Behind a wall, a declared or reserved variable that neither a
placeholder, the run nor the runtime's preparation sets goes in empty (§Variables). The
session checks `secrets` when it reads the descriptor: the schema, that ids are
distinct, and that every id of a group is declared and in one group at most.

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
It is not the gateway's link, whose socket is the gateway's (§The gateway's link).
It is a Unix domain socket the session creates before the runtime starts, in a private
directory of its own under the system's temporary directory, mode `0700`, because a
socket path has a short limit on some systems and a run directory in a deep checkout can
exceed it. A client connects, writes one record per line in the shape of
`record.schema.json`, and closes; the session reads until end of file, one connection at
a time in the order they arrive, so two hook calls in a row keep their order. There is
no answer and no framing beyond the newline. The forwarder the session installs as a hook
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
- never the container runtime's own socket: a process that can request a
  container on the host's network from the daemon has left the wall. A mount that is a
  socket, or a directory containing a runtime's, is refused.

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

- the paths the caller lists as its own: for `qory`, the directory of `forager.yaml`, with
  the access key secret;
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
- the wall's own: for `docker`, the directory of the `docker` command and of the
  helper, and the command's configuration directory, `DOCKER_CONFIG` or `~/.docker`,
  whose context and credential helpers start programs;
- the runs directory, where the session makes the run directories;
- the session's registry of walled runs (below).

An agent that can change a program Forager starts outside the wall, or read a file a
credential is read from, has left the wall.

**No bind from a place a walled agent can change.** An engine looks up every name of a
bind's source path again when it binds it, links included, so a check of the path
before cannot hold if a name is looked up in a directory an agent can write. So no name
on the way to a walled run's bind source is looked up in a writable bind, the run's own
or another walled run's still going, or in a directory inside one. A bind's own root
is looked up in its parent, so two binds of one root are allowed:

- the enclosure binds the outermost of the places the run lists, the mounts and the
  workspace, each once, and the run directory, read-only. The workspace is writable and
  is the working directory inside, through the bind that holds it, or bound at its own
  path when no mount holds it. The session passes the wall every bind, each path clean,
  and the working directory lies in one of them by its names, or the run fails; a wall
  binds nothing of the caller's the launch does not list;
- a place inside another one, or the same, of the same mode is reached through the
  outer one, which alone is bound. Of the other mode it is no run,
  `mount_mode_conflict`, with the inner place and the outer one as its names, in that
  order: a read-only part of a writable bind is one the agent replaces, and a writable
  part of a read-only one writes what the run shows read-only;
- a place, of either mode, whose path goes through a link inside a writable place of
  the run's and that does not resolve into it is no run, `mount_through_link`: the
  agent that writes the link would choose what is bound. Its names are the place as
  passed, the link, absolute and clean, the last one inside the writable place on the
  way, and the writable place as passed;
- the runs directory is one of Forager's files, so the run directory lies in no
  place the run lists, and a writable place that holds a directory a name on the way
  to one of Forager's files is looked up in is `mount_contains_forager_files`;
- the session keeps a registry of the walled runs still going on the machine, per user,
  with each run's binds: the places, the run directory and the wall's own, for `docker`
  its helper, the hook socket's directory and the private directory that holds the run's
  environment files and, with a CA, the bundle the enclosure binds. The wall's are listed
  when the run starts, those it makes later as their patterns, which never conflict with
  another session's. A run is no run, `mount_shared_with_run`, when one of its binds lies
  inside a writable bind of another run's or is reached through one, when one of its
  writable binds holds a bind of another run's or a directory a name on the way to one is
  looked up in, or when one of its binds is, holds or lies inside another run's run
  directory, whatever the modes: a run directory is its run's alone. Two binds of the same
  root never conflict otherwise, and neither do two read-only ones. Its names are the path
  of this run's, the other run's id and the other run's path. A place that lies inside a
  writable directory another run's wall binds of its own is refused too. A run whose own
  helper, or another directory of Forager's its wall binds, lies inside a writable bind
  of another run's, or is reached through one, does not start. The session checks and lists
  the run in one step, before it contacts the server, and the run leaves the registry when
  it ends, however it ends, unless its wall could not be removed. A run is still going
  while its session holds its entry, or, once its session is gone, while the container
  engine its entry records, pinned by its selection and by its id when it gave one, holds
  a container labelled `dev.qory.run=<id>`, in any state. The selection is pinned by the
  variables the command reads: for the command named podman, `CONTAINER_HOST` or
  `CONTAINER_CONNECTION` set and recorded; for any other command, `DOCKER_HOST` or
  `DOCKER_CONTEXT` set and recorded, or the context the command shows. A variable of the
  other kind never pins. A command other than podman is asked by its id, through its
  pinned selection; podman is asked by its pinned selection when it gave no id. A run that
  cannot ask that engine, reaches another, or finds an entry whose engine is a command
  other than podman with no id, or podman with neither a pinned selection nor an id, is no
  run, `engine_unreachable`, whose names are the earlier run's id and then the absolute
  path of its entry in the registry.

Each of these refusals lists its names in the order given with it. A place of this run's,
a mount or the workspace, is named by its path as the caller passed it, and its run
directory by the runs directory the caller passed; a bind of another run's is named as
that run passed it, a file of Forager's, a link and a registry entry by their paths, and an
earlier or another run by its id. The first name of each `mount_` refusal is one of this
run's places, or for `mount_shared_with_run` also its run directory; the first name of
`engine_unreachable` is the earlier run's id. The session checks again just before the enclosure binds, with the wall's own binds, and
a place that resolves otherwise, or whose names are looked up in other directories,
than at the start does not start. So no name on the way to a bind source is looked up
in a place a walled agent of this user's can write. A process outside every wall, the
user's own or another user's, can still change a path between the session's last check
and the bind.

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
inside: behind a wall it is **guarded**, and what is on Forager's machine is not
reached by default. Two rules, in either mode, observe included:

- The link-local range, where a cloud keeps its metadata service, is refused whatever
  the allow list contains.
- Forager's own machine, loopback and every address it has, is refused unless an
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

**What crosses**, all three the session's, none containing a credential of the
gateway's: the proxy, as a network address; the pseudo-terminal or the pipes, through the
adapter's own command; the hook socket, as a mounted file where a file can cross.

**The relay.** The agent reaches the proxy by a name, through a relay: a process of
Forager's on the enclosure's network and on an ordinary one, listening on a fixed port and
copying every byte to one address fixed when it starts, the proxy's. It reads nothing,
decides nothing and takes no instruction from the agent; the policy stays in the
gateway. It exists because the host is not always where a container expects it: with
the engine in a virtual machine the network's gateway is the virtual machine's, not the
host's. It forwards no packet between its two networks: IP forwarding is off in its
namespace, so what it passes on is the connections it copies and nothing routed
through it.

**A Docker of the agent's own.** *Experimental.* Under the nested runtime the enclosure
has a root, and whether that root reaches the mounts the run lists as the machine's root
is unverified, so the option is experimental: it may change, and a run that uses it
mounts nothing the machine's root must protect.

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

**One conformance suite**, the `e2e` package, checks the list from inside the
enclosure with a real session behind the adapter, and an adapter ships when the suite
passes for it. The suite needs Linux and the tool, so it runs in Forager's CI on a
Linux machine; the ordinary tests compare the commands an adapter generates with golden
files and need neither.

**What ships:** `docker`, through the `docker` command and no library, serving whatever
engine that command reaches. It is supported where the suite passes. An engine in a
virtual machine on a Mac is where a wall is developed, not a target: the suite passes
there without the hook check (§Limits). The agent's image is the caller's; the wall
builds none. A Docker of the agent's own is experimental, under `sysbox-runc`, where the
suite passes with it: Forager's CI installs Sysbox on a Linux machine and runs the
suite in an enclosure with a daemon. The suite checks the list as the agent's user; what
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
| `fixtures/policy/` | policy documents that are accepted: observe, enforce, enforce with nothing, observe with a deny list, enforce with a tool, a credential and a tool each with an argument of 4096 characters, the most one may have | `policy.schema.json` |
| `fixtures/server/` | server documents that are accepted, with the fixture access key id and the fixture signing key as the pin | `server.schema.json` |
| `fixtures/configuration/` | configuration documents a server returns: events only, with a run section, with a section this revision does not define, with `secrets` and two keys of a rotation | `configuration.schema.json` |
| `fixtures/run-configuration/` | run configuration documents a server returns: with a policy of each mode, with variables, and with neither, which leaves the node's policy in force | `run-configuration.schema.json` |
| `fixtures/batch/` | delivery bodies: the ping, a first batch, the `dev.qory.run.refused` of a run whose run configuration was refused, `run_configuration_invalid`, the first and the last batch of a run a gateway opened, `gateway-first.json` and `gateway-quiet.json`, and the `dev.qory.run.exited` of such a run that ends `gateway_lost`, `failed` with no `exit_code`, `gateway-lost.json`, and of one its starter ended with the outcome `succeeded` and the reason `all_checks_passed`, `gateway-outcome.json`; the gateway's `dev.qory.run.exited` of a session's run whose starter gave no outcome, `cancelled` with `stopped` and `exit_code` `-1`, `session-stopped.json`, and a session's own of a runtime that exited 0 and whose starter gave `failed` and `checks_failed` at the exit, `session-outcome.json`; and, in the shape of a batch, `refused-differs-from-credential.json`, the `dev.qory.run.refused` a session records when a gateway refuses its run request with `differs_from_credential`, each name a member and the run credential's value; and the `dev.qory.run.refused` of the server's `not_found` with its `status` `404`, `refused-not-found.json`, and of a code of the server's the schema's list does not hold, with its `status`, `refused-unlisted-server-code.json` | `batch.schema.json` |
| `fixtures/signed/` | signed requests, one per file, under the fixture access key secret, with the status a receiver returns and the code of a coded refusal | the receiver, replaying each with its clock at `1700000000` and checking each answer's signature |
| `fixtures/run/<id>/` | recorded runs, `events.jsonl` and `output.log` each: one on a developer machine, one behind a wall that reaches a tool started with an argument, with a credential an adapter mints, and one a gateway opened, with no process, that ends `quiet` | `event.schema.json` per line, plus the sequence, source and concatenation rules, and that every `dev.qory.run.exited` contains `state`, a session's `exit_code` too and a gateway-opened run's none |
| `fixtures/run/about-*.json` | the `about` of `dev.qory.run.started` (§What a run is about): accepted ones, with a title alone, with every member and `details` 4 levels deep, with a `type` of two words and one of a dotted name; and refused ones, `about-refused-<reason>.json`, one per bound. A refused one named `about-refused-beyond-schema-<reason>.json` breaks a rule only Forager checks, and passes the schema: a `kind` of 64 characters and 128 bytes, two subjects with the same `type` and `ref`, a `url` with no host, a `url` with a user name and password, `details` over 8192 bytes as the event contains it, and `details` with a member name twice | the `about` of `events/run.started.schema.json`, expecting a failure for each refused one the name does not mark beyond the schema; the session's check, `session.CheckAbout`, expecting a failure for every refused one |
| `fixtures/link/` | documents of the gateway's link, each named after its schema: the discovery of the local link and of a separate gateway, each with its `proxy`, a run request without a wall with its `passes`, one with a wall, its `passes` and `images`, and one with a narrowing as well, a run answer with a wall, its `credential` `starter`, the run credential's labels and `details`, `placeholders`, `reserved`, `image`, `applied` and `certificate_authority`, one with a wall and an `image` whose default is a reference but no `certificate_authority`, one without a wall and one without a policy, each with its `applied`, a reload answer with and without a policy, each with its `applied`, an outcome answer with the outcome `cancelled` and the reason `no_longer_needed`, one with an outcome alone and one with none, `{}`, a batch of a session's events without `sequence`, its `dev.qory.run.started` first, a batch of the `dev.qory.run.refused` of a session's own code, a batch of a session's `dev.qory.run.exited` with `timeout`, `cancelled`, one of a session's `dev.qory.run.exited` with the starter's outcome at the exit, and refusals: `run_closed`, `credential_expired`, `session_lost` with its `state` and `reason`, `stopped` with `cancelled` and `stopped` and with the starter's `failed` and `checks_failed`, `batch_refused`, `differs_from_credential` with its name, `placeholder_conflict`, `image_unknown`, `tool_unknown`, `wall_required` and `internal`, once with a `message` of one line and once with one that spans lines, from `gateway`, each with today's text as its `message` but `run_closed`, `credential_expired` and `differs_from_credential`, which show it optional, and the signed `409` `instance_limit` to the ping from `apiary` with Qory Apiary's URL in its `message`, each the body alone | the `link-*.schema.json` its name starts with |
| `fixtures/run-credentials/` | run credentials documents that are accepted: one issuer with one key without a kid, and one issuer during a rotation, two keys with kids, a scope, details, `max_lifetime` and introspection | `run-credentials.schema.json`; `runcredential.Issuers.Check` |
| `fixtures/invalid/` | documents each schema refuses, whose name is `<schema>-<reason>` | the schema the name starts with, expecting a failure |
| `fixtures/enrolment/` | enrolment requests, with a code that carries one fingerprint and with one that carries two, the answer, the signed refusals `key_limit` and `key_invalid`, each with one key and during a rotation with two, and the signed `429` `rate_limited` with one key | `enrolment.schema.json`; each proof under the fixture access key, each answer's and refusal's signature under the fixture signing key |
| `fixtures/known-answers/` | `keys.json`, the fixture access key with its secret, instance id and X25519 keys, and the fixture signing keys, current and next; `signatures.json`, the request, enrolment and answer strings line by line with their signatures, the signed enrolment refusals among the answers; `discovery.json`, the body an answer signature covers; `small-order.json`, the public keys enrolment refuses | `configuration.schema.json` for `discovery.json`; each key recomputed from its seed, each signature verified and signed again, each point checked with integer arithmetic |
| `fixtures/known-answers/run-credentials/` | `keys.json`, the fixture issuer's seed, bytes 193 to 224, and how its keys derive from it; the public keys `rs256.pem`, `es256.pem` and `eddsa.pem`; `one-key.json` and `two-keys.json`, two configurations of the fixture issuer; `credentials.json`, run credentials signed under the keys, with `now`, each with its outcome and, for a refused one, the step that refuses it: the serialisation (padding, a line feed, a space, four parts, two parts), the header (`alg` `none`, `HS256` under the RSA public key as the secret, a `kid` unknown, no `kid` with two keys, an `alg` other than the key's, `crit`, a `typ` other than `JWT`, a member name twice), the signature (over an altered payload, over an altered header, an `ES256` signature of 63 or 65 bytes, with `R` zero or `S` the order), the claims (a member name twice, `aud` and `iss` another's, no `aud`, expired, no `exp`, `iat` ahead, a lifetime above `max_lifetime`, no `iat`, no `sub`), the scope, or the mapping (a `requester` that is not a string, a `project` with a control character); accepted ones per algorithm, with `typ` `jwt` and without `typ`, and one without `requester`, which leaves that key of `about.details` to the session. The keys are public: Forager refuses each in a configuration, and they are never pinned | `run-credentials.schema.json` for the configurations; `runcredential`'s tests, which derive every file from the seed again, run `Verifier.Verify` on each, and check each on its own against the serialisation, the header, the claims, the scope and the mapping up to the step that refuses it, and verify the signature of each that reaches the signature step |
| `runtimes/<name>/fixtures/<case>/` | descriptor fixtures | `record.schema.json` and the data schema of each expected type |

After a change to a batch's body, Forager's module signs the batches under
`fixtures/signed/` again, under the fixture access key secret, with
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
  [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) §2.1 for the header
  `Authorization: Bearer` the run credential is presented in, and §3 for
  `WWW-Authenticate`. UUID version 7 from
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
  the only version a separate gateway speaks;
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
- The run credential: JWT, [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), and
  its best current practices, [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html);
  JWS, [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), for the compact
  serialisation, `kid` and `crit`; the algorithms of
  [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) §3.3 and §3.4, `RS256` and
  `ES256` with its 64-byte signature, and `EdDSA` of
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html); OAuth 2.0 token
  introspection, [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html); and
  [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) §11.7 with the Basic scheme of
  [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html) for the proxy login and its
  `407`.
