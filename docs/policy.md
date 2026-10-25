# The policy

Forager pins one policy for the run. A policy can only narrow what the binary allows.
Forager observes and enforces egress through a proxy it owns.

## The modes

| Mode      | What it does                                                   |
| --------- | -------------------------------------------------------------- |
| `enforce` | Records every connection; denies every host outside `allow` and `allow_first` |
| `observe` | Records every connection; denies only the hosts `deny` covers  |

`deny` applies in either mode, whatever `allow` lists. `allow_first` is checked before
`deny` and `allow`: a host it lists is allowed in either mode, though `deny` covers it.

## Hosts

`allow` and `deny` list hosts, and nothing else:

- a name, such as `api.anthropic.com`,
- or `*.` and a name, for every host below it.

`allow_first` lists hosts themselves: a name or an IPv4 address, never a `*.` pattern,
at most 64 entries. A host below an entry is not matched. Behind a wall, the guard and
the path rules still apply to a host `allow_first` lists.

## What else a policy selects

A policy selects more. `credentials` applies with or without a wall; the others need a
wall, and a run without one does not start (`wall_required`):

| Field          | What it does                                                       |
| -------------- | ------------------------------------------------------------------ |
| `egress.paths` | Limits a host to paths                                             |
| `credentials`  | Selects the machine's credentials by name                          |
| `tools`        | Selects the machine's tools by name                                |
| `image`        | Selects the machine's image by name, or an allowed image by digest |

The machine defines the credentials, the tools and the images. A policy selects among
them. See [credentials](credentials.md), [tools](credentials.md#tools) and
[images](wall.md#images).

## Where the policy comes from

A run has one policy. It comes from one of three places:

- **The machine's policy.** For `qory`, the `gateway.egress` section of `forager.yaml`,
  below. From Go, `Policy` in the gateway's `gateway.Config`.
- **A run's policy file.** `qory run --policy <file>` reads it, in the format of the
  contract's [policy](../contracts/forager/v1/README.md#the-policy).
  - It narrows the machine's `gateway.egress`, and never widens it.
  - Keep the file outside the checkout: the agent can write there. `qory` refuses a file
    in the checkout, or in a mount the container may write.
  - With a server configured, it needs `--local`.
- **The server's run configuration.** The gateway registers the run at the server's
  run endpoint, with the run's labels, and the answer is the run configuration. Its
  `security_policy` is the server's policy, and the node's policy narrows it.

The node's policy is `gateway.Config.Policy`, the policy Forager is passed: for `qory`,
the machine's `gateway.egress` with the run's policy file under it. Which one applies:

| Forager has            | The policy is                                                           |
| ---------------------- | ----------------------------------------------------------------------- |
| no server              | the node's                                                              |
| a server               | the server's, narrowed by the node's; the node's when the server has none |
| a server and `--local` | the node's                                                              |

## The node narrows the server's policy

The server leads, and the node only takes away. A node is easier to compromise than the
server, so what the node contributes can only narrow the run:

| Field          | The run's                                                                 |
| -------------- | ------------------------------------------------------------------------- |
| `egress.mode`  | `enforce` when either side sets it                                        |
| `egress.allow` | the hosts both sides allow; a side under `observe` allows every host      |
| `egress.deny`  | both sides' entries                                                       |
| `egress.allow_first` | each side's entries the other side allows: a node's `deny` still denies a server's entry |
| `egress.paths` | a request to a host either side lists must match an entry of each side that lists it |
| `tools`        | the server's selection, within the node's `tools` when it has that member |
| `image`        | the one both select, or the one a side selects                            |

- A tool the node's `tools` does not list is no run, `tool_unknown`. `tools: []` allows
  none.
- Two different images are no run, `image_unknown`. The server's run configuration may
  name the image too, by reference only, in its `image` member beside its
  `security_policy`: the run configuration, the server's policy and the node's policy
  name the same image wherever two of them name one, else `image_unknown`.
- The record reports the policy the table computes, and the node's policy as
  `node_policy`: its digest and its paths.

With no policy at all, the gateway observes everything: every connection is allowed and
recorded.

## In forager.yaml

For `qory`, one optional file changes what Forager does: `~/.config/qory/forager.yaml`.
It is never in a repository.

```yaml
apiVersion: qory.dev/v1alpha1
gateway:
  egress:
    mode: enforce                       # or observe: record everything, deny only what deny names
    allow: [api.anthropic.com, "*.github.com"]
    deny: [gist.github.com]             # denied in either mode, whatever allow says
  run_limits:                           # optional; the same for every run on this gateway
    connections: 256                    # open at once, 1 to 65536
    requests_per_second: 50             # 1 to 10000
    burst: 200                          # requests at once after a pause, 1 to 100000
  stack_hosts: [git.example.com, "*.example.org"]   # optional; where qory fetches the harness definition
  server:                               # optional
    url: https://qory.example
    access_key_id: ak_f1xt0re000000000  # or QORY_ACCESS_KEY_ID in the environment
    apiary_public_key:                  # the pin; or QORY_APIARY_PUBLIC_KEY, as JSON
      - {alg: ed25519, public_key: <the server's public key>}   # enrolment writes it
```

- `gateway.egress` is the machine's policy. It is the ceiling on a run's policy file,
  and it narrows the server's. See
  [where the policy comes from](#where-the-policy-comes-from).
- Without `gateway.egress`, and with no other policy, everything is allowed and recorded.
- `gateway.server` defines the server Forager reports to. See [the server](server.md).
- `gateway.lock_memory`, on Linux, keeps the gateway's memory out of swap. See
  [keep the memory out of swap](credentials.md#keep-the-memory-out-of-swap).
- `gateway.run_limits` limits each run on the gateway, so that one run cannot slow down
  the others. Each run has counters of its own. A field you leave out is its default.
  See [run limits](#run-limits).
- `gateway.stack_hosts` lists the hosts qory fetches a run's harness definition from
  before the run's first session, over HTTPS or plain HTTP, on any port: each a
  lower-case host name, an IPv4 address or a `*.` suffix. The run's policy is not
  checked. Each fetch shows in the gateway's log, and in the run's record as a
  `dev.qory.run.egress` with `channel: stack`. Behind a
  wall or a separate gateway, a host at this machine's address or a private network
  address is reached only when `gateway.stack_hosts` and `egress.allow` of the node's
  policy both list it by name, not by a `*.` pattern. A link-local or cloud metadata
  address is never reached.

## Run limits

Each run on a gateway can have at most `connections` connections open at once: `CONNECT`
tunnels and plain HTTP requests in flight. The next one gets `429 Too Many Requests` with
`Retry-After: 1` at once.

Each run can send `requests_per_second` requests a second, and up to `burst` at once
after a pause. Every `CONNECT`, plain request and request inside a tunnel the gateway
terminates counts. A request past the limit waits up to 5 seconds, then gets `429 Too Many
Requests` with `Retry-After: 1`. While `connections` requests of the run already wait, the
next request past the limit gets the `429` at once.

The body of each `429` says which limit refused the request and its value, such as:

```
qory: retry in 1 second. This run's requests came faster than 50 a second, the most gateway.run_limits.requests_per_second allows, and this request waited 5 seconds.
```

The record has a `dev.qory.run.egress` with `decision: denied` and the rule
`wall:connection-limit` or `wall:rate-limit`, at most one per limit per second. The
details: the contract's
[policy section](../contracts/forager/v1/README.md#the-policy).

## A denied connection

A denied connection is:

- one `403` to the runtime, and
- one `dev.qory.run.egress` event with `decision: denied`.

The session goes on. A denial never ends a session.

Of what the session does itself, only a time limit ends a session: `Timeout` in the
spec. At the limit, the runtime is stopped, and `dev.qory.run.exited` records the
reason. The session stops the runtime the same way when the caller's context ends, and
when the gateway closes the run. See
[the server](server.md#when-the-server-refuses-a-run-or-wants-nothing-more).

## Hosts the harness declares

The hosts the harness's modules declare are reported. They decide nothing. The policy's
list decides.

The spec's `Declared` is the egress the harness declared. The record reports it as
`harness_hosts`, a host that contains `qak_`, `qrk_`, `qecr_`, `qecn_`, `qecp_`, `qecg_`
or `qeci_` as the value's phrase in its place. `nil` means no declaration.

## Behind a wall

Behind a wall, the proxy is guarded. It refuses some addresses in either mode. See
[the guard](wall.md#the-guard).

## The details

Every field, and how a connection and a path are matched: the contract's
[policy section](../contracts/forager/v1/README.md#the-policy).
