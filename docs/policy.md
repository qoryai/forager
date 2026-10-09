# The policy

Forager pins one policy for the run. A policy can only narrow what the binary allows.
Forager observes and enforces egress through a proxy it owns.

## The modes

| Mode      | What it does                                                   |
| --------- | -------------------------------------------------------------- |
| `enforce` | Records every connection; denies every host outside `allow`    |
| `observe` | Records every connection; denies only the hosts `deny` covers  |

`deny` applies in either mode, whatever `allow` lists.

## Hosts

`allow` and `deny` list hosts, and nothing else:

- a name, such as `api.anthropic.com`,
- or `*.` and a name, for every host below it.

## What else a policy selects

Behind a wall, a policy does more:

| Field          | What it does                              |
| -------------- | ----------------------------------------- |
| `egress.paths` | Limits a host to paths                    |
| `credentials`  | Selects the machine's credentials by name |
| `tools`        | Selects the machine's tools by name       |
| `image`        | Selects the machine's image by name       |

The machine defines the credentials, the tools and the images. A policy selects among
them. See [credentials](credentials.md), [tools](credentials.md#tools) and
[images](wall.md#images).

## Where the policy comes from

A run has one policy. It comes from one of three places:

- **The machine's policy.** For `qory`, the `egress` section of `forager.yaml`, below.
  From Go, `Policy` in the spec.
- **A run's own policy.** `qory run --policy <file>` reads it, in the format of the
  contract's [policy](../contracts/forager/v1/README.md#the-policy).
  - It narrows the machine's `egress`, and never widens it.
  - Keep the file outside the checkout: the agent can write there. `qory` refuses a file
    in the checkout, or in a mount the container may write.
  - With a server configured, it needs `--local`.
- **The server's run configuration.** The server's configuration may contain a `run`
  section. Then the gateway fetches the run configuration, with the run's labels. Its
  `security_policy` is the server's policy, and the node's policy narrows it.

The node's policy is `Spec.Policy`, the policy Forager is passed: for `qory`, the
machine's `egress` with the run's own under it. Which one applies:

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
| `egress.paths` | a request to a host either side lists must match an entry of each side that lists it |
| `tools`        | the server's selection, within the node's `tools` when it has that member |
| `image`        | the one both select, or the one a side selects                            |

- A tool the node's `tools` does not list is no run, `tool_unknown`. `tools: []` allows
  none.
- Two different images are no run, `image_unknown`.
- The record reports the policy the table computes, and the node's policy as
  `node_policy`: its digest and its paths.

With no policy at all, the gateway observes everything: every connection is allowed and
recorded.

## In forager.yaml

For `qory`, one optional file changes what Forager does: `~/.config/qory/forager.yaml`.
It is never in a repository.

```yaml
apiVersion: qory.dev/v1alpha1
egress:
  mode: enforce                         # or observe: record everything, deny only what deny names
  allow: [api.anthropic.com, "*.github.com"]
  deny: [gist.github.com]               # denied in either mode, whatever allow says
server:                                 # optional
  url: https://qory.example
  access_key_id: ak_f1xt0re000000000   # or QORY_ACCESS_KEY_ID in the environment
  apiary_public_key:                   # the pin; or QORY_APIARY_PUBLIC_KEY, as JSON
    - {alg: ed25519, public_key: <the server's public key>}   # enrolment writes it
```

- `egress` is the machine's policy. It is the ceiling on a run's own, and it narrows
  the server's. See [where the policy comes from](#where-the-policy-comes-from).
- Without `egress`, and with no other policy, everything is allowed and recorded.
- `server` defines the server the gateway reports to. See [the server](server.md).

## A denied connection

A denied connection is:

- one `403` to the runtime, and
- one `dev.qory.run.egress` event with `decision: denied`.

The session goes on. A denial never ends a session.

Of what Forager does, only a time limit ends a session: `Timeout` in the spec. At the
limit, the runtime is stopped, and `dev.qory.run.exited` records the reason. The session
stops the runtime the same way when the caller's context ends.

## Hosts the harness declares

The hosts the harness's modules declare are reported. They decide nothing. The policy's
list decides.

The spec's `Declared` is the egress the harness declared. The record reports it as
`harness_hosts`. `nil` means no declaration.

## Behind a wall

Behind a wall, the proxy is guarded. It refuses some addresses in either mode. See
[the guard](wall.md#the-guard).

## The details

Every field, and how a connection and a path are matched: the contract's
[policy section](../contracts/forager/v1/README.md#the-policy).
