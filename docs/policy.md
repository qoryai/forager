# The policy

The runner pins one policy for the run. A policy can only narrow what the binary allows.
The runner observes and enforces egress through a proxy it owns.

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

## In runner.yaml

For `qory`, one optional file changes what the runner does: `~/.config/qory/runner.yaml`.
It is never in a repository.

```yaml
apiVersion: qory.dev/v1alpha1
egress:
  mode: enforce                         # or observe: record everything, deny only what deny names
  allow: [api.anthropic.com, "*.github.com"]
  deny: [gist.github.com]               # denied in either mode, whatever allow says
server:                                 # optional
  url: https://qory.example
  access_key: ak_f1xt0re000000000
  secret: sixteen-characters-at-least   # or QORY_SERVER_SECRET in the environment
```

- `egress` is the ceiling on what the runtime may reach.
- Without `egress`, everything is allowed and recorded.
- `egress` is the policy when the server offers no run configuration.
- `server` defines the server the runner reports to. See [the server](server.md).

## A denied connection

A denied connection is:

- one `403` to the runtime, and
- one `dev.qory.run.egress` event with `decision: denied`.

The session goes on. A denial never ends a session.

Of what the runner does, only a time limit ends a session: `Timeout` in the spec. At the
limit, the runtime is stopped, and `dev.qory.run.exited` records the reason. The runner
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
[policy section](../contracts/runner/v1/README.md#the-policy).
