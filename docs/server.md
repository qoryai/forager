# The server

Every event goes to files. With a server configured, every event its configuration
selects goes there too, signed. The server can also set the run's policy.

A server is a control plane, or a receiver of your own.

## In runner.yaml

For `qory`, the `server` section of `~/.config/qory/runner.yaml` defines the server. The
example is in [the policy](policy.md#in-runneryaml).

- The runner reports to the server, signed.
- The run's policy comes from the server, when the server offers one. The node's policy
  narrows it. See [the policy](policy.md#the-node-narrows-the-servers-policy).
- The run's variables come from the server as well. See [variables](#variables).
- `secret` can come from `QORY_SERVER_SECRET` in the environment instead of the file.
- With `server` set, the run starts only when the server answers the fetch and a ping.
  So a run meant to be observed never runs unobserved.
- `qory run --local` runs with the files alone.
- Without `server`, the run writes files only.

## How the runner uses the server

A `session.Server` in the spec defines the server the runner reports to. The runner:

1. fetches the server's configuration document, with a signed `GET` of
   `/.well-known/qory-configuration`;
2. posts the events that document selects to the URL it defines, signed, with the
   access key beside the signature;
3. when the document contains a run configuration, fetches it, with every label of the
   run as its query. Its `security_policy`, narrowed by the node's policy, is the run's
   policy. Its `variables` are the server's variables for the run.

The server decides which labels identify what the run works on.

## A policy that changes while the run goes

A server may answer a later batch with another digest. The runner then fetches the run
configuration again, and puts it in force while the run goes, narrowed by the same node
policy. The variables stay as they were when the run started.

## Variables

A run configuration may contain `variables`: names and string values for the agent's
process. The server leads:

- The server's variables are the run's.
- The node's own variables add names. For `qory`, these are `wall.env` and `--env`. A
  node variable for a name the server sets is left out, and the record lists it as
  `node_ignored`.
- A name on the deny list is left out, and listed as `denied`. The list is the
  contract's [`denied-variables.json`](../contracts/runner/v1/denied-variables.json),
  the runtime's `denies`, and `variables.deny` in `runner.yaml`. It holds the runner's
  own names, the proxy's, the trust store's, Docker's and `PATH`.
- A name the runner or the runtime sets itself is left out the same way, as is one the
  runtime reads its credential from.
- A run without a wall takes none of the server's variables, unless `runner.yaml` sets
  `variables.unwalled: accept`. The record lists them as `unwalled`.

```yaml
# ~/.config/qory/runner.yaml
variables:
  deny: [LEGACY_SETTING, ACME_*] # names and patterns, in any case
  unwalled: ignore               # or accept: an unwalled run takes them too
```

Behind a wall, the run refuses to pass in what stays outside:

| The run passes                                   | The refusal               |
| ------------------------------------------------ | ------------------------- |
| a `QORY_` variable, or one a credential is read from | `variable_reserved`   |
| a value for a placeholder                        | `placeholder_conflict`    |

The record lists every variable by name, never a value. From Go, `Variables` in the
spec holds the node's own variables, its deny entries and `Unwalled`, and `LaunchEnv`
what the harness sets.

## A control plane

Reporting to a control plane works today, without the fleet layer of the
[node runner](node.md). A control plane is the same server every run has:

- it creates the run from the first event it sees;
- it supplies the run's policy, as the server's run configuration.

## Writing a server

- **The rules**: the contract's
  [server section](../contracts/runner/v1/README.md#the-server).
- **A worked example**: the public package [`receiver`](../receiver/receiver.go). It is a
  server of the contract that is not a control plane. The runner's tests run against
  it, and it is tested against the signed fixtures.
- **The test data**: `contracts/runner/v1/fixtures/signed/`. Any receiver is tested
  against it.
