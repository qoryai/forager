# The server

Every event goes to files. With a server configured, every event its configuration
selects goes there too, signed. The server can also set the run's policy.

A server is a control plane, or a receiver of your own.

## In runner.yaml

For `qory`, the `server` section of `~/.config/qory/runner.yaml` defines the server. The
example is in [the policy](policy.md#in-runneryaml).

- The runner reports to the server, signed.
- The run's policy comes from the server, when the server offers one.
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
   run as its query, and takes its `security_policy` as the run's policy.

The server decides which labels identify what the run works on.

## A policy that changes while the run goes

A server may answer a later batch with another digest. The runner then fetches the run
configuration again, and puts it in force while the run goes.

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
