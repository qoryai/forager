# The server

Every event goes to files. With a server configured, every event its configuration
selects goes there too, signed. The server can also set the run's policy.

A server is a control plane, or a receiver of your own.

## In runner.yaml

For `qory`, the `server` section of `~/.config/qory/runner.yaml` defines the server. The
example is in [the policy](policy.md#in-runneryaml).

- The runner reports to the server as an access key: `access_key_id` is its id, and
  its secret, one line starting `qak_`, lives in the file `access-key-secret` beside
  `runner.yaml`, or in `QORY_ACCESS_KEY_SECRET`. The secret signs every request with
  Ed25519 and is never sent.
- `apiary_public_key` is the pin, the server's keys: the runner verifies every answer
  under it. A server without a pin is no run.
- `qory access-key enrol` enrols a new key with a code from the server and writes the
  id and the pin; the key awaits approval, and until then a run is refused with
  `key_pending`. `qory access-key create` prints a public key for the server's owner to
  paste, and a pasted key is approved as it is entered.
- The run's policy comes from the server, when the server offers one.
- With `server` set, the run starts only when the server answers the fetch and a ping,
  signed. So a run meant to be observed never runs unobserved.
- `qory run --local` runs with the files alone.
- Without `server`, the run writes files only.

## How the runner uses the server

A `session.Server` in the spec defines the server the runner reports to. The runner:

1. fetches the server's configuration document, with a signed `GET` of
   `/.well-known/qory-configuration`;
2. posts the events that document selects to the URL it defines, signed, after a
   ping that announces the heartbeat interval; heartbeats run from the accepted ping;
3. when the document contains a run configuration, fetches it, with every label of the
   run as its query, and takes its `security_policy` as the run's policy.

Every request is signed with the access key, the access key id and the instance id
among the signed lines. Every answer is signed with the server's key and bound to the
request, and the runner reads an answer only once it verifies under the pin. The
server decides which labels identify what the run works on.

## When the server refuses or closes a run

A refusal at the start has a code, `session.Refusal` in Go: `unauthorized` for a key the
server does not hold, `key_pending` for a key that awaits approval, `instance_limit`
when the node's live instances are at its limit, `answer_unsigned` for an answer that
does not verify under the pin, and `apiary_public_key_missing` for a server without a
pin. A server closes a running run with a signed `410` `run_closed`: the runner stops
the runtime as at its time limit, records `reason: run_closed`, and sends nothing
further.

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
