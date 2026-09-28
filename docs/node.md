# The node runner

A node runner is a machine that runs agents for someone else. It takes work, starts each
run behind a wall, and reports what happened.

It has two halves. One of them ships.

## The wall

The wall starts the agent in a container with no route out except to the session
runner's proxy. The policy, the record and the server's secret stay on the node.

It ships. The versions are the runner's:

- **0.2.0**: as `qory run --wall docker`.
- **0.3.0**: it keeps a run's credentials outside the container, and limits a host to
  paths.
- **0.6.0**: it starts a run's tools outside the container, and passes them the requests
  to the hosts they serve.
- **0.6.0**: it starts a run in the image of the machine's that its policy selects.
- **0.6.0**, experimental: it starts a Docker daemon of the agent's own inside the
  container, under `sysbox-runc`.

To start and configure it: [the wall](wall.md#start-a-walled-run).

## The fleet layer

The fleet layer registers the node with a control plane, heartbeats and claims work.

It is not built. No command starts it, and nothing here describes it as if one did. The
run's policy from the control plane has shipped since 0.4.0, as the server's run
configuration.

It will live in `node/`. It will:

- register,
- heartbeat,
- take a dispatched task,
- keep the run's credentials,
- start a session through `session`, behind a wall.

`node` will import `session`; `session` never imports `node`.

## A node today

Today a node is a machine with Docker, on which `qory run --wall docker` is started: by a
person, a CI job or a scheduler of your own.

Reporting to a control plane already works without the fleet layer. It is the same
server every run has:

- the control plane creates the run from the first event it sees;
- it supplies the run's policy.

See [the server](server.md).
