# Nodes

A node is a machine that runs agents behind the wall, for someone else, and reports what
happened.

## The wall

The wall starts the agent in a container with no route out except to the
gateway. The policy, the record and the access key secret stay on the node.

Forager added it in these versions:

- **0.2.0**: as `qory run --wall docker`.
- **0.3.0**: it keeps a run's credentials outside the container, and limits a host to
  paths.
- **0.6.0**: it starts a run's tools outside the container, and passes them the requests
  to the hosts they serve.
- **0.6.0**: it starts a run in the image of the machine's that its policy selects.
- **0.6.0**, experimental: it starts a Docker daemon of the agent's own inside the
  container, under `sysbox-runc`.

To start and configure it: [the wall](wall.md#start-a-walled-run).

## Runs on a node

On a node, `qory run --wall docker` is started by a person, a CI job or a scheduler of
your own. The node needs Docker.

Reporting to a control plane uses the same server every run has:

- the control plane creates the run from the first event it sees;
- it supplies the run's policy.

See [the server](server.md).
