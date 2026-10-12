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
- **0.6.0**, experimental: it starts nested Docker inside the container, under
  `sysbox-runc`.
- **0.7.0**: it runs a run's containers on the engine it recorded as the run started,
  and refuses a mount or workspace that lies inside a writable directory another run's
  wall binds.
- **0.7.0**: it refuses a requested host that is neither a plain name nor an IP address
  in canonical form, and judges an address in `::/96` (other than `::1` and `::`),
  `::ffff:0:0:0/96` or `64:ff9b::/96` by the IPv4 address it carries as well.
- **0.7.0**, experimental: with nested Docker, the wall's inside network has an IPv6
  subnet in Docker's isolated gateway mode, and nested Docker needs Docker Engine 28 or
  later.

To start and configure it: [the wall](wall.md#start-a-walled-run).

## Runs on a node

On a node, `qory run --wall docker` is started by a person, a CI job or your scheduler.
The node needs Docker.

Reporting to Qory Apiary uses the same server every run has:

- Qory Apiary creates the run from the first event it sees;
- it supplies the run's policy.

See [the server](server.md).
