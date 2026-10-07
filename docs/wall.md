# The wall

The proxy sees only programs that honour it. Without a wall, enforcement is cooperative:
a program that ignores the proxy variables is not seen.

A **wall** starts the runtime in a container with no route out except to the proxy. So
the rest fails, instead of going unseen. A program that ignores the proxy reaches
nothing.

## How it works

```
 the node                                              elsewhere
┌─────────────────────────────────────────────────────┐
│ qory run: the session runner, outside the wall      │
│   policy ─▶ proxy ─▶ decides, records, dials ───────┼──▶ the hosts the policy allows
│   events ─▶ .qory/runs/<id>/events.jsonl            │
│          └▶ events, signed ─────────────────────────┼──▶ the server: your control plane
│      ▲ proxy      ▲ hooks       ▲ terminal          │
│══════╪════════════╪═════════════╪════ the wall ═════│
│  ┌───┴───┐   ┌────┴─────────────┴────────────────┐  │
│  │ relay │◀──│ the agent's container: your image │  │
│  └───────┘   │ no route · no resolver · not root │  │
│              └───────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

- The agent's container is on a network with no route out.
- The one peer it reaches is the relay. The relay copies a fixed port to the proxy, and
  decides nothing. It forwards no packet between its networks.
- So every connection is the proxy's to decide and record.
- The checkout and the composed home are mounted at their own paths. The run's record is
  mounted read-only.
- Nothing else of the node is visible inside.
- A mount that is, contains or lies inside one of the runner's files is no run,
  `mount_contains_runner_files`: the runner file's directory with the access key
  secret, the programs the runner starts outside the wall, their configuration. See
  [the runner's files](#the-runners-files).
- The session runner, the policy and the access key secret stay outside, on the node.
  The record is written from outside.

What every wall guarantees is in the contract's
[wall section](../contracts/runner/v1/README.md#the-wall). The
[conformance suite](../wall/walltest/walltest.go) checks it from inside the container, in
this repository's CI.

## Turn it on

In `qory`, turn it on with a `wall` section, or with
`qory run --wall docker --image <image>`:

```yaml
wall:
  adapter: docker
  image: example.com/agent:1            # yours: the runtime and your toolchain
  env: [ANTHROPIC_API_KEY]              # names; nothing else of your environment goes in
```

## Start a walled run

You need:

- the `docker` command, with an engine behind it;
- [`qory`](https://github.com/qoryai/qory) 0.7.0 or later;
- an image of yours that contains the runtime and your toolchain. The wall builds none.

A minimal image for Claude Code:

```dockerfile
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* && npm install -g @anthropic-ai/claude-code
# The container runs as the node's user, who has no home in the image.
ENV HOME=/tmp
```

```sh
docker build -t agent:1 .
cd your-checkout && qory harness compose
export ANTHROPIC_API_KEY=...            # a key, or CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token`
qory run --wall docker --image agent:1 --env ANTHROPIC_API_KEY claude -- -p "Reply pong"
```

The run is recorded in `.qory/runs/<id>/`, as without a wall. `dev.qory.run.started`
contains the wall and the image. The exit status is the agent's.

### On Linux and on a Mac

The helper and the hooks differ by machine:

- **On Linux**, `qory` mounts itself into the container as the relay and the hook
  forwarder. The agent's hooks reach the runner.
- **On a Mac**, the container cannot run the Mac's binary. Download the Linux archive of
  the same `qory` release, for your engine's architecture. Set `wall.helper` to that
  binary.

On a Mac, the hook socket does not cross the engine's virtual machine. So a walled run
there has the log, the egress record and the structured output, and no hook events.

## Configure it

One file on the node defines it: `~/.config/qory/runner.yaml`. It is never in a
repository, so a checkout cannot set what it runs under. With a `wall` section, a bare
`qory run` is walled:

```yaml
apiVersion: qory.dev/v1alpha1
egress:                         # what the agent may reach; without it, everything, recorded
  mode: enforce                 # or observe: record everything, deny only what deny names
  allow: [api.anthropic.com, github.com, "*.githubusercontent.com"]
server:                         # how the node reports; without it, files only
  url: https://control-plane.example.com
  access_key_id: ak_f1xt0re000000000   # or QORY_ACCESS_KEY_ID in the environment
  apiary_public_key:                   # the pin; or QORY_APIARY_PUBLIC_KEY, as JSON
    - {alg: ed25519, public_key: <the server's public key>}   # enrolment writes it
wall:
  adapter: docker
  image: agent:1                # or --image
  env: [ANTHROPIC_API_KEY]      # names; the values come from qory run's environment
  user: "1000:1000"             # only where qory runs as root, which a wall refuses
  helper: /opt/qory/qory-linux  # only where qory is not a Linux build
  command: podman               # only for another command than docker
```

- `egress` is the policy when the server offers no run configuration, and it narrows
  the server's when the server offers one. See [the policy](policy.md).
- `server` defines the control plane. See [the server](server.md).
- `wall.env` is the whole of the node's environment that goes in, by name: the node's
  own variables. A server's variables come beside them. See
  [variables](server.md#variables) and [credentials](credentials.md).

Two flags change one run:

| Flag                        | What it does                                     |
| --------------------------- | ------------------------------------------------ |
| `--wall none`               | Runs once without the wall                       |
| `--wall docker --image ...` | Runs once behind a wall, where `wall` is not set |

## The guard

Behind a wall, the proxy is guarded:

- It never dials link-local addresses, the cloud metadata service among them.
- It dials the node itself only for a host that an `egress.allow` entry lists by its own
  name. A `*.` entry above that host is not enough.

A model endpoint or MCP server on the node is reached through the proxy. The session
reaches it by the node's host name, listed in `egress`. `localhost` inside the container
is the container.

## From Go

A [`wall.Wall`](../wall/wall.go) in the spec starts the runtime in an enclosure. Its only
route out leads to the proxy.

- The session runner, the policy and the access key secret stay outside.
- The run's record is read-only inside.

The Docker adapter uses the `docker` command, and whatever engine it reaches:

```go
res, err := session.Run(ctx, session.Spec{
	Runtime: rt,
	Command: "claude",                            // a path inside the image
	Args:    []string{"-p", "Reply pong."},
	Env:     []string{"ANTHROPIC_API_KEY=" + key}, // under a wall, nothing else goes in
	Dir:     checkout,                            // the workspace, mounted at its own path
	Mounts:  []wall.Mount{{Path: home, ReadOnly: true}}, // what else of this machine it sees
	RunnerFiles: []string{configDir},             // the caller's own files, which no mount may hold
	Image:   "base",                              // the default: a name of Images, or a reference
	Images: []session.Image{                      // the machine's; a policy's image selects one by name
		{Name: "base", Ref: "example.com/agent:1"},   // yours: the runtime and the toolchain
		{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true},
	},
	Limits:  wall.Limits{Memory: "8g", ShmSize: "2g"},  // what the agent may use: at most 8 GB of memory, 2 GB of /dev/shm; zero is the engine's default
	Timeout: 5 * time.Hour,                       // the runtime is stopped at it; run.exited says so
	Labels:  map[string]string{"issue": "77"},    // the caller's names for the run, in run.started and the run configuration request
	Wall: &wall.Docker{
		Helper:    linuxBuild,                    // a static Linux build of this program
		RelayArgs: []string{"relay"},             // the mode of it that calls wall.Relay
		NestArgs:  []string{"nest"},              // the mode of it that calls wall.Nest
	},
	Forwarder: []string{wall.HelperPath, "forward"},
	Events:    os.Stdout,                         // every event as a JSON line, as well
})
```

Sizes are written the way Docker writes them: a number, and optionally `b`, `k`, `m` or
`g`, in either case. A number alone is bytes. So `8g` is 8 GB. `8GB` or `8GiB` is
refused.

### The runner's files

A walled run refuses a mount, or the workspace, that is, contains or lies inside one of
the runner's files. Such a run returns a `*session.Refusal` with the code
`mount_contains_runner_files`, and `Names` holds the mount, then the runner's file. The
check comes before the server is contacted and before anything starts, `Local` included.
An agent that changes a program the runner starts outside the wall, or reads the access
key secret, has left the wall. The runner's files are:

- `Spec.RunnerFiles`, the absolute paths the caller lists as its own. `qory` lists the
  runner file's directory, with the access key secret.
- The directory of every credential program and every tool program the machine defines,
  found in `PATH` as the runner starts it, and the directory of the file a link to one
  leads to. A program's neighbours, an interpreter or a module, are covered with it.
- The file a credential with `File` is read from.
- The private directories of the tools' sockets, which are made in the system's
  temporary directory when the tools start: a mount that contains that directory is
  refused.
- A wall's own files, when it implements `wall.Filer`. For `wall.Docker` they are the
  directory of the `docker` command, the directory of the helper, and the command's
  configuration directory, `DOCKER_CONFIG` or `~/.docker`.

Both sides are resolved through symbolic links, a part that does not exist yet through
its nearest parent that does, and compared by whole path components: `/a/bc` does not
lie inside `/a/b`. The comparison is exact, so on a filesystem that ignores case, as a
Mac's does by default, a path written in another case is another path.
`session.Overlap(mount, path)` returns how two paths stand: `is`, `contains`,
`lies inside`, or empty. A caller uses it to word its own message.

### The helper

The helper is the caller's own binary:

- It is built static for Linux.
- It is mounted read-only into the enclosure.
- It runs there as the relay the agent reaches the proxy through.
- It runs there as the hook forwarder.
- For an image with a Docker of the agent's own, it also runs as `wall.Nest`. That
  starts the daemon inside, then the agent as its user.

So the wall needs no image of its own.

## Images

The machine defines the images a run may start in. The run's policy selects one by name,
with `image`, as it selects credentials and tools. Without a selection, the run starts
in `Image`.

From Go, images and a Docker of the agent's own work today. `qory` reads one image from
`runner.yaml`, `wall.image`, and starts every `qory run` in it.

## A Docker of the agent's own

*Experimental.* An image with `Docker` gets a daemon of its own inside the enclosure,
never the machine's:

- The enclosure runs under a runtime that runs a daemon without privileges:
  `sysbox-runc`.
- The enclosure's root is then a user of the machine's that is not root.
- The agent is not root.
- `wall.Nest` refuses a runtime that maps the enclosure's root to the machine's.
- `wall.Nest` starts `dockerd`, and the daemon starts `containerd`, `runc` and
  `iptables`, from the image's system directories, `/usr/local/sbin`, `/usr/local/bin`,
  `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`: these are the daemon's `PATH`.
- Of the run's environment, the daemon gets the proxy and, when the run has one, the
  run's certificate bundle.
- Unless the run sets a non-empty `DOCKER_CONFIG`, the agent's docker configuration is
  `/run/qory/docker` and its `config.json`, the agent's, 0700 and 0600, in a `/run/qory`
  that is root's, mode 0755. A link at either path stops the run.

What to know:

- The daemon's store has no size limit of the run's.
- A daemon that exits during the run is not started again.

It is experimental because one question is open: whether the enclosure's root reaches
the mounts the run lists as the machine's root. It has not been verified. So:

- the option may change, or be withdrawn, in a minor release;
- a run that uses it mounts nothing the machine's root must protect.

## Not built yet

- Hook events on an engine inside a virtual machine. They come when the forwarder has a
  network transport through the relay.
- Git inside the container when the checkout is a git worktree. The repository's data
  lies outside the mounts. Git works there once the run lists that directory among its
  mounts.
- Images selected by the policy, and a Docker of the agent's own, from `runner.yaml`.
  The runner has both. See [images](#images).
- The fleet layer. See [the node runner](node.md).

## The details

What every wall guarantees, what crosses it, and its limits: the contract's
[wall section](../contracts/runner/v1/README.md#the-wall). The
[`wall/walltest`](../wall/walltest/walltest.go) suite checks the list from inside the
enclosure. Every adapter passes it before it ships.
