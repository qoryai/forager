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
│   events ─▶ <runs directory>/<id>/events.jsonl      │
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
- The checkout and the composed home are mounted at their own paths. The workspace is
  the working directory inside. The run's record is mounted read-only, from a runs
  directory outside every mount.
- Nothing else of the node is visible inside.
- No mount comes from a place a walled agent can change: no name on the way to it is
  looked up inside a writable mount of the run's own, or of another walled run still
  going.
  See
  [no bind from a place an agent can change](#no-bind-from-a-place-an-agent-can-change).
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

The run is recorded in its run directory, as without a wall: `events.jsonl` and
`output.log`, in the directory `qory` prints, under its state directory and outside the
checkout. `dev.qory.run.started` contains the wall and the image. The exit status is the
agent's.

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
- `wall.env` is the whole of the node's environment that goes in, by name: the
  machine's variables. A server's value of the same name wins over one, and `--env`
  does too. See [variables](server.md#variables) and [credentials](credentials.md).

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
	Dir:     checkout,                            // the workspace and working directory
	Mounts:  []wall.Mount{{Path: home, ReadOnly: true}}, // what else of this machine it sees
	RunsDir: runs,                                // the run directories, outside every mount
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
key secret, has left the wall. The check covers `Spec.Mounts` and the workspace; the
run directory and the hook socket's directory, which the runner shows the enclosure
itself, are the run's own, and lie in the runner's files. The runner's files are:

- `Spec.RunnerFiles`, the absolute paths the caller lists as its own. `qory` lists the
  runner file's directory, with the access key secret.
- The directory of every credential program and every tool program the machine defines,
  found in `PATH` as the runner starts it, and the directory of the file a link to one
  leads to. A program's neighbours, an interpreter or a module, are covered with it.
- The file a credential with `File` is read from.
- The private directories of the tools' sockets, this run's and every other run's on
  the machine, which are made in the system's temporary directory when the tools
  start: a mount that contains that directory is refused, whether or not the run has
  tools.
- The private directories in the system's temporary directory where every run on the
  machine makes its record socket, `qory-run-*`, and where the Docker wall writes a
  run's environment files, `qory-wall-*`, the relay's with the proxy's secret among
  them.
- A wall's own files, when it implements `wall.Filer`. For `wall.Docker` they are the
  directory of the `docker` command, the directory of the helper, and the command's
  configuration directory, `DOCKER_CONFIG` or `~/.docker`.
- `Spec.RunsDir`, where the run directories are made. Its default, `.qory/runs` in the
  workspace, lies inside the workspace, so a walled run passes one outside it.
- The runner's registry of walled runs, `$XDG_STATE_HOME/qory-runner/walled`, else
  `~/.local/state/qory-runner/walled`.

Both sides are resolved through symbolic links, a part that does not exist yet through
its nearest parent that does, and a link whose target does not exist yet through that
target. A path that cannot be resolved, such as one through a directory the runner
cannot search, is no run, with a plain error. The check runs again just before the
enclosure binds the mounts.

The filesystem judges what exists: two directories are the same when they are one file,
by device and inode. So on a disk that ignores case, as a Mac's does by default,
`/USERS/USER` is `/Users/user`, and a bind mount is the directory it shows. A part that
does not exist yet is compared by name, regardless of case. The comparison is by whole
path components: `/a/bc` does not lie inside `/a/b`. `session.Overlap(mount, path)`
returns how two paths stand: `is`, `contains`, `lies inside`, or empty, also for a path
it cannot resolve. A caller uses it to word its own message.

### No bind from a place an agent can change

An engine looks up every name of a bind's source path again when it binds it, links
included. A check of the path before cannot hold when a name is looked up in a
directory an agent can write: the agent swaps a link in after the check. So no name on
the way to a walled run's bind source is looked up in a writable bind, the run's own or
another walled run's still going, or in a directory inside one. A bind's own root is
looked up in its parent, so two binds of one root are allowed.

- **One bind for the workspace.** The enclosure binds the outermost of the places the
  run lists, `Spec.Mounts` and the workspace, each once. The workspace is the working
  directory inside (`--workdir` for Docker), reached through the mount that holds it.
  `qory` passes the checkout's root as a mount and the current directory as `Dir`:
  one bind, the checkout's root, and the working directory below it. A workspace that
  no mount holds is bound at its own path, writable. The runner passes every bind to
  the enclosure, each path clean, and the working directory lies in one of them, by
  its names, or the run fails; `wall.Docker` binds nothing of the caller's the launch
  does not list, and refuses a launch whose `Dir` no mount holds.
- **Nested places.** A mount, or the workspace, inside another one of the same mode is
  reached through the outer one, which alone is bound. One inside another of the other
  mode is no run, `mount_mode_conflict`, and `Names` holds the inner path, then the
  outer one. Its sentence reads: "the mount /work/vendor (read-only) lies inside the
  mount /work (writable): a part of a writable mount can't be read-only", or, through a
  link, "the mount /work/home (read-only) is reached through /work/home, which lies
  inside the mount /work (writable): …". When the outer place is the workspace, it
  says "place" for "mount".

  A writable place inside a read-only one is refused the same way: a part of a
  read-only mount can't be writable. Two places of one path in both modes are refused
  too.
- **Places through a link.** A place whose path goes through a link inside a writable
  place of the run's, and that does not lie inside that place, is bound at its target:
  the path it resolves to, with no link in it, at that same path inside. The link
  inside leads to it as it does here, and the agent that changes the link changes
  nothing that is bound. The target is checked as every bind is: inside another place
  of the run's, of the same mode, it is reached through that one; inside a writable
  bind of another walled run, it is refused. A workspace bound at its target is the
  working directory at its path as passed, when a bound place holds that path by its
  names, and at its target otherwise. A read-only place through a link inside a
  writable one is `mount_mode_conflict`, with the sentence above.

  Inside, the link reads as it does here. A link whose text goes through another link
  of this machine, outside every place, such as `/tmp` on macOS, leads nowhere inside.
- **The runner's files.** A writable place that contains a directory a name on the way
  to one of the runner's files is looked up in, such as a runs directory that is a link
  inside the checkout, is `mount_contains_runner_files`: the agent could point the link
  elsewhere.
- **The run directory.** The runs directory is one of the runner's files, so the run
  directory lies inside no place the run lists. It is bound read-only to its own run's
  enclosure, and to no other: a bind that is, holds or lies inside another walled run's
  run directory, whatever its mode, is `mount_shared_with_run`.
- **The wall's own binds.** For `wall.Docker` they are the helper, read-only, the hook
  socket's directory, writable, and, read-only, the private directory that holds the
  run's environment files and, with a CA, the `ca-bundle.pem` the enclosure binds. A
  wall, and its enclosure, lists them through `wall.Binder`. The runner lists the
  wall's in the registry when the run starts, the directories it makes later as their
  patterns, `wall.TempDirs()` and the pattern of the runs' socket directories, and the
  enclosure's, made by then, just before it binds them. A pattern stands for the
  directories its runner makes; two runners' patterns never conflict.
- **Other walled runs.** The runner keeps a registry of the walled runs still going on the
  machine, per user, in `$XDG_STATE_HOME/qory-runner/walled`, else
  `~/.local/state/qory-runner/walled`: a directory of the user's, 0700, which the runner
  refuses when it is anything else. Each run holds a file there, named by its run id, with
  its process id and its binds: each as the run passed it, as it resolved, the entries its
  names are looked up as, whether it is writable, and what it is when it is not a place,
  the run directory, the helper or a directory of the runner's, and whether it is a
  pattern. The run holds the file locked until it ends. A file whose lock is free is a run
  that is over, and the runner removes it. Under a lock of the registry's own, a run reads
  the entries, checks its binds against them and adds its own, so two runs that start
  together are checked one after the other. A run is no run, `mount_shared_with_run`, when
  one of its binds lies inside a writable bind of another run's or is reached through one,
  or when one of its writable binds holds a bind of another run's or a directory a name on
  the way to one is looked up in. Two runs that bind the same root, both writable, run
  side by side, and two read-only binds never conflict. `Names` holds this run's path, the
  other run's id and the other run's path, as each run passed it. A place of this run's
  that lies inside a writable directory another run's wall binds of its own is refused
  too. A bind of another run's, or a directory on the way to it, that is gone is compared
  by its names, like a part that does not exist yet; any other failure to resolve one
  stops the run. Its sentence reads: "the mount /work/sub (writable) lies inside the
  writable bind /work of the walled run 0199f0e2-7c1a-7d3e-8b9a-0123456789ab, which is
  still going: a walled agent of that run can change it".

  A run whose own helper, or another directory of the runner's it binds, lies inside a
  writable bind of another run's, or is reached through one, fails with a plain error:
  "the runner's helper /work/bin/qory lies inside the writable bind /work of the walled
  run 0199f0e2-7c1a-7d3e-8b9a-0123456789ab, which is still going: a walled agent of that
  run can change it", or "the runner's directory …" for a directory.

  The check comes before the server is contacted, and the run leaves the registry when
  it ends, however it ends.

A refusal's first name is always a `Spec.Mounts` path or `Dir`, exactly as passed, and
the run directory is named by `Spec.RunsDir`. Every check runs again just before the
enclosure binds the mounts, with the wall's own binds, and the run's entry is updated. A
place that resolves otherwise than at the start, or whose names are looked up in other
directories, fails the run, with a sentence that says which.

So no name on the way to a bind source is looked up in a place a walled agent of this
user's can write. A process outside every wall, the user's own or another user's, can
still change a path between the last check and the bind.

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
