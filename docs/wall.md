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
│ qory run, outside the wall                          │
│   the gateway: policy ─▶ proxy ─▶ decides, dials ───┼──▶ the hosts the policy allows
│   events ─▶ <runs directory>/<id>/events.jsonl      │
│          └▶ events, signed ─────────────────────────┼──▶ the server: your control plane
│   the session ─▶ the gateway's link: run, events    │
│      ▲ proxy      ▲ hooks       ▲ terminal          │
│══════╪════════════╪═════════════╪════ the wall ═════│
│  ┌───┴───┐   ┌────┴─────────────┴────────────────┐  │
│  │ relay │◀──│ the agent's container: your image │  │
│  └───────┘   │ no route · no resolver · not root │  │
│              └───────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

- The agent's container is on a network with no route out.
- On the inside network, the relay is the one peer the agent's container reaches; the
  engine's host is not one.
- The relay copies a fixed port to the gateway's proxy, opening every connection with the
  run's proxy secret, and decides nothing. It forwards no packet between its networks.
- Neither the relay nor the agent's container runs the image's health check.
- The relay listens on the wall's inside network alone, on its one address in each of
  its subnets, and takes a connection only from an address in those subnets.
- So every connection is the proxy's to decide and record.
- The checkout and the composed home are each mounted at the same path as on the
  machine, except in an image a run's policy names by reference, where the checkout is
  at `/workspace` ([Images](#images)). The workspace is the working directory inside. The run's record is mounted
  read-only, from a runs directory outside every mount.
- In a git worktree the repository's data lies in the main checkout; git inside the
  container works only with that directory mounted.
- Nothing else of the node is visible inside.
- No mount comes from a place a walled agent can change: no name on the way to it is
  looked up inside a writable mount of the run's, or of another walled run still going.
  See
  [no bind from a place an agent can change](#no-bind-from-a-place-an-agent-can-change).
- A mount that is, contains or lies inside one of Forager's files is no run,
  `mount_contains_forager_files`: the directory of `forager.yaml` with the access key
  secret, the programs Forager starts outside the wall, their configuration. See
  [Forager's files](#foragers-files).
- The session and the gateway, with the policy, the credentials and the access key
  secret, stay outside, on the node. The record is written from outside.

What every wall guarantees is in the contract's
[wall section](../contracts/forager/v1/README.md#the-wall). The
[conformance suite](../e2e/e2e.go) checks it from inside the container, in this
repository's CI.

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

- the `docker` command, with an engine behind it; for [nested Docker](#nested-docker),
  Docker Engine 28 or later;
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
  forwarder. The agent's hooks reach the session.
- **On a Mac**, the container cannot run the Mac's binary. Download the Linux archive of
  the same `qory` release, for your engine's architecture. Set `wall.helper` to that
  binary.

On a Mac, the hook socket does not cross the engine's virtual machine. So a walled run
there has the log, the egress record and the structured output, and no hook events.

## Configure it

One file on the node defines it: `~/.config/qory/forager.yaml`. It is never in a
repository, so a checkout cannot set what it runs under. With a `wall` section, a bare
`qory run` is walled:

```yaml
apiVersion: qory.dev/v1alpha1
gateway:
  egress:                       # what the agent may reach; without it, everything, recorded
    mode: enforce               # or observe: record everything, deny only what deny names
    allow: [api.anthropic.com, github.com, "*.githubusercontent.com"]
  server:                       # how the node reports; without it, files only
    url: https://control-plane.example.com
    access_key_id: ak_f1xt0re000000000  # or QORY_ACCESS_KEY_ID in the environment
    apiary_public_key:                  # the pin; or QORY_APIARY_PUBLIC_KEY, as JSON
      - {alg: ed25519, public_key: <the server's public key>}   # enrolment writes it
wall:
  adapter: docker
  image: agent:1                # or --image
  env: [ANTHROPIC_API_KEY]      # names; the values come from qory run's environment
  user: "1000:1000"             # only where qory runs as root, which a wall refuses
  helper: /opt/qory/qory-linux  # only where qory is not a Linux build
  command: podman               # only for another command than docker
```

- `gateway.egress` is the policy when the server's run configuration holds none, and
  it narrows the server's when it holds one. See [the policy](policy.md).
- `gateway.server` defines Qory Apiary. See [the server](server.md).
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
- It dials the node itself only for a host that an `egress.allow` entry lists by its
  name. A `*.` entry above that host is not enough.

A model endpoint or MCP server on the node is reached through the proxy. The session
reaches it by the node's host name, listed in `egress`, as the hosts file or a name
server gives it; no search domain is added. `localhost` inside the container is the
container.

## From Go

A [`wall.Wall`](../wall/wall.go) in the spec starts the runtime in an enclosure. Its only
route out leads to the gateway's proxy.

- The session and the gateway, with the policy and the access key secret, stay outside.
- The run's record is read-only inside.
- The session asks the gateway for a walled run, with the machine's images. The run
  answer names the image the run starts in, the run's certificate authority, which the
  enclosure trusts, and the placeholders the enclosure gets in place of the gateway's
  credentials. The run's proxy secret goes to the wall's relay alone.

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
	ForagerFiles: []string{configDir},            // the caller's files, which no mount may hold
	Image:   "base",                              // the default: a name of Images, or a reference
	Images: []session.Image{                      // the machine's; a policy's image selects one by name
		{Name: "base", Ref: "example.com/agent:1"},   // yours: the runtime and the toolchain
		{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true},
	},
	Limits:  wall.Limits{Memory: "8g", ShmSize: "2g"},  // what the agent may use: at most 8 GB of memory, 2 GB of /dev/shm; zero is the engine's default
	Timeout: 5 * time.Hour,                       // the runtime is stopped at it; run.exited says so
	Labels:  map[string]string{"issue": "77"},    // the caller's names for the run, in run.started and the run's registration
	Wall: &wall.Docker{
		Helper:    linuxBuild,                    // a static Linux build of this program
		RelayArgs: []string{"relay"},             // the mode of it that calls wall.Relay
		NestArgs:  []string{"nest"},              // the mode of it that calls wall.Nest
	},
	Forwarder: []string{wall.HelperPath, "forward"},
	Exec:      []string{wall.HelperPath, "exec"},  // the mode of it that calls session.Exec
	Gateway:   session.LocalGateway(g.LocalLink()), // the gateway on this machine, with the policy and the credentials
})
```

When a walled run has names to unset, its launch starts through `Exec`, the helper's
`exec` mode, which calls `os.Exit(session.Exec(os.Args[2:], os.Stderr))`: it unsets the
runtime's declared, reserved and denied variables and the node's denied ones that
nothing sets, so a value the image's `ENV` gives one never reaches the runtime, and
neither does an empty one. A name Forager or the wall sets is never unset. One
exception limits this: with nested Docker, `DOCKER_CONFIG` is never unset, and a
non-empty value, the image's included, takes the place of the wall's docker
configuration, as [Nested Docker](#nested-docker) says. Only an image the machine
defines has nested Docker. A `Wall` needs an `Exec`.

Sizes are written the way Docker writes them: a number, and optionally `b`, `k`, `m` or
`g`, in either case. A number alone is bytes. So `8g` is 8 GB. `8GB` or `8GiB` is
refused.

### The relay to a separate gateway

Behind a `session.RemoteGateway` the gateway's proxy is on another machine, at the
gateway's one address, the run key's `gateway_url`. The relay still reaches the session's
forwarder, on the address the enclosure names, as on one machine, and the forwarder
carries every connection to the gateway over TLS 1.3, its chain checked against the
system's roots for the host name of the gateway's URL.

- The relay opens every connection with `QORY-RELAY` and a hop secret the session makes
  for the run's forwarder alone, 256 bits from the system's random source. It is the
  value the wall's relay is given, `wall.Launch.ProxyToken`, and so the one in the
  relay's environment file.
- The forwarder reads the hop secret first, compares it in constant time, takes it off,
  and closes a connection without it unanswered: whoever else reaches the forwarder's
  address, another container of the engine or a process of the machine, reaches nothing.
- It then opens the connection to the gateway, which proves on it that it holds a key
  the run key names (`QORY-BIND`, `QORY-BOUND`), and only then sends `QORY-RELAY` and
  the run key inside TLS, before what the relay sent.
- So the run key is in no file of the wall's and never leaves the machine outside TLS,
  and the hop secret opens nothing at the gateway.

On one machine nothing changes: the relay sends the run's proxy secret, and the
forwarder passes the connection on to the gateway's proxy on loopback as it is.

### Forager's files

A walled run refuses a mount, or the workspace, that is, contains or lies inside one of
Forager's files. Such a run returns a `*session.Refusal` with the code
`mount_contains_forager_files`, and `Names` holds the mount, then Forager's file. The
check comes before the gateway is contacted and before anything starts.
An agent that changes a program Forager starts outside the wall, or reads the access
key secret, has left the wall. The check covers `Spec.Mounts` and the workspace; the run
directory and the hook socket's directory, which the session shows the enclosure itself,
are the run's, and lie in Forager's files. Forager's files are:

- `Spec.ForagerFiles`, the absolute paths the caller lists as Forager's files. `qory`
  lists the directory of `forager.yaml`, with the access key secret.
- The gateway's files, which it hands the session with its local link,
  `link.Local.Files`, each with what it is:
  - the directory of every credential program and every tool program the machine
    defines, found in `PATH` as the gateway starts it, and the directory of the file a
    link to one leads to. A program's neighbours, an interpreter or a module, are
    covered with it;
  - the file a credential with `File` is read from;
  - the private directories of the tools' sockets, this run's and every other run's on
    the machine, which are made in the system's temporary directory when the tools
    start: a mount that contains that directory is refused, whether or not the run has
    tools;
  - the gateway's link directory, the pattern of every gateway's, the gateway's
    directory, `gateway.Config.Dir`, and where it keeps the runs' records.
- The private directories in the system's temporary directory where every run on the
  machine makes its record socket, `qory-run-*`, and where the Docker wall writes a
  run's environment files, `qory-wall-*`, the relay's with the proxy's secret among
  them.
- The private directories in the system's temporary directory where every gateway on the
  machine makes its link's socket, `qory-link-*`, for a session in another process; a
  session in the same process as the gateway reaches it in memory, never by that path
  (see [the gateway's link](../contracts/forager/v1/README.md#the-gateways-link)).
- A wall's files, when it implements `wall.Filer`. For `wall.Docker` they are the
  directory of the `docker` command, the directory of the helper, and the command's
  configuration directory, `DOCKER_CONFIG` or `~/.docker`.
- `Spec.RunsDir`, where the run directories are made. Its default, `.qory/runs` in the
  workspace, lies inside the workspace, so a walled run passes one outside it.
- The session's registry of walled runs, `$XDG_STATE_HOME/qory-forager/walled`, else
  `~/.local/state/qory-forager/walled`.

Both sides are resolved through symbolic links, a part that does not exist yet through
its nearest parent that does, and a link whose target does not exist yet through that
target. A path that cannot be resolved, such as one through a directory Forager
cannot search, is no run, with a plain error. The check runs again just before the
enclosure binds the mounts.

The filesystem judges what exists: two directories are the same when they are one file,
by device and inode. So on a disk that ignores case, as a Mac's does by default,
`/USERS/USER` is `/Users/user`, and a bind mount is the directory it shows. A part that
does not exist yet is compared by name, regardless of case. The comparison is by whole
path components: `/a/bc` does not lie inside `/a/b`. `session.Overlap(mount, path)`
returns how two paths stand: `is`, `contains`, `lies inside`, or empty, also for a path
it cannot resolve. A caller uses it to word its message.

### No bind from a place an agent can change

An engine looks up every name of a bind's source path again when it binds it, links
included. A check of the path before cannot hold when a name is looked up in a
directory an agent can write: the agent swaps a link in after the check. So no name on
the way to a walled run's bind source is looked up in a writable bind, the run's or
another walled run's still going, or in a directory inside one. A bind's root is looked
up in its parent, so two binds of one root are allowed.

- **One bind for the workspace.** The enclosure binds the outermost of the places the
  run lists, `Spec.Mounts` and the workspace, each once. The workspace is the working
  directory inside (`--workdir` for Docker), reached through the mount that holds it.
  `qory` passes the checkout's root as a mount and the current directory as `Dir`:
  one bind, the checkout's root, and the working directory below it. A workspace that no
  mount holds is bound at the same path as on the machine, writable. The session passes
  every bind to the enclosure, each path clean, and the working directory lies in one of
  them, by its names, or the run fails; `wall.Docker` binds nothing of the caller's the
  launch does not list, and refuses a launch whose `Dir` no mount holds.
- **Nested places.** A mount, or the workspace, inside another one of the same mode is
  reached through the outer one, which alone is bound. One inside another of the other
  mode is no run, `mount_mode_conflict`, and `Names` holds the inner path, then the
  outer one. Its sentence reads: "the mount /work/vendor (read-only) lies inside the
  mount /work (writable): a part of a writable mount can't be read-only". When the
  outer place is the workspace, it says "place" for "mount".

  A writable place inside a read-only one is refused the same way: a part of a
  read-only mount can't be writable. Two places of one path in both modes are refused
  too.
- **Places through a link.** A mount, or the workspace, of either mode, whose path goes
  through a link inside a writable place of the run's, and that does not resolve into
  that place, is no run, `mount_through_link`: the agent that writes the link would
  choose the directory of this machine that is bound. `Names` holds the place as
  passed, the link, absolute and clean, and the writable place as passed. The link is
  the last one inside the writable place on the way to the place, the one that leads
  out of it. Its sentence reads: "/work/home is reached through the link /work/home
  inside /work, which a walled agent can change: list the link's target itself". A
  place whose link leads back into the writable place lies inside it and is reached
  through it, and nothing is bound through the link. A link on the way to a place that
  lies inside no writable place of the run's is followed by the engine as it binds.

  The same holds of a link inside a place of `Spec.Written`, the places the caller
  records as written by walled runs, though no walled run that wrote it is still
  going: `Names` holds the place, the link and the written place as passed. Its
  sentence reads: "/code/repo/.claude/worktrees/wt is reached through the link
  /code/repo/.claude/worktrees/wt inside /code/repo, which a walled agent can change:
  list the link's target itself".
- **Forager's files.** A writable place that contains a directory a name on the way
  to one of Forager's files is looked up in, such as a runs directory that is a link
  inside the checkout, is `mount_contains_forager_files`: the agent could point the link
  elsewhere.
- **The run directory.** The runs directory is one of Forager's files, so the run
  directory lies inside no place the run lists. It is bound read-only to its run's
  enclosure, and to no other: a bind that is, holds or lies inside another walled run's
  run directory, whatever its mode, is `mount_shared_with_run`.
- **The wall's extra binds.** For `wall.Docker` they are the helper, read-only, the hook
  socket's directory, writable, and, read-only, the private directory that holds the
  run's environment files and, with a CA, the `ca-bundle.pem` the enclosure binds. A
  wall, and its enclosure, lists them through `wall.Binder`. The session lists the
  wall's in the registry when the run starts, the directories it makes later as their
  patterns, `wall.TempDirs()` and the pattern of the runs' socket directories, and the
  enclosure's, made by then, just before it binds them. A pattern stands for the
  directories its session makes; two sessions' patterns never conflict.
- **Other walled runs.** The session keeps a registry of the walled runs still going on the
  machine, per user, in `$XDG_STATE_HOME/qory-forager/walled`, else
  `~/.local/state/qory-forager/walled`: a directory of the user's, 0700, which the session
  refuses when it is anything else. Each run holds a file there, named by its run id, with
  its process id and its binds: each as the run passed it, as it resolved, the entries its
  names are looked up as, whether it is writable, and what it is when it is not a place,
  the run directory, the helper or a directory of Forager's, and whether it is a
  pattern, and, for a wall in a container engine, the engine: the command, the variables
  that select it, a password in an address left out, whether that selection is pinned, and
  the engine's id. The selection is pinned by the variables the command reads. For the
  command named podman, it is pinned when `CONTAINER_HOST` or `CONTAINER_CONNECTION` is
  set and recorded, and unpinned otherwise. For any other command, it is pinned when
  `DOCKER_HOST` or `DOCKER_CONTEXT` is set and recorded; with neither set, the entry pins
  the context the command shows and `DOCKER_CONFIG`, else `~/.docker`, so a later
  `docker context use` does not change the engine asked, and a command whose
  `context show` fails is unpinned. A variable of the other kind stays recorded and never
  pins. The command named podman is asked by its pinned selection when it gave no id. A
  command other than podman is asked by its id, through its pinned selection, and one that
  gave no id is no answer: podman installed under another name reads no `DOCKER_HOST`, and
  every Docker engine gives an id. An address that cannot be read is left out whole and
  leaves the selection unpinned, and then neither the context nor the id is asked. Every
  engine command of the run's, and the agent's container, runs with the recorded
  selection in place of the session's, so the engine recorded is the one the run uses;
  with an address left out, they run with the session's environment. An engine that
  gives no id as the run starts is asked again through the recorded selection once the
  enclosure is prepared, and its answer goes in the entry. The run holds the file locked
  until it ends, and the file stays when the wall could not be removed. An entry is live
  while its session holds it, or while a container labelled `dev.qory.run=<id>` exists,
  in any state, on the engine the entry records: an agent killed with its session keeps
  its binds. The session asks that engine, with the recorded variables, for its id, when
  one is recorded, and then
  `<command> ps --all --quiet --filter label=dev.qory.run=<id>`, and removes an entry
  whose engine holds no such container. For an entry whose lock is free, a run that cannot
  ask, whose engine fails or answers with another id, whose entry records no id for a
  command other than podman, or neither a pinned selection nor an id for podman, or that
  reads an entry that records no engine or cannot be read, is no run,
  `engine_unreachable`, with the earlier run's id and then the absolute path of its entry
  in `Names`: "The check for a container of the walled run <id> failed, so this run
  does not start: <the error>". Under the registry's lock, a run reads the entries,
  checks its binds against them and adds its entry, so two runs that start together are
  checked one after the other. A run is no run, `mount_shared_with_run`,
  when one of its binds lies inside a writable bind of another run's or is reached
  through one, or when one of its writable binds holds a bind of another run's or a
  directory a name on the way to one is looked up in. Two runs that bind the same root,
  both writable, run side by side, and two read-only binds never conflict. `Names` holds
  this run's path, the other run's id and the other run's path, as each run passed it. A
  place of this run's that lies inside a writable directory among another run's extra
  binds is refused too. A bind of another run's, or a directory on the way to it, that
  is gone is compared by its names, like a part that does not exist yet; any other
  failure to resolve one stops the run. Its sentence reads: "the mount /work/sub
  (writable) lies inside the writable bind /work of the walled run
  0199f0e2-7c1a-7d3e-8b9a-0123456789ab, which is still going: a walled agent of that run
  can change it".

  A run whose helper, or another directory of Forager's it binds, lies inside a writable
  bind of another run's, or is reached through one, fails with a plain error: "Forager's
  helper /work/bin/qory lies inside the writable bind /work of the walled run
  0199f0e2-7c1a-7d3e-8b9a-0123456789ab, which is still going: a walled agent of that run
  can change it", or "Forager's directory …" for a directory.

  The check comes before the gateway is contacted, and the run leaves the registry when
  it ends, however it ends, unless its wall could not be removed.

  `session.RunsBinding(ctx, d, p)` reads the registry, under its lock, for a caller that
  removes or reuses a place p, an absolute path: it returns each walled run still going,
  by the same rule, one of whose writable binds overlaps p, as a `session.WalledRun` of
  the run's id and the absolute path of its entry. A bind overlaps p when it is p, holds
  p or lies inside p, so a run that binds only `p/.git` counts, and when a name on the
  way to p is looked up in it, or a name on the way to it is looked up in p. The paths
  are compared as written and as resolved through links, either side resolved now, so a
  link on neither side hides an overlap; p is resolved as the filesystem resolves it, a
  `..` after a link from the link's target. The run directory is bound read-only, so a
  run whose run directory alone overlaps p is not returned. The answer holds when the
  read returns: a caller that removes or reuses p on it holds a lock that the runs it
  starts on p wait for, from the check to the action. A read-only bind does not count,
  and the read asks after an entry only when one of its writable binds overlaps p, or
  one cannot be resolved now. It removes the entries of those runs that are over, as a
  run that starts does, is `engine_unreachable`, with the same `Names`, when it cannot
  ask, or cannot read an entry whose lock is free, with `EntryUnreadable` set on the
  refusal for that, in the sentence "The check for a container of the walled run <id>
  failed, so the run counts as still going: <the error>", and is a plain error for a
  relative p. It asks an engine through d, the caller's `*wall.Docker`, by
  `(*wall.Docker).RunContainersExist`, as a run asks through its wall when that is a
  `*wall.Docker`; a nil d, like a run behind another wall, asks as
  `wall.RunContainersExist` does, the method of a Docker with no field set.

A refusal's first name is always a `Spec.Mounts` path or `Dir`, exactly as passed, and
the run directory is named by `Spec.RunsDir`. Every check runs again just before the
enclosure binds the mounts, with the wall's extra binds, and the run's entry is updated.
A place that resolves otherwise than at the start, or whose names are looked up in other
directories, fails the run, with a sentence that says which.

So no name on the way to a bind source is looked up in a place a walled agent of this
user's can write. A process outside every wall, the user's or another user's, can still
change a path between the last check and the bind.

### No file read from a place an agent can write

Claude Code's runtime reads the settings file passed with `--settings` as the run
starts, and copies it into the run directory with Forager's hooks added. The session
refuses that file when it lies in a place a walled run can write, so no walled run
chooses what a later run is given:

- the places the caller lists in `Spec.Written`, the workspaces and the writable mounts
  of the walled runs it starts, with or without a wall for this run;
- the writable binds of the other walled runs of this user's in the registry, by the
  paths they resolved to, with or without a wall for this run. An entry whose session is
  gone counts too, until a walled run finds its containers gone and removes it;
- behind a wall, this run's writable binds: the workspace, or the mount that holds it,
  the writable mounts and the wall's writable binds.

A path with a `..` name is refused first, "it has a ".." part": the system applies `..`
after the link before it, so the path made clean would name another file than the one
opened. Otherwise the path is made absolute once, and that one path is checked and
opened. A file is refused when its path, absolute and clean or resolved through every
link, is or lies inside such a place, the place taken as given and resolved, by whole
names and regardless of case; when a name on the way to it is looked up inside such a
place; when its last part is a link; and when it is not a regular file. The file is then
opened without following a link as its last part, and read only when it is a regular
file of at most 1 MiB and the same file as the one its path resolved to when it was
checked, or the run is refused with "it changed while it was checked". A refusal stops
the run before the runtime starts, with the session's error, such as "runtime claude:
settings /work/launch-settings.json: it lies in /work, which a walled run can write".
Settings passed as a document, `--settings '{…}'`, are no file and are not checked.
Claude Code reads only the last `--settings` it is passed, and the session checks only
the first, so a walled launch that passes `--settings` more than once does not start:
"This launch passes --settings more than once, and Claude Code reads only the last one,
so the run does not start. Pass one --settings file." The places are worked out only
when a file is to be read: a run that passes none does not read the registry for them.

A walled launch's `--mcp-config`, `--agents`, `--plugin-dir`, `--plugin-dir-no-mcp` and
`--add-dir` are checked too, against the same places, before the settings are read. An
unwalled launch passes them unchecked.

- **Which words are values.** Every value is listed as Claude Code's parser takes it:
  the word after the flag, whatever it is, the part after `=` of `--flag=value`, and for
  `--mcp-config` and `--add-dir` every further word up to one that starts with `-` and is
  longer than one character. The list ends at a `--`, unless the word before that `--`
  starts with `-` and is not a `--name=value` word: that option may take the `--` as its
  value, so the words after it are listed too.
- **JSON passes unchanged.** Only JSON's white space, space, tab, newline and carriage
  return, is taken off a value before it is judged. An `--mcp-config` value that is then
  JSON is servers, not a path, unless it is `null`, `false`, `""`, or a number that is
  0 or does not fit a 64-bit float, such as `1e400`. An `--agents` value that then
  starts with `{`, or is JSON other than `null`, is agents, not a path. Every other
  value is a path, so a value that starts with other white space, such as a no-break
  space, `1e400` for `--mcp-config` and `null` for `--agents` are refused as relative
  paths.
- **Path rules.** Every other value is a path. A value that starts with `~` is refused:
  "This launch passes --add-dir ~/ref, and inside the wall ~ is the home of the wall's
  user, which Forager cannot check, so the run does not start. Pass an absolute path." A
  relative value is refused, because Claude Code reads it from the workspace: "This
  launch passes --mcp-config mcp.json, a relative path that Claude Code reads from the
  workspace, which a walled run can write, so the run does not start. Pass an absolute
  path outside the workspace." A value with a `..` part is refused: "This launch passes
  --mcp-config /a/../b.json, and the path has a ".." part, so the run does not start.
  Pass the path without ".."."
- **`--mcp-config` and `--agents` files** are checked and read as the settings file is,
  and Claude Code is passed a copy in the run directory, `mcp-config-<n>.json` or
  `agents-<n>.json`, numbered from 1 in the order the files appear. For a run whose
  workspace is at `/workspace` inside, a copy that is JSON has every string written as
  the enclosure sees it. A file in such a place is refused: "This launch passes
  --mcp-config /work/mcp.json, and that file lies in /work, which a walled run can
  write, so the run does not start. Move the file to a directory no walled run writes,
  or pass the servers as a JSON string." A file whose path is looked up in such a place
  says "is reached through /work", and an `--agents` file ends "or pass the agents as a
  JSON object." A file refused by the read says why, such as "This launch passes
  --mcp-config /a/mcp.json, and that file is a link, so the run does not start." No
  copy is written before every value has passed.
- **`--plugin-dir` and `--plugin-dir-no-mcp` directories** may not lie in, be reached
  through, or contain such a place, by whole names and regardless of case: "This launch
  passes --plugin-dir /home/p, and that directory contains /home/p/work, which a walled
  run can write, so the run does not start. Move the plugin to a directory no walled run
  writes." Every entry under the directory is then read without following a link as it
  is read, and the check stops after 10,000 entries: "This launch passes --plugin-dir
  /home/p, which has more than 10,000 entries, the most Forager checks, so the run does
  not start. Pass a smaller plugin directory."
  - A link must not lead into such a place: "This launch passes --plugin-dir /home/p,
    and its link /home/p/skills/x leads into /work, which a walled run can write, so the
    run does not start. Replace the link with a copy, or move what it leads to out of
    /work." A link whose path goes through such a place says so: "This launch passes
    --plugin-dir /home/p, and its link /home/p/skills/x leads through /work, which a
    walled run can write, so the run does not start. Replace the link with a copy, or
    point it at a path that does not go through /work."
  - A link to a directory is checked as the directory is: "This launch passes
    --plugin-dir /home/p, and its link /home/p/skills/x leads to /h/other, and /h/other
    contains /h/other/work, which a walled run can write, so the run does not start.
    Replace the link with a copy, or link to a directory that contains no place a
    walled run writes." The entries under the directory it leads to are read the same
    way. Each directory is read once, by its device and inode: one reached again,
    through a link or as an entry, counts as one entry and is not read again.
  - For a run whose workspace is at `/workspace` inside, a link whose path, followed a
    name at a time on this machine, reaches `/workspace` is refused the same way, with
    `/workspace` as the place. So is a value whose path reaches `/workspace`, before
    Forager checks the path on this machine: "This launch passes --plugin-dir
    /workspace/plug, and that directory lies in /workspace, which a walled run can
    write, so the run does not start. Move the plugin to a directory no walled run
    writes." For a value whose name ends in `.zip`, the text says "that file" in place
    of "that directory". A link with more than 40 links on the way is refused with the
    reason, "--plugin-dir /home/p: /home/p/skills/x: too many links", and a value with
    more than 40 with "--plugin-dir /home/p: too many links".
  - A regular file, or a file a link leads to, with more than one name is refused:
    "This launch passes --plugin-dir /home/p, and /home/p/agents/a.md has more than one
    hard link, so a walled run could change it under another name, and the run does
    not start. Replace the file with a copy that has one name."
  - A value that is no directory, a `.zip` say, is checked as a file: it must not lie
    in or be reached through such a place, must be no link, a regular file, and have
    one name.
- **`--add-dir` directories** are checked as `--plugin-dir`'s, with the entries read
  only at `<dir>/.claude`, and under it, and at `<dir>/CLAUDE.md`: "This launch passes
  --add-dir /work/ref, and that directory lies in /work, which a walled run can write,
  so the run does not start. Remove --add-dir /work/ref, or add a directory no walled
  run writes." A directory in a read-only mount passes. A link under `.claude`, or
  `.claude` itself, that leads back to the directory reads all of the directory.
- **Any other reason**, a file that does not exist say, is the flag, the value and the
  reason, as for the settings: "runtime claude: --mcp-config /a/mcp.json: stat
  /a/mcp.json: no such file or directory".

A refusal stops the run before the wall is prepared, with the prefix `runtime claude: `.
The programs a checked file or plugin starts, such as a server's command, are not
checked. Claude Code also loads plugin directories named in `CLAUDE_CODE_PLUGIN_DIRS`,
adds the directories named in `CLAUDE_RELAUNCH_SESSION_ADD_DIRS`, and reads plugins or
settings from `CLAUDE_CODE_PLUGIN_SEED_DIR`, `CLAUDE_CODE_PLUGIN_CACHE_DIR` and
`CLAUDE_CODE_MANAGED_SETTINGS_PATH`. The Claude descriptor denies all five, so no value
of the server's, the run's or the machine's reaches the enclosure, and a walled run has
them unset.

### The helper

The helper is the caller's binary:

- It is built static for Linux.
- It is mounted read-only into the enclosure.
- It runs there as the relay the agent reaches the proxy through.
- It runs there as the hook forwarder.
- For an image with nested Docker, it also runs as `wall.Nest`. That starts the daemon
  inside, then the agent as its user.

So the wall needs no separate image.

## Images

The machine defines the images a run may start in, `Spec.Images`, and the session sends
them with a walled run's request. The run's policy selects one by name, with `image`, as
it selects credentials and tools; the gateway resolves the selection and its answer
names the image. Without a selection, the run starts in `Image`.

`qory` reads `wall.images` from `forager.yaml`: named images, each with a `ref`, and a
`runtime` and `docker` when it needs them. It reads `wall.image` too, the image a run
starts in when its policy selects none.

A policy may also name an image by its reference pinned by digest, `NAME@sha256:` and 64
lower-case hexadecimal digits, with no tag. The machine runs one only under a prefix of
`Spec.ImagesAllow`, its `images.allow`: an entry such as `registry.example/agents/` or
`registry.example/agents` covers the references that start with it at a whole part;
without a list no reference runs. Any other reference is refused with
`image_not_allowed`, and one with a tag or in upper case with
`run_configuration_invalid`. `images.allow` needs a default image, `Image`.

An image by reference starts as the default does: under the default's runtime, with no
nested Docker, as the node's user, which must then be given as `uid:gid` in numbers,
neither 0: the engine would look a name, or a uid's groups, up in the image's
`/etc/passwd` and `/etc/group`, which the image writes, so a user given by name or as a
uid alone is refused. The wall pulls it before it makes anything else for the run,
unless the engine holds it by that digest, and refuses with `image_user_root` an image
whose user is root: no user, `root`, uid 0, or a name the image's `/etc/passwd` maps to
uid 0. An image whose user is a name its `/etc/passwd` does not map, or that has no
`/etc/passwd`, is refused the same way, since its user cannot be checked: give the user
as a uid. The relay always starts from the
default image, never from the run's, and the authorities the run trusts are read out of
the run's image. `dev.qory.run.started` reports `image_fetch_ms`, how long finding
the image took, the pull included when there was one.

In such an image the checkout is mounted at `/workspace` and the working directory is
under it; the paths Forager puts inside name it there, and values from the server,
`--env` and the machine pass as they are. The checkout must be a full repository: a git
worktree's `.git` file names the main checkout by its path on the machine, which is not
inside. An image that brings a tree for the run keeps it at `/qory/seed`, and `qory`
copies it into the workspace; Forager copies none of it. Hooks reach the session through
`/qory/hooks` as in every walled run, reporting what the runtime reports from inside.

Against an image by reference, which a repository may have built, what holds is what
Forager enforces outside the enclosure: the wall, the egress policy, the credentials the
proxy sets, the tools the gateway starts and the `dev.qory.run.*` records. The runtime's
settings, its hooks and its prompts, and the `dev.qory.session.*` records, which the
runtime reports from inside, are not that boundary: the image can change or forge them.

## Nested Docker

*Experimental.* An image with `Docker` gets nested Docker: a Docker daemon inside the
wall, separate from the machine's:

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
- Unless the enclosure's environment has a non-empty `DOCKER_CONFIG`, the image's
  included, the agent's docker configuration is `/run/qory/docker` and its
  `config.json`, the agent's, 0700 and 0600, in a `/run/qory` that is root's, mode
  0755. A link at either path stops the run.
- It needs the `docker` command and Docker Engine 28 or later; with podman, nerdctl or an
  earlier engine the run is refused before anything is made.
- Its inside network has an IPv6 subnet, the engine's choice, in Docker's isolated
  gateway mode, and the relay listens on its address in it too.

What to know:

- The daemon's store has no size limit of the run's.
- A daemon that exits during the run is not started again.

It is experimental because one question is open: whether the enclosure's root reaches
the mounts the run lists as the machine's root. It has not been verified. So:

- the option may change;
- a run that uses it mounts nothing the machine's root must protect.

## The details

What every wall guarantees, what crosses it, and its limits: the contract's
[wall section](../contracts/forager/v1/README.md#the-wall). The
[`e2e`](../e2e/e2e.go) suite checks the list from inside the enclosure. Every adapter passes it before it ships.
