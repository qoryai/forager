# Credentials

Forager keeps its credentials out of the session. Behind a wall, it keeps the run's
credentials outside the container too. Its proxy sets each credential on the way out.

The gateway sets every credential, with or without a wall. A wall also makes a
connection around the proxy fail.

Without a wall, Forager gives the run only placeholders, but the agent can read every credential the machine already holds; run a brokered run on a machine that holds none.

## Without a wall

- The agent's environment gets the placeholders. A placeholder wins over a value the
  run inherits, and the variables the machine's credentials are read from are left out.
- The run trusts the gateway through `ca-bundle.pem` in the run directory: the
  machine's authorities, then the run's certificate. `SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `AWS_CA_BUNDLE`
  point at it, or the names the caller gives in `Spec.CAEnv`. `qory` is to give them
  from `wall.ca_env`.
- Forager reads the machine's authorities from the first of
  `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
  `/etc/ssl/ca-bundle.pem` and `/etc/ssl/cert.pem` that contains a certificate. On a
  machine with none of them the run does not start.
- A program that ignores the proxy sends only the placeholder, and its connection is
  not recorded.
- If no credential has a placeholder of a model key's variable, such as
  `ANTHROPIC_API_KEY`, the run starts, and Claude Code can use the machine's Claude
  login. If one has, the run stops with `model_key_missing` unless such a credential
  covers the model host, `api.anthropic.com` or the host of `ANTHROPIC_BASE_URL`, or a
  value of a model key's variable reaches the runtime.
- In an interactive run, Claude Code shows its approval prompt for the placeholder of
  `ANTHROPIC_API_KEY` once; approve it. Behind a wall the session approves it inside
  the container.

## What goes into the container

Behind a wall, the container gets only what the run lists of the machine's environment:

- `wall.env` is the whole of the node's environment that goes in, by name.
- A model credential listed in `wall.env` is the agent's.
- A credential defined under `gateway.credentials`, and selected by the run's policy,
  stays outside instead.

For a credential that stays outside:

- The proxy sets it on the requests to its hosts, such as `api.anthropic.com`.
- The container gets a placeholder, such as `ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`, that is no credential.

## How it works

The machine defines credentials. A run's policy selects among them by name, and defines
none. A run configuration from Qory Apiary may also list credentials whose values Qory
Apiary stores; see [From Qory Apiary](#from-qory-apiary).

A credential's secret comes from one of three sources:

| Source    | The secret is                                 |
| --------- | --------------------------------------------- |
| `env`     | a variable of Forager's environment           |
| `file`    | a file's content, read again on each use      |
| `adapter` | what a program of the machine's prints        |

- The gateway keeps each secret in memory, outside the container.
- For the hosts a credential is for, the proxy ends the container's TLS itself. It uses
  an authority made for the run. The authority's key never leaves the gateway.
- A placeholder has the value `qory-sets-the-credential-outside-the-enclosure`. The proxy
  replaces what the program sends.
- The record lists each credential the run uses, by name. No event contains a
  credential's secret.

In `qory`, the `gateway.credentials` section of `forager.yaml` defines them. See
[qory's docs][qory-credentials].

[qory-credentials]: https://github.com/qoryai/qory/blob/main/docs/run.md#credentials-the-agent-never-has

## From Qory Apiary

A run configuration may list `credentials`: each a name, its hosts, how its value is set
and its placeholders, with no value. Qory Apiary stores the values.

- The run needs no wall: the gateway sets these credentials with or without one.
  On an unwalled local run the agent can read the gateway's access key, which opens the
  sealed values. The program that starts the run must refuse stored credentials there,
  as qory's `key_needs_wall` does.
- When the run starts, the gateway fetches the values once, sealed to its access key,
  and opens them. The values stay outside the container.
- On a host that one of these credentials is for, its value replaces the machine's
  credential, such as the model key in `forager.yaml`, whatever its name.
- A model credential may have `key_variables`: the names of the variables from which a
  runtime reads its key. The session gives the placeholder to the one name the run's
  runtime declares, when the declaration and the credential have the same `auth`.
  Claude Code sends the key in `ANTHROPIC_API_KEY` as the header `x-api-key`, and the
  key in `ANTHROPIC_AUTH_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN` as a bearer. A
  credential for an API key sent as a bearer lists `ANTHROPIC_AUTH_TOKEN`. When the
  runtime declares none of the names or more than one, or the declaration has another
  `auth`, the run does not start (`run_configuration_invalid`).
- A placeholder goes only into a variable for a credential. A credential from
  Qory Apiary whose `placeholders` list a variable the runtime denies, a model override,
  the model endpoint's variable, or a key's variable that the session did not
  choose from its `key_variables` stops the run (`run_configuration_invalid`). The same
  holds for the run's placeholders from this machine's credentials and tools, apart
  from a machine credential's key variable. A tool's variable, such as `GITHUB_TOKEN`,
  is fine. Two credentials with `key_variables` on different hosts may each set one
  key's variable; both get a placeholder.
- The credentials are fixed for the run. A reload that changes them fails, and the run
  keeps its policy.
- Without `credentials`, the run gets the machine's credentials as before.

## Tools

A **tool** is a program of the machine's that serves hosts. It is for what a run reaches
that needs more than a credential in a header.

- The gateway starts a run's tools outside the container.
- The proxy passes each tool the requests to the hosts it serves.
- A policy selects tools by name, as it selects credentials.
- Tools need a wall.

## The gateway's process

The gateway holds each credential's secret and the access key in memory. Before it
starts anything, `gateway.Start` limits core dumps of the process and debugger access
to it:

- **Linux**: `prctl(PR_SET_DUMPABLE, 0)`, so that the kernel writes no core dump of
  the process, and a process of the same user without `CAP_SYS_PTRACE` can neither
  attach to it with `ptrace` nor read its memory or its environment under
  `/proc/<pid>/`; and `RLIMIT_CORE` 0, soft and hard.
- **macOS**: `RLIMIT_CORE` 0, soft and hard; and `ptrace(PT_DENY_ATTACH)`, so that no
  debugger attaches to the process with `ptrace`. Root, or a debugger that macOS allows
  to call `task_for_pid` on the process, can still read its memory through its task
  port.
- **Other systems**: nothing.

The settings stay for the life of the process, after `Close` too. In `qory run` the
session runs in that process, so the settings apply to it as well.

- A program the process starts keeps `RLIMIT_CORE` at 0. On Linux it is dumpable again
  after its `execve`.
- On macOS, a process that a debugger traces exits at `Start` with status 45
  (`ENOTSUP`). To debug the gateway, debug its tests: a test binary, the one `go test`
  builds, gets none of these settings. The tests of the settings run them in a child
  process.
- If a call fails, `Start` returns an error that starts with the fix, and the gateway
  does not start:
  - Linux: `allow prctl in the gateway's seccomp profile: PR_SET_DUMPABLE 0 failed: <reason>`
  - Linux: `allow prlimit64 in the gateway's seccomp profile: RLIMIT_CORE 0 failed: <reason>`
  - macOS: `allow setrlimit in the gateway's sandbox: RLIMIT_CORE 0 failed: <reason>`
  - macOS: `allow ptrace in the gateway's sandbox: PT_DENY_ATTACH failed: <reason>`

### Keep the memory out of swap

On Linux, `gateway.lock_memory: true` in `forager.yaml` keeps every page of the
gateway's process in RAM, so that the kernel writes no key to swap. A Go program sets
`gateway.Config.LockMemory`. The default is `false`, which locks nothing.

```yaml
gateway:
  lock_memory: true   # Linux only
```

1. Set the locked-memory limit of the gateway's process, `RLIMIT_MEMLOCK`, to
   unlimited:
   - in a systemd unit, `LimitMEMLOCK=infinity` under `[Service]`;
   - in a shell, `ulimit -l unlimited`, which needs a hard limit of unlimited;
   - in Docker, `docker run --ulimit memlock=-1`.
2. Start the gateway.

With `true`, `Start` calls `mlockall(MCL_CURRENT|MCL_FUTURE)`: the pages mapped now,
and each page mapped later.

- Linux counts the whole address space of the process against `RLIMIT_MEMLOCK`, not
  only the memory in use. A small Go program on Linux arm64 maps about 1.2 GB, so a
  lower limit fails at `Start`. A limit that the gateway reaches later ends it with
  `runtime: out of memory`. Set the limit to unlimited.
- A process with `CAP_IPC_LOCK` has no limit.
- Locking loads the mapped pages into RAM: the resident memory of the same small
  program grew from 2.5 MB to 42 MB when it locked its memory.
- A program the process starts locks nothing.
- If `mlockall` fails, `Start` returns an error of two lines, and the gateway does not
  start:

  ```text
  raise RLIMIT_MEMLOCK to unlimited: LimitMEMLOCK=infinity in a systemd unit, or ulimit -l unlimited
  gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK at 8388608 bytes: cannot allocate memory; in Docker, pass --ulimit memlock=-1, or set gateway.lock_memory to false
  ```

  That first line is for a failure the limit causes: `cannot allocate memory`
  (`ENOMEM`) under a finite limit, or `operation not permitted` (`EPERM`) under a
  limit of 0. Any other failure, such as `EPERM` under an unlimited or a nonzero
  limit, comes from a seccomp filter that refuses the call. The error is then:

  ```text
  allow mlockall in the gateway's seccomp profile, or set gateway.lock_memory to false
  gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK unlimited: operation not permitted
  ```

  If reading `RLIMIT_MEMLOCK` fails too, the first line is
  `raise RLIMIT_MEMLOCK to unlimited, or allow mlockall and prlimit64 in the gateway's seccomp profile`.

- On macOS and other systems, `true` stops the gateway:
  `set gateway.lock_memory to false: Forager locks memory only on Linux, and this system is darwin`.

## The details

The rules, the adapter's document and the tools: the contract's
[credentials section](../contracts/forager/v1/README.md#credentials) and
[tools section](../contracts/forager/v1/README.md#tools).
