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
- Without a model key, the run starts, and Claude Code can use the machine's Claude
  login. With one, Claude Code gets the model key's placeholder and endpoint (see
  [Model keys](#model-keys)).
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

- The proxy sets it on the requests to its hosts, such as `git.example`, or to a
  model key's endpoint host, such as `api.model.example`.
- The container gets a placeholder, such as `GITHUB_TOKEN` or `ANTHROPIC_API_KEY`,
  that is no credential.

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
- A request that carries a credential goes to its host over HTTP/1.1, so no HTTP/2
  header table (HPACK) keeps a copy of the secret. Other requests may use HTTP/2.
- When the run ends, the gateway closes every idle connection to a credential's host.
  While the run goes on, a connection idle for 90 seconds closes.
- The authority's certificate has name constraints: it is good only for the names the
  proxy terminates when the run starts and the names under them (`*.example.com` also
  covers `example.com`), and for the addresses it terminates. A program that checks
  them rejects a certificate the key makes for any other host. A reload that sets a
  credential or path rules for a host outside them fails; start a new run for it.
- A placeholder has the value `qory-sets-the-credential-outside-the-enclosure`. A model
  key's placeholder contains the key's name, such as
  `qory-model-sets-the-credential-outside-the-enclosure` for the key `model`. The proxy
  replaces what the program sends.
- The record lists each credential the run uses, by name. No event contains a
  credential's secret.

In `qory`, the `gateway.credentials` section of `forager.yaml` defines them. See
[qory's docs][qory-credentials].

[qory-credentials]: https://github.com/qoryai/qory/blob/main/docs/run.md#credentials-the-agent-never-has

## What the agent gets back

A host can send back what it received: the answer to a `TRACE`, a debug endpoint, an
error page. The proxy replaces a credential's value with its placeholder in every answer
from a host that gets the credential, before the answer reaches the agent.

- Send each request to such a host as `https://` through `CONNECT`, as an HTTPS client
  behind a proxy does. If the policy allows the host, a plain request, `http://` or an
  absolute-form `https://` sent without `CONNECT`, gets a `403` from the gateway and
  never reaches the host, in either mode, with the rule `wall:plain-request`.
- A `TRACE` or `TRACK` through `CONNECT` to such a host gets a `405` from the gateway
  and never reaches the host, in either mode, with the rule `wall:echo-method`. Use
  another method.
- The proxy replaces the value in the answer's headers, those of a `1xx` and the
  trailer included, in their names and values in any case, and in the body as it
  streams.
- For a `basic` credential, the proxy also replaces the base64 of the username and the
  value, as the header has it, with or without its padding.
- The proxy also looks for each form percent-encoded and JSON-escaped. For a key of
  letters, digits, `-`, `_`, `.` and `~`, such as an API key, these forms are the key
  itself. A base64 form with `+` or `/` differs percent-encoded, and a `/` differs in
  JSON whose encoder writes it as `\/`.
- The request goes to the host with `Accept-Encoding: identity`, and without `Range`,
  `If-Range` and `Upgrade`. If the host compresses its answer anyway, or switches
  protocols, the agent gets a `502` from the gateway.
- An answer with a body has no `Content-Length` and comes chunked, since the
  placeholder and the value differ in length; an empty answer may have
  `Content-Length: 0`.

The proxy does not replace:

- a part of the value;
- a copy in the body in another case, or in another encoding, such as hex;
- a copy inside a compressed file, such as a zip archive;
- a value the credential had before a renewal;
- anything from another name or address of the same server that no credential is for,
  such as its IP address: the proxy replaces the value only in answers from a host a
  credential is for.

A tool's answers are the tool's.

## Model keys

A model key is the key of a model API. In `forager.yaml`, a model key has `format`,
`endpoint` and `auth` in place of `hosts`, `paths` and `placeholders`:

```yaml
# ~/.config/qory/forager.yaml
gateway:
  credentials:
    model:
      env: MODEL_API_KEY                    # or file, or adapter
      format: anthropic-messages            # the API the endpoint serves
      endpoint: https://api.model.example/anthropic
      auth: {scheme: header, header: x-api-key}
      key_prefixes: [sk-ant-]               # optional
```

- `format` is one of `anthropic-messages`, `openai-responses`, `openai-chat` and
  `gemini`.
- `endpoint` is the base URL of the model API: `https`, a host, an optional port and
  path, and no user name, query or fragment. The proxy sets the key on every path and
  on any port of the endpoint's host, and on no other host.
- `auth` is `{scheme: bearer}`, `{scheme: header, header: …}` or
  `{scheme: basic, username: …}`. Add `oauth: true` to a bearer for an OAuth token,
  such as a Claude subscription login's.
- `key_prefixes`, optional, are 1 to 4 prefixes, each 1 to 32 printable ASCII
  characters without a space. If the key starts with none of them, the run does not
  start, and the message does not contain the key. If a `file` key read again later
  starts with none of them, the gateway keeps setting the key it read when the run
  started.
- Under `egress.mode: enforce`, the run's allow list must cover the endpoint's host.

The session gives the key to the runtime's variable for its format and `auth`. For
Claude Code:

| `auth` | Claude Code's variable |
| --- | --- |
| `{scheme: header, header: x-api-key}` | `ANTHROPIC_API_KEY` |
| `{scheme: bearer}` | `ANTHROPIC_AUTH_TOKEN` |
| `{scheme: bearer, oauth: true}` | `CLAUDE_CODE_OAUTH_TOKEN` |

The session also sets `ANTHROPIC_BASE_URL` to the endpoint. Every other value of
`ANTHROPIC_BASE_URL`, from the server, `--env`, `wall.env`, the harness or the shell, is
left out. Claude Code's other key variables get no value in its process environment
either: with the start key in `ANTHROPIC_API_KEY`, a value of `ANTHROPIC_AUTH_TOKEN` or
`CLAUDE_CODE_OAUTH_TOKEN` from any of these sources or the runtime's preparation is left
out, and behind a wall the image's value is unset. One exception applies: when the run
has an authority, a variable that points at the CA bundle is set to the bundle's path,
even one of these. Without a wall these are the names the caller gives in
`Spec.CAEnv`; `qory` is to set it from `wall.ca_env`. Behind a wall they are the names
in `CAEnv` of `wall.Docker`. A nil list means `wall.DefaultCAEnv`.

Claude Code also applies the `env` object of a settings file. The session copies the
`env` of the `--settings` file into the run's `settings.json` without
`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` and
`ANTHROPIC_BASE_URL`, and without the variables Claude Code's descriptor lists in
`denies` and, behind a wall, in its model `overrides`, as the session leaves those out
of Claude Code's process environment. It keeps the other members. It also leaves out the
file's top-level `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`,
`gcpAuthRefresh` and `modelOverrides`: Claude Code ranks `apiKeyHelper` above
`CLAUDE_CODE_OAUTH_TOKEN`, and the others set cloud credentials or a provider's model
ids. In a run whose image is named by its reference, a path in it is written as the
enclosure sees it. The session does not read Claude Code's other settings files, such as
`~/.claude/settings.json`, or the workspace's `.claude/settings.json`, which Claude Code
reads unless the launch passes `--setting-sources user`. A value set in one of them can
reach Claude Code.

If the runtime reads no key for the format or the `auth`, the run stops with
`run_configuration_invalid`.

A run may have several model keys, from `forager.yaml` and from the control plane. The
gateway holds every one and sets only the start key, the one the runtime starts with.
The proxy sets the start key only on a request to its endpoint's host that carries its
placeholder. With two or more model keys, the run configuration's `model_credential`
names the start key; without it, the run stops with `run_configuration_invalid`. With
one, that one is the start key.

A credential without `format` whose `placeholders` list a model key's variable, such as
`ANTHROPIC_API_KEY`, stops the run with `run_configuration_invalid`. Rewrite it as a
model key.

## From Qory Apiary

A run configuration may list `credentials`, with no value; the control plane stores the
values. An entry is one of two kinds:

- An API credential is a model key: `{name, format, endpoint, auth, key_prefixes}`, as
  in [Model keys](#model-keys).
- A host credential is any other secret: `{name, hosts, paths, auth, placeholders}`.

```json
{"version": 1,
 "model_credential": "model",
 "credentials": [
   {"name": "model", "format": "anthropic-messages",
    "endpoint": "https://api.model.example/anthropic",
    "auth": {"scheme": "header", "header": "x-api-key"},
    "key_prefixes": ["sk-ant-"]},
   {"name": "forge", "hosts": ["git.example"],
    "auth": {"scheme": "basic", "username": "x-access-token"}}]}
```

- The run needs no wall: the gateway sets these credentials with or without one.
  On an unwalled local run the agent can read the gateway's access key, which opens the
  sealed values. The program that starts the run must refuse stored credentials there,
  as qory's `key_needs_wall` does.
- When the run starts, the gateway fetches the values once, sealed to its access key,
  and opens them. The values stay outside the container. A model key's value that
  starts with none of its `key_prefixes` stops the run with
  `run_configuration_invalid`.
- On a host that one of these credentials is for, its value replaces the machine's
  credential, such as the model key in `forager.yaml` for the same endpoint host,
  whatever its name.
- `model_credential` names the start key: an API credential of the run configuration,
  or a model key of `forager.yaml`.
- A placeholder goes only into a variable for a credential. A host credential whose
  `placeholders` list a variable the runtime denies, a model override, the model
  endpoint's variable or a model key's variable stops the run
  (`run_configuration_invalid`). The same holds for the run's placeholders from this
  machine's credentials and tools. A tool's variable, such as `GITHUB_TOKEN`, is fine.
- The credentials and `model_credential` are fixed for the run. A reload that changes
  them fails, and the run keeps its policy. So does a reload that selects another
  model key of this machine's as the start key, with or without `model_credential`.
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

The caller's configuration, the TLS key and the environment are in memory before
`Start` runs. A Go program calls `gateway.HardenProcess` first in `main`: it makes the
same calls then, with the same errors, and in a test binary too. `Start` makes them
again, and the second call succeeds. `HardenProcess` locks no memory.

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
