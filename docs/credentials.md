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
- A placeholder has the value `qory-sets-the-credential-outside-the-enclosure`. A model
  key's placeholder contains the key's name, such as
  `qory-model-sets-the-credential-outside-the-enclosure` for the key `model`. The proxy
  replaces what the program sends.
- The record lists each credential the run uses, by name. No event contains a
  credential's secret.

In `qory`, the `gateway.credentials` section of `forager.yaml` defines them. See
[qory's docs][qory-credentials].

[qory-credentials]: https://github.com/qoryai/qory/blob/main/docs/run.md#credentials-the-agent-never-has

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
left out. Claude Code's other key variables get no value either: with the start key in
`ANTHROPIC_API_KEY`, a value of `ANTHROPIC_AUTH_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN` from
any of these sources is left out, and behind a wall the image's value is unset. If the
runtime reads no key for the format or the `auth`, the run stops with
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

## The details

The rules, the adapter's document and the tools: the contract's
[credentials section](../contracts/forager/v1/README.md#credentials) and
[tools section](../contracts/forager/v1/README.md#tools).
