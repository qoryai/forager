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

## What the agent gets back

A host can send back what it received: the answer to a `TRACE`, a debug endpoint, an
error page. The proxy replaces a credential's value with its placeholder in every answer
from a host that gets the credential, before the answer reaches the agent.

- A `TRACE` or `TRACK` to such a host gets a `405` from the gateway and never reaches the
  host, in either mode, with the rule `wall:echo-method`. Use another method.
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
- The answer has no `Content-Length` and comes chunked, since the placeholder and the
  value differ in length.

The proxy does not replace:

- a part of the value;
- a copy in the body in another case, or in another encoding, such as hex;
- a copy inside a compressed file, such as a zip archive;
- a value the credential had before a renewal;
- anything from another name or address of the same server that no credential is for,
  such as its IP address: the connection to it is a tunnel the proxy does not read.

A tool's answers are the tool's.

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

## The details

The rules, the adapter's document and the tools: the contract's
[credentials section](../contracts/forager/v1/README.md#credentials) and
[tools section](../contracts/forager/v1/README.md#tools).
