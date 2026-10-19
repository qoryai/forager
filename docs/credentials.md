# Credentials

Forager keeps its credentials out of the session. Behind a wall, it keeps the run's
credentials outside the container too. Its proxy sets each credential on the way out.

Credentials need a wall. Without one, a program that ignores the proxy is bound by
nothing here.

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

- The run needs a wall. Without one it does not start (`wall_required`).
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
- Tools need a wall, as credentials do.

## The details

The rules, the adapter's document and the tools: the contract's
[credentials section](../contracts/forager/v1/README.md#credentials) and
[tools section](../contracts/forager/v1/README.md#tools).
