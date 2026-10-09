# Credentials

Forager keeps its own credentials out of the session. Behind a wall, it keeps the
run's credentials outside the container too. Its proxy sets each credential on the
way out.

Credentials need a wall. Without one, a program that ignores the proxy is bound by
nothing here.

## What goes into the container

Behind a wall, the container gets only what the run lists of the machine's environment:

- `wall.env` is the whole of the node's environment that goes in, by name.
- A model credential listed in `wall.env` is the agent's.
- A credential defined under `credentials`, and selected by the run's policy, stays
  outside instead.

For a credential that stays outside:

- The proxy sets it on the requests to its hosts, such as `api.anthropic.com`.
- The container gets a placeholder, such as `ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`, that is no credential.

## How it works

The machine defines credentials. A run's policy selects among them by name, and defines
none.

A credential's secret comes from one of three sources:

| Source    | The secret is                                 |
| --------- | --------------------------------------------- |
| `env`     | a variable of Forager's own environment       |
| `file`    | a file's content, read again on each use      |
| `adapter` | what a program of the machine's prints        |

- The gateway keeps each secret in memory, outside the container.
- For the hosts a credential is for, the proxy ends the container's TLS itself. It uses
  an authority made for the run. The authority's key never leaves the gateway.
- A placeholder has the value `qory-sets-the-credential-outside-the-enclosure`. The proxy
  replaces what the program sends.
- The record lists each credential the run uses, by name. No event contains a
  credential's secret.

In `qory`, the `credentials` section of `runner.yaml` defines them. See
[qory's docs](https://github.com/qoryai/qory/blob/main/docs/run.md#credentials-the-agent-never-has).

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
