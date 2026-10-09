# The record

Forager records the whole session as events. It reports three things, all as
CloudEvents:

- the session's output,
- its own observations,
- what the runtime reports of its session.

Every event goes to files, always. With a server configured, every event the server's
configuration selects goes there too. See [the server](server.md).

## Where the record is

Install [`qory`](https://github.com/qoryai/qory) and compose a harness. Then run the
runtime through `qory` instead of starting it yourself:

```sh
qory harness compose
qory run                                # the composed runtime, at your terminal
qory run claude -- -p "Reply pong"      # one headless turn
```

Every connection the runtime makes goes through the gateway, and is recorded.
The session is written to its run directory, `<id>/` in the runs directory the caller
passes. `qory` keeps them under its state directory and prints the path:

- `events.jsonl`: one CloudEvent per line.
- `output.log`: the session's bytes.

A run behind a wall is recorded the same way. See [the wall](wall.md).

## Forager's events

| Type                          | When                                                    |
| ----------------------------- | ------------------------------------------------------- |
| `dev.qory.ping`               | Before the runtime starts, with a server only           |
| `dev.qory.run.started`        | The run is open: the runtime is about to start          |
| `dev.qory.run.policy_applied` | Right after; again when a new policy takes effect       |
| `dev.qory.run.log`            | One per chunk of output                                 |
| `dev.qory.run.resized`        | The pseudo-terminal was resized                         |
| `dev.qory.run.egress`         | One per connection, or per request on a terminated host |
| `dev.qory.run.heartbeat`      | Every 30 seconds while the runtime runs                 |
| `dev.qory.run.exited`         | The run ended: the result, the last event               |

Forager heartbeats while the session runs. The exit status of a run is the runtime's.

`dev.qory.run.started` says what opened the run, in `opened_by`: `session` for a run
around a runtime, as above, or `gateway` for a run a gateway opened on a run credential,
with no session. A run a gateway opened has no process, so its `dev.qory.run.started`
names no runtime, command or host, and its `dev.qory.run.exited` contains no exit status
and no state.

When a run ends other than by the runtime's own exit, `dev.qory.run.exited` says why in
`reason`. The session writes `timeout` and `run_closed`, and sending a record again
writes `gateway_lost`. The gateway writes `session_lost` and `quiet`, and
`credential_expired` and `run_ended_at_issuer` for a run with no session; on a session's
run the gateway's link ends the run with that code, and the session writes it. The
contract describes each.

## The session's events

The runtime reports what happens in its session, through its hooks and its structured
output. A **descriptor** maps those reports to events:

| Type                                 | When                                  |
| ------------------------------------ | ------------------------------------- |
| `dev.qory.session.started`           | The runtime opened its session        |
| `dev.qory.session.prompt_submitted`  | A prompt reached the runtime          |
| `dev.qory.session.tool_started`      | The runtime is about to run a tool    |
| `dev.qory.session.tool_finished`     | A tool ran and returned               |
| `dev.qory.session.tool_failed`       | A tool ran and failed                 |
| `dev.qory.session.turn_finished`     | The runtime finished responding       |
| `dev.qory.session.turn_failed`       | A turn ended on an API error          |
| `dev.qory.session.subagent_started`  | A subagent was spawned                |
| `dev.qory.session.subagent_finished` | A subagent finished                   |
| `dev.qory.session.notification`      | The runtime notified its user         |
| `dev.qory.session.ended`             | The runtime closed its session        |
| `dev.qory.session.result`            | A headless session printed its result |

Forager ships the descriptor for Claude Code. A runtime that nothing describes still
runs: its run, its log and its egress are recorded, with no session events. See
[the runtime](go.md#the-runtime).

## Following a run

[`Events`](go.md#the-spec) in the spec is any stream. A run with no receiver is followed
on standard output, with the lines `events.jsonl` contains.

## The details

The whole sequence, every event type and every file are in the
[contract](../contracts/forager/v1/README.md#the-events).
