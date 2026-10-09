# The record

Forager records the whole session as events. It reports three things, all as
CloudEvents:

- the session's output,
- its own observations,
- what the runtime reports of its session.

Every event goes to files, always. With a server configured, every event the server's
configuration selects goes there too, sent by the gateway. See [the server](server.md).

## Where the record is

Install [`qory`](https://github.com/qoryai/qory) and compose a harness. Then run the
runtime through `qory` instead of starting it yourself:

```sh
qory harness compose
qory run                                # the composed runtime, at your terminal
qory run claude -- -p "Reply pong"      # one headless turn
```

Every connection the runtime makes goes through the gateway, and is recorded.
The run is written to its run directory, `<id>/` in the runs directory the caller
passes. `qory` keeps them under its state directory and prints the path:

- `events.jsonl`: the run's stream, one CloudEvent per line, numbered. The gateway
  writes it, with the run's delivery state toward the server beside it,
  `delivered.log` and `undelivered/`: every event the session posts on the gateway's
  link, and the gateway's own.
- `session.jsonl`: the session's own record, one CloudEvent per line, numbered by the
  session's own sequence, which is not the stream's: every event the session posts,
  and the few it records alone (below).
- `output.log`: the session's bytes.

The gateway's record and the session's are in the same directory when the caller
points `gateway.Config.RunDir` at the session's runs directory, `Spec.RunsDir`.
Otherwise the gateway keeps its record under `gateway.Config.Dir`, in `runs/<id>/`.

Behind a separate gateway the two records are on two machines. The gateway's machine
holds `events.jsonl`, with its `delivered.log` and `undelivered/` toward the server. The
session's machine holds `session.jsonl` and `output.log`, and the session's delivery
state toward the gateway beside them:

- `delivered.log`: what the gateway accepted of `session.jsonl`, a line per batch, by
  the session's sequence, and `stopped` when the gateway ended the run.
- `undelivered/`: the session's batches the gateway did not accept, when there are any.

Neither holds the run credential. `session.Resend` sends the gateway what they say it
still lacks ([sending the session's record again](go.md#sending-the-sessions-record-again)).

A run behind a wall is recorded the same way. See [the wall](wall.md).

## Forager's events

| Type                          | When                                                         |
| ----------------------------- | ------------------------------------------------------------ |
| `dev.qory.ping`               | The gateway's, before the run's first, with a server only    |
| `dev.qory.run.started`        | The run is open: the runtime is about to start               |
| `dev.qory.run.policy_applied` | Right after; again when a new policy takes effect            |
| `dev.qory.run.log`            | One per chunk of output                                      |
| `dev.qory.run.resized`        | The pseudo-terminal was resized                              |
| `dev.qory.run.egress`         | One per connection, or per request on a terminated host      |
| `dev.qory.run.heartbeat`      | Every interval while the runtime runs, 30 seconds by default |
| `dev.qory.run.exited`         | The run ended: the result, the last event                    |

Forager heartbeats while the session runs: the session sends one every interval the
gateway's discovery announces, `gateway.Config.Heartbeat`, and the gateway ends a run
whose session sends nothing for three. The exit status of a run is the runtime's.

`dev.qory.run.started` says what opened the run, in `opened_by`: `session` for a run
around a runtime, as above, or `gateway` for a run a gateway opened on a run credential,
with no session. A run a gateway opened has no process, so its `dev.qory.run.started`
names no runtime, command or host, and its `dev.qory.run.exited` contains no exit status
and no state. Its `credential` says where the run's credential came from: `issuer`, an
issuer gave the run its run credential, for a session's run behind a separate gateway
and every run a gateway opened; `none` for a run on the local link. The gateway decides
it and refuses a session's batch whose `dev.qory.run.started` says otherwise.

When a run ends other than by the runtime's own exit, `dev.qory.run.exited` says why in
`reason`. The session writes `timeout`, and posts it, and `batch_refused`, in its own
record alone (below). The gateway writes the others:
`session_lost`, the session was silent, or the gateway refused a batch of the
session's (see the contract's §The gateway's link); `quiet`; `credential_expired`;
`run_ended_at_issuer`; `issuer_unreachable`, the issuer's introspection endpoint could
not be reached after the gateway's tries; `issuer_answer_invalid`, it gave no valid
answer; `run_closed` when the server closes a session's run; and sending
a record again writes `gateway_lost`. When the gateway or the server ends a session's
run, the gateway writes the run's `dev.qory.run.exited`, and answers the session's next
request with a `410` and a code. The session records its own `dev.qory.run.exited` in
`session.jsonl` alone, with the 410's code as its reason, and posts nothing more:
`credential_expired`, `run_ended_at_issuer`, `issuer_unreachable`,
`issuer_answer_invalid`, `run_closed` or `session_lost` as the gateway ended the run, and `batch_refused` when the gateway refused a batch of its,
which the gateway's record says as `session_lost`. A refusal of the run request with a
code other than `wall_required` is recorded the same way: the session records
`dev.qory.run.refused` in its own record alone, since the gateway opened no run;
`issuer_unreachable`, the gateway's `503`, and `issuer_answer_invalid`, its `502`, among
them. A code of the server's comes with its status, and is recorded as the server sent
it, `not_found` among them, and one the contract does not list yet too. A run the gateway could not open for a reason
without a code, a `5xx` `internal`, is recorded nowhere: the run returns the error the
gateway's message says. The contract describes each.

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

`gateway.Config.Events` is any stream that gets every numbered event of every run as
well, the lines `events.jsonl` contains. A run with no receiver is followed on
standard output this way.

## The details

The whole sequence, every event type and every file are in the
[contract](../contracts/forager/v1/README.md#the-events).
