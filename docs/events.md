# The record

Forager records the whole session as events. It reports three things, all as
CloudEvents:

- the session's output,
- Forager's observations,
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
  link, and the gateway's. `delivered.log` begins `registered <seq>`, the sequence of
  the run's `dev.qory.run.registered`, once the server accepts the run's registration,
  then holds a line per batch the server accepted.
- `session.jsonl`: the session's record, one CloudEvent per line, numbered by the
  session's sequence, which is not the stream's: every event the session posts, and the
  few it records alone (below).
- `output.log`: the session's bytes.
- The files the session writes for the runtime, such as `preparation.sh`,
  `ca-bundle.pem`, and Claude Code's `settings.json` and `approve-key.sh`: each is
  written to a new file beside it and renamed, so a link at its path is replaced, not
  followed.

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

`session.Resend` sends the gateway what they say it
still lacks ([sending the session's record again](go.md#sending-the-sessions-record-again)).

A run behind a wall is recorded the same way. See [the wall](wall.md).

## Forager's events

| Type                          | When                                                         |
| ----------------------------- | ------------------------------------------------------------ |
| `dev.qory.run.registered`     | Line 1 of the gateway's record, with a server; never posted  |
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

`dev.qory.run.started` says what opened the run, in `opened_by`: `session`, a session
around a runtime, as above.

Every `dev.qory.run.exited` says how the run ended in `state`: `succeeded`, `failed` or
`cancelled`, stopped before it said how it went. A runtime that exits by itself is
`succeeded` on 0 and `failed` otherwise. A run its starter ends with an outcome has
that outcome. When a run ends other than by the runtime exiting by itself, or its
starter gives a reason, `dev.qory.run.exited` says why in `reason`: an open code,
Forager's or the starter's, carried as given. The session writes `timeout`, `cancelled`,
and `interrupted`, `cancelled`, a run stopped from where it was started (a Ctrl-C), and
posts them. The gateway writes the others: `session_lost`, `failed`, the session was
silent; `batch_refused`, `failed`, the gateway refused a batch from the run's session
(see the contract's §The gateway's link); `stopped`, `cancelled`, the starter ended the run and
gave no outcome, or the starter's outcome and reason when it gave one; and sending a
record again writes `gateway_lost`, `failed`. Forager's codes are reserved, and so are
the old names `quiet`, `credential_expired`, `credential_check_unreachable` and
`credential_check_invalid`, which Forager no longer writes: a starter's reason that
equals one is dropped. When the gateway ends a session's run, the gateway writes
the run's `dev.qory.run.exited`, and answers the session's next request with a `410`, a
code, and the state and the reason of that end. The session records its
`dev.qory.run.exited` in `session.jsonl` alone, with them, and posts nothing more:
`stopped`, `run_closed`, `session_lost` or `batch_refused` as the gateway ended the
run. A refusal of the run request with a
code other than `wall_required` is recorded the same way: the session records
`dev.qory.run.refused` only in the session's record, since the gateway opened no run. A
code of the server's comes with its status, and is recorded as the server sent it,
`not_found` among them, and one the contract does not list yet too. A run the gateway
could not open for a reason without a code, a `5xx` `internal`, is recorded nowhere: the
run returns the error the gateway's message says. The contract describes each.

## The runtime's events

The runtime reports what happens in its session, through its hooks and its structured
output, from inside the enclosure: in an image by reference, which a repository may have
built, the image can change or forge these events, while Forager's `dev.qory.run.*`
records come from outside. A **descriptor** maps those reports to events:

| Type                                 | When                                  |
| ------------------------------------ | ------------------------------------- |
| `dev.qory.runtime.started`           | The runtime opened its session        |
| `dev.qory.runtime.prompt_submitted`  | A prompt reached the runtime          |
| `dev.qory.runtime.tool_started`      | The runtime is about to run a tool    |
| `dev.qory.runtime.tool_finished`     | A tool ran and returned               |
| `dev.qory.runtime.tool_failed`       | A tool ran and failed                 |
| `dev.qory.runtime.turn_finished`     | The runtime finished responding       |
| `dev.qory.runtime.turn_failed`       | A turn ended on an API error          |
| `dev.qory.runtime.subagent_started`  | A subagent was spawned                |
| `dev.qory.runtime.subagent_finished` | A subagent finished                   |
| `dev.qory.runtime.notification`      | The runtime notified its user         |
| `dev.qory.runtime.ended`             | The runtime closed its session        |
| `dev.qory.runtime.result`            | A headless session printed its result |

Forager ships the descriptor for Claude Code. A runtime that nothing describes still
runs: its run, its log and its egress are recorded, with no runtime events. See
[the runtime](go.md#the-runtime).

## Following a run

`gateway.Config.Events` is any stream that gets every numbered event of every run as
well, the lines `events.jsonl` contains. A run with no receiver is followed on
standard output this way.

## The details

The whole sequence, every event type and every file are in the
[contract](../contracts/forager/v1/README.md#the-events).
