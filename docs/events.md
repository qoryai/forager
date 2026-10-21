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
- `output.log`: the bytes of the run's `dev.qory.run.log` chunks, every session's, in
  sequence order.
- `sessions/<n>/`: a directory per session that started, `<n>` the session's number,
  `session.Result.SessionDir`. It contains the session's `output.log`, the bytes of its
  `dev.qory.run.log` chunks, so you can replay one session's terminal from that file
  alone, and the files the session writes for its runtime, such as `preparation.sh` and
  Claude Code's `settings.json` and `approve-key.sh`. A join that writes no
  `dev.qory.session.started`, such as one the gateway refuses, leaves no directory.

The files the session writes for the runtime, these and `ca-bundle.pem`, are each
written to a new file beside it and renamed, so a link at its path is replaced, not
followed.

The gateway's record and the session's are in the same directory when the caller
points `gateway.Config.RunDir` at the session's runs directory, `OpenSpec.RunsDir`.
Otherwise the gateway keeps its record under `gateway.Config.Dir`, in `runs/<id>/`.

Behind a separate gateway the two records are on two machines. The gateway's machine
holds `events.jsonl`, with its `delivered.log` and `undelivered/` toward the server. The
session's machine holds `session.jsonl`, `output.log` and `sessions/`, and the session's
delivery state toward the gateway beside them:

- `delivered.log`: what the gateway accepted of `session.jsonl`, a line per batch, by
  the session's sequence, and `stopped` when the gateway ended the run.
- `undelivered/`: the session's batches the gateway did not accept, when there are any.

`session.Resend` sends the gateway what they say it
still lacks ([sending the session's record again](go.md#sending-the-sessions-record-again)).

A run behind a wall is recorded the same way. See [the wall](wall.md).

## Forager's events

| Type                          | When                                                                       |
| ----------------------------- | -------------------------------------------------------------------------- |
| `dev.qory.run.registered`     | Line 1 of the gateway's record, with a server; never posted                |
| `dev.qory.run.started`        | The run is open, before its host work and before any session               |
| `dev.qory.run.policy_applied` | After the open; after each session's start; when a new policy takes effect |
| `dev.qory.run.step_started`   | A step of the run's host work started, such as a fetch or a compose        |
| `dev.qory.run.step_exited`    | A step ended, with its state and exit code                                 |
| `dev.qory.session.started`    | A session joined the run: its runtime is about to start                    |
| `dev.qory.run.log`            | One per chunk of a session's output, or of host work outside a session     |
| `dev.qory.run.resized`        | The pseudo-terminal was resized                                            |
| `dev.qory.run.egress`         | One per connection, or per request on a terminated host                    |
| `dev.qory.run.heartbeat`      | Every interval while the run is open, 30 seconds by default                |
| `dev.qory.session.exited`     | A session ended, its join was refused, or the run ended while it ran       |
| `dev.qory.run.exited`         | The run ended: the result, the last event                                  |

Forager heartbeats while the run is open: the session sends one every interval the
gateway's discovery announces, `gateway.Config.Heartbeat`, and the gateway ends a run
whose session sends nothing for three. The exit code of a run is its last session's,
124 at the run's time limit, and -1 when no session ran.

`dev.qory.run.started` shows what opened the run, in `opened_by`: `run`, Forager's open
of the run at its gateway, before any session. Each session then has a
`dev.qory.session.started`, with its number from 1 in `session`, the runtime, the
command and the image, and a `dev.qory.session.exited`, with how the session ended: the
runtime's exit decides `succeeded` or `failed`, and `cancelled` comes with `timeout` or
`interrupted`. A join that is refused has only a `dev.qory.session.exited`, `failed`
with exit code -1 and the refusal's code, such as `mount_mode_conflict`, as its reason.
A session whose wall fails to start has its `dev.qory.session.started`, then its
`dev.qory.session.exited`, `failed` with exit code -1 and no reason, or the refusal's
code as its reason when the wall refused with one, such as `image_user_root`, an image
whose user is root. A failure with no reason, such as an image pull that fails, has the
error's text as a `dev.qory.run.log` on `stderr` of that session, and of the image or
the wall step that failed, before that step's `dev.qory.run.step_exited` and the
session's `dev.qory.session.exited`.
When the run ends while a session runs, that session's `dev.qory.session.exited` comes
right before the run's `dev.qory.run.exited`, with the same state and reason and exit
code -1. So every `dev.qory.session.started` has its `dev.qory.session.exited`.

Every `dev.qory.run.log`, `dev.qory.run.resized` and `dev.qory.runtime.*` event of a
session contains the session's number in `session`, so a reader of a run with several
sessions can show each session's terminal and events apart. A line of the run's host
work, such as a fetch or a compose, is a `dev.qory.run.log` on `stderr` with no
`session`, in a step. An event without `session`, of a record that Forager wrote before
the member was added, stays valid.

The record has the run's host work as a list of steps, as a CI job has. A step is one
named unit of host work, such as a fetch of a repository or a compose of the harness: a
`dev.qory.run.step_started`, the step's lines, and a `dev.qory.run.step_exited`. A
reader such as a control plane's run page can show each step, the step that failed,
and the log lines of each step.

- `dev.qory.run.step_started` has `step`, the step's number in the run from 1, `name`,
  a readable name such as `fetch github.com/example-org/app`, and `kind`: `fetch`,
  `compose`, `image`, `setup`, `join` or `wall`.
- `dev.qory.run.step_exited` has the same `step`, `state` (`succeeded`, `failed` or
  `cancelled`), `exit_code`, -1 when no process exit status exists, and `duration_ms`.
- Each host line of a step is a `dev.qory.run.log` with the step's number in `step`,
  between the step's two events. A host line outside every step has no `step`.

The steps come after `dev.qory.run.started`, numbered in the order they start, one at
a time:

- The caller writes the `fetch` and `compose` steps of its host work with
  `(*session.Run).StartStep`, before the first join or between two joins.
- Each join writes a `join` step, `join session <n>`, around its join request and the
  session's checks. It ends before `dev.qory.session.started`, or `failed` before the
  `dev.qory.session.exited` of a refused join.
- Behind a wall, after `dev.qory.session.started`, the join writes an `image` step,
  with the image's reference as its name, when the policy's image is a reference,
  and a `wall` step, `start the wall`, up to the runtime's start. The runtime runs in no
  step, and a session's lines have `step` only in these two steps.

The close ends a host step still open `cancelled` with -1, before
`dev.qory.run.exited`. When the gateway ends a run during a step, the run's stream has
no `dev.qory.run.step_exited` for that step; the session writes that step's
`dev.qory.run.step_exited` in `session.jsonl` alone, with the step's outcome. Forager writes no `setup` step: a session's `preparation`
runs with its runtime, in no step. A step's `name` has `qory-proxy-password` in place
of a forwarder's password, and a phrase in place of a name that contains `qak_` or
`qrk_`.

`dev.qory.session.started` contains `harness` when the caller passes it: one entry per
harness source the session's compose used, each with `source`, the source as it is
configured, and `commit`, the full commit id compose used, 40 or 64 hexadecimal
characters.

Every `dev.qory.run.exited` shows how the run ended in `state`: `succeeded`, `failed` or
`cancelled`, stopped before it said how it went. The close of the run writes the
outcome its caller gives. A run its starter ends with an outcome has that outcome. When
the close's outcome has a reason, or the run ends without a close, or its starter gives
a reason, `dev.qory.run.exited` contains why in `reason`: an open code, Forager's or the
starter's, carried as given. The close writes `timeout`, `cancelled`, `interrupted`,
`cancelled`, a run stopped from where it was started (a Ctrl-C), and `no_session`,
`failed`, a run closed with no session after its host work failed, such as a fetch,
and posts them. The gateway writes the others: `session_lost`, `failed`, the session was
silent; `batch_refused`, `failed`, the gateway refused a batch from the run's session
(see the contract's §The gateway's link); `stopped`, `cancelled`, the starter ended the run and
gave no outcome, or the starter's outcome and reason when it gave one; and sending a
record again writes `gateway_lost`, `failed`. Forager's codes are reserved, and so are
the old names `quiet`, `credential_expired`, `credential_check_unreachable` and
`credential_check_invalid`, which Forager no longer writes: a starter's reason that
equals one is dropped. When the gateway ends a session's run, the gateway writes the
open session's `dev.qory.session.exited` and then the run's `dev.qory.run.exited`, and
answers the session's next request with a `410`, a code, and the state and the reason
of that end. Sending a record again writes the open session's `dev.qory.session.exited`
the same way before its `gateway_lost`. The session records its
`dev.qory.session.exited` and its `dev.qory.run.exited` in `session.jsonl` alone, with
them and exit code -1, and posts nothing more:
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
