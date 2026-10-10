# The server

Every event goes to files. With a server configured, every event its configuration
selects goes there too, signed. The server can also set the run's policy.

A server is a control plane, or a receiver of your own.

## In forager.yaml

For `qory`, the `gateway.server` section of `~/.config/qory/forager.yaml` defines the
server. The example is in [the policy](policy.md#in-forageryaml).

- Forager reports to the server as an access key: `access_key_id` is its id, and
  its secret, one line starting `qak_`, lives in the file `access-key-secret` beside
  `forager.yaml`, or in `QORY_ACCESS_KEY_SECRET`. The secret signs every request with
  Ed25519 and is never sent.
- `apiary_public_key` is the pin, the server's keys: Forager verifies every answer
  under it. A server without a pin is no run.
- `qory access-key enrol` enrols a new key with a code from the server and writes the
  id and the pin; the code's use activates the key at once. A key made for an existing
  node or node pool in the server's console is active at once: the machine takes its id,
  secret and pin as `QORY_ACCESS_KEY_ID`, `QORY_ACCESS_KEY_SECRET` and
  `QORY_APIARY_PUBLIC_KEY`.
- The run's policy comes from the server, when the server offers one. The node's
  policy, `gateway.Config.Policy`, narrows it. See
  [the policy](policy.md#the-node-narrows-the-servers-policy).
- The run's variables come from the server as well. See [variables](#variables).
- With `gateway.server` set, the run starts only when the server answers the fetch and
  accepts the run's registration, signed. So a run meant to be observed never runs
  unobserved.
- `qory run --local` runs with the files alone.
- Without `gateway.server`, the run writes files only.

## How Forager uses the server

The gateway reports to the server; the session never speaks to it. A
`gateway.Server` in `gateway.Config` defines the server. The gateway:

1. fetches the server's configuration document when it starts, with a signed `GET` of
   `/.well-known/qory-configuration`. The document names the run endpoint, `run.url`,
   with no trailing slash, query or fragment; a document without it is refused;
2. for each run a session asks it for, registers the run with one signed `POST` to
   `run.url`. The body holds the run's id, its labels, what it is about, the heartbeat
   interval, the event types the server receives, the contract and Forager versions,
   and the time. The labels travel in the body, never in a URL, and what the run is
   about never selects a policy. The registration opens the run at the server, which
   decides `instance_limit` there;
3. reads the answer, the run's run configuration. Its `security_policy`, narrowed by
   the node's policy, is the run's policy. Its `variables` are the server's variables
   for the run. A server with no policy answers `{"version":1}`. The gateway answers
   the session's run request with what follows of them;
4. posts the events the document selects to the URL it defines, signed: the
   session's, which it receives on its link and numbers, and its own.

Every request is signed with the access key, the access key id and the instance id
among the signed lines. Every answer is signed with the server's key and bound to the
request, and the gateway reads an answer only once it verifies under the pin. The
server decides which labels identify what the run works on.

`gateway.Server` holds what identifies the run to the server:

- `AccessKey` is the access key, an `*accesskey.Key` held from its secret, which the
  caller reads. It signs every request.
- `InstanceID` is this instance's id: `qory` reads it from its instance-id file. It is
  sent in `X-Qory-Instance-Id` and signed into every request, and it matches
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.
- `InstanceName` is this instance's display name, sent in `X-Qory-Instance-Name` on
  every request, unsigned. It matches the same pattern; empty sends none.

`gateway.Config.Discovered`, when not nil, is called once the configuration document is
read and verified, before `gateway.Start` returns, with a `gateway.Discovery`: `NodeID`,
the id of the access key's node, `nd_`, or node pool, `np_`; and `Secrets`, true when
the document lists a `secrets` section, which it does for an access key allowed stored
secrets. `qory` prints the node id. An error it returns is no gateway, and nothing
more is sent.

## When the server refuses a run, or wants nothing more

A refusal at the start has a code. The gateway passes the server's on to the session,
which returns it as a `*session.Refusal` whose `From` is `apiary`: `unauthorized` for a
key the server does not hold, `instance_limit` when the node's live instances are at
its limit. An answer that does not verify under the pin is `answer_unsigned`, and a
server without a pin `apiary_public_key_missing`: `gateway.Start` returns either as a
`*accesskey.Refusal` when it fetches the configuration document, and starts no
gateway.

Qory Apiary records what a run reports and never ends a run it did not start. A
server's signed `410`, with any code or none, says it wants nothing more of the run:
the gateway sends it no further batch, writes `stopped` to the run's `delivered.log`,
and reports it once. The run goes on. The gateway keeps numbering the run's events and
recording them in `events.jsonl`, it answers the session's requests as before, and the
runtime runs to its own exit. A resend of the run's record sends the server nothing.
A `410` to the registration, signed or not, with any code or none, is no run, a failure
without a code: the session returns the gateway's error, which names `run.url` and the
status, such as
`register https://qory.example/v1/runs: status 410: the server did not accept the run`
for a signed one.

## A policy that changes while the run goes

A server may answer a later batch with another digest. The gateway then fetches the
run's configuration again by the run's id, with a signed `GET <run.url>/<run_id>`, and
puts it in force while the run goes, narrowed by the same node
policy. Its answers to the session then carry the new run-configuration digest, and the
session fetches the run's configuration from the gateway and records it in another
`dev.qory.run.policy_applied`. The variables stay as they were when the run started.

## Variables

A run configuration may contain `variables`: for each name, an object with its string
`value`, such as `{"LOG_LEVEL": {"value": "info"}}`. Several sources may set one name,
and for each name the run takes the value of the highest that sets it:

| Source, highest first | What it is | In the spec |
| --- | --- | --- |
| `fixed` | the session's, the proxy's, the wall's and the preparation's names, the placeholders, the values the harness computes | `HarnessHome`, `LaunchFixed` |
| `apiary` | the server's run configuration, resolved by the server | |
| `run` | the run's own, `qory run --env` | `Variables.Run` |
| `machine` | the machine's, `wall.env` | `Variables.Machine` |
| `harness` | the harness's written defaults | `LaunchDefaults` |
| `shell` | what the run inherits | `Env` |

- The server's value of a name wins over the node's whenever the run applies it: the
  node's sources apply to the names the server leaves alone, and to a name whose
  server value is left out.
- The deny list leaves out a value of the server, the run, the machine or the harness's
  defaults. The list is the contract's
  [`denied-variables.json`](../contracts/forager/v1/denied-variables.json), the runtime's
  `denies`, and `Spec.Variables.Deny`. It holds the session's own names, the proxy's, the
  trust store's, Docker's and `PATH`. The built-in list leaves out a value the harness
  computes as well; the runtime's `denies` and `Variables.Deny` leave those in.
- A value of a fixed name from any other source is left out.
- The server's value of a variable the runtime declares or reserves, or one a
  credential is read from, is left out. A node's value of a declared one reaches the
  runtime.
- A run without a wall takes none of the server's variables, unless
  `Spec.Variables.Unwalled` is `session.UnwalledAccept`. The run's own variables apply
  with or without a wall.
- A value that loses is left out, and the run starts.

```go
spec.Env = os.Environ()                                      // what the run inherits
spec.LaunchFixed = []string{"CODEX_HOME=/home/agent/.codex"} // what the harness computes itself
spec.LaunchDefaults = []string{"HARNESS_PROFILE=nextjs"}     // what its author wrote as defaults
spec.HarnessHome = "/home/agent/.qory/harness"               // QORY_HARNESS_HOME
spec.Variables = session.Variables{
	Run:      []string{"LOG_LEVEL=debug"},          // --env; the server's win
	Machine:  []string{"BUILD_NUMBER=42"},          // wall.env
	Deny:     []string{"LEGACY_SETTING", "ACME_*"}, // names and patterns, in any case
	Unwalled: session.UnwalledIgnore,               // or UnwalledAccept
}
spec.OnVariables = func(applied session.Applied) { // once, before the agent starts
	for _, v := range applied {
		for _, l := range v.Lost {
			if l.From == session.FromRun {
				fmt.Printf("--env %s is not applied: %s\n", v.Name, l.Why)
			}
		}
	}
}
```

`LaunchFixed` is the values the harness computes itself, and `LaunchDefaults` the values
its author wrote as defaults; the session applies each as its source. `HarnessHome` is an absolute path, and the session sets `QORY_HARNESS_HOME` to it
as one of its own names; a path that is not absolute, or that holds a NUL, a carriage
return or a line feed, is an error before anything starts.

Before it resolves anything, the session refuses to pass in what stays outside. It
checks every value the node passes: `Env`, `LaunchFixed`, `LaunchDefaults`,
`Variables.Run` and `Variables.Machine`.

| The run passes | In | The refusal |
| --- | --- | --- |
| a `QORY_` variable, or one the gateway sets, such as one a credential is read from | a walled run | `variable_reserved` |
| a value for a placeholder | any run | `placeholder_conflict` |

`QORY_RUN_ID` and `QORY_RUN_SOCKET` are exempt from the first. Without a wall, a
`QORY_` value of the server, the run, the machine or the harness is denied instead.

The record lists every variable by name, never a value: `dev.qory.run.policy_applied`'s
`variables` contains each name, `from`, the source that applies, and `lost`, each value
that lost with its source and why: `overridden`, `denied`, `fixed` or `unwalled`. A
fixed name, and a name the run inherits, is listed only beside a value of the server,
the run, the machine or the harness's defaults. `Spec.OnVariables` receives the same
list, as `session.Applied`.

## A control plane

A control plane is the same server every run has:

- it opens the run at its registration;
- it supplies the run's policy, as the server's run configuration, the registration's
  answer.

## Writing a server

- **The rules**: the contract's
  [server section](../contracts/forager/v1/README.md#the-server).
- **A worked example**: the public package [`receiver`](../receiver/receiver.go). It is a
  server of the contract that is not a control plane. Forager's tests run against
  it, and it is tested against the signed fixtures.
- **The test data**: `contracts/forager/v1/fixtures/signed/`. Any receiver is tested
  against it.
