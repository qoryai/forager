# Proposal: secrets and variables

Status: draft. Nothing here is part of the contract until it is merged into
`contracts/runner/v1/README.md` and its schemas. Section references (§) are to that
README.

## Summary

A secret is a name and a value, or several values each with a value id. What needs a secret
is one of three kinds, and each kind defines how and where its secrets are sent:

- a **runtime**, such as Claude Code, through its descriptor;
- an **integration**, a program that implements the integrations contract;
- a **service**, a definition of exact hosts, an authentication scheme and the secrets it
  needs.

A **connection** links each secret a kind needs to a secret. Connections are the only
way a run sends a credential anywhere: the policy selects no credential. A run's
connections come from its run configuration when the document has a `connections`
member, beside an optional `security_policy` and optional `variables`, all covered by
the digest; otherwise from the machine's runner file in the same shapes. Connections and
variables are fixed when the run starts and stay fixed for the run's life.

An access key is the credential: one secret, an Ed25519 key, which a fleet of machines may
share. It signs every request, and the same key, converted to X25519, opens what the
server seals to it; the server stores only the public key. A machine is an instance that
runs with the key, reported by id for display and audit only. A value the server stores is
sealed to that key (HPKE base mode, X25519, HKDF-SHA256, AES-256-GCM) and fetched once per
run from a new signed endpoint, for the connections the run applies. A value the machine
keeps comes from a provider on the machine, bounded by the hosts the machine allows it.
Every answer of the server is signed with the server's own Ed25519 key, which every runner
pins, and bound to the request it answers, and the runner recomputes the run
configuration's digest, so the values it opens are bound to the exact document that routes
them.

From the server to the runner a stored value is end to end: only the runner process opens
it. From the runner to the host it is sent to, the value travels in a TLS connection that
the proxy verifies against public roots only, by default (`tls.public_roots_only`), so
only a host whose certificate chains to a public root receives it. A machine value travels
in an ordinary TLS connection verified against the machine's trust store.

The contract is `v1`, revision 1, and describes the runner as it is; a later change goes
through `X-Qory-Contract-Version`.

## What this changes in the contract

Against `contracts/runner/v1/README.md` on main. The contract stays `v1`, revision 1,
amended in place. README passages this amends gives the new wording passage by passage,
Fixtures on main the fixtures, and Sources the sources.

**§The server: identity and signing**

- The access key and its secret become an access key with an Ed25519 key (Decision 4).
  The server document has `url`, `access_key_id` and the pin `apiary_public_key`; the
  secret lives in `access-key-secret` or `QORY_ACCESS_KEY_SECRET`, in place of the
  document's `secret` and `QORY_SERVER_SECRET`.
- Requests are signed with Ed25519: `X-Qory-Access-Key-Id`, `X-Qory-Machine-Id` and
  `X-Qory-Signature-Ed25519` take the place of `X-Qory-Access-Key` and the HMAC
  `X-Qory-Signature-256`, and `X-Qory-Machine-Name` carries a display name. The request
  strings, for a GET and for a POST, are defined here in full; a POST's covers its path
  and its body. The HMAC known answers give way to the Ed25519 ones of Wire format.
- Every answer to a verified request is signed with the server's Ed25519 key, which every
  runner pins, and bound to the request by its signature (Signed answers). Every `401` is
  unsigned.
- A machine is an instance with a machine id, signed into every request for display,
  audit and per-instance events; authorisation rests on the access key.
- Access keys enrol with a code or by a pasted public key, need approval, rotate, and
  re-key with an administrator's code: three new endpoints, enrolment, re-key and
  `access_key.url` (Wire format).

**§The server: documents**

- Discovery gains `secrets`, `access_key`, `apiary_public_key`, `current_key`,
  `pending_key` and `key_rotation_required`, and is per access key and verifying key.
- The run configuration gains `connections`, `variables` and `withheld`, and
  `security_policy` becomes optional. Its digest becomes normative: the runner recomputes
  it, and the server keeps a rendering per holder and variant (Decision 6).
- A new endpoint, `secrets.url`, returns stored values sealed with HPKE to the access
  key, for the connections the run applies (Decisions 5 and 6).
- The order of refusals and the coded refusals are defined for every endpoint, the
  events endpoint included (Endpoint rules).

**§The policy and §Credentials**

- The policy's `credentials` moves to connections: a run's credentials come from its run
  configuration's `connections`, else from the runner file's, and the policy keeps
  `egress`, `tools` and `image`.
- A credential definition's sources map onto connections. An `env` or `file` token is a
  machine value in `secrets.local`, bounded by its `hosts`, sent through a service
  connection. An `adapter` is an integration: a program of the integrations contract,
  started as `<program> credential -- <argument>` with its settings on standard input,
  whose answer, `credential.schema.json`, keeps its role.
- A runtime declares the secrets it needs in its descriptor: `declares`, `one_of`,
  `reserves`, `denies` and `credential_files` (Runtimes).
- A host that receives a stored value is verified against public roots only
  (`tls.public_roots_only`), and values are set on port 443 alone; `TRACE` and `TRACK`
  are refused there.

**Variables**

- A run configuration's `variables` reach the agent's process, resolved by level and
  `locked`, with a built-in deny list, the runtime's `denies` and the machine's
  `variables.deny`; an unwalled run receives them only with `variables.unwalled: accept`
  (Decision 1).

**The runner file**

- It gains `connections:`, `secrets.providers`, `secrets.local`, bounds on
  `integrations:` (`arguments`, `settings`), `variables.deny`, `variables.unwalled`,
  `machine.name` and `tls.public_roots_only`.
- Its directory holds everything `qory` keeps for the server, the secret, `machine-id`,
  the `stored-secrets` marker and the locks among them, and every walled run refuses a
  mount of it.

**§The wall**

- A walled run refuses a mount of the runner's files and of a runtime's credential
  files, sets the runtime's declared and reserved variables it leaves unused to empty,
  and keeps a `secrets.local` source and the access key's variables out of the
  enclosure.
- A server that lists `secrets` requires a wall for every run, and so does a machine
  with the `stored-secrets` marker.

**§The events**

- `dev.qory.run.refused` is new: every no-run after the ping emits it as the run's first
  and last event, always sent, like the ping. Main's refusals before the start, of tools,
  images and the run configuration's fetch, get codes of their own.
- `dev.qory.run.policy_applied` reports `connections`, `connections_withheld` and
  `variables` in place of `credentials`, keeps `terminated`, and allows `url` and
  `run_configuration` with `source` `none`. `dev.qory.run.egress` names the `connection`
  in place of the `credential`, gains `renewal_failed`, and records `wall:trace` and
  `wall:public-roots` in `rule`, as main records `wall:own-address`.

**Refusal codes**

- The server's codes for keys and secrets: `key_pending`, `key_invalid`,
  `key_rotation_pending`, `key_rotation_required`, `secrets_not_allowed`, `run_closed`,
  `run_configuration_superseded`, `run_connections_invalid`, `run_secrets_conflict`,
  `run_secrets_expired`, and `bad_request` for a machine id.
- The runner's codes for the pin, the answers, the wall, connections, runtimes,
  integrations, secrets and variables, from `apiary_public_key_missing` to
  `placeholder_conflict`, and `qory`'s `labels_changed` (Refusal codes).

**Schemas and data files**

- New: `secrets-request`, `secrets-answer`, `sealed-plaintext`, `enrolment`, `rekey`,
  `access-key` and `auth` schemas, `events/run.refused`, and the data files
  `headers.json`, `runtimes.json` and `denied-variables.json`.
- Changed: `server`, `configuration`, `run-configuration`, `policy`, `descriptor`,
  `events/run.policy_applied`, and `events/run.egress`, whose `credential` becomes
  `connection` and which gains `renewal_failed`, a boolean, true on a request whose
  connection's last renewal failed.

**§Fixtures**

- `fixtures/server/` and `fixtures/signed/` use the fixture access key and Ed25519 in
  place of the published HMAC secret; `fixtures/sealed/` is new; the policy fixtures
  select tools, with connections in the run configuration fixtures.

## README passages this amends

Each line names a passage of the README on main and what it becomes.

**Rules that change**

- **§Versions.** Revision 1, amended in place, stands. Its list of sections gains
  connections, variables, the secrets endpoint, enrolment and re-key, and access keys and
  machines. The rest of §Versions is unchanged.
- **§Limits, the server bullet.** "The secret authenticates the runner to the server.
  Over `https`, TLS authenticates the server to the runner; over `http` to a loopback
  address, nothing does" becomes: "The access key authenticates the runner to the
  server. Every answer is signed under the key the runner pins, so the runner
  authenticates the server over `https` and over loopback `http` alike."
- **§The events, the first and last events.** `dev.qory.run.started` is the first event
  and `dev.qory.run.exited` the last, except for a refused run, whose
  `dev.qory.run.refused` is both its first and its last event.
- **§The server, after a runner stops.** The resend adds `dev.qory.run.exited` with
  `reason: runner_lost` only to a record that has `dev.qory.run.started` and no
  `dev.qory.run.exited`.
- **§The server, delivery.** "The server returns a status; the body is ignored" and
  "nothing in an answer's body is read" become: "the runner reads a body's code only
  from a signed answer".
- **§The server, failure.** A missing or empty `X-Qory-Access-Key-Id` or
  `X-Qory-Signature-Ed25519` is an unsigned `401`; a header sent twice is an unsigned
  `400` before verification; a missing or malformed `X-Qory-Machine-Id` is a signed `400`
  after it. "The server verifies with a constant-time comparison … and logs nothing about
  the headers" becomes: "The server verifies the Ed25519 signature, logs nothing about the
  signature header, and records the machine id and name as display data." The delivery
  paragraph's "verifies the signature over the raw bytes with a constant-time comparison
  before parsing" becomes "verifies the Ed25519 signature over the request string before
  parsing".
- **§The server, the secret.** "with the secret from `QORY_SERVER_SECRET` when the file
  does not contain it" becomes: "with the access key secret from a file descriptor, else
  `QORY_ACCESS_KEY_SECRET`, else the file `access-key-secret`" (Decision 4).
- **§Credentials and §Tools, a host outside the allow list.** Under `enforce`, a tool
  whose host the allow list does not cover is no run, as on main. A connection whose
  host the policy denies gets `hosts_denied`, and the run goes on, because denied egress
  never ends a run. The two differ because a tool needs its host to work at all, while a
  connection only adds a value to requests the policy already governs.
- **§The policy, paths under `observe`.** Under `enforce`, a request outside a
  connection's `paths` is refused; under `observe`, it passes without the value and is
  recorded. The value is set only on a connection's own hosts, whatever the mode.

**The old credential wording**

- **§The boundary, duty 1.** "which of the machine's credentials the run may use"
  becomes "which hosts and paths the run reaches"; credentials come from connections
  (Decision 7). "Nothing in a policy grants" stands, and connections grant only within
  the hosts the machine and the runtime allow.
- **§The boundary, duty 3.** "keeps the credentials the run's policy selects" becomes
  "keeps the values its connections supply"; "with the developer's own environment"
  gains "and the server's variables only with `variables.unwalled: accept`".
- **§Limits, the termination bullet.** "a host the run has a credential or path rules
  for, or a tool serves" becomes "a host of a connection, a host with path rules, or a
  host a tool serves"; `dev.qory.run.policy_applied` still lists those hosts as
  `terminated`.
- **§Limits, the enclosure bullet.** "one the policy selects stays outside" becomes "a
  value a connection supplies stays outside", with `runtime_secret_conflict` (Runtimes).
- **§Sequence, step 1.** The launch spec gains the connections, the providers and local
  values, the integrations, the access key secret, the machine id, the variables and
  `tls.public_roots_only`.
- **§Sequence, step 5.** "Nothing else of the runner's enters the environment" gains:
  "the variables, the placeholders and, in a walled run, the runtime's declared and
  reserved variables as empty".
- **§Sequence, behind a wall.** "starts the tools the policy selects" is preceded by:
  "runs each integration's `credential`".
- **§The policy and `policy.schema.json`'s description.** `credentials` leaves the table;
  "a credential for it never apply", "the paths of the credential that is for it" and
  "the proxy never sets a credential on it" name a connection; the schema's description
  reads "a tool or an image it selects is one the machine defines".
- **§Tools.** "as it selects credentials" becomes "as it selects images"; "in a
  credential's grammar" becomes "in a connection id's grammar of the runner file";
  "placeholders … as a credential's (§Credentials)" becomes "as a connection's"; "as for
  a credential's host" becomes "as for a connection's host"; "a host a tool serves and a
  credential is for" becomes "a host a tool serves and a connection covers",
  `connection_host_conflict`; the refusals before the start take the codes of Events.
- **§Images.** "as it selects credentials and tools" becomes "as it selects tools", and
  "in a credential's grammar" becomes "in a tool's name grammar".
- **§The wall.** "the proxy, the policy and the server's secret" becomes "the proxy, the
  policy and the access key secret"; the guarantee "no credential the run's policy
  selects" becomes "no value a connection supplies"; "When the run has an authority of
  its own (§Credentials)" refers to §Connections at the proxy.
- **§The runtime.** "A runtime defines six things" becomes seven, the secrets it
  declares; the descriptor "has five parts" becomes six, `secrets` (Runtimes).

## Fixtures on main

**They go:**

- `fixtures/policy/enforce-long-argument.yaml`: its `credentials` entry; the file keeps
  its tool with a 4096-character argument.
- `fixtures/invalid/policy-credential-argument-too-long.yaml`: the policy has no
  `credentials`.
- `fixtures/invalid/event-policy-applied-empty-credential-argument.json`:
  `policy_applied` has no `credentials`.
- `fixtures/server/https.yaml` and `fixtures/server/loopback.yaml`, with `access_key` and
  `secret: fixture-secret-not-a-real-one`.
- `fixtures/invalid/server-no-key.yaml`, about `access_key`.
- The nine `fixtures/signed/*` files, signed with the HMAC secret.
- In the recorded run `fixtures/run/0192a0b1-7c2d-7e3f-8a4b-5c6d7e8f9a0b/`, the
  `credentials` of its `policy_applied` and the `credential` of its egress events.

**They take their place:**

- `fixtures/server/https.yaml` and `loopback.yaml`: `access_key_id` and
  `apiary_public_key`, the fixture keys of Decision 5.
- `fixtures/invalid/server-no-access-key-id.yaml`, `server-no-pin.yaml` and
  `server-secret-member.yaml`: a server document without its id, without its pin, or
  with a secret.
- `fixtures/configuration/with-secrets.json` and `key-rotation-required.json`: discovery
  with `secrets`, `access_key`, `apiary_public_key`, `current_key`, `pending_key` and,
  in the second, `key_rotation_required`.
- `fixtures/run-configuration/` documents with each kind of connection, with
  `variables`, and the variant with `withheld`.
- `fixtures/signed/*`, rebuilt in the new form (The access key and signed requests).
- `fixtures/sealed/`, the sealed fixture of Decision 5.
- `fixtures/invalid/` for what the schemas refuse: `run-configuration-variable-not-object`,
  `run-configuration-connection-bad-id`, `secrets-request-unknown-member`,
  `enrolment-code-lower-case`, `rekey-answer-no-pin`, `event-egress-credential` and
  `event-policy-applied-credentials`.
- `fixtures/run/<id>/`, the recorded run re-recorded with an integration connection.

## Sources

§Sources changes in two ways.

- **Dropped as models:** RFC 2104 for HMAC, AWS Signature Version 4 for the access key
  and secret pair, and GitHub's signature validation. GitHub's delivery headers and its
  ten-second answer stay the model for `X-Qory-Delivery` and the events answer, and
  OpenID Connect Discovery stays the model for discovery.
- **Added:**
  - [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), Ed25519;
  - [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), HPKE, with the CFRG test
    vectors, `test-vectors.json`;
  - Thormarker, "On using the same key pair for Ed25519 and an X25519 based KEM", IACR
    ePrint 2021/509;
  - [machine-id(5)](https://www.freedesktop.org/software/systemd/man/latest/machine-id.html),
    for the keyed hash of the machine's identity;
  - the IANA [HTTP Field Name Registry](https://www.iana.org/assignments/http-fields/)
    and the Fetch standard's [forbidden request-header
    names](https://fetch.spec.whatwg.org/#forbidden-request-header), for `headers.json`;
  - the [Public Suffix List](https://publicsuffix.org/), for an integration's `*.` hosts.

## The model

- **A secret** is a name, `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, and either one value without a
  value id or several values, each with a value id unique within the secret,
  `^[a-z0-9][a-z0-9_.-]{0,63}$`. A stored secret's identity is its id, `sec_` and 16
  lower-case Crockford base32 characters; the name is what people read.
- **A declaration** is what a kind needs: an id unique within the kind,
  `^[a-z][a-z0-9_]{0,63}$`, a title for people, and optionally `name`, the conventional
  variable a program reads it from, which becomes the run's placeholder.
- **A connection** links a kind's declarations to secrets: `id`, the kind and what
  identifies it, and `secrets`, a map from a declaration's id to a reference. In a run
  configuration its id is `con_` and 16 lower-case Crockford base32 characters; in the
  runner file, a name the machine chooses, `^[a-z0-9][a-z0-9_-]{0,63}$`. The server
  decides which connections apply to a run and sends them as one flat list; it refuses on
  save two connections that would apply to one run for the same runtime, the same
  integration name or overlapping hosts.
- **A reference** is `{"id": "sec_…", "name": "…", "value_id": "…"}` for a value the server
  stores, where the id is the identity and the name is for display; or
  `{"source": "external", "name": "…", "value_id": "…"}` for a value a provider on the
  machine resolves, where the name is the lookup key. `value_id` selects one value of a
  secret with several; a reference to such a secret without one is refused,
  `secret_value_id_missing`. The runner file's connections contain external references only.
- **Where a value goes** is decided by the connection's kind:

  | Kind | Hosts | How |
  |---|---|---|
  | `runtime` | the declaration's, in the runtime's descriptor | the declaration's scheme |
  | `integration` | `roles.credential.hosts` of the program's `describe` | the program's answer: scheme and paths |
  | `service` | the definition's exact hosts | the definition's scheme |

- **A holder** is what the server renders a run configuration for: a workspace's
  baseline, or a repository of the workspace that has rules, connections or variables of
  its own. The run's labels select the holder within the access key's workspace, and the
  server keeps every rendering of a holder with its digest (Decision 6).
- **Where connections come from.** A run configuration's `connections`, when the member
  is present, even as an empty array, is the server's whole set. When the run
  configuration has no `connections` member, or the run has no run configuration (no
  server, `--local`, or a server that offers none), the runner file's `connections:`
  apply, as the machine's policy applies without `security_policy`; `qory` parses them
  and passes them through `session.Spec`. Machine values stay within their `hosts`
  either way.

## Decisions

### 1. Variables: precedence, denied and reserved names

**Variables reach the agent's process alone.** The runner adds them to the launch's
environment, and tools, integrations, the relay, the agent's Docker daemon and the wall's
`docker` command keep their own environment. The
nested Docker helper starts `dockerd` with the system `PATH`, the proxy variables and the
bundle only (Issues, item 3).

**Precedence.** A variable is set at levels, the more specific winning: the organisation
(in the commercial editions), the workspace, the repository, all three resolved by the
server, then the machine. Every kind of run resolves the same levels.

- The server sends each variable with its value and `locked`. A level that locks a
  variable stops every level below it from overriding it; the server's resolution
  honours locks among its own levels, and the runner honours `locked` for the machine's.
- `locked` is true when any server level of the chain locks the name, and the value sent
  is then the topmost locking level's. A lock always carries a value. Whether a lower
  level may still save a value under a lock is the server's to decide.
- The machine's level is what the run sets on the machine, its machine-level variables:
  `wall.env` in `runner.yaml`, `--env`, the harness's composed launch and what the
  runtime's `Prepare` sets, the names a new `session.Spec` field lists (Issues, item 2).
  "Machine value" keeps its own sense, a value of `secrets.local`.
- A machine-level variable replaces an unlocked one. Where a value from `wall.env` or
  `--env` meets a locked one, the server's value wins. A name the runtime's `Prepare` or the
  harness's launch sets wins even over a locked variable, because the runtime needs it;
  the server's variable is then left out and reported in `denied`.
- A run with two sources for one name starts, and `dev.qory.run.policy_applied` reports, by
  name only, every variable a machine-level variable replaced and every locked one that
  kept the server's value against one (Events).

**Unwalled runs.** The runner file's `variables.unwalled` decides whether an unwalled run
receives the server's variables: `ignore`, the default, or `accept`. With `ignore`, an
unwalled run starts without them; they are left out and reported by name in
`policy_applied`'s `variables.unwalled`. With `accept`,
the deny list below still applies. A walled run receives them as this decision
describes, whatever the setting. Plainly: `accept` hands the server code execution as
the developer, through settings no list can foresee, such as a package index whose
install scripts run. It is for a machine whose owner trusts the server as fully as their
own shell.

**Denied names.** A machine accepts every variable the server sends except the names of a
deny list: the built-in list below, the run's runtime's `denies` (Runtimes), and the
names the machine's owner adds in the runner file, `variables.deny: [NAME, PREFIX_*]`.

- A denied variable is left out of the run and reported by name. The run starts, a
  locked variable's case included.
- An entry is a name or a pattern, `^[A-Za-z0-9_*]{1,128}$` with at least one character
  other than `*`. It matches a whole name: `*` matches any run of characters, the empty
  run included, anywhere in the entry. Matching ignores case, because programs read
  `http_proxy` and `HTTP_PROXY` alike.
- The list applies to the server's variables alone, with and without a wall.
- The reason: in an unwalled run that accepts the server's variables, a server-sent
  `LD_PRELOAD` runs code as the developer, and in a walled one these names would undo the
  wall's own set-up: its proxy, its trust bundle, its Docker configuration and the
  program the launch starts.
- **Exceptions.** Six names are allowed although `GIT_*` is denied: `GIT_AUTHOR_NAME`,
  `GIT_AUTHOR_EMAIL`, `GIT_AUTHOR_DATE`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL` and
  `GIT_COMMITTER_DATE`. They set a commit's name, email and date and run nothing, and
  teams set them so an agent's commits carry a bot identity. A name is denied when it
  matches an entry of the built-in `names`, or matches an entry of `patterns` and no
  entry of `except`; `except` lifts a pattern's match only, and a named entry always
  denies. It applies to the built-in list only: the runtime's `denies` and the owner's
  `variables.deny` always win.
- The server vendors the built-in list as `denied-variables.json`, `{"version": 1,
  "names": [...], "patterns": [...], "except": [...]}`, `except` holding the six names
  above, under the same matching rule. It holds every row of the table except three,
  which depend on the machine and the run: the names `Docker.CAEnv` sets, the runtime's
  `declares` and `reserves`, and the runtime's `denies`, which come from
  `runtimes.json`. The server refuses a name the file covers when it is saved,
  and warns about a name a catalogued runtime declares, reserves or denies, or a
  placeholder of the holder's connections; the runner leaves both out anyway.

| Category | Name | Why |
|---|---|---|
| Loader | `LD_*` | the Linux loader loads libraries and audit modules from `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` |
| Loader | `DYLD_*` | the same for the macOS loader |
| Loader | `GCONV_PATH` | glibc loads character-set conversion modules from it |
| Loader | `GLIBC_TUNABLES` | glibc parses it in every program at start-up, and its parser has had exploitable flaws |
| Start-up, Node | `NODE_OPTIONS` | flags for every Node process, `--require` included |
| Start-up, Node | `NODE_PATH` | where Node finds modules |
| Start-up, Node | `NODE_REPL_EXTERNAL_MODULE` | a module Node loads in place of its REPL |
| Start-up, Python | `PYTHONSTARTUP` | a file Python runs at interactive start |
| Start-up, Python | `PYTHONPATH` | where Python finds modules |
| Start-up, Python | `PYTHONHOME` | where Python finds its standard library |
| Start-up, Python | `PYTHONINSPECT` | a prompt that reads input after a script ends |
| Start-up, Python | `PYTHONUSERBASE` | the user site directory, whose `.pth` files run code |
| Start-up, Perl | `PERL5OPT` | switches for every Perl, `-M` loading a module |
| Start-up, Perl | `PERL5LIB`, `PERLLIB` | where Perl finds modules |
| Start-up, Ruby | `RUBYOPT` | switches for every Ruby, `-r` loading a library |
| Start-up, Ruby | `RUBYLIB` | where Ruby finds libraries |
| Start-up, Ruby | `GEM_PATH`, `GEM_HOME` | where Ruby loads gems from |
| Start-up, Ruby | `BUNDLE_GEMFILE` | which Gemfile, itself Ruby code, Bundler runs |
| Start-up, Ruby | `RUBYGEMS_GEMDEPS` | a gem dependency file RubyGems loads when Ruby starts |
| Start-up, others | `PSQLRC` | a start-up file `psql` reads, whose `\!` runs a shell command |
| Start-up, others | `R_PROFILE_USER` | R code R runs at start |
| Start-up, Java | `JAVA_TOOL_OPTIONS` | options every JVM reads, `-javaagent` included |
| Start-up, Java | `_JAVA_OPTIONS` | the same, read by HotSpot |
| Start-up, Java | `JDK_JAVA_OPTIONS` | the same, read by the `java` launcher |
| Start-up, Java | `JAVA_OPTS` | options the launcher scripts of many Java programs pass to the JVM |
| Start-up, Java | `CLASSPATH` | where the JVM loads classes from |
| Start-up, Java | `GRADLE_USER_HOME` | where Gradle reads init scripts and properties, which run code |
| Start-up, PHP and Lua | `PHPRC`, `PHP_INI_SCAN_DIR` | where PHP reads its configuration, whose `auto_prepend_file` runs code |
| Start-up, PHP and Lua | `LUA_INIT` | code Lua runs at start |
| Start-up, .NET | `DOTNET_STARTUP_HOOKS` | assemblies .NET runs before `Main` |
| Start-up, .NET | `CORECLR_*` | `CORECLR_ENABLE_PROFILING` with `CORECLR_PROFILER_PATH` loads a native profiler |
| Start-up, Erlang | `ERL_AFLAGS`, `ERL_ZFLAGS`, `ERL_FLAGS` | flags for every `erl`, `-eval` included |
| Start-up, Erlang | `ERL_LIBS` | where Erlang finds applications |
| Start-up, Erlang | `ELIXIR_ERL_OPTIONS` | `erl` flags for every Elixir program, `-eval` included |
| Start-up, build tools | `GOFLAGS` | `-toolexec` runs a program for every step of a Go build |
| Start-up, build tools | `GOENV` | a Go environment file, which can set `GOFLAGS` |
| Start-up, build tools | `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER` | Cargo runs it in place of the compiler |
| Start-up, build tools | `CARGO_TARGET_*_RUNNER` | Cargo runs it to start every program and test it builds |
| Start-up, build tools | `CARGO_TARGET_*_LINKER` | Cargo runs it to link |
| Start-up, build tools | `CC`, `CXX` | the compiler make, cgo and build scripts start |
| Start-up, build tools | `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS` | compiler and linker flags, which can load plugins and specs |
| Start-up, build tools | `MAKEFLAGS`, `GNUMAKEFLAGS` | options and variable assignments for every make, `SHELL` among them |
| Start-up, build tools | `MAKEFILES` | makefiles make reads before any other |
| Start-up, build tools | `CMAKE_*_COMPILER_LAUNCHER` | a program CMake runs in front of every compiler |
| Start-up, build tools | `RUSTC`, `RUSTDOC`, `CARGO_BUILD_RUSTC` | the compiler and documentation tool Cargo runs |
| Start-up, build tools | `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS` | compiler flags, `-C linker=` among them, which runs a program |
| Start-up, build tools | `RUSTUP_*` | which toolchain rustup runs, where it downloads toolchains and itself from, and where it keeps them |
| Start-up, build tools | `CGO_*FLAGS` | flags cgo passes to the C compiler and linker as given, `CGO_CFLAGS`, `CGO_CPPFLAGS`, `CGO_CXXFLAGS`, `CGO_FFLAGS` and `CGO_LDFLAGS` among them |
| Start-up, build tools | `CARGO_HOME` | where Cargo reads its configuration, which can set runners and wrappers |
| Start-up, build tools | `CARGO_REGISTRY_CREDENTIAL_PROVIDER` | a program Cargo runs for registry credentials |
| Start-up, build tools | `GOTOOLCHAIN` | another Go toolchain the `go` command downloads and runs |
| Start-up, build tools | `GOROOT` | which Go installation, compiler and standard library the `go` command uses |
| Start-up, build tools | `MAVEN_OPTS`, `GRADLE_OPTS` | JVM options for the build, `-javaagent` included |
| Shell | `BASH_ENV` | a file bash runs at the start of every non-interactive shell |
| Shell | `ENV` | the same for an interactive POSIX shell |
| Shell | `PROMPT_COMMAND` | a command bash runs before each prompt |
| Shell | `SHELLOPTS` | bash takes its options from it; `xtrace` with `PS4` runs commands |
| Shell | `BASHOPTS` | bash takes its `shopt` options from it |
| Shell | `IFS` | word splitting in a shell that inherits it |
| Shell | `PS4` | expanded, command substitutions included, on every traced line |
| Shell | `BASH_FUNC_*` | bash imports exported functions from it, which can replace any command |
| Shell | `CDPATH` | moves a script's relative `cd` elsewhere |
| Shell | `ZDOTDIR` | zsh reads its start-up files, `.zshenv` first, from it |
| Programs others start | `EDITOR`, `VISUAL` | git, crontab and others start it to edit a file |
| Programs others start | `PAGER`, `MANPAGER` | started to page output |
| Programs others start | `LESSOPEN`, `LESSCLOSE` | `less` runs them on every file it opens and closes |
| Programs others start | `BROWSER` | started to open a URL |
| Programs others start | `SSH_ASKPASS` | ssh runs it to read a passphrase |
| Programs others start | `SUDO_ASKPASS` | sudo runs it with `-A` |
| Git and SSH | `GIT_*`, except the six author and committer names above | `GIT_SSH_COMMAND`, `GIT_EXEC_PATH`, `GIT_ASKPASS` and `GIT_CONFIG_*` start programs or change configuration, and `GIT_SSL_CAINFO` the trust |
| Git and SSH | `SSH_AUTH_SOCK` | points ssh and git at an agent holding keys |
| Docker | `DOCKER_*` | `DOCKER_HOST` and `DOCKER_CONFIG` choose the daemon and its credentials; the wall sets `DOCKER_CONFIG` for a Docker of the agent's own |
| Routing and trust | `*_PROXY` | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `FTP_PROXY`: the runner sets the proxy variables (§Sequence step 5), and any other routes around them |
| Routing and trust | `SSL_CERT_FILE`, `SSL_CERT_DIR` | the trust store of OpenSSL and of Go; the wall points them at the run's bundle (§The wall) |
| Routing and trust | `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE` | the trust of curl, Python Requests, Node and the AWS SDKs, which the wall sets the same way |
| Routing and trust | `NODE_TLS_REJECT_UNAUTHORIZED` | `0` turns off certificate checks in Node |
| Routing and trust | `GODEBUG` | its settings turn insecure TLS and X.509 behaviour back on in every Go program |
| Routing and trust | `PYTHONHTTPSVERIFY` | `0` turns off certificate checks in Python builds that honour it (PEP 493) |
| Routing and trust | `CARGO_HTTP_CAINFO` | Cargo's trust |
| Routing and trust | `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` | gRPC's trust |
| Routing and trust | `GOSUMDB`, `GONOSUMDB`, `GOPRIVATE`, `GOINSECURE` | they turn off or move the checksum database that verifies every Go module, or allow insecure fetches |
| Routing and trust | `OPENSSL_CONF` | an OpenSSL configuration, which can load engines and providers and change trust |
| Routing and trust | `OPENSSL_ENGINES`, `OPENSSL_MODULES` | where OpenSSL loads engines and providers from |
| Routing and trust | `CURL_HOME` | where curl reads `.curlrc`, which can set a proxy or turn off verification |
| Routing and trust | `WGETRC` | the same for wget |
| Routing and trust | `HOSTALIASES` | a file of host aliases the glibc resolver reads |
| Routing and trust | `RES_OPTIONS`, `LOCALDOMAIN` | resolver options and search domains, which change where a short name leads |
| Cloud configuration | `KUBECONFIG` | a kubeconfig, whose `exec` entries start credential programs and whose clusters receive credentials |
| Cloud configuration | `AWS_CONFIG_FILE` | an AWS configuration, whose `credential_process` starts a program |
| Cloud configuration | `AWS_SHARED_CREDENTIALS_FILE` | which credentials AWS tools send |
| Cloud configuration | `AWS_ENDPOINT_URL*` | where AWS tools send requests, and their credentials |
| Cloud configuration | `GOOGLE_APPLICATION_CREDENTIALS` | which credential file Google's libraries read, whose external-account source can start a program |
| Cloud configuration | `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES` | lets such a credential file start its program |
| Cloud configuration | `CLOUDSDK_CONFIG` | where `gcloud` reads its configuration and credentials |
| Cloud configuration | `TF_CLI_CONFIG_FILE` | Terraform's configuration, with its credential helpers and provider sources |
| Cloud configuration | `HGRCPATH` | Mercurial's configuration, whose hooks run commands |
| Package managers | `npm_config_node_options` | Node options for the scripts npm runs |
| Package managers | `npm_config_script_shell`, `npm_config_shell` | the shell npm runs scripts and commands with |
| Package managers | `npm_config_git` | the `git` program npm runs |
| Package managers | `YARN_YARN_PATH` | a file of JavaScript Yarn runs in place of itself |
| Package managers | `YARN_RC_FILENAME` | which Yarn configuration file is read |
| Package managers | `npm_config_userconfig`, `npm_config_globalconfig` | which npm configuration file is read, and it can set every other npm setting |
| Package managers | `npm_config_strict_ssl`, `npm_config_cafile`, `npm_config_ca` | npm's trust |
| Package managers | `PIP_CONFIG_FILE` | which pip configuration file is read |
| Package managers | `PIP_CERT` | pip's trust store |
| Package managers | `PIP_TRUSTED_HOST` | hosts pip reaches without verifying their certificates |
| Package managers | `UV_INSECURE_HOST` | hosts uv reaches without verifying their certificates |
| Package managers | `HEX_UNSAFE_HTTPS`, `HEX_CACERTS_PATH` | Hex's certificate checks and its trust store |
| Package managers | `HEX_UNSAFE_REGISTRY`, `HEX_NO_VERIFY_REPO_ORIGIN` | Hex's checks of the registry's signature and origin |
| Package managers | `BUNDLE_SSL_VERIFY_MODE`, `BUNDLE_SSL_CA_CERT` | Bundler's certificate checks and its trust |
| Package managers | `YARN_ENABLE_STRICT_SSL`, `YARN_HTTPS_CA_FILE_PATH` | Yarn's certificate checks and its trust |
| Package managers | `npm_config_noproxy` | hosts npm reaches around the proxy; `npm_config_proxy` and `npm_config_https_proxy` already match `*_PROXY` |
| Routing and trust | every name `Docker.CAEnv` sets | the machine's own names for the run's bundle |
| Identity and lookup | `PATH` | which program a name starts; the enclosure resolves the launch's program through it (§Images) |
| Identity and lookup | `HOME` | where programs read their configuration: `.bashrc`, `.gitconfig`, `.npmrc` |
| Identity and lookup | `SHELL` | the shell programs start for a command |
| Identity and lookup | `USER`, `LOGNAME` | who programs take the user to be |
| Identity and lookup | `TMPDIR` | where programs write temporary files, scripts among them |
| Identity and lookup | `XDG_*` | where programs read configuration and data and keep runtime files |
| Reserved, for completeness | `QORY_*` | the runner's own, `QORY_ACCESS_KEY_SECRET` included |
| Reserved, for completeness | the run's runtime's `declares` and `reserves` | the stand-in or an empty value goes there (Runtimes) |
| Runtime | the run's runtime's `denies` | names that move the runtime's model credential or run its commands (Runtimes) |

`MALLOC_*` is left off the list: it changes glibc's allocator checks and loads no code.
Package-manager settings that only choose a mirror, such as `PIP_INDEX_URL`,
`npm_config_registry` or `GOPROXY`, stay allowed: a team sets them for a mirror, and the
egress policy bounds where they lead. `GOPROXY` stays allowed only because `GOSUMDB`,
`GONOSUMDB`, `GOPRIVATE` and `GOINSECURE` are denied: the `go` command then checks every
module a server-chosen proxy serves against the public checksum database. Settings that
run a program, load a configuration file or change trust are denied, as the table lists.
A machine's owner extends the list with `variables.deny` for any name it lacks.

**Also left out, the same way:** a server variable with the name of a placeholder of this
run, a declaration's `name` or an integration's, where the placeholder wins; and one a
`secrets.local` value reads (`env:`), whose machine value stays outside the enclosure.
A denied or reserved name wins over a lock: the variable is left out and reported.

**The machine's own environment** keeps three refusals, because they keep the machine's
secrets and the stand-ins out of the enclosure. A run whose environment passes a `QORY_`
variable, or a variable a `secrets.local` value reads, into the enclosure is no run,
`variable_reserved`. `QORY_RUN_ID` and `QORY_RUN_SOCKET`, which the runner itself sets for
the session, are exempt. One whose environment contains a variable the run's runtime
declares or reserves is `runtime_secret_conflict` (Runtimes). One that passes a value for
a placeholder is `placeholder_conflict`.

### 2. Names, value ids and identity

- **Identity is the id.** A stored value is selected by its secret's `sec_` id and, for a
  secret with several values, its value id. A machine value is selected by its name and
  value id in `secrets.local`.
- **The name is in the document.** A reference contains the secret's name for display, so
  renaming a secret changes every rendering that links it and gives it a new digest; a
  run already started keeps what it received.
- **Names** are variable-style, `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, for secrets, variables
  and an external reference's lookup key, `secrets.local` names included. A server
  refuses on save, within a workspace, two secrets whose names differ only in case, and,
  at the level being saved, two variables in one chain of levels whose names differ only
  in case.
- **No duplicates.** Two connections with one `id`, or two runtime connections for one
  runtime name, is no run: `connection_duplicate`, `runtime_connection_duplicate`. The
  run configuration is decoded with `encoding/json/v2`, which refuses a member name twice
  in one object, before the schema validates it: `run_configuration_invalid`, `variables`
  included.
- **One value, sealed once.** A value that two connections reference is sealed once and
  set wherever the connections route it.
- **Empty lists.** An empty `connections` is the server's whole set, no connection, and
  keeps the runner file's out; a server that leaves the machine's connections in force
  omits the member. A server omits an empty `variables`; a runner reads an empty one as
  absent.

### 3. Expiry, clock skew, reload

- **Expiry.** The server sets `exp` to its own time plus 600 seconds. The runner opens the
  payload while its clock is at most `exp + 300`, and refuses an `exp` more than 900
  seconds ahead of its clock: `secret_sealed_expired`. The 300 seconds are the window a
  signed GET already allows. Expiry applies to opening only: the values serve the run for
  its whole life.
- **`exp` is canonical.** A JSON integer, no sign, no leading zero, below 2^53, with no
  fraction or exponent; the runner renders the parsed integer in decimal again for `aad`.
- **Request freshness.** The secrets request contains a `timestamp` the server accepts
  within ±300 seconds.
- **Resealing.** The server records the first payload it seals for an access key and a run
  id, with its digest, its set of connections and the key the request verified under. It
  seals again for that pair only with the same digest, set and key (else `409`
  `run_secrets_conflict`), and
  only until the first payload's `exp` (else `409` `run_secrets_expired`). A run whose row
  the server has already closed receives nothing: `410` `run_closed`.
- **A new run id per attempt.** A caller mints a new run id for every attempt to start a
  run, so each attempt has a reseal window of its own.
- **Superseded run configurations.** The server keeps every rendering. It seals for the
  holder's current one, or for one superseded at most 15 minutes ago, and for an older one
  no longer: `410` `run_configuration_superseded`. From a superseded rendering it seals a
  pair only when every listed connection that references it is identical in the holder's
  current rendering, so removing a link or moving a host takes effect at once.
  "Identical" means the connection's bytes as the server rendered it, in the rendering's
  canonical form, hosts and secret references included, are equal. A cosmetic edit, such
  as renaming the secret or the connection, therefore makes a run inside the 15 minutes
  `secret_unresolved`. A holder has two renderings at a time, one per variant
  (Decision 6), and these rules apply to each.
- **Reload.** The runner reads `connections` and `variables` from the run-start fetch
  only. A reload's document may contain them, changed or not, or omit them; the runner
  ignores them either way, and each further `dev.qory.run.policy_applied` repeats the
  start's connections with `hosts_denied` recomputed for the policy now in force. A
  change in the server applies from the next run. To cut a running run off a host, the
  server reloads a policy that denies it: the proxy refuses new requests there, closes the
  open connections to it and records each (§The server, Reload, rules 1 and 2). To cut a
  run off entirely: reload with a `deny`, then revoke the access key. An integration's
  credential keeps renewing.
- **Discovery during a run.** A discovery document that starts listing `secrets` while a
  run goes on takes effect at the next run.
- **A reload is only as strong as its delivery.** A middlebox that drops answers keeps the
  run on the policy it has. "No run, never a weaker run" applies at the start; during a
  run, the policy in force stays until a signed answer replaces it.

### 4. Access keys and machines

**The access key is the credential.** A machine is an instance that runs with it. An
access key's *keys* are the Ed25519 key pairs it holds over time, current, pending and
old; "its key" or "a public key" means one of them. `key_invalid` is about such a key;
a revoked access key gets `401`.

- **One secret per access key.** An access key's current key signs every request the
  runner sends, and the same key, converted to X25519, opens what the server seals to
  it. The server stores only public keys. The access key id, `ak_` and 16 lower-case
  Crockford base32 characters, is assigned by the server when the access key enrols and
  is sent on every request. The access key is enrolled, approved and rotated once, and a
  fleet may share it: ten ephemeral instances on one access key are one access key.
- **One server per secret.** `qory` keeps one secret per server: it enrols an existing
  secret only with the server whose `url` the runner file names beside it, and moves it
  aside before it enrols with another. The reason is hygiene: a compromise of one
  server's records then involves no key another server trusts. This is a `qory` rule
  and a known limit, not a cryptographic guarantee: a public key pasted into two servers
  is outside `qory`'s reach (Security considerations).
- **On the key row.** Approval, the stored-secrets flag, the workspace, the rate limits,
  rotation and the integrity code all belong to the access key's row, and seals bind to
  the access key. Every change to its keys, approvals, rejections, re-keys, rotations and
  the flag, takes the row's lock, so they happen one at a time. Revoking the access key
  cuts off every machine that uses it and ends its outstanding re-key codes. Deleting an
  access key, or the workspace or organisation that holds it, revokes it first, so every
  key it holds becomes a tombstone.
- **A machine is an instance.** The runner reports a machine id as a signed line of every
  request, for display, audit and per-instance events. Authorisation rests on the access
  key alone: the seal, the variant and the rate bucket are per access key, and anyone who
  holds the access key can claim any machine id.
  - The id matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. `qory` generates `m_` and 16
    random bytes in base64url, 24 characters, and keeps it in the file `machine-id` in
    the runner file's directory, two lines: the id and HMAC-SHA256, keyed with the
    constant `qory machine-id v1`, of the machine's identity, `/etc/machine-id` on Linux,
    `IOPlatformUUID` on macOS, else the host name, as machine-id(5) recommends.
    When the directory is read-only the id lives for the process, which suits an
    ephemeral instance. Before the first request `qory` reads the file and generates a
    new id when the file's id fails the pattern or the identity's hash differs, which
    catches a file copied with a home directory. An image that keeps `/etc/machine-id`
    gives its instances one id; most image builds reset that file. The runner module
    takes the id through `session.Spec`.
  - The display name is `machine.name` in `runner.yaml`, under enrolment's name pattern,
    `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and defaults to the host name, or its first
    label when the host name does not fit. `qory` refuses a configured name outside the
    pattern at start. The runner sends it in `X-Qory-Machine-Name` on every request,
    unsigned and for display alone. The server accepts a request whatever its name
    header: it ignores a name outside the pattern, an absent one or one sent twice, and
    the record keeps its last valid name. A new name for the same id replaces the stored
    one, and the Machines page always shows the id beside the name.
  - The server records a machine id once the request verifies and the id matches its
    pattern, whatever the answer, so instances of a pending access key are listed too. A
    known id always updates its record. The server creates at most 256 new records per
    access key in any rolling 24 hours; the number is the server's, and the runner
    cannot observe it. Past the bound the server answers as before, so a fleet keeps
    running, and counts requests from unrecorded ids as a plain number on the access
    key, outside its integrity code, since that is display data. A record unseen for a
    period the server sets may expire.
  - Events and runs keep the machine id as a plain string, whether or not a record
    exists. A delivery keeps the machine id its POST's signed line carried, as sent; for
    a delivery id already stored, the first accepted stays, since a resend is
    deduplicated.
  - The server's live Machines page shows each machine of an access key: when it was
    last seen, its runs and its events. Heartbeats arrive during runs only. A machine is
    running until it misses two heartbeats in a row, that is, until no
    `dev.qory.run.heartbeat` has arrived for 3 × `interval_seconds`; then the server knows
    when it was last seen, and an idle machine looks like one
    that is switched off.
  - The server ignores machine headers at enrolment and re-keying, which no access key
    signs.
- **Names.** A name ending in `_SECRET` is kept hidden; one ending in `_PUBLIC_KEY` or
  `_ID` is safe to show. `QORY_ACCESS_KEY_ID` is the access key id,
  `QORY_ACCESS_KEY_SECRET` the access key's only secret, and `QORY_APIARY_PUBLIC_KEY` the
  pin of the server's key (Decision 6). Apiary's server has `APIARY_ENCRYPTION_SECRET`,
  the instance key, `APIARY_SIGNING_SECRET`, its signing key, and
  `APIARY_NEXT_SIGNING_SECRET` during a rotation of it. Third-party names, such as
  `ANTHROPIC_API_KEY`, keep their names.
- **The secret.** One line: `qak_` and the 32-byte Ed25519 seed in base64url without
  padding, 47 characters. The prefix lets secret scanners recognise it. `qory` generates
  the seed from the system's random source and reads the secret from a file descriptor
  it is given, else from `QORY_ACCESS_KEY_SECRET`, else from the file `access-key-secret`
  in the runner file's directory, `$XDG_CONFIG_HOME/qory`, else `~/.config/qory`. The
  variable wins over the file.
- **The runner file's directory** holds everything `qory` keeps for the server: the runner
  file, `access-key-secret` and `access-key-secret.next`, `machine-id`, the
  `stored-secrets` marker, `enrolment-pending` and `rekey-pending`, the pinned labels
  under `labels/` and the lock files under `locks/`. It is mode `0700`, and every walled
  run refuses a mount of it (below).
- **The files.** `qory` creates `access-key-secret` and `access-key-secret.next` with
  `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, under the key lock, and refuses a file whose
  mode grants anything to the group or to others, a file or directory owned by another
  user than the effective one, and the published fixture secret (Decision 5). A file it
  moves aside gets a name with the time, such as `access-key-secret.old.1700000000`,
  under a name no existing file has. Keeping the secret in the system's keychain is a
  later option.
- **On a CI machine** the secret comes from the CI's secret store, through
  `QORY_ACCESS_KEY_SECRET` or a file descriptor, and `qory` writes no secret file.
  `QORY_ACCESS_KEY_ID` and `QORY_APIARY_PUBLIC_KEY` are plain settings of the CI; only the
  secret goes to its secret store. The variables are reserved (`QORY_`) and stay with
  `qory`: once it has read them, it removes them from its own environment, so the run's
  processes start without them.
- **The runner module keeps everything in memory; `qory` owns the files.** The module
  takes the secret and the machine id through `session.Spec`.
- **Locks.** Every command that generates a key, `enrol`, `create`, `rekey` and `rotate`,
  takes `locks/key.lock` exclusively with `flock`. A run takes `locks/key.lock` shared,
  creates its own lock file `locks/<run id>.lock`, naming whether it is walled, holds
  that file with `flock` for its life, and then drops the key lock; so a key command
  waits for starting runs, and starting runs wait for it. A key command refuses while
  any unwalled run's lock file is held, and says to stop those sessions first. A lock
  file whose `flock` can be taken belongs to a run that has ended, and is removed.
- **The marker and key commands.** Every key command that keeps its key on this machine
  writes the `stored-secrets` marker before it generates the key, unconditionally, and a
  marker it cannot write means no key. `qory` removes the marker only on a signed answer
  that shows this machine's access key has no stored secrets: discovery without
  `secrets`, or an enrolment or re-key answer with `stored_secrets: false`. With
  `--print`, a key command takes the key lock and refuses while an unwalled run is live,
  and leaves the marker as it is: the printed key is kept elsewhere, and the answer's
  `stored_secrets` describes that holder's access key. Deleting the file by hand also
  restores unwalled runs.
- **The key pair.** Everything comes from the seed:
  - the Ed25519 public key A, as RFC 8032 derives it;
  - the X25519 private key, the clamped first 32 bytes of SHA-512(seed), the same scalar
    Ed25519 signs with. Go's `crypto/ecdh` `X25519().NewPrivateKey` accepts those bytes
    and clamps them itself;
  - the X25519 public key, the Montgomery u-coordinate of A: u = (1 + y) / (1 − y) mod
    2^255 − 19, where y is A's y-coordinate. The runner computes it from its private
    key. The server converts A with integer arithmetic: `filippo.io/edwards25519`
    `Point.BytesMontgomery` in Go, a few lines of big-integer code in Elixir.

  The HPKE suite is unchanged: X25519, HKDF-SHA256, AES-256-GCM (Decision 5).
- **Why one key is sound.** Ed25519 signing and an X25519-based KEM under one key pair
  are proven jointly secure (Thormarker, "On using the same key pair for Ed25519 and an
  X25519 based KEM", IACR ePrint 2021/509), and age converts ssh-ed25519 recipients the
  same way. Signatures and HPKE use distinct domain strings: every message a key signs
  starts with a line of its own, `qory-request-ed25519-v1`, `qory-enrol-ed25519-v1`,
  `qory-rekey-ed25519-v1` or `qory-rotate-ed25519-v1`, and HPKE derives its keys under
  its own labels. Two costs: the signing key and the opening key rotate together, and a
  hardware key store that keeps the scalar to itself cannot open envelopes, which
  matters when keychain storage comes. A post-quantum KEM key, later, is derived from the
  same seed with HKDF-SHA256 under a label of its own, so the access key keeps one
  secret.
- **Codes.** An owner or administrator creates a code in Settings › Access keys. A code
  is single use, valid for at most 15 minutes, and of one kind, visible in its prefix:
  `qec_` to enrol a new access key, bound to a workspace and to the access key's
  settings, or `qrk_` to re-key an existing one, bound to that access key's id, which the
  page shows beside the code. Both have the same body, 26 Crockford base32 characters,
  then `.` and the fingerprint of the server's public key; during a rotation of the
  server's key, `.` and the next key's fingerprint follow (Decision 6). The server keeps
  only a code's SHA-256, its kind and, for a re-key code, the access key id; with 130
  random bits a fast hash is enough. It accepts a code only when its first fingerprint is
  its current signing key's and a second, when present, its next key's, so a change of
  the server's key ends every outstanding code by itself; revoking or deleting the access
  key ends its re-key codes, and an owner or administrator can cancel an outstanding
  code on the Access keys page. A used code passes again for a retry with the same
  public key for 15 minutes after its first use. When a code is used or expired, `qory`
  says so plainly: "this code was used or has expired; if you did not use it, tell your
  administrator, who must reject the pending key".
- **An existing pin.** When the machine has a pin and none of a code's fingerprints is in
  it, `qory access-key enrol` and `rekey` refuse before they generate a key: the code is
  from another server, or the pin is out of date, and the operator updates the pin out
  of band. `qory` writes a pin from an answer only where none exists.
- **Enrolment** gives an access key its id, in one of two ways.
  - (a) **An enrolment code.** On the machine, `qory access-key enrol <server> <code>`
    takes the key lock, writes the marker, generates the secret, keeps it as above,
    records the code's SHA-256 and the time in `enrolment-pending`, prints the key's
    fingerprint, and posts the enrolment request (Wire format): the public key, a name
    for the access key, a timestamp, the code, and a proof of possession, an Ed25519
    signature under the new key.
    - A retry uses the existing secret only with the same code: while `enrolment-pending`
      holds that code's hash and is younger than 15 minutes. With any other code, or
      later, `qory` moves the secret aside and generates a fresh one, so a key the flag
      makes eligible is always fresh. A `401` to a retry means the code was used or has
      expired; a `409` `key_invalid` means the key was refused. Either way `qory` moves
      the secret aside and asks for a new code. An `access-key-secret.next` left from
      earlier is moved aside too.
    - The answer is signed with the server's key; `qory` verifies it against the listed
      key whose fingerprint the code carries first, and pins only the keys whose
      fingerprints the code carries, writing `access_key_id` and `apiary_public_key` into
      `runner.yaml`'s `server` section, and removes `enrolment-pending`. The answer
      contains the access key id, `approved`, `stored_secrets` and the server's keys;
      `stored_secrets: false` removes the marker.
    - The access key awaits approval, and an owner or administrator compares the
      fingerprint `qory` printed with the one Settings › Access keys shows, and sees the
      settings the access key will get, before approving it.
    - `qory access-key enrol --print` writes no file, the marker included, and prints
      `QORY_ACCESS_KEY_ID`, `QORY_ACCESS_KEY_SECRET` and `QORY_APIARY_PUBLIC_KEY` for a
      CI's settings.
  - (b) **A pasted key.** `qory access-key create` takes the key lock, writes the marker,
    generates the secret, keeps it as above, and prints the public key and its
    fingerprint; with `--print` it writes no file and prints `QORY_ACCESS_KEY_SECRET` as
    well. An owner or administrator adds the access key in Settings › Access keys by
    pasting the public key, with its settings, and it is approved at once, since an
    administrator entered the key. The page then shows `QORY_ACCESS_KEY_ID` and the pin,
    which the machine sets in `runner.yaml` or its environment. A pasted key the server
    refuses gets one message, "this key cannot be used", whatever the reason, so a paste
    tells nothing about other access keys.

  A fingerprint is `base64url(SHA-256(raw public key)[:16])`, 22 characters, for an
  access key's key and the server's alike.
- **One public key, one access key.** A public key serves one access key, ever. The
  server keeps a global unique index over every access key's current key, pending key,
  old key in its window and every tombstone, checks it at enrolment, re-key, paste and
  rotation, and keeps it beyond the deletion of a workspace. A key already in the index,
  held by any access key or a tombstone, is `409` `key_invalid`, the same answer as an
  invalid key, so a refusal reveals nothing about other access keys. An enrolment or
  re-key retry is exempt for its own row.
- **What the server checks.** At enrolment, re-key and rotation it verifies the proof of
  possession first, so a key's status is told only to whoever holds its private key.
  Then it checks every public key it is given, the pasted key included:
  - a canonical encoding: decode, re-encode and compare the bytes, since a lenient
    decoder such as `filippo.io/edwards25519` `SetBytes` accepts non-canonical encodings;
  - a point on the curve;
  - not of small order: [8]A is not the identity;
  - of prime order: [ℓ]A is the identity, where ℓ is the order of the base point;
  - y ≠ 1, so u is defined (y = 1 is the identity, of small order already; the check
    stays explicit because the conversion divides by 1 − y).

  Anything else is `409` `key_invalid`, the published fixture key included. The checks
  run on every path because a proof of possession proves nothing for a key of small
  order: OpenSSL accepts the identity key with R = identity and S = 0, and the order-4
  key y = 0 with an all-zero signature, for any message. Nor does a proof replace the
  prime-order check: whoever knows a key's scalar can make a valid proof for that key
  plus a torsion point in about one try in eight, since cofactorless verification then
  accepts whenever 8 divides the challenge.
- **Tombstones.** A tombstone holds a public key, its access key id and when the key was
  retired: by revocation, by rotation, by the rejection of a pending key, or by deletion,
  which revokes first. It outlives the deletion of its workspace and organisation: that
  public key and that access key id stay retired for good, and a rejected key stays
  refused wherever it is posted again.
- **Approval.** Every access key needs approval, and every new key of it needs approval
  before it is used. A new access key that awaits approval receives only `key_pending`, on
  every signed endpoint, discovery included, and `401` at `access_key.url`: its run
  configuration, variables, stored values and events wait for approval. Settings › Access
  keys refuses to enable stored secrets on an access key that awaits approval: the
  administrator approves or rejects it first. A pending key beside an approved current
  key, from a rotation or a re-key, is answered `401` everywhere until it is approved. An
  access key enrolled with a code awaits approval; a pasted key is approved as it is
  entered. Approval applies under every setting of the server. An access key has at most
  one pending key at a time, and Settings › Access keys shows how it arrived: by
  enrolment, by a rotation signed under which key, or by which re-key code, created by
  whom and when, used when and from which address.
- **Key settings.** What the server sets per key row: whether the access key may receive
  stored secrets, off by default and enabled only by owners and administrators, with
  the sequence number of its last enabling; its rate limits; and its workspace. In 0.7.0
  an access key belongs to exactly one workspace in every edition, and a fleet that
  serves several workspaces holds one access key per workspace. Discovery is per access
  key and lists `secrets` only for one allowed stored secrets. A developer's own access
  key keeps unwalled runs; a CI or shared one receives stored secrets and runs walled.
- **Eligibility.** Stored values open only with an eligible key: one the server received
  after the access key's stored-secrets flag was last enabled. A secret an earlier
  unwalled agent read therefore unlocks none.
  - Order comes from a sequence the server keeps per access key and advances under the
    row's lock: every key received, every re-key code created and every enabling of the
    flag takes the next number, these being what eligibility reads, and wall-clock time
    plays no part. When a new access key is
    created with the flag, the flag's number precedes its key's. Enabling the flag also
    rejects any pending key, which becomes a tombstone.
  - While the flag is set, the secrets request and a rotation signed by a key received
    before its last enabling are `409` `key_rotation_required`, whatever other keys the
    access key holds; such a key stays ineligible through the old key's window, and the seal
    goes only to an eligible key. Discovery under such a key, the old key of a window
    included, lists `key_rotation_required: true`.
  - `qory` then says, from discovery's `current_key` and `pending_key`, one of three
    messages: "re-key with a code" when its key is the current one and none is pending;
    "a new key awaits approval" when one is; "this key was replaced; use the access
    key's new secret" when its key is an old one.
  - A key enrolled or pasted while the flag is set is received after it. The server
    cannot know when a pasted key was generated, so the owner pastes a key
    `qory access-key create` generated for that purpose.
  - The variant follows the flag alone, by intent. An access key with the flag and no
    eligible key receives the full rendering and is refused at the secrets request,
    `key_rotation_required`, which discovery has already announced, so the failure is
    explicit rather than a run quietly missing its connections.
- **Re-key.** `qory access-key rekey <code>`, with the options `--print`,
  `--server <url>` and `--access-key-id <id>`, brings a new key with an administrator's
  code. The server and the access key id come from the flags, else from `runner.yaml`
  and `QORY_ACCESS_KEY_ID`, so it works when the runner file is lost too. It takes the
  key lock, writes the marker, generates a new secret, writes it to
  `access-key-secret.next` when a current secret exists, else to `access-key-secret`,
  records the code's SHA-256 and the time in `rekey-pending`, prints its fingerprint,
  and posts the new public key with the code and a proof of possession by the new key
  (Wire format). The request is authenticated by the code and the new key's proof, so it
  works when the old secret is lost.
  - A second `rekey` with the same code within 15 minutes reuses the pending secret and
    re-posts it; its answer is the same `202`, and `qory` reports that the key awaits
    approval. With a different code it moves the earlier `.next` aside under a name with
    the time and generates a fresh key.
  - While its new key is pending, a machine sees `401` under that key, so `qory` keeps
    using the current key, and its message says which key is pending.
  - A re-key code is valid whether or not the access key has the flag: it is the
    administrator's alternative to a self-signed rotation, and the recovery path for a
    lost secret, so the access key keeps its id. The access key id is public, so a
    stolen re-key code works for anyone; approval after comparing the fingerprint is the
    control, and the page shows how the pending key arrived.
  - The answer carries `approved`, `stored_secrets` and the server's keys, as
    enrolment's does; `approved` says whether the posted key is the access key's current
    key. `qory` verifies it under the listed key whose fingerprint the code carries
    first, pins only the keys whose fingerprints the code carries, writing the pin only
    where none exists, and removes the marker on `stored_secrets: false`.
  - The new key arrives pending, and an owner or administrator approves it after
    comparing the fingerprint `qory` printed. A re-key while another key is pending is
    `409` `key_rotation_pending`. The administrator's order for a re-key while a key is
    pending: create the re-key code first, which blocks self-signed rotation, then reject
    the pending key, then run `rekey`.
  - On approval the old key enters the usual 24-hour window. For a lost or compromised
    secret the administrator ends the window at once, which retires the old key
    immediately.
  - With `--print`, `qory` writes no file, the marker included, and prints
    `QORY_ACCESS_KEY_SECRET`,
    `QORY_ACCESS_KEY_ID` and `QORY_APIARY_PUBLIC_KEY` for a fleet's settings (Rotation of
    a shared key). With the secret held in `QORY_ACCESS_KEY_SECRET` or a file
    descriptor, `rekey` and `rotate` run only with `--print`.
- **Rotation.** A planned rotation is the operator's: `qory access-key rotate` takes the
  key lock, writes the marker, generates a new secret, writes it to
  `access-key-secret.next`, prints the new key's fingerprint, and posts the new public
  key with a proof of possession by the new key, signed under the current secret, which
  must be an eligible key (Wire format). The new key needs approval, given after
  comparing that fingerprint with the one Settings › Access keys shows; until then the
  current key keeps working.
  - Only the current key may rotate: the old key of an open window and the pending key
    each get `401` there. While a re-key code for the access key is outstanding, or a
    new key awaits approval, a rotation is `409` `key_rotation_pending`; a repeat of the
    pending key's own request is answered as the first was. A rotation that posts a key
    already in the index, this access key's or another's, is `key_invalid`. An owner or
    administrator can reject a pending key without revoking the access key, and a
    rejected key becomes a tombstone.
  - On approval the old key stays valid for a fixed window of 24 hours, whatever the
    machines do, and then becomes a tombstone. An owner or administrator can end the
    window early in Settings › Access keys, for example once a CI's secret store holds
    the new secret. An access key has at most one old key: approving a new key ends any
    window still open, and that old key becomes a tombstone. The access key id stays.
  - Before each run while `access-key-secret.next` exists, `qory` reads discovery signed
    under the current secret: when `current_key` is the new key's fingerprint, the key
    is approved, and `qory` moves `access-key-secret.next` over `access-key-secret`; when
    `pending_key` is, it awaits approval, and the run uses the current secret; when
    neither is, the key was rejected or retired, and `qory` moves `.next` aside under a
    name with the time and says to rotate afresh, or, for a key a re-key brought, to ask
    for a new re-key code. When the current secret gets `401`, such as after its window
    ended, `qory` reads discovery under the new key instead: a signed `200` whose
    `current_key` is the new key's fingerprint approves it, and one that names another
    key means the new key was approved and since replaced, which `qory` promotes and
    reports. On any unsigned answer `qory` leaves both files and reports.
  - A key a fleet shares, or one held in `QORY_ACCESS_KEY_SECRET`, is rotated by its
    operator with `--print`, and the 24-hour window covers the whole fleet.
  - A planned rotation therefore keeps every run working: every run or job started
    under the old key finishes within the window. Three cases are left: a run longer
    than 24 hours that began before the approval; for a shared key, a run that starts
    under the old key close to the window's end, which the end cuts off; and, after a
    re-key the flag forced, every run that needs stored values on an instance still on
    the old key, which gets `key_rotation_required` until it has the new secret.
    Revocation, the action for a compromised key, is immediate and separate.
- **Rotation or re-key of a shared key.** The operator runs
  `qory access-key rotate --print` with the current secret, or
  `qory access-key rekey --print` with a code,
  which posts the new key, writes no file and prints the new `QORY_ACCESS_KEY_SECRET`;
  approves the new key in Settings › Access keys; within 24 hours, puts the new secret
  in the fleet's secret store; then, optionally, ends the window. Instances sign with the
  old key until the store changes and with the new one after, and both keys verify
  throughout the window, so runs keep working. The order matters: an instance that signs
  with the new key before its approval is refused, `401`.
- **Revocation.** An owner or administrator revokes an access key in Settings › Access
  keys. Its requests then fail verification, `401`, from every machine that uses it, so
  the server seals nothing to it, and the runner reports the `401` as `unauthorized`.
  Its keys become tombstones, and its outstanding re-key codes end.
- **Unused keys.** The server may revoke an access key unused for a period it sets; its
  operator then enrols a new access key, which gets a new id.
- **What it protects, plainly.** The server stores public keys only, so a reader of its
  database cannot act as an access key; a writer could swap a public key, and the key
  row's integrity code stops that (Decision 6). The access key protects stored values
  against TLS-terminating middleboxes, logs and the server's stored answers. Approval is
  the control between a stolen code and the workspace: whoever uses the code enrols or
  re-keys with a key of their own, and the key waits for approval. Whoever holds an
  access key's secret is that access key, on any machine, under any machine id.
- **The secret** is 32 bytes from the system's random source; the contract requires it.
- **Labels.** Labels select the holder, and so whose connections a run receives, so they
  come from outside the agent's reach. A CI or a job spec passes them explicitly. For a
  local checkout, `qory` pins the labels it derived at the checkout's first run the
  server accepts, under `labels/` in the runner file's directory, keyed by the
  checkout's resolved real path. A later run whose derived labels differ, such as after
  the agent rewrote `.git/config`'s origin, is no run, `labels_changed`, until the user
  confirms with `--relabel`.

**Keeping the secret from the agent.** An agent that reads the access key secret fetches
every value the server stores for that access key.

- *Unwalled runs.* Once a server's signed discovery lists `secrets`, every run against it
  needs a wall: `server_needs_wall`. With a server, that refusal comes after the ping,
  so it reaches the server. The marker is the offline signal: `qory` writes it when
  signed discovery lists `secrets` and before every key it generates, and while it
  exists `qory` refuses every unwalled run, `--local` included, with the same code,
  before the run starts. A marker that cannot be written means no run. In 0.7.0 stored
  secrets go only to walled runs; a credentials broker is a later direction (Later: a
  credentials broker).
- *Mounts.* Every walled run, `--local` included, refuses a mount that is, contains or
  lies inside one of the runner's files, resolved through symbolic links:
  `mount_contains_runner_files`, with the path. The runner's files are:
  - the runner file's directory, with the secret, `machine-id`, the marker,
    `enrolment-pending`, `rekey-pending`, the pinned labels and the lock files, whether or
    not the runner file configures a server;
  - the directory of every integration program, every tool program, the `docker` command
    the wall runs and the wall's helper binary, the directory and not only the file, so
    an interpreter, a module or a configuration beside a program is covered too; a
    statically linked program needs nothing else;
  - the `docker` command's configuration directory, `DOCKER_CONFIG` or `~/.docker`,
    whose `currentContext`, `credsStore` and `credHelpers` start programs;
  - every `file:` path of `secrets.local`.

  An agent that can write a program the runner starts outside the wall, or read a value
  file, has left the wall. A mount that contains a runtime's
  `credential_files` is `mount_contains_credential_files` (Runtimes). The runner module
  takes the paths through `session.Spec`. Optionally the runner opens each program at
  the start and starts it by its file descriptor, so the program started is the one
  opened at the start.
- *The enclosure's environment.* A run that passes `QORY_ACCESS_KEY_SECRET` or a variable a
  `secrets.local` value reads (`env:`) into the enclosure is no run, `variable_reserved`.
  `QORY_ACCESS_KEY_ID` and `QORY_APIARY_PUBLIC_KEY` are safe to show, and `qory` keeps them
  out of the enclosure all the same, because only the runner needs them.
- *Integrations and tools* run as the runner's user and are trusted. None of them,
  `describe` included, receives `QORY_ACCESS_KEY_SECRET`, `QORY_ACCESS_KEY_ID`,
  `QORY_APIARY_PUBLIC_KEY`, a variable a `secrets.local` value reads, or the variables a
  node runner passes its spec in. A node runner passes the access key secret through a
  file descriptor.
- *Memory*, optionally: on Linux `PR_SET_DUMPABLE 0`, which also makes the runner's
  `/proc/<pid>/environ` unreadable to other processes of the same user, `RLIMIT_CORE 0`,
  and `mlock` of the opened plaintext.

### 5. HPKE implementation

- **Suite.** RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256
  `0x0001`, AES-256-GCM `0x0002`, written `x25519-sha256-aes256gcm` on the wire. Base mode
  authenticates no sender; the request's binding, the digest in `aad` and the answer's
  signature take that role.
- **Go.** `crypto/hpke` (Go 1.26 and later; the module is at Go 1.27.1):
  `hpke.DHKEM(ecdh.X25519())`, `hpke.HKDFSHA256()`, `hpke.AES256GCM()`; `NewRecipient`
  with `info`, then `Open` on the context with `aad`, since the single-shot `Open` takes
  no `aad`. The recipient's key is `DHKEM(ecdh.X25519()).NewPrivateKey` of the clamped
  first 32 bytes of SHA-512(seed) (Decision 4). The server seals to the key the secrets
  request verified under, so during a rotation's window a run that signs with the old
  key receives an envelope it opens with the old key, and one that signs with the new
  key an envelope for the new key. `NewSender` and `NewRecipient` refuse a
  low-order point; enrolment refuses an Ed25519 key of small order, the only kind that
  converts to a low-order u, so the server meets prime-order keys only.
- **Elixir.** `:crypto` alone implements base mode for this suite. The sealer converts the
  access key's Ed25519 public key to its u-coordinate itself (Decision 4).
  `:crypto.compute_key` raises for a low-order point, because OpenSSL's `EVP_PKEY_derive`
  refuses an all-zero result; the sealer checks for an all-zero DH output itself all the
  same, for a defined error independent of the OpenSSL build. Every seal uses a fresh
  ephemeral key; a seam that fixes it exists for the known-answer test only and is
  compiled out of production builds; a test checks that two seals of one plaintext have
  different `enc`.
- **Encodings.** base64url without padding for every binary value, decoded strictly: a
  value with padding, with a character of the standard alphabet (`+` or `/`), or with
  non-zero bits after its last full byte is refused. Enrolment and rotation send the raw
  32-byte Ed25519 public key. The server seals to its u-coordinate; no key id travels,
  because the access key id and the request's signature imply the key.
- **Signature verification.** Ed25519 everywhere is verified cofactorless, by RFC 8032,
  refusing a non-canonical `R` and an `S` not below ℓ, as Go's `crypto/ed25519` does.
- **Interoperability tests.** Each side checks its implementation against the CFRG
  `test-vectors.json` for this suite, base mode, the file Go vendors as
  `crypto/hpke/testdata/rfc9180.json`; the server's implementation passes it. Each side
  also seals with its own code and the other side's test opens the result, and each side
  converts the fixture access key and compares u with the published one.
- **Deliverable: `contracts/runner/v1/fixtures/sealed/`**, a fixed-ephemeral vector. It
  was sealed by an RFC 9180 implementation written for this check and opened twice
  (verified): by Go's `crypto/hpke` with the X25519 key derived from the seed, and by a
  second RFC 9180 implementation over pyca/cryptography whose key came from libsodium's
  `crypto_sign_ed25519_sk_to_curve25519`. libsodium's
  `crypto_sign_ed25519_pk_to_curve25519`, `filippo.io/edwards25519` and big-integer
  arithmetic each give the same u from the Ed25519 public key, and it equals X25519 of the
  clamped scalar.

  | Input | Value |
  |---|---|
  | access key secret | `qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA`, the seed being bytes 1 to 32; access key id `ak_f1xt0re000000000` |
  | Ed25519 public key | `ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ`; fingerprint `ZbYGc9btiEvwHCwiLYKtoA` |
  | machine id | `m_gYKDhIWGh4iJiouMjY6PkA`, `m_` and bytes 129 to 144 in base64url, for the request vectors |
  | X25519 private key | `cHiPGgzqABomMdrl0F29BiAI1bMPULnim-sqeCIokEQ`, the first 32 bytes of SHA-512(seed) with the clamping applied, as published |
  | X25519 public key | `SjgH0GTQdxgcwHCYnnaJHSDcpVWVSNwsd8GlAnOIKzg`, the u-coordinate of the Ed25519 public key |
  | ephemeral private key | `ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A` (bytes 33 to 64) |
  | run id, access key id, exp | `01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a`, `ak_f1xt0re000000000`, `1700000600` |
  | run configuration | the 583 bytes below, the two connections the plaintext lists; digest `sha256=4a6a9f4309a202d3c8663b8e6ce1d6ffce29afcf1f3516397e79b2ad9987f768` |
  | `info` (hex) | `716f72792073656372657473207631000020000100020013616b5f66317874307265303030303030303030`, 43 bytes |
  | `aad` (hex) | `002430313932386634652d376333612d376432652d396231612d3366356536643763386239610013616b5f6631787430726530303030303030303000477368613235363d34613661396634333039613230326433633836363362386536636531643666666365323961666366316633353136333937653739623261643939383766373638000a31373030303030363030`, 144 bytes |
  | plaintext | `{"version":1,"run_configuration":"sha256=4a6a9f4309a202d3c8663b8e6ce1d6ffce29afcf1f3516397e79b2ad9987f768","connections":["con_0b5n6t2r9y4f7j3s","con_7q2m4k9x0d3h8w1c"],"values":[{"secret":"sec_3fz8k2m9q4w7x1d6","value":"fixture-value-not-a-real-one"},{"secret":"sec_9c4r7t2y5b8n1h3e","value_id":"production","value":"-----BEGIN FIXTURE-----\nnot-a-real-key\n-----END FIXTURE-----\n"}]}`, 386 bytes, the `\n` being JSON escapes |
  | `enc` | `WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns` |
  | `ct` | 402 bytes, SHA-256 `593665d701893d09a70d5acaf09fb7bdcd37ff5c81451b2694a7a87f5a05c7b9` |

  The run configuration:

  ```json
  {"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.anthropic.com","github.com","api.github.com"]}},"connections":[{"kind":"runtime","id":"con_7q2m4k9x0d3h8w1c","name":"claude","secrets":{"oauth_token":{"id":"sec_3fz8k2m9q4w7x1d6","name":"CLAUDE_OAUTH"}}},{"kind":"integration","id":"con_0b5n6t2r9y4f7j3s","name":"qory-github","repository":"github.com/qoryai/qory-github","version":"1.4.0","argument":"acme/shop","settings":{"app_id":"123456"},"secrets":{"private_key":{"id":"sec_9c4r7t2y5b8n1h3e","name":"GITHUB_APP_KEY","value_id":"production"}}}]}
  ```

  `ct`:

  ```
  lhQhSrBwqVESXVYLN44ttNMY3PZJUN1SV4XUz7kCx_ngnotLha21-V69jTwd8co_eMUZYkC3h-sE_alQeOgs7oYKgh6Rmq7HgsaQQ26WqrZ1G_59LGJ_9HXDCjkw2efdJVRPKGMr-h_LAyDwr_MCCmJQhuhDwJ1B9_hZa_Yf2p0GlchdPzRPxCDGJMF4E2m9aj8ReeMTstBygjMZM0X6qYF-3uHUWTsRAcXJjxQ8jmAFhICqbFxhGMHQvsaZWIPO4Afc0otkI8sMCNhGY7c9JPQp5sbnlAQseRWJ4qu7Bf-igmRrIjiJW_HyS2gSfF2UplgOX9eYAvw_mYqmOt6KcG0aw9xE23CQueQ6HDHiorzyHUln-FhlhOQUFpiC5Ns_Ay-2hW-Gjua6AzVHgZuryC5hAmrJgKe4fsfShBhXeAVXP-tZLP7KDTu90fLpv8x6IdFDIkE_h5Gxq1d8LQzQK77DLEYLudFh-_0mVMXwo1AliGvhn9fYCMeJowTAs-drgZteMal8geAW5cAYYbGVz7a2
  ```

  A second case alters `aad` and expects the open to fail.

  The envelope's `sig` (Decision 6), under the fixture signing key, seed bytes 65 to 96,
  `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A`, public key
  `rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc`, fingerprint `uoES-kuj1vk0sq0qoGlmAg`:
  the signed message is 641 bytes, SHA-256
  `e7765caf6fbfdb0135856eb45d4585c0b9fcba33c8acc143dec0929ca1528806`, and `sig` is
  `mJJQf4Fp6daTUYcve1fxschVR96VkcVCJ-pRZYVioAuofXVEuXB7nWPUGLugXWha3n0fLrYVmMXLTxsniziXCQ`,
  verified with Go's `crypto/ed25519`, pyca/cryptography and libsodium.

  Every fixture published here is refused in production: `qory` refuses the fixture
  access key secret, the server refuses the fixture access key at enrolment,
  `key_invalid`, and the fixture signing keys, current and next, as a pin and as its own
  key.
- **Public keys enrolment refuses**, a test list. The points of small order are eight. Their
  canonical encodings and the six non-canonical encodings a lenient decoder accepts are
  fourteen; the canonical-encoding check refuses the six and the small-order check the
  eight (verified with `filippo.io/edwards25519` and with big-integer arithmetic):

  | Point | base64url |
  |---|---|
  | identity, y = 1 | `AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` |
  | order 2, y = p − 1 | `7P_______________________________________38` |
  | order 4, y = 0 | `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA` |
  | order 8 | `xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o`, `xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA_o`, `JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_AU`, `JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_IU` |
  | non-canonical: x = 0 with the sign bit set | `AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA` (y = 1), `7P________________________________________8` (y = p − 1) |
  | non-canonical: y = p, read as 0 | `7f_______________________________________38`, `7f________________________________________8` |
  | non-canonical: y = p + 1, read as 1 | `7v_______________________________________38`, `7v________________________________________8` |

  A key with a torsion component passes the other checks and fails prime order:
  `KH9r2npX9PKHPzv_Xl6pwmCmpjQ73zfHq800btWQTBE`, the fixture access key plus the first
  order-8 point above, canonical, on the curve, not of small order, and [ℓ]A not the
  identity (verified with `filippo.io/edwards25519` and with big-integer arithmetic).
  Enrolment refuses it, `key_invalid`. The fixture access key passes all five
  checks and is refused only as a published fixture.

- **Later.** X25519 is refused under `GODEBUG=fips140=only`. ML-KEM-768 with X25519,
  `0x647a`, is in the same Go package; it becomes another suite value, its ML-KEM key
  derived from the access key secret (Decision 4).

### 6. Routing and the seal

**Decided.** Routing leaves the seal. The runner recomputes the run configuration's
digest, and the server seals from the verified rendering for the connections the run
lists. The reasoning follows.

**The question.** Base mode authenticates no sender: anyone with the access key's public
key can seal. One way to bind a value to where it goes is to put its routing inside the
seal. This design puts routing in the connections instead, inside the signed run
configuration whose digest is in `aad`.

**For keeping routing in the seal.** It binds each value to its hosts under the access
key, whatever happens to the document. But a connection's routing is more than a list of
hosts: an integration's hosts come from the machine's program and its scheme and paths
from the program's answer, and a value two connections share would be sealed once per
route. The seal would repeat half the document, and still not cover the policy or the
variables.

**Binding the document instead (decided).** The digest in `aad` and in the plaintext
binds the values to one rendering, once the runner knows the document it has is that
rendering:

- A run configuration's digest is `sha256=` and the lower-case hex SHA-256 of the
  answer's body bytes after content decoding: the server's stored bytes, which it serves
  as stored. The runner recomputes it and refuses a mismatch,
  `run_configuration_digest_mismatch`.
- The secrets request sends that digest and the connections the run applies. The server
  takes what to seal from the stored rendering's bytes for that digest, never from live
  rows, and only for the listed connections.
- The sealed plaintext contains the digest, the sorted set of connections and the values
  by secret id and value id, nothing else; the runner checks both against what it sent.

That binds every value to the whole document: connections, policy and variables. Without
it, whoever can sign answers, a holder of the server's signing secret on the path, could
serve forged connections under a real digest and have real values routed to a host of
its choosing. With it, such a holder seals only values of its own: the real ones are
sealed to the access key for the rendering the server stored, it holds no access key
secret, and every new key needs approval (Decision 4).

**A write to the server's database.** Whoever can edit a service definition's hosts, a
connection's link to a secret, or a stored rendering, in the server's database, reroutes
a real value: the server serves it, signs it and seals for it. The server's obligations,
whose exact bytes the server defines:

- an integrity code, an HMAC under a key derived from the instance key, over the whole
  canonical connection row and over each custom service definition, never a field list;
  a built-in definition lives in the server's release and has no code, and the
  rendering records the definitions it was rendered from;
- an integrity code over each stored rendering, its body bytes and its digest, checked
  when serving the GET and again before sealing; a failure is `503` `unavailable` on both,
  no run;
- an integrity code over each key row: its id, its public key, the pending key, and the
  old key and the end of its window, whichever exist, the sequence number at which the
  server received each of those keys, its
  workspace, its stored-secrets flag and the sequence number of its last enabling, its
  rate limits, its approval and whether it is revoked. The server stores no secret of the
  key, so a reader of the database cannot act as an access key; writing to it could swap
  a public key for one of the writer's own, and the code stops that, as it stops a writer
  who moves an access key to another workspace, enables stored secrets, approves a key or
  un-revokes one. Approval is required under every setting, so a writer finds nothing
  to turn off;
- the key row's code verified on every request, before the signature: a row whose
  code fails does not verify, `401`, unsigned, on every endpoint, so a writer cannot
  swap a key or un-revoke an access key for the GET or the events endpoint either;
- an integrity code over each code row: the code's SHA-256, its kind, its workspace and
  the settings the access key will get for an enrolment code, the access key id for a
  re-key code, its expiry and who issued it, so a writer cannot insert a code that
  creates or re-keys an access key of its choosing;
- a per-row version inside the coded data, with the audit recording the current version
  of each row, so an older row restored over a newer one is detected unless the audit is
  rolled back with it;
- audit of every change with before and after.

Policy rules and variables carry no integrity code: they route no stored value, and the
runner's deny list bounds what a variable can do.

All codes use the same key, derived from the instance key with HKDF-SHA256. A connection
or definition whose code fails refuses the render, and the holder keeps its last good
rendering; a key row whose code fails verifies nothing, so nothing is sealed to it.
None of this stops a writer who has the instance key, nor a change made through the
server's own pages, which is authorisation's matter.

**Who may route a value.** In 0.7.0 only owners and administrators may link a secret into
a connection, define a custom service, edit variables, or enable stored secrets on an
access key. Linking
a secret needs the `secret.use` permission on it, which only owners and administrators
hold. Finer roles are a later release.

**The server's signing key.** The server holds no secret of the access key, so it signs
with a key of its own. Base mode authenticates no sender, so the runner opens only an
envelope the server signed and reads only answers the server signed, both under a key
the machine pins:

- The server has an Ed25519 key of the instance: `APIARY_SIGNING_SECRET` when it is set,
  which overrides the default, else one derived from the instance key,
  `APIARY_ENCRYPTION_SECRET`, with HKDF-SHA256 under a label of its own, distinct from
  the integrity key's. The server's documentation recommends setting
  `APIARY_SIGNING_SECRET`, so a rotation of the instance key does not break the pins.
  Discovery for every verified access key lists the current public key, and during a
  rotation the next one too, `apiary_public_key: [{"alg": "ed25519", "public_key": "<32
  bytes, base64url>"}]`, for information only; Settings › Access keys shows it, and an
  enrolment code carries its fingerprint. The published fixture signing key is refused
  as a pin and as the server's key, in `APIARY_NEXT_SIGNING_SECRET` too, as the fixture
  access key secret is.
- **Rotating the server's key.**
  1. The operator sets `APIARY_NEXT_SIGNING_SECRET`. The current key keeps signing, and
     discovery and the enrolment and re-key answers list both public keys, current then
     next. A code created now carries both fingerprints, current then next, so a machine
     enrolled or re-keyed now pins both, and only keys its code names.
  2. The operator adds the next public key to every other machine's pin out of band: in
     `runner.yaml`, the image or the CI variable. A pin is a list, so both fit. The
     runner takes keys from its pin alone, because a stolen signing secret could
     otherwise make itself permanent.
  3. The switch: `APIARY_SIGNING_SECRET` takes the next value, and
     `APIARY_NEXT_SIGNING_SECRET` is unset.
  4. A code carries the fingerprint of the key that was signing when the code was made,
     and of the next key during a rotation. Enrolment's step 4 accepts a code only when
     its fingerprints are the current and next keys', so every outstanding code ends at
     the switch, and when the next key is replaced or unset. Every node of the server
     switches together.
  5. A machine whose pin lacks the new key gets `answer_unsigned` until its pin is
     updated.
  6. The retired public key is removed from every pin. After the switch the server signs
     with the new key alone, and the operator's out-of-band update removes the old one.
- The server signs every answer to a verified request with it, and every answer to an
  enrolment or re-key whose code it accepted: `X-Qory-Signature-Ed25519: <64 bytes, base64url>`,
  over the six lines of Signed answers. Every `401` is unsigned, wherever it falls, and
  so is a `400` before verification.
- The envelope gains `sig`, the 64-byte signature in base64url, over
  `lp32("qory envelope v1") ‖ lp32(suite) ‖ lp32(access_key_id) ‖ lp32(run_id) ‖
  lp32(run_configuration) ‖ lp32(exp in canonical decimal) ‖ lp32(enc, raw) ‖
  lp32(ct, raw)`, where `lp32` is a u32 big-endian length, then the bytes.
- The pin is `apiary_public_key` in `runner.yaml`'s `server` section, a list of public
  keys so the key can rotate. The runner takes keys from its pin alone, not from
  discovery, and requires both: the signature on every answer, discovery, the run
  configuration, the secrets request, rotation and every event answer, treated as an
  unsigned answer when it fails (no run at start, a retry where today's rules retry);
  and the envelope's `sig`, verified before opening, `envelope_signature_invalid`. The
  pin is the machine's, so only the machine's owner changes it.
- **Every machine needs the pin.** Every runner requires answer signatures, with no
  exemption (Decision 8), and only the server's key signs them, so the pin is required on
  every machine with a server, not only on access keys allowed stored secrets. A runner
  with a server and no pinned `apiary_public_key` is no run,
  `apiary_public_key_missing`, decided before the first request.
- **How a machine gets the pin.** Enrolment with a code installs it verifiably: the code
  carries the key's fingerprint, and `qory` writes the pin only after the signed answer
  verifies under that key. For a pasted key, Settings › Access keys shows the pin. The pin
  is a public key, so it needs no secret store: it comes through the runner file, baked
  into the machine's image, or through a plain CI variable, `QORY_APIARY_PUBLIC_KEY`,
  whose value is the same list as `apiary_public_key`, written as JSON: `[{"alg":
  "ed25519", "public_key": "<32 bytes, base64url>"}]`. `qory` takes the pin from the
  variable when the runner file's `server` section has no `apiary_public_key`, and refuses
  to start when both are set, so the pin has one source. `qory` removes the variable from
  its own environment and keeps it out of the enclosure, because only the runner needs it.

### 7. Machine values and the runner file

- **Providers.** `secrets.providers` in the runner file is the ordered list of providers
  an external reference `{source: external, name, value_id?}` is resolved through; the
  default is `[local]`. The first provider that defines the name, and the value id when one
  is given, resolves it; none is `secret_unresolved`, with the connection and the
  providers tried. Later: `vault`, a cloud's secrets manager, and the like.
- **The `local` provider** is the section `secrets.local`: values by variable-style name,
  each from the runner's environment or a file, or several under value ids, each with
  `hosts`, the most the machine allows it to be sent to, in `egress.allow`'s grammar:

  ```yaml
  secrets:
    providers: [local]
    local:
      SENTRY_AUTH:
        env: SENTRY_AUTH_SOURCE         # read once at run start
        hosts: [sentry.io]
      GITHUB_APP_KEY:
        hosts: [github.com, api.github.com]
        values:
          production: {file: ~/.config/qory/github-app-production.pem}   # read at each use
          staging:    {file: ~/.config/qory/github-app-staging.pem}
  ```

- **The bound.** A connection that sends a machine value to a host its `hosts` do not
  cover is no run, `secret_hosts_exceeded`, whether the connection comes from the server
  or from the runner file. The hosts compared are the service's, the runtime declaration's
  for a runtime connection, and `describe`'s `roles.credential.hosts` for an integration.
  For an integration the bound covers where the produced credential is set, not where
  the program sends the raw value (Integrations).
- **Every provider is bounded.** A provider resolves a reference a server sent only for
  a name the machine defines a `hosts` bound for. `secrets.local` requires `hosts` on
  every entry; a later provider, such as a vault, configures a bound per name, and a name
  without one does not resolve.
- **Source decides.** A reference with an id is resolved from the sealed payload and
  nothing else; `qory` refuses `apiary` in `secrets.providers`. An external reference is
  resolved through the providers alone.
- **The runner file's `connections:`** has the shapes of Wire format, in YAML, with
  external references only. A machine's static credential is a service connection. A
  machine's adapter program is an integration connection: `qory`'s `integrations:`
  section lists the program by name and path, the connection's `repository` and `version`
  are optional, and `describe` still runs and its `name` must equal the connection's.
  Anything that takes an argument is an integration; a service takes none.

  ```yaml
  connections:
    - kind: runtime
      id: claude
      name: claude
      secrets: {oauth_token: {source: external, name: CLAUDE_OAUTH}}
    - kind: service
      id: sentry
      name: Sentry
      hosts: [sentry.io]
      auth: {scheme: bearer, secret: auth}
      declares: [{id: auth, title: Sentry auth, name: SENTRY_AUTH}]
      secrets: {auth: {source: external, name: SENTRY_AUTH}}
    - kind: integration
      id: github
      name: qory-github
      argument: acme/shop
      secrets: {private_key: {source: external, name: GITHUB_APP_KEY, value_id: production}}
  ```

- **Connections alone select credentials.** `credentials` leaves `policy.schema.json`, and
  with it the run configuration's `security_policy`, `--policy` files and the machine's
  policy: what a run may send where is decided by connections alone. The policy keeps
  `egress`, `tools` and `image`.
- **Connections need a wall**: `connection_needs_wall`. The wall is what binds a program
  that ignores the proxy.
- **Where it lives.** `qory` parses `runner.yaml`; the runner module takes the providers,
  the local values, the integrations, the runner file's connections and
  `tls.public_roots_only` (Connections at the proxy) through `session.Spec`.

### 8. Contract version and behaviour

- **Revision 1.** Every document here is `v1`, revision 1, and the runner sends
  `X-Qory-Contract-Version: 1`. A later change to what a server may rely on goes through
  that header.
- **Answer signatures are required.** Every runner refuses an answer without a valid
  signature under its pinned `apiary_public_key`, whatever the runner file contains.
- **`TRACE` and `TRACK`** are refused with a `403`, `decision: denied`, `outcome:
  refused`, rule `wall:trace`, on every host where the proxy sets a value, because such a
  request returns its headers to the sender.
  §Limits gains that sentence beside the echo service.

## Runtimes

**Declarations.** The descriptor (`descriptor.schema.json`, `internal/descriptor`,
`runtimes/catalog`) gains `secrets`, and its `runtime` name is bounded,
`^[a-z][a-z0-9-]{0,63}$`:

```yaml
# contracts/runner/v1/runtimes/claude/descriptor.yaml, added
secrets:
  declares:
    - id: api_key
      title: Anthropic API key
      name: ANTHROPIC_API_KEY
      hosts: [api.anthropic.com]
      paths: [/v1/*]
      auth: {scheme: header, header: x-api-key}
    - id: oauth_token
      title: Claude OAuth credential
      name: CLAUDE_CODE_OAUTH_TOKEN
      hosts: [api.anthropic.com]
      paths: [/v1/*]
      auth: {scheme: bearer}
  one_of:
    - id: model_key
      required: true
      of: [api_key, oauth_token]
  reserves: [ANTHROPIC_AUTH_TOKEN]
  credential_files: [~/.claude/.credentials.json]
  denies: [ANTHROPIC_BASE_URL, ANTHROPIC_BEDROCK_BASE_URL, ANTHROPIC_BEDROCK_MANTLE_BASE_URL,
           ANTHROPIC_VERTEX_BASE_URL, ANTHROPIC_FOUNDRY_BASE_URL, ANTHROPIC_AWS_BASE_URL,
           ANTHROPIC_CUSTOM_HEADERS, CLAUDE_CODE_USE_BEDROCK, CLAUDE_CODE_USE_VERTEX,
           CLAUDE_CODE_USE_FOUNDRY, CLAUDE_CODE_USE_ANTHROPIC_AWS, CLAUDE_CODE_SHELL,
           CLAUDE_CODE_SHELL_PREFIX, CLAUDE_ENV_FILE, CLAUDE_CONFIG_DIR,
           CLAUDE_CODE_CLIENT_CERT, CLAUDE_CODE_CLIENT_KEY, CLAUDE_CODE_CERT_STORE]
```

- **`denies`** lists variables the runner always leaves out of the server's set for the
  runtime, and reports (Decision 1). For Claude Code, each name is checked
  against its documentation's environment-variable reference and found in the
  `claude` 2.1.288 binary:
  - `ANTHROPIC_BASE_URL` and the `*_BASE_URL` of Amazon Bedrock, its Mantle endpoint,
    Google Cloud's Agent Platform, Microsoft Foundry and Claude Platform on AWS move
    where requests, and the model credential, go;
  - `ANTHROPIC_CUSTOM_HEADERS` adds headers, an `Authorization` among them;
  - `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, `CLAUDE_CODE_USE_FOUNDRY` and
    `CLAUDE_CODE_USE_ANTHROPIC_AWS` switch to another provider and its credentials;
  - `CLAUDE_CODE_SHELL` chooses the shell for Bash commands, `CLAUDE_CODE_SHELL_PREFIX`
    wraps every command Claude Code starts, hooks included, and `CLAUDE_ENV_FILE` is a
    script run before each Bash command;
  - `CLAUDE_CONFIG_DIR` moves the settings, hooks included, and the credential file;
  - `CLAUDE_CODE_CLIENT_CERT`, `CLAUDE_CODE_CLIENT_KEY` and `CLAUDE_CODE_CERT_STORE`
    change the client certificate and the trust of its TLS connections.

- A declaration's `hosts` are exact DNS names, no wildcard, no IP literal; its `auth` is a
  scheme from the closed set; its optional `paths`, in the policy's path grammar, bound
  the requests its value is set on. A credential that can mint credentials gives the agent
  a readable one if the agent reaches the minting path, so a declaration bounds its value
  with `paths`: Claude Code's are `/v1/*`. Under `enforce`, a request of the run to
  `api.anthropic.com` outside `/v1/` is refused, as on any host with paths; under
  `observe`, it passes without the value and is recorded. The exact paths Claude Code
  needs are a release-gate check. Whether `api.anthropic.com` serves a path that creates
  an API key from an OAuth credential is to verify. Warning about an administrative key on
  save is the server's matter.
- A group of `one_of` has an `id`, its declarations under `of`, and may be `required`.
  A runtime connection supplies at most one declaration of each group, else
  `runtime_secret_choice`; a declaration in no group is optional. A walled run of the
  runtime with no connection that supplies one declaration of a required group is refused
  before anything starts, `runtime_secret_missing`, with the group's id. Claude Code's
  `model_key` group is required, so a walled Claude Code run needs a runtime connection
  for its model credential. A key that is no declaration of the runtime is
  `connection_secret_unknown`.
- **The stand-in.** The runner sets the placeholder value only in the chosen
  declaration's variable, and the proxy sets the value on its hosts by its scheme. The
  placeholder value is `qory-sets-the-credential-outside-the-enclosure`, as on main;
  Claude Code accepts any format. Another
  connection whose placeholder is a variable the run's runtime declares or reserves is
  refused, `placeholder_conflict`: only the runtime connection sets those.
- **Conflicts.** A walled run is refused when its environment, `Spec.Env` with
  `wall.env`, `--env` and the harness's launch, contains a variable the run's runtime
  declares or reserves: `runtime_secret_conflict`. A server variable with such a name is
  left out and reported (Decision 1). For Claude Code these
  are `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN`. Claude
  Code reads `ANTHROPIC_AUTH_TOKEN` before `ANTHROPIC_API_KEY` before
  `CLAUDE_CODE_OAUTH_TOKEN`, so a stray value for another alternative would win over the
  stand-in. A walled run's model credential comes from its runtime connection alone.
- **Credential files.** `credential_files` lists files in which the runtime keeps a
  credential of its own, for Claude Code `~/.claude/.credentials.json`, `~` being the home
  of the user the runner runs as; for Claude Code the runner also reads
  `CLAUDE_CONFIG_DIR`, and `.credentials.json` in it. A walled run refuses a mount that is
  or contains one, resolved through symbolic links:
  `mount_contains_credential_files`. A file baked into the image is out of the runner's
  reach; that is the image owner's matter.
- **Emptied.** In a walled run, the wall writes every variable the runtime declares or
  reserves that the run does not set a placeholder in, as an empty value in the
  enclosure's environment file, so an image's own `ENV` cannot set one. This relies on
  Claude Code reading an empty value as unset, a check of Tests and release gates.
- **Interactive mode.** With `ANTHROPIC_API_KEY` set, an interactive Claude Code waits for
  the user to approve the key unless its last 20 characters are listed in
  `~/.claude.json` under `customApiKeyResponses.approved`; headless (`-p`) proceeds at
  once.
  Follow-up work: the claude runtime's `Prepare` pre-approves the constant stand-in,
  whose last 20 characters are `utside-the-enclosure`, in the run's copy of the
  configuration.
- **Which runtime.** One runtime connection per runtime name: two are
  `runtime_connection_duplicate`. The runner applies the runtime connection for the run's
  own runtime and sets any other aside: it stays out of the secrets request, the seal and
  the record.
- **Go API.** An optional interface, checked by type assertion, so `runtimes.Runtime`
  keeps its methods:

  ```go
  // Secrets is implemented by a runtime that declares the secrets it needs.
  type Secrets interface {
  	Secrets() Declarations // declares, one_of, reserves
  }
  ```

  The descriptor-backed runtime implements it; a runtime without it declares nothing, and
  a runtime connection for it is `connection_secret_unknown`.
- **What is verified.** The OAuth credential through the placeholder works end to end, with
  no refresh and no other host. The API key path is a release gate (Tests and release
  gates).

## Integrations

An integration is a program implementing the integrations contract, `describe` and
`credential` among its commands; its own contract changes ship in the integrations
module's next release. It is the one way a program of the machine's produces a
credential.

- **The machine's integrations** are what `qory`'s `runner.yaml` `integrations:` defines,
  keyed by the description's `name`. `qory` resolves each program's path with its
  ownership checks and passes the runner module the installed integrations through
  `session.Spec`, name to program path. Installing is `qory`'s; the runner runs the
  programs it is given. A connection
  whose `name` the machine lacks is `integration_missing`.
- **Name and version.** At run start the runner runs `describe` and requires its `name` to
  equal the connection's, else `integration_name_mismatch`, so a program registered under
  another name cannot answer for a connection. When the connection has a `version`, which
  a server's always has, `program_version` must equal it after removing one leading `v`;
  `dev` is always a mismatch: `integration_version_mismatch`. This is a check for
  equality, not of identity: `describe` is the program's own report about itself. Trust in
  the program rests on `qory`'s path and ownership checks; matching by name and version is
  enough, and a program digest recorded at install is a later option.
- **Hosts** are `describe`'s `roles.credential.hosts`; a `*.` entry over a public suffix,
  the private section included, is `connection_host_public_suffix`. Scheme and paths come
  from the program's answer, `credential.schema.json`; a claim above the described hosts
  is refused, `integration_hosts_exceeded`.
- **The answer** keeps main's `credential.schema.json`: `version`, `token`, `expires_at`,
  `apply` with `hosts`, `scheme`, `username`, `header`, `token` and `paths`, and
  `placeholders`. An `apply` entry's `header` is checked against `headers.json`, as a
  service's is, `connection_header_reserved`. The placeholders an integration sets are
  the ones its description lists under `roles.credential.placeholders`, so the runner
  knows them before the program runs; an answer's `placeholders` must be among them.
- **Timing and renewal** carry over from main's adapter. A program has a minute to
  answer. The runner runs `credential` again five minutes before `expires_at`, and when a
  host returns `401` to a request it set the credential on, at most once every thirty
  seconds. A new answer changes the credential and nothing else; one that lists other
  hosts, schemes or paths is refused and reported, and the old credential stays. A
  renewal that fails leaves the old credential in use, and every later request it is set
  on is a `dev.qory.run.egress` with `connection` and `renewal_failed: true`, until a
  renewal succeeds; what the program wrote is reported, redacted, as the runner's lines.
  `dev.qory.run.refused` covers the start alone.
- **What the hosts bound.** For an integration, the hosts bound only where the proxy sets
  the credential the program produces. The program runs outside the wall and receives
  the raw value, and where it sends that value is the program's. The server chooses
  `argument` and `settings`, which steer the program.
- **The machine's bounds.** An entry of `integrations:` may bound what a server chooses:
  `arguments`, an RE2 pattern the argument must match whole, else
  `integration_argument_not_allowed`; and `settings`, per member a fixed value or
  `{pattern: <RE2>}`, a member the bound does not list being refused,
  `integration_settings_not_allowed`; and `paths`, by host, the most paths the program's
  answer may claim, a claim above it being `integration_hosts_exceeded`, as main's
  definition bounded an adapter. A server-sent integration connection that references a
  machine value needs both of the first two bounds: without an `arguments` bound it is no
  run, `integration_argument_not_allowed`, and without a `settings` bound its `settings`
  must be `{}`, else `integration_settings_not_allowed`. Before it writes standard input
  the runner also validates the settings, with the secret values inlined so a required
  `writeOnly` member passes, against the program's own description, else
  `integration_settings_invalid`.

  ```yaml
  integrations:
    qory-github:
      path: /usr/local/bin/qory-github
      arguments: '^acme/[a-z0-9._-]+$'
      settings:
        app_id: '123456'
  ```
- **Invocation.** The runner starts every role as `<program> <role> -- [the role's own
  arguments]`, with `--` always present. The credential role is
  `<program> credential -- <argument>`: exactly one argument, the empty string when the
  connection has no `argument`. A program refuses every flag for a role.
- **Standard input** always carries exactly one JSON document: the connection's
  `settings` with each secret's value inline under its setting's name, a name in both
  being `run_configuration_invalid`. It is `{}` when there is nothing to send, so a
  connection without `settings` runs with `{}`. The runner always connects standard input
  to the document, writes it whole and closes it. The program reads
  it to its end before any network request, and refuses empty input, a second document
  or trailing data. `describe` reads no standard input.
- **The settings document** is written from memory, from a goroutine (`cmd.Stdin` set to
  a `bytes.Reader`), so the runner proceeds whether or not the program reads it. It is
  written again on every invocation, renewals included, and exists in memory and on
  standard input alone. It is at most 65536 bytes (64 KiB) as encoded; the runner
  refuses a larger one before it starts the program, `integration_settings_too_large`,
  and the server refuses on save a link that would make it larger with a stored value. No
  `${argument}` is replaced inside it.
- **What the program writes to standard error** is reported, in errors and as the runner's
  lines, only after `[redacted]` replaces, matched exactly, every value written to its
  standard input, every line of 8 bytes or more of a value that has several lines, and the
  credential the program returned. Redaction, not dropping, keeps the program's own reason
  readable. Redaction matches values as written; keeping a transformed form, such as an
  encoded one, out of its output is the program's task.
- **Validation.** The server validates `argument` and `settings` against the release's
  `description.json`, and that each key of `secrets` is a top-level `writeOnly` property
  of it; the runner passes them as received.

## Services

A service arrives inline in its connection: `hosts`, exact DNS names, no wildcard, no IP
literal (`connection_host_invalid`); optional `paths`, the policy's path grammar, which
bound every request the value is set on; `auth`; and `declares`, the secrets it needs. A
service takes no argument. The runner enforces the hosts exactly.

- `auth.scheme` is `bearer`, `header` with `header`, or `basic` with exactly one of
  `username`, a fixed string, or `username_secret`, a declaration whose value is the
  username and contains no `:` (`secret_value_invalid`), which the server checks when the
  value is saved and when the link is saved. `auth.secret` is the declaration whose value
  is sent.
- A declaration with `name` gets the placeholder in that variable.

**Header names.** `auth.header`, in a service and in a runtime declaration, is an RFC
9110 field name of at most 64 characters that `contracts/runner/v1/headers.json` does
not refuse, compared in lower case: `connection_header_reserved`. The file is
`{"version": 1, "refused": [names], "refused_prefixes": [prefixes]}`, all lower case, a
snapshot frozen per contract pin and regenerated only with a contract change:

- every field of the IANA HTTP Field Name Registry at the snapshot;
- the Fetch standard's forbidden request headers;
- names hosts commonly send back or log beside a request: `origin`, `content-type`,
  `x-request-id`, `x-correlation-id`, `forwarded`, `via`, `range`, `user-agent`,
  `referer`;
- `host`, `content-length`, `transfer-encoding`, `connection`, `keep-alive`, `te`,
  `trailer`, `upgrade`, `cookie`, `authorization`;
- the prefixes `accept`, `if-`, `x-forwarded-`, `proxy-`, `sec-`, `x-qory-` and `qory-`.

`authorization` is reachable only through `bearer` and `basic`. The server validates
custom definitions on save and its built-in definitions in CI against the same file.

## Connections at the proxy

- **Termination.** Every host of a connection is terminated, and the proxy sets a value
  only on port 443 of a host. Today the proxy ignores the port when it sets a credential
  (`internal/proxy/terminate.go`); a request to another port of the host is decided by
  the policy and receives no value.
- **Public roots.** The proxy verifies a host that receives a stored value against public
  roots only: the runner's own public root store alone
  (`golang.org/x/crypto/x509roots/fallback`), so stored values reach only hosts with
  publicly rooted certificates, and an authority added to the machine, such as a
  TLS-inspecting proxy's, receives none. The runner file switches it explicitly:

  ```yaml
  tls:
    public_roots_only: true   # the default
  ```

  The setting covers every host where the proxy sets a value from the sealed payload,
  through a runtime or a service connection, and every host where it sets the credential
  an integration produced from a stored value; it covers every request to such a host.
  `true`, the default, verifies those hosts against public roots only; `false` verifies
  them against the machine's trust store, as every other host is. A machine value, and the
  credential of an integration that received machine values only, is verified against the
  machine's trust store under either setting, because the machine chose it. A machine
  behind a TLS-inspecting proxy of its own sets `false` and accepts that its proxy reads
  stored values. When a host fails verification against public roots, the proxy refuses
  the request: `dev.qory.run.egress` records `decision: denied`, `outcome: refused` and
  the rule `wall:public-roots`, the session gets a `403`, the value stays with the proxy,
  and the run goes on.
- **A host the policy denies** leaves the run running, because denied egress never ends
  a run: the policy refuses requests there, so the value stays unset there; the host is
  listed in the connection's `hosts_denied`. The list comes from the proxy's own decision
  function, the host lists and the path rules both, so the record and the proxy agree.
  Under `observe`, every connection host that `deny` does not cover receives the value.
  A tool differs: under `enforce`, a tool whose host the allow list does not cover is no
  run, `tool_host_denied`, as on main, because a tool needs its host to work at all,
  while a connection only adds a value to requests the policy already governs.
- **Nested Docker.** A run with stored values may use a Docker of the agent's own: values
  stay outside the enclosure and so outside the containers the agent starts.
- **One credential per host.** Two connections, or a connection and a tool, whose hosts
  overlap, one entry covering the other as `*.github.com` covers `api.github.com`, are
  `connection_host_conflict`.
- **Paths.** A service's or runtime declaration's `paths` and an integration's answer
  bound the requests the value is set on; the policy's path rules apply as well, and a
  request passes when every list that exists has an entry that matches. Under `enforce`,
  a request outside a connection's `paths` is refused; under `observe`, it passes without
  the value and is recorded, as main's credential paths do. The value is set only on a
  connection's own hosts, whatever the mode.
- **Values.** A value set in a header, for a runtime or a service, follows the header
  rules of Endpoint rules, else `secret_value_invalid`; a value an integration receives
  on standard input is any text.

## Wire format

### The configuration document

```json
{"version": 1,
 "events": {"url": "https://qory.example/v1/events", "types": ["*"]},
 "run": {"url": "https://qory.example/v1/run-configuration"},
 "secrets": {"url": "https://qory.example/v1/secrets"},
 "access_key": {"url": "https://qory.example/v1/access-key"},
 "apiary_public_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}],
 "current_key": "ZbYGc9btiEvwHCwiLYKtoA",
 "pending_key": null}
```

`secrets` is optional, `{url}` with `run.url`'s grammar, listed only for an access key
allowed to receive stored secrets. `access_key`, the same shape, is where the runner posts
a new key (Rotation); it and `apiary_public_key` are listed for every verified access key,
the key for information: a runner takes keys from its pin alone. `current_key` and
`pending_key` are listed for every verified access key: the fingerprints of its current
key and of its pending key, `null` when none is pending, so `qory` decides about
`access-key-secret.next` from a signed answer. `key_rotation_required: true` is listed,
beside `secrets`, under every key the server received before the stored-secrets flag's
last enabling while the flag is set, and is omitted otherwise (Decision 4). `run` is
listed when
the workspace has a policy, a connection or a variable in force, its own or from a level
above.

### The run configuration

`version` is required; `security_policy`, `connections` and `variables` are optional, all
covered by the digest. Without `security_policy` the machine's own policy applies, the
policy the command passes, else observe everything: `dev.qory.run.policy_applied` reports
`source` `config` or `none` with `url` and `run_configuration`, a reload that brings a
`security_policy` puts it in force and one that drops it puts the machine's back, and
`--policy` keeps its meaning. Without `connections` the runner file's connections apply;
a present `connections`, even `[]`, is the whole set. The request is the labels, and
nothing else, as the query; labels the contract refuses are `400` `invalid_request` here
and on the secrets request alike, decided by one resolver.

**The holder and its variant.** The labels select a holder within the access key's
workspace only; labels that select no holder there, such as a repository the workspace
does not hold, get the workspace's baseline, as today. The server stores a rendering, with
its digest, per holder and variant. There are two variants: the full rendering, and one
with every connection that references a stored value left out. The server picks the
variant from the key row's stored-secrets flag alone: the full one for an access key
allowed stored secrets, the other for any other key. The key row alone selects it. On
every answer that carries them, the GET's and the events endpoint's alike,
`X-Qory-Run-Configuration` is the digest of the access key's variant, and
`X-Qory-Configuration` that of the discovery document for the access key and the key the
request verified under. A running run therefore reloads once whenever its own variant or
its own discovery document changes, and every key event of its access key, an approval, a
rejection, a rotation, a re-key or an enabling of the flag, changes that document. The
variant without stored values lists what it left out in the optional member `withheld`, by
`id`, `kind` and `name`, and omits `withheld` when it left nothing out, so a holder
without stored-value connections has one rendering, and one digest, for both variants. It
keeps `connections`, even `[]`, whenever the full rendering has it, since an absent member
would put the runner file's connections in force. The runner reports them in
`policy_applied` as `connections_withheld`, and they raise no `connection_needs_wall` or
`secrets_endpoint_missing`. When leaving them out leaves a required group of the run's
runtime unmet, `runtime_secret_missing` applies as usual.

```json
{"version": 1,
 "security_policy": {"version": 1,
   "egress": {"mode": "enforce",
              "allow": ["api.anthropic.com", "github.com", "api.github.com", "sentry.io"]}},
 "connections": [
   {"kind": "runtime", "id": "con_7q2m4k9x0d3h8w1c", "name": "claude",
    "secrets": {"oauth_token": {"id": "sec_3fz8k2m9q4w7x1d6", "name": "CLAUDE_OAUTH"}}},
   {"kind": "integration", "id": "con_0b5n6t2r9y4f7j3s", "name": "qory-github",
    "repository": "github.com/qoryai/qory-github", "version": "1.4.0",
    "argument": "acme/shop", "settings": {"app_id": "123456"},
    "secrets": {"private_key": {"id": "sec_9c4r7t2y5b8n1h3e", "name": "GITHUB_APP_KEY", "value_id": "production"}}},
   {"kind": "service", "id": "con_5h1k8m3p6r0t4w9x", "name": "Sentry",
    "hosts": ["sentry.io"], "paths": ["/api/0/*"],
    "auth": {"scheme": "bearer", "secret": "auth"},
    "declares": [{"id": "auth", "title": "Sentry auth", "name": "SENTRY_AUTH"}],
    "secrets": {"auth": {"source": "external", "name": "SENTRY_AUTH"}}}],
 "variables": {"NODE_ENV": {"value": "test", "locked": false},
               "APP_REGION": {"value": "eu-west-1", "locked": true}}}
```

`connections` is in the server's order, which the record repeats. Schema sketch:

```json
"connections": {"type": "array", "maxItems": 32, "items": {"oneOf": [
  {"$ref": "#/$defs/runtime"}, {"$ref": "#/$defs/integration"}, {"$ref": "#/$defs/service"}]}},
"withheld": {"type": "array", "maxItems": 32, "items": {"type": "object",
  "additionalProperties": false, "required": ["id", "kind", "name"],
  "properties": {"id": {"$ref": "#/$defs/id"},
                 "kind": {"enum": ["runtime", "integration", "service"]},
                 "name": {"type": "string", "minLength": 1, "maxLength": 128}}}},
"variables": {"type": "object", "maxProperties": 128,
  "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_]{0,127}$"},
  "additionalProperties": {"type": "object", "additionalProperties": false,
    "required": ["value", "locked"],
    "properties": {"value": {"type": "string", "maxLength": 4096, "pattern": "^[^\\u0000\\r\\n]*$"},
                   "locked": {"type": "boolean"}}}},
"$defs": {
  "id": {"type": "string", "pattern": "^con_[0-9a-hjkmnp-tv-z]{16}$"},
  "declared": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"},
  "exact_host": {"type": "string", "maxLength": 253,
    "pattern": "^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"},
  "ref": {"oneOf": [
    {"type": "object", "additionalProperties": false, "required": ["id", "name"],
     "properties": {"id": {"type": "string", "pattern": "^sec_[0-9a-hjkmnp-tv-z]{16}$"},
                    "name": {"$ref": "#/$defs/name"}, "value_id": {"$ref": "#/$defs/value_id"}}},
    {"type": "object", "additionalProperties": false, "required": ["source", "name"],
     "properties": {"source": {"const": "external"},
                    "name": {"$ref": "#/$defs/name"}, "value_id": {"$ref": "#/$defs/value_id"}}}]},
  "name": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,127}$"},
  "value_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_.-]{0,63}$"},
  "secrets": {"type": "object", "maxProperties": 16,
    "propertyNames": {"$ref": "#/$defs/declared"}, "additionalProperties": {"$ref": "#/$defs/ref"}},
  "runtime": {"type": "object", "additionalProperties": false,
    "required": ["kind", "id", "name", "secrets"],
    "properties": {"kind": {"const": "runtime"}, "id": {"$ref": "#/$defs/id"},
      "name": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,63}$"},
      "secrets": {"$ref": "#/$defs/secrets"}}},
  "integration": {"type": "object", "additionalProperties": false,
    "required": ["kind", "id", "name", "repository", "version", "secrets"],
    "properties": {"kind": {"const": "integration"}, "id": {"$ref": "#/$defs/id"},
      "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
      "repository": {"type": "string", "pattern": "^github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"},
      "version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
      "argument": {"type": "string", "minLength": 1, "maxLength": 4096},
      "settings": {"type": "object"},
      "secrets": {"type": "object", "maxProperties": 16,
        "propertyNames": {"maxLength": 128}, "additionalProperties": {"$ref": "#/$defs/ref"}}}},
  "service": {"type": "object", "additionalProperties": false,
    "required": ["kind", "id", "name", "hosts", "auth", "declares", "secrets"],
    "properties": {"kind": {"const": "service"}, "id": {"$ref": "#/$defs/id"},
      "name": {"type": "string", "minLength": 1, "maxLength": 128},
      "hosts": {"type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": {"$ref": "#/$defs/exact_host"}},
      "paths": {"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": true, "items": {"type": "string", "pattern": "^/[^*?#\\s]*\\*?$"}},
      "auth": {"$ref": "auth.schema.json"},
      "declares": {"type": "array", "minItems": 1, "maxItems": 16, "items": {
        "type": "object", "additionalProperties": false, "required": ["id", "title"],
        "properties": {"id": {"$ref": "#/$defs/declared"}, "title": {"type": "string", "minLength": 1, "maxLength": 128},
                       "name": {"$ref": "#/$defs/name"}}}},
      "secrets": {"$ref": "#/$defs/secrets"}}}}
```

A `maxLength` in the sketch counts characters, so it is not the check: the runner and the
server count UTF-8 bytes, 4096 for a variable's value and for an integration's
`argument`, and 1 to 16384 for a secret value (Endpoint rules).

The runner file's connections follow the same shapes with three differences: `id` is
`^[a-z0-9][a-z0-9_-]{0,63}$`, references are external only, and an integration's
`repository` and `version` are optional. `auth.schema.json` is shared with the
descriptor:

```json
{"type": "object", "additionalProperties": false, "required": ["scheme"],
 "properties": {
   "scheme": {"enum": ["bearer", "header", "basic"]},
   "header": {"type": "string", "maxLength": 64, "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"},
   "username": {"type": "string", "minLength": 1, "pattern": "^[^:\\s]+$"},
   "username_secret": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"},
   "secret": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"}},
 "allOf": [
   {"if": {"properties": {"scheme": {"const": "header"}}}, "then": {"required": ["header"]}, "else": {"not": {"required": ["header"]}}},
   {"if": {"properties": {"scheme": {"const": "basic"}}},
    "then": {"oneOf": [{"required": ["username"]}, {"required": ["username_secret"]}]},
    "else": {"not": {"anyOf": [{"required": ["username"]}, {"required": ["username_secret"]}]}}}]}
```

In a service connection `auth.secret` is required and is a declared id; in a runtime
declaration `auth` has no `secret` or `username_secret`. The runner checks what the
schema cannot: every `auth.secret` and `username_secret` is a declared id, every declared
id has a reference, and `headers.json`.

### The descriptor

`descriptor.schema.json` gains `secrets`: `declares`, a list of `{id, title, name, hosts,
paths?, auth}`; `one_of`, a list of groups `{id, required?, of}`, `of` a list of declared
ids, each id in at most one group;
`reserves`, variable names; `denies`, variable names the runner always leaves out of the
server's set for the runtime; `credential_files`, paths, `~` for the runner's user's home.
Its `runtime` pattern becomes `^[a-z][a-z0-9-]{0,63}$`.

### Contract files the server vendors

All under `contracts/runner/v1`, so one pin covers them:

- `runtimes.json`, generated from the built-in descriptors and checked in CI against them:
  per runtime its `name`, a `title`, its `reserves`, its `denies`, its `credential_files`,
  its declarations with `id`, `title`, `name`, `hosts`, `auth` with its `header`, and
  `paths`, and its `one_of` groups with `id`, `required` and `of`;
- `denied-variables.json`, the built-in deny list of Decision 1: `names`, `patterns` and
  `except`;
- `headers.json`;
- `configuration.schema.json`, discovery's document, with `access_key`,
  `apiary_public_key`, `current_key`, `pending_key` and `key_rotation_required`;
- `run-configuration.schema.json`, with the optional `withheld`, and `policy.schema.json`,
  both without `credentials`;
- `auth.schema.json`;
- `secrets-request.schema.json`, the secrets request's body;
  `secrets-answer.schema.json`, its answer, the envelope; `sealed-plaintext.schema.json`,
  the plaintext the envelope opens to; `enrolment.schema.json`, the enrolment's body and
  its answer, with `approved` and `stored_secrets` required; `rekey.schema.json`, the
  re-key's body and its answer, which requires every member: `version`, `access_key_id`,
  `approved`, `stored_secrets` and `apiary_public_key`; and `access-key.schema.json`, the
  rotation's body;
- `events/run.refused.schema.json` and `events/run.policy_applied.schema.json`, with
  `connections` and `uses`. An event has no member for the machine id: the server takes
  it from the POST's signed line;
- `server.schema.json`, with `access_key_id` and the required `apiary_public_key` pin, and
  no secret.

### The access key and signed requests

The access key is the identity §The server describes, and it signs every request. The
server document, `server.schema.json` and `runner.yaml`'s `server` section, becomes:

```yaml
version: 1
url: https://qory.example
access_key_id: ak_f1xt0re000000000     # ak_ and 16 lower-case Crockford base32 characters
apiary_public_key:
  - {alg: ed25519, public_key: rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc}
```

The runner file's `machine` section is separate: `machine.name`, the display name
(Decision 4).

The access key secret lives outside this document: `qory` reads it from a file
descriptor, `QORY_ACCESS_KEY_SECRET` or `access-key-secret`, in that order (Decision 4),
and passes it through `session.Spec` with the machine id. `qory` takes `access_key_id`
from `QORY_ACCESS_KEY_ID` when the section has none, and refuses to start when both are
set, as for the pin.

- **On every request** `X-Qory-Access-Key-Id` carries the access key id,
  `X-Qory-Machine-Id` the machine id, and `X-Qory-Machine-Name` the display name, the
  host name by default.
- **Every request is signed** with Ed25519 under the access key secret:
  `X-Qory-Signature-Ed25519: <64 bytes, base64url>`. §The server defines a canonical
  string for a GET only; the request strings are defined here in full. Each starts with
  three lines: the domain line, the access key id and the machine id, exactly as the
  headers carry them. Lines are joined by `\n`, with no newline after the last:
  - a GET, with `X-Qory-Timestamp` as before: `qory-request-ed25519-v1`, the access key
    id, the machine id, the method in upper case, the request target exactly as sent, the
    timestamp as sent;
  - a POST: `qory-request-ed25519-v1`, the access key id, the machine id, `POST`, the
    request target exactly as sent, then the raw request body. A POST's signature covers
    its path and its body, so a body signed for one endpoint fails at every other; the
    secrets and rotation bodies contain a timestamp of their own.
- **Verification.** The server checks the access key id's shape, looks the access key up,
  verifies the key row's integrity code (Decision 6), then builds the message from the two
  headers, an absent machine id as an empty line, and verifies the signature under the
  stored public key, cofactorless (Decision 5). A missing or empty `X-Qory-Access-Key-Id`
  or `X-Qory-Signature-Ed25519` is an unsigned `401`. Every failure is `401` with
  `{"error":"unauthorized"}`, as §The server describes, a revoked access key's request
  included; the runner reports it as `unauthorized`. A request under a new access key that
  awaits approval, its only key, verifies, and every signed endpoint answers it with a
  signed `409` `key_pending`, discovery and the events endpoint included; at
  `access_key.url` it gets `401`. A pending key beside an approved current one, from a
  rotation or a re-key, gets `401` everywhere until it is approved (Decision 4). During
  the 24-hour window after a rotation or a re-key the server verifies under either key,
  except at `access_key.url`, which takes the current key only. "A header sent twice"
  covers `X-Qory-Access-Key-Id`, `X-Qory-Machine-Id`, `X-Qory-Signature-Ed25519` and
  `X-Qory-Timestamp`, and is answered before the `401`, unsigned.
- **The machine id's shape.** After the `429` and before `409` `key_pending`, a machine
  id that is absent or outside `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` is `400`
  `bad_request`, signed (Endpoint rules). `qory` checks its `machine-id` file against the
  pattern before the first request and replaces a file that fails, and a middlebox
  cannot change a signed line without the `401`, so this `400` meets only a broken
  client.
- **Authorisation rests on the access key alone.** The seal, the variant and the rate
  bucket are per access key. The server records the machine id as reported, for display,
  audit and per-instance events, and anyone who holds the access key can claim any machine
  id.
- **Unsigned headers.** The signature covers the access key id, the machine id, and the
  method, the target and the timestamp of a GET, or the method, the target and the body of
  a POST. `User-Agent`, `Content-Type`, `X-Qory-Contract-Version`, `X-Qory-Machine-Name`,
  `X-Qory-Delivery` and `X-Qory-Run-Configuration` are unsigned. The server takes every
  authorisation decision from the signed lines and body. It reads one unsigned header to
  decide: the contract version, which only selects a revision, so a changed value gets a
  `400` or another revision's answer, signed all the same and bound to the request. The
  display name is for display alone, outside the audit log's identities, and the
  delivery id and the run-configuration digest of an events POST are hints the signed
  events repeat. `X-Qory-Access-Key-Id` selects the key the signature must verify under,
  and is signed as well.
- **Digest headers.** `X-Qory-Configuration` stays opaque to the runner, which compares
  it only for change. The runner sends `X-Qory-Run-Configuration` on a POST whenever the
  run uses a fetched run configuration, with or without `security_policy`, and the
  server's answers carry the access key's variant's digest. The run configuration's
  `ETag` is unchanged.
- **The modes of a run.** With a server, events go to the server's `events.url` after a
  signed discovery fetch and a ping, as on main. The policy comes from the run
  configuration's `security_policy` when it has one, else the machine's; the
  connections from its `connections` when it has the member, else the runner file's;
  the variables from its `variables`. Stored values come from `secrets.url`, and keys
  change through enrolment, re-key and `access_key.url`. With `--local`, or with no
  server, everything comes from the machine.
- **A plain receiver** still works. It serves discovery, the events endpoint and
  `access_key.url`, and signs its answers under its own key, with no exemption. It may
  accept only public keys pasted into its own configuration and skip enrolment codes,
  and it lists no `secrets`. Its discovery lists `version`, `events`, `access_key`,
  `apiary_public_key`, `current_key` and `pending_key`. The reference receiver in this
  repository is such a receiver, and it answers labels the contract refuses with a signed
  `400` `invalid_request`.
- **`fixtures/signed/`** keeps its form: one request per file, `method`, `target`,
  `headers`, `body`, `expect` and `note`, with `expect_code` for a coded refusal. The
  headers are `X-Qory-Access-Key-Id`, `X-Qory-Machine-Id`, `X-Qory-Signature-Ed25519`,
  `X-Qory-Timestamp` on a GET and `X-Qory-Contract-Version`, signed under the fixture
  access key secret and machine id of Decision 5, with timestamps around `1700000000`.
  The files: `get-configuration-valid`, `-bad-signature`, `-stale`,
  `-no-machine-id` (`400`), `-header-twice` (`400`) and `-pending-key` (`409`
  `key_pending`); `get-run-configuration-valid` and `-labels-valid`; `batch-valid`,
  `-tampered`, `-replayed` and `-unknown-key`; `post-access-key-valid` (`202`) and
  `-bad-proof` (`409` `key_invalid`).
- **Known answers**, under the fixture access key secret and machine id (Decision 5):
  - the 115-byte message
    `qory-request-ed25519-v1\nak_f1xt0re000000000\nm_gYKDhIWGh4iJiouMjY6PkA\nGET\n/.well-known/qory-configuration\n1700000000`:
    `q7tv_FdWMid18PivX9Z3doioUEWHq1dRfB0cWDnVrxs5i1K0k6S7JB4269_m_JPT6PwXCCrZc-ndMIhN9ZjWCA`;
  - the same with the target `/.well-known/qory-configuration?x=1`, 119 bytes:
    `A2uagWUSKkoQqMk3JzLJecHKp0CoYVdtEedF1iCxxVoDcKX3T_6K7DeDsqUrSz9gse9c3H_89EVHPMX7fhYTBA`;
  - a POST to `/v1/secrets` of the fixture's secrets request, the 297-byte body below,
    SHA-256 `f104c0975354dd7cdae68b20b11c155471a83fa6752bb6aa486883f241659bd5`, a signed
    message of 383 bytes: `KKIgXirqfl7cbwfE66vkCYOfxVdRp4bqyynXAsLtfrGhukSEU4_pxI9LBhMp1UrREzSMRstweCsaWg1XQA9DAQ`.

    ```json
    {"version":1,"run_id":"01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a","labels":{"forge":"github.com","repository":"acme/shop"},"run_configuration":"sha256=4a6a9f4309a202d3c8663b8e6ce1d6ffce29afcf1f3516397e79b2ad9987f768","connections":["con_7q2m4k9x0d3h8w1c","con_0b5n6t2r9y4f7j3s"],"timestamp":1700000000}
    ```

### Enrolment

A POST to `<url>/.well-known/qory-enrolment`, beside discovery's path, because the
access key has no id yet. The request carries no `X-Qory-Access-Key-Id` and no request
signature; the code and the proof authenticate it. The server ignores `X-Qory-Machine-Id`
and `X-Qory-Machine-Name` here.

```json
{"version": 1,
 "code": "qec_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg",
 "name": "build-01",
 "public_key": "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
 "timestamp": 1700000000,
 "proof": "<64 bytes, base64url>"}
```

- `code` is an enrolment code, `qec_`, 26 Crockford base32 characters, 130 random bits,
  then `.` and the fingerprint of the server's public key, and during a rotation of the
  server's key a second `.` and the next key's fingerprint (Decision 6). `qory` sends it,
  and the proof covers it, in its normalised form: the 26 characters in upper case, `I`
  and `L` read as `1`, `O` as `0`, and hyphens removed, so a person may type it in either
  case and in groups. `U` and every character outside Crockford's alphabet are refused.
  The fingerprints are sent as issued. The schema's pattern is
  `^qec_[0-9A-HJKMNP-TV-Z]{26}(\.[A-Za-z0-9_-]{22}){1,2}$`, so the server refuses a code
  in any other form, `400` `invalid_request`, and builds the proof's second line from
  the code as sent. Settings › Access keys may show a code in groups, `qec_F1XT-0RE0-…`,
  because `qory` normalises.
- `name` is the access key's name for people, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, by
  default the host name of the machine that enrols it.
- `public_key` is the raw 32-byte Ed25519 public key.
- `proof` is the Ed25519 signature under the new key of five lines joined by `\n`, with no
  newline after the last: `qory-enrol-ed25519-v1`, the normalised code, the public key as
  in the body, the name, and the timestamp as the body's value in decimal seconds,
  canonical as `exp` is.

The server's order at enrolment is its own, because the code that authenticates the
request is in the body:

1. `413`; `415`; `400` `bad_request` for a header sent twice;
2. `429` per source address;
3. `400` `unsupported_contract_version`; `400` `invalid_request` for a body that is not
   JSON, fails its schema, a code outside the pattern included, or has another `version`;
4. `401` for a code it did not issue, or that is used, expired or cancelled, the whole
   code compared; for a code whose first fingerprint is not the server's current signing
   key's, or whose second, when present, is not its next key's; then for a `timestamp`
   outside ±300 seconds. A used code passes this step for a retry with the same public
   key for 15 minutes after its first use;
5. `429` per code;
6. `409` `key_invalid` for a `proof` that does not verify, then for a key the checks
   refuse or the index holds (Decision 4);
7. `201`: the server creates the key row with the code's workspace and settings, the
   code is used, and the answer is

```json
{"version": 1, "access_key_id": "ak_f1xt0re000000000", "approved": false,
 "stored_secrets": false,
 "apiary_public_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
```

Steps 1 to 4 go out unsigned; from step 5 on every answer is signed as Signed answers
describes, line 3 being the request's `proof` exactly as sent. A retry still passes steps
5 and 6, so a key since rejected, revoked or retired is `409` `key_invalid`. Otherwise it
receives a `201` for the same access key, built afresh: the access key's current
`approved`, `stored_secrets` and `apiary_public_key`, signed with the retry's own proof
as line 3, so a machine whose answer was lost still learns the access key's id. Any other
use of a used code is `401`. `qory` verifies the answer under the entry of
`apiary_public_key` whose fingerprint the code carries first, refuses an answer that lists
no such entry or does not verify under it, and pins only the entries whose fingerprints
the code carries; only then does it write `access_key_id` and `apiary_public_key`.

Known answers, under the fixture access key secret and the fixture signing key: the five
lines of the body above are 139 bytes, and `proof` is
`stcDcwasYMSLUxHX7A9AH-LXGRsRfpbHpMwGKd5ND6LI1WRsH10Rt4dhp8VmIYEau2sj31kCJSUzsDkSlCV8AQ`.
The answer above, without spaces, is 190 bytes, SHA-256
`106d9ddca5e1f8e624b902a0b975592a92f4a69c01238bbefd291b0611271517`; its six lines are 180
bytes, and `X-Qory-Signature-Ed25519` is
`yCgKNLXJxfaPS0yTNhHiwYbLrTPc09nYkuGBJX4COykQZEgd-NIjBGbo5s87fBJNYBZoRZxwlZK4joHgI4ZDBQ`.

A code made during a rotation of the server's key carries both fingerprints. With a
fixture next signing key from the seed of bytes 161 to 192,
`oaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2-v8A`, public key
`C0eCPnEJXdWb54rCccV27zifh7ZFYasHz5pOvNAtIEE`, fingerprint `52vzzF--Ic7qH_eZWi5K2A`,
which production refuses as it refuses every fixture, the code is
`qec_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg.52vzzF--Ic7qH_eZWi5K2A`. Over it,
with the body's other members as above, the five lines are 162 bytes, and `proof` is
`R2IX6Eyxs9kAClN3XbdGVUDglrdgsYrY8da3kitMtYg4uWsdQODpsQFv5Q22wCrHh9y6_f8ruU3YE2nIEBlhCg`.

### Re-key

A POST to `<url>/.well-known/qory-rekey`, beside enrolment's path. The re-key code and the
new key's proof authenticate it, so it works when the old secret is lost. The server
ignores `X-Qory-Machine-Id` and `X-Qory-Machine-Name` here.

```json
{"version": 1,
 "code": "qrk_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg",
 "access_key_id": "ak_f1xt0re000000000",
 "public_key": "iC0Oo7KGTnpYfz5pjOpEWZmDEuZV4F-l6LURnYuqyM0",
 "timestamp": 1700000000,
 "proof": "<64 bytes, base64url>"}
```

- `code` is a re-key code, `qrk_`, with an enrolment code's body, normalisation and
  fingerprints; the schema's pattern is
  `^qrk_[0-9A-HJKMNP-TV-Z]{26}(\.[A-Za-z0-9_-]{22}){1,2}$`.
- `access_key_id` must equal the one the code is bound to.
- `proof` is the Ed25519 signature under the new key of five lines joined by `\n`, with no
  newline after the last: `qory-rekey-ed25519-v1`, the normalised code, the access key
  id, the public key as in the body, and the timestamp as the body's value in decimal
  seconds.

The order is enrolment's, with these steps changed:

- step 4 is also `401`, unsigned, for an access key id other than the code's, and for a
  code whose access key is revoked or deleted, which ends its codes; a used code passes
  for a retry with the same public key for 15 minutes after its first use;
- after step 5, an access key that is itself awaiting approval is `409` `key_pending`:
  the administrator rejects it and enrols afresh instead;
- step 6 is `409` `key_invalid` for a `proof` that does not verify; then `409`
  `key_rotation_pending` for a new key while another awaits approval, a retry's own
  pending key excepted; then `409` `key_invalid` for a key the checks refuse or the index
  holds, this access key's current key, old key and tombstones included;
- step 7 keeps the key as the access key's pending key, with its sequence number, uses
  the code, and answers `202` with enrolment's members: `access_key_id`, `approved`,
  `stored_secrets` and `apiary_public_key`. Here `approved` says whether the posted key
  is the access key's current key: `false` while it is pending. A retry gets this `202`
  again, built afresh: `approved: true` once the key is current, and `401` once it is
  retired.

`qory` verifies the answer as at enrolment: under the entry of `apiary_public_key` whose
fingerprint the code carries first, pinning only the entries the code's fingerprints
name, and writing the pin only where none exists.

Known answers, under the new key of Rotation's known answer and the fixture signing key:
the five lines are 150 bytes, and `proof` is
`tlLAdBQVRnIgjjc1gyjUqSOkcDbqFQ8y4fxPYqVuWNg0jfpunNlEl9PK1lGdzpKxx_ysDYIdx3hW-8I9Hq63Bg`.
The answer, the 190 bytes of enrolment's known answer, SHA-256
`106d9ddca5e1f8e624b902a0b975592a92f4a69c01238bbefd291b0611271517`, has six lines of 180
bytes with status `202` and this proof as line 3, and `X-Qory-Signature-Ed25519` is
`HnXY-Cy1FxULYX6lZDPLaIXbe4dKsHEepRvheAhknfXQB5f99YtlbGpxfx-XhS67jN9b5Wwbe7oQU8-ckAGWAQ`.

### Rotation

A signed POST to `access_key.url`, under the current access key secret:

```json
{"version": 1,
 "public_key": "iC0Oo7KGTnpYfz5pjOpEWZmDEuZV4F-l6LURnYuqyM0",
 "timestamp": 1700000000,
 "proof": "<64 bytes, base64url>"}
```

`proof` is the Ed25519 signature under the new key of four lines joined by `\n`, with no
newline after the last: `qory-rotate-ed25519-v1`, the access key id, the new public key as
in the body, and the timestamp as the body's value in decimal seconds. The request
verifies under the access key's current key alone; the old key of an open window and the
pending key each get `401`. After the endpoint rules' order, the server refuses, in
order:

1. a `timestamp` outside ±300 seconds, `401`, unsigned;
2. a request signed by a key received before the stored-secrets flag's last enabling,
   while the flag is set, `409` `key_rotation_required`: the way forward is a re-key
   code (Decision 4);
3. a `proof` that does not verify, `409` `key_invalid`;
4. a new key while another awaits approval, or while a re-key code for the access key is
   outstanding, `409` `key_rotation_pending`; a request that repeats the pending key
   with a valid proof is answered as the first request was;
5. a key the checks refuse, or one the index holds, this access key's own keys and
   tombstones included, `409` `key_invalid` (Decision 4).

It keeps the key as the access key's pending key, with its sequence number, and answers
`202` with `{"version": 1}`.

Known answer: a new key from the seed of bytes 97 to 128,
`qak_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A`, public key
`iC0Oo7KGTnpYfz5pjOpEWZmDEuZV4F-l6LURnYuqyM0`; for `ak_f1xt0re000000000` and
`1700000000` the four lines are 97 bytes, and `proof` is
`03vpvsjoK68nHlk7R4koWxy9RLfAL2epFRgSYmH-PffmEq7nrsHouNeucx_6wEmbjLfkH6S8K1rDGLuN8mWFBg`.

### The secrets request and the envelope

A signed POST to `secrets.url`, once per run, after the run configuration and only when a
connection the run applies references a stored value:

```json
{"version": 1, "run_id": "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a",
 "labels": {"forge": "github.com", "repository": "acme/shop"},
 "run_configuration": "sha256=<64 hex digits>",
 "connections": ["con_7q2m4k9x0d3h8w1c", "con_0b5n6t2r9y4f7j3s", "con_5h1k8m3p6r0t4w9x"],
 "timestamp": 1700000000}
```

- `run_id` is the `subject` of the run's events and of the ping already accepted; the
  server does not require its run row to exist yet.
- `labels` are the run's labels exactly as the GET sent them.
- `run_configuration` is the digest exactly as the header contained it, which the runner
  has checked against the body.
- `connections` lists the connections the run applies, 1 to 32 unique ids: every
  connection of the document that is not a runtime connection, and at most one runtime
  connection, the run's own.

The server, in order, after the endpoint rules:

1. accepts `timestamp` within ±300 seconds, else `401`, unsigned;
2. refuses an access key not allowed stored secrets: `409` `secrets_not_allowed`. A key
   that awaits approval was answered `409` `key_pending` before this step, and a
   revoked one did not authenticate, `401`;
3. refuses a request whose key the server received before the access key's stored-secrets
   flag was last enabled: `409` `key_rotation_required` (Decision 4);
4. refuses a run whose row it has closed: `410` `run_closed`;
5. resolves the holder the labels select, with the GET's resolver, within the access key's
   workspace, and requires the current rendering of
   that holder's variant for the access key, or one superseded at most 15 minutes ago, to
   have the digest, else `410` `run_configuration_superseded`, a digest of the other
   variant included; that rendering's integrity code must verify, else `503`
   `unavailable`, as on the GET;
6. requires `connections` to be connections of that rendering, every one that is not a
   runtime connection and at most one runtime connection, else `409`
   `run_connections_invalid`;
7. applies the reseal rules (`409` `run_secrets_conflict`, `run_secrets_expired`);
8. parses the rendering's stored bytes and collects the distinct pairs of secret id and
   value id that the listed connections reference with an id;
9. for each pair, seals the stored value only when the secret still exists and has that
   value id, and, for a superseded rendering, every listed connection that references the
   pair is identical in the holder's current rendering (Decision 3). Any other pair is
   left out, and the runner refuses the run, `secret_unresolved`. The value sealed is the
   current one;
10. seals to the key the request's signature verified under, the u-coordinate of that
    Ed25519 public key, with a fresh ephemeral key, `exp` its own time plus 600 seconds.

The answer, `200`:

```json
{"version": 1,
 "sealed": {"suite": "x25519-sha256-aes256gcm",
            "access_key_id": "ak_f1xt0re000000000",
            "run_id": "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a",
            "run_configuration": "sha256=<64 hex digits>",
            "exp": 1700000600,
            "enc": "<32 bytes, base64url>",
            "ct": "<ciphertext and tag, base64url>",
            "sig": "<64 bytes, base64url, Ed25519 of Decision 6>"}}
```

A `410` here is no run, distinct from the events endpoint's "stop". The runner checks
the envelope's identifiers against its own and `exp` against its clock, then builds
`info` and `aad` from its own values alone. The server keeps its own record per access
key and run id, with the reason for each value it left out, and that record stays with
the server.

### Endpoint rules

For the enrolment and re-key paths, `access_key.url` and `secrets.url`:

- **Content type** `application/json`, else `415`; every answer `application/json`. A
  request has no `Content-Encoding` (a server answers `415` to one); the runner sends
  no `Accept-Encoding` but `gzip`.
- **Sizes.** A request body at most 32 KiB, else `413`. The largest secrets request has
  16 labels with a 64-byte key and a 256-byte value, at most 1,606 bytes each once every
  byte of a value is escaped as `\u00XX`, 25,696 in all; 32 connection ids, 736 bytes;
  and under 300 bytes besides: at most 26,732 bytes, about 26.1 KiB. Without escapes it is
  at most 6,252 bytes, about 6.1 KiB. The
  secrets answer is at most 5 MiB: 512 KiB of values, every byte escaped at six bytes,
  is 3 MiB of plaintext and 4 MiB in base64url. A refusal body is at most 64 KiB.
- **Members.** A member the schema does not define is refused, and so is a member name
  twice in one object. A POST's signature covers its path, and each endpoint's strict
  schema refuses a body meant for another as well. Member names are compared with case;
  a value decoded in part before an error is discarded; and `exp` is decoded as an
  unsigned integer, so a negative one is refused. The runner decodes the envelope and the
  plaintext with `encoding/json/v2` and `RejectUnknownMembers(true)`, since v2 accepts
  unknown members by default; a server whose decoder keeps the last of two members
  checks for them itself.
- **Order of refusals**, on every endpoint but enrolment and re-key (Enrolment has its
  own, which Re-key follows),
  discovery, the run-configuration GET and the events endpoint included: `413`; `415`;
  `400` `bad_request` for a header sent twice; `401`; `429`; `400` `bad_request` for a
  machine id absent or outside its pattern; `409` `key_pending`;
  `400` `unsupported_contract_version`; `400` `invalid_request` for a body that is not
  JSON, fails its schema, has another `version`, a `run_id` that is not a canonical
  lower-case UUID, a malformed digest or labels the labels' rules refuse; `401` for a
  `timestamp` outside ±300 seconds; then each endpoint's own. Every `401` is unsigned,
  wherever it falls; every other answer from `429` on is signed, except at enrolment and
  re-key, whose steps 1 to 4 go out unsigned, the `429` per source address and the
  `400`s included.
- **Rate limits** are the server's policy, per access key, and on the enrolment and
  re-key paths per code and per source address. A `429` at run start is no
  run, `rate_limited`; an event POST's `429` is retried as today.
- **Answer headers.** Answers of these three endpoints contain neither digest header.
- **Counts.** At most 32 connections, 16 references per connection, 16 hosts and 32 paths
  per service, 32 distinct stored values and 512 KiB of values per secrets request, and a
  settings document of 64 KiB (65536 bytes) per integration. The server checks the counts
  per holder when it renders.
- **Values.** Every secret value is UTF-8 text, 1 to 16384 bytes, with no NUL; a binary
  secret is stored encoded, base64 for one, as its consumer expects. A value linked to a
  runtime or service connection, which goes into a header, also has no byte
  `0x01`–`0x08`, `0x0A`–`0x1F` or `0x7F` and no leading or trailing space or tab; bytes
  from `0x80` travel as `obs-text`, which some hosts refuse. A value linked only to
  integrations, which goes on standard input, may contain line breaks, such as a PEM key.
  The server checks a value against every link when the value is saved and when a link
  is saved, such as an existing PEM key linked to a service connection; the runner checks
  it where it uses it, `secret_value_invalid`. A variable's value is at most 4096 bytes
  of UTF-8, with no NUL, carriage return or line feed; a holder's resolved variables are
  at most 128, and at most 64 KiB, names and values. The server refuses a save that would
  take any holder over these limits, and a runner refuses a document over them,
  `run_configuration_invalid`.

### info and aad

`lp(x)` is `x`'s length as a u16 big-endian, then `x`; `lp32(x)`, in the envelope's
signature (Decision 6), is the same with a u32.

| Input | Bytes |
|---|---|
| `info` | `qory secrets v1` ‖ `0x00` ‖ `0x0020` ‖ `0x0001` ‖ `0x0002` ‖ lp(access key id) |
| `aad` | lp(run id) ‖ lp(access key id) ‖ lp(run configuration digest) ‖ lp(`exp` in canonical decimal) |

With the example values, `info` is 43 bytes and `aad` 144. The set of connections is not
in `aad`: the answer's signature binds the answer to the request that listed it, and the
plaintext echoes it. The access key's public key is in neither: the KEM binds the
recipient's public key into the shared secret, and the access key id and the request's
signature imply the key.

### The sealed plaintext

```json
{"version": 1,
 "run_configuration": "sha256=<64 hex digits>",
 "connections": ["con_0b5n6t2r9y4f7j3s", "con_5h1k8m3p6r0t4w9x", "con_7q2m4k9x0d3h8w1c"],
 "values": [
   {"secret": "sec_3fz8k2m9q4w7x1d6", "value": "<the value>"},
   {"secret": "sec_9c4r7t2y5b8n1h3e", "value_id": "production", "value": "<the value>"}]}
```

- `run_configuration` equals the digest the runner computed, and `connections`, sorted,
  equals the set it sent. The pairs of `secret` and `value_id` are exactly the distinct
  pairs those connections reference with an id, each once, sorted by `secret` and then by
  `value_id`, a value without one first: a missing pair is
  `secret_unresolved` with the connections that reference it, an extra or repeated one,
  another digest or another set `secret_sealed_mismatch`.
- A value follows the value rules above, for where it is used.
- The runner decodes with `encoding/json/v2` under the options of Endpoint rules; v2
  refuses a member name twice in one object by default (verified on Go 1.27.1):
  `secret_sealed_invalid`. It reports its own error text in place of the decoder's and
  the validator's, whose messages can quote input.

### Signed answers

Every answer to a request that verified, and every answer to an enrolment or a re-key
whose code the server accepted, contains `X-Qory-Signature-Ed25519: <64 bytes, base64url>`, the Ed25519
signature under the server's signing key, `APIARY_SIGNING_SECRET` (Decision 6), of six
lines joined by `\n`, with no newline after the last:

1. `qory-answer-ed25519-v1`;
2. the status, three decimal digits;
3. the request's `X-Qory-Signature-Ed25519` value exactly as sent, or for an enrolment
   or a re-key the body's `proof`;
4. the lower-case hex SHA-256 of the body as the server produced it, before any content
   coding, which for an empty body is the SHA-256 of the empty string;
5. the answer's `X-Qory-Configuration`, or empty when the answer has none;
6. the answer's `X-Qory-Run-Configuration`, or empty when the answer has none.

The server holds no secret shared with the access key, so this is the only answer
signature. The server signs in a hook that runs before the answer is sent, over every
answer to a verified request, `202`, `404` and `503` included. Every `401` goes out
unsigned, wherever it falls, and so does a `400`, `413` or `415` sent before verification;
at enrolment and re-key, steps 1 to 4 are unsigned. Every signed answer contains
`Cache-Control: no-store, no-transform`. Every runner verifies the signature under its
pinned `apiary_public_key`, so every machine with a server needs the pin (Decision 6). At
run start the runner treats an answer without a valid signature as no run,
`answer_unsigned`. During the run an event answer without one is no answer, retried as
today, its headers unread; a reload's fetch without one fails the reload. A code in a body
is reported only from a signed answer; a refusal body over 64 KiB counts as unsigned. The
resend after a runner stops verifies signatures too. Line 3 binds the answer to its
request, and through the request's signature to the access key and the machine id that
sent it. Ed25519 signatures are deterministic, so two identical GETs in one second share a
request signature and receive the same bytes. Two retries of one secrets POST share a
request signature too, and each answer seals afresh, so their bytes differ; either answer
is bound to that request, and a swap between them is harmless.

Two known answers under the fixture signing key, for the GET of discovery signed
`q7tv_FdWMid18PivX9Z3doioUEWHq1dRfB0cWDnVrxs5i1K0k6S7JB4269_m_JPT6PwXCCrZc-ndMIhN9ZjWCA`
under the fixture access key secret (The access key and signed requests):

- `200`; the discovery body as an access key's current key receives it with no key pending, 292 bytes:

  ```json
  {"version":1,"events":{"url":"https://qory.example/v1/events","types":["*"]},"access_key":{"url":"https://qory.example/v1/access-key"},"apiary_public_key":[{"alg":"ed25519","public_key":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}],"current_key":"ZbYGc9btiEvwHCwiLYKtoA","pending_key":null}
  ```

  SHA-256 `05441755e189396d00e6f1edbd73fd4f06446c006ec596e9c08004d324023281`;
  `X-Qory-Configuration: sha256=` and the same hex; no run-configuration digest. The six
  lines are 251 bytes:
  `X-Qory-Signature-Ed25519: hjjyIfUkhWR5HSIkrGiOIaz-NXbNKG0faMGQ-Bl9Bt9K7Ps-Mooel1HqqcAubwUUjqoMWEDXMox4Fwgle237Cw`
- `404`, empty body, no digest, 180 bytes:
  `X-Qory-Signature-Ed25519: NOGTucKY0qKpLV23wlSkyLthtXLrilzBrta6pDdFVKh6eykIboIapfBPWR4HmdtvCB2BIePL9GBrby0VSS8dDw`

### Coded refusals

After verification, `409`, `410` (`run_configuration_superseded`, `run_closed`), `429`,
`503` or `400`, `application/json`, signed: `{"error": "<code>", "names": ["…"]}`. Every
`401` is `{"error":"unauthorized"}`, unsigned, and the runner reports it as
`unauthorized`. `413`, `415`, and `bad_request` for a header sent twice, come before
verification, unsigned, and are reported by status only; `bad_request` for a machine id
comes after it and is signed.

### Values at rest (guidance for the server)

Not part of the contract. The server encrypts each stored value with AES-256-GCM under a
key derived from its instance key with HKDF-SHA256, stored with a key id, and binds as
associated data `lp("qory-secret-v1") ‖ lp(workspace id) ‖ lp(secret id) ‖ lp(value id)`,
so a value moved to another secret or value id no longer decrypts. The instance key is
`APIARY_ENCRYPTION_SECRET`. The server stores access keys' public keys and no secret of
theirs. Organisation secrets are not in 0.7.0. Connections, service definitions and renderings are covered by the
integrity codes of Decision 6.

### Events

**`dev.qory.run.refused`**, new: emitted in place of `dev.qory.run.started` when a run
does not start after the ping, as the run's first and last event; the runner waits up
to fifteen seconds for its delivery. It is always sent, like the ping, whatever
`events.types` lists. Data: `code`; `connection`, the connection's id, for every
refusal that concerns one; `names`, names alone; `providers` with `secret_unresolved`;
`status` when the code came from the server. Every no-run after an accepted ping emits
it, whatever stops the run: a refusal of Runner behaviour's checks, the wall check
included, which runs after the ping; an integration whose `describe` or `credential`
does not start or does not answer, `integration_failed`; a tool that does not start or
does not listen in time, `tool_not_started`; and any other failure before
`dev.qory.run.started`, such as the wall, the image or the runtime's launch,
`start_failed`. For these three, `names` contains the integration's or the tool's name
where there is one, and the error the caller receives contains the reason the program
wrote. Main's other refusals before the start take codes too:

| Case | Code |
|---|---|
| a tool the machine does not define | `tool_unknown` |
| a tool selected twice, an argument its definition does not provide for, or a host two tools serve | `tool_invalid` |
| under `enforce`, a tool host the allow list does not cover | `tool_host_denied` |
| a value the run passes for a tool's placeholder | `placeholder_conflict` |
| an image the machine does not define | `image_unknown` |
| an image selected without a wall, defined twice, or a daemon without a runtime | `image_invalid` |
| a fetch of the run configuration that answers other than `200`, with no code in a signed body | `fetch_failed`, with `status` |
| a transport failure on that fetch | `fetch_failed`, without `status` |
| a fetched `security_policy` the schema refuses | `run_configuration_invalid` |
| a fetched `security_policy` and the command's `--policy` together | `policy_conflict` |

**`dev.qory.run.policy_applied`** loses `credentials` and gains `connections`, in the
order of the run's connections:

```json
"connections": [
  {"id": "con_7q2m4k9x0d3h8w1c", "kind": "runtime", "name": "claude",
   "secrets": [{"id": "sec_3fz8k2m9q4w7x1d6", "name": "CLAUDE_OAUTH"}],
   "uses": [{"hosts": ["api.anthropic.com"], "scheme": "bearer"}],
   "hosts_denied": []},
  {"id": "con_5h1k8m3p6r0t4w9x", "kind": "service", "name": "Sentry",
   "secrets": [{"name": "SENTRY_AUTH", "source": "external"}],
   "uses": [{"hosts": ["sentry.io"], "scheme": "bearer", "paths": ["/api/0/*"]}],
   "hosts_denied": ["sentry.io"]}]
```

`secrets` lists the references each connection received, by `id` for a stored value, name
and value id; `uses` where and how the proxy sets each value; `hosts_denied` the
connection's hosts the policy in force denies, recomputed in every further
`policy_applied`. An integration connection's entry also records its `argument`, `version`
and `repository`, so the record shows what each credential is minted for. `terminated`
stays: the hosts where the proxy terminates TLS in this run, namely those a connection
sets a value on, those a tool serves, and those with path rules; a host verified against
public roots only is among them as a connection's host. `dev.qory.run.egress` has
`connection`, the id, in place of `credential`, matching a run configuration's
`^con_[0-9a-hjkmnp-tv-z]{16}$` or the runner file's `^[a-z0-9][a-z0-9_-]{0,63}$`, and
`renewal_failed` (Integrations). `wall:trace` and `wall:public-roots` go in `rule`, as
`wall:own-address` does on main: `decision: denied`, `outcome: refused`, and the session
gets a `403`. The heartbeat schema's "a receiver that misses two in a row may consider the
run lost" reads "misses two in a row, that is, receives none for 3 × `interval_seconds`",
as Decision 4 says. A top-level `variables` reports the variables by name:

```json
"variables": {"names": ["APP_REGION", "NODE_ENV"],
              "overridden": ["NODE_ENV"],
              "locked": ["APP_REGION"],
              "denied": ["ANTHROPIC_BASE_URL"],
              "unwalled": []}
```

Each server variable appears in exactly one of `names`, `denied` and `unwalled`.
`names` lists those the run applies; `overridden` those of them, unlocked, whose value a
machine-level variable replaced; `locked` those, locked, that kept the server's value
against a machine-level variable; `denied` the server's variables left out: a denied
name, a reserved name, a placeholder's name, one a `secrets.local` value reads, or one the
runtime's `Prepare` or the harness sets; `unwalled` the server's variables an unwalled
run left out because `variables.unwalled` is `ignore`, which then holds every one of them.
Each list is sorted and may be empty. A
top-level `connections_withheld` lists, by `id`, `kind` and `name`, the connections the
server left out of the variant for an access key without stored secrets (The run
configuration), and is empty otherwise. With no
`security_policy`, `url` and `run_configuration` are allowed beside `source` `config` or
`none`. Events carry names and ids alone.

## Runner behaviour

Order at run start; the steps not listed are §Sequence's.

1. With a server: validate the server document; without a pinned `apiary_public_key`,
   `apiary_public_key_missing`, before any request. Every request is signed with the
   access key secret. Every answer's signature is verified under the pin before its body or
   headers are read.
2. Discovery: a signed `409` `key_pending` is no run, `key_pending`; a `401` is
   no run, `unauthorized`. Ping. When discovery lists `secrets` and the run has no wall:
   `server_needs_wall`. When it lists `secrets`, the runner reports that to its caller,
   and `qory` writes the `stored-secrets` marker; a marker it cannot write is no run.
   When it lists `key_rotation_required`, `qory` gives one of Decision 4's three
   messages, from `current_key` and `pending_key`.
   Before discovery, `qory` checks the run's labels against the checkout's pinned ones,
   `labels_changed`, and its `machine-id` file.
3. When the configuration lists `run`: fetch the run configuration; recompute its digest;
   decode it with `encoding/json/v2`; validate it against the schema and the limits.
   Without `security_policy`, the machine's policy is the run's; without a
   `connections` member, or without a run configuration, the connections are the runner
   file's. Keep `withheld` for the record.
4. Check the connections: connections without a wall; duplicates; the runtime connection
   for the run's runtime kept and any other set aside; declarations and `one_of`, a
   required group included; hosts and `headers.json`; the mounts against the runner's
   files and the runtime's credential files; for each integration, the machine's
   `arguments` and `settings` bounds.
5. For each integration connection: find the program, run `describe`, compare its name
   and version, and read its hosts, which the steps below need. A `describe` that does
   not start or does not answer is `integration_failed`.
6. When a connection the run applies references a stored value: no `secrets` section in
   discovery is no run, `secrets_endpoint_missing`. Otherwise the secrets request with
   the applied connections; verify the envelope's signature under the pinned
   `apiary_public_key`; check the envelope and open it with the X25519 key of the
   access key secret the request was signed with; check the plaintext.
7. Resolve every external reference through the providers in order, and check each
   machine value's `hosts` against where its connection sends it, an integration's
   hosts being those `describe` reported.
8. Check the hosts and the values together: `connection_host_conflict`, the value rules
   for where each value goes; validate each integration's settings, values inlined,
   against its description; compute `hosts_denied`.
9. Resolve the variables: in an unwalled run with `variables.unwalled` unset or
   `ignore`, leave out every server variable; otherwise leave out every denied or
   reserved name, every placeholder's name and every name a `secrets.local` value reads;
   apply the machine's level by precedence. Then check the environment: `variable_reserved`,
   `runtime_secret_conflict`, and placeholders the run passes a value for,
   `placeholder_conflict`.
10. Run each integration's `credential` with its settings document; check its answer. An
    integration that does not start or does not answer is `integration_failed`.
11. Then §Sequence from the tools on. A tool that does not start or does not listen in
    time is `tool_not_started`; any other failure before the next step, such as the wall,
    the image or the runtime's launch, is `start_failed`. The proxy receives the uses and
    the hosts it verifies against public roots only (`tls.public_roots_only`); the
    launch's environment is the run's and the variables resolved by precedence, then the
    runner's own, the placeholders, and, in a walled run, the runtime's other declared
    and reserved variables as empty.
12. `dev.qory.run.started`, then `dev.qory.run.policy_applied`.

Every no-run after an accepted ping, at steps 2 to 11, emits `dev.qory.run.refused` as
the run's last event, a tool or an integration that does not start included. The caller
receives the error in every case, with or without a ping. Values live in the runner's
memory alone; at run end they are unreferenced, since Go cannot wipe a string.

## Refusal codes

| Code | Decided by | When |
|---|---|---|
| `bad_request` | server, `400` | a header sent twice, before verification, unsigned; after the `429`, a machine id absent or outside its pattern, signed |
| `unsupported_contract_version` | server, `400` | `X-Qory-Contract-Version` other than `1` |
| `invalid_request` | server, `400` | a body that is not JSON, fails its schema or has an unknown member; labels the contract refuses |
| `rate_limited` | server, `429` | the access key's rate, or the enrolment path's, is exceeded |
| `unavailable` | server, `503` | a stored rendering fails its integrity code, on the GET or the secrets request; a failing key row is `401` |
| `key_invalid` | server, `409` | at enrolment, re-key, paste or rotation, about a public key: a `proof` that does not verify; a key that is not a canonical encoding of a point on the curve, is of small order or not of prime order, has y = 1, or is the published fixture key; or a key the index holds, any access key's current, pending or old key or any tombstone, this access key's own included. One answer for all, so a refusal reveals nothing about other access keys |
| `key_pending` | server, `409` | on every signed endpoint except `access_key.url`, which answers `401`, discovery and events included, after the machine id's `400`: a request under a new access key that awaits approval, its only key; at re-key, an access key that awaits approval itself |
| `key_rotation_pending` | server, `409` | a rotation or a re-key while another new key awaits approval, or a rotation while a re-key code for the access key is outstanding |
| `key_rotation_required` | server, `409` | while the stored-secrets flag is set, the secrets request or a rotation signed by a key the server received before the flag's last enabling, whatever other keys the access key holds |
| `secrets_not_allowed` | server, `409` | the access key is not allowed stored secrets |
| `run_closed` | server, `410` | the server has closed the run's row |
| `run_configuration_superseded` | server, `410` | no rendering of the holder's variant for the access key with that digest, current or within 15 minutes; a digest of the other variant included |
| `run_connections_invalid` | server, `409` | the listed connections are not those the rendering requires |
| `run_secrets_conflict` | server, `409` | a reseal with another digest, set of connections or verifying key |
| `run_secrets_expired` | server, `409` | a reseal after the first payload's `exp` |
| `secrets_endpoint_missing` | runner | a stored value referenced and discovery lists no `secrets` |
| `envelope_signature_invalid` | runner | an envelope without a valid signature under the pinned `apiary_public_key` |
| `apiary_public_key_missing` | runner | a server and no pinned `apiary_public_key`, decided before the first request |
| `answer_unsigned` | runner | an answer at run start without a valid signature, other than a `401` |
| `unauthorized` | runner | a `401` at run start: the access key is unknown or revoked, or its key or row does not verify |
| `labels_changed` | `qory` | a local checkout's derived labels differ from those pinned at its first run the server accepted, the checkout keyed by its resolved real path, until the user confirms with `--relabel` |
| `server_needs_wall` | runner, and `qory` offline | with a server, after the ping: discovery lists `secrets` and the run has no wall; offline, decided by `qory` before the run: an unwalled run, `--local` included, while the `stored-secrets` marker exists |
| `mount_contains_runner_files` | runner | a mount is, contains or lies inside the runner's configuration directory, the directory of an integration program, a tool program, the wall's `docker` command or helper, the `docker` configuration directory, or a `secrets.local` file |
| `mount_contains_credential_files` | runner | a mount is or contains a file the run's runtime lists in `credential_files` |
| `run_configuration_invalid` | runner | the decoder, the schema or the limits refuse the document, a fetched `security_policy` included |
| `fetch_failed` | runner | the run configuration's fetch answers other than `200` with no code in a signed body, reported with `status`, or fails in transport, without it |
| `policy_conflict` | runner | a fetched `security_policy` and the command's `--policy` together |
| `run_configuration_digest_mismatch` | runner | the recomputed digest differs from the header's |
| `connection_needs_wall` | runner | a connection and no wall |
| `connection_duplicate` | runner | two connections with one id |
| `connection_secret_unknown` | runner | a reference under a key the kind does not declare, or an `auth` with an undeclared id |
| `connection_host_invalid` | runner, and the server on save | a service or runtime host that is not an exact DNS name, such as an IP literal |
| `connection_host_public_suffix` | runner | an integration's `*.` host over a public suffix |
| `connection_header_reserved` | runner, and the server on save | a header name `headers.json` refuses, in a service, a runtime declaration or an integration's answer |
| `connection_host_conflict` | runner | hosts of two connections, or of a connection and a tool, overlap |
| `runtime_connection_duplicate` | runner | two runtime connections for one runtime |
| `runtime_secret_choice` | runner | more than one declaration of one `one_of` group |
| `runtime_secret_missing` | runner | a walled run with no connection that supplies a required group; reported with the group's id |
| `runtime_secret_conflict` | runner | the run's environment contains a variable the runtime declares or reserves |
| `integration_missing` | runner | the machine has no integration of that name |
| `integration_name_mismatch` | runner | `describe`'s `name` differs from the connection's |
| `integration_version_mismatch` | runner | `program_version` differs from the connection's `version` |
| `integration_argument_not_allowed` | runner | the argument does not match the machine's `arguments` pattern |
| `integration_settings_not_allowed` | runner | a setting outside the machine's `settings` bound, or settings other than `{}` for a server-sent integration with a machine value and no `settings` bound |
| `integration_hosts_exceeded` | runner | the program's answer claims hosts above those `describe` lists |
| `integration_settings_invalid` | runner | the settings fail the program's own description |
| `integration_settings_too_large` | runner | the settings document exceeds 65536 bytes (64 KiB), refused before the program starts |
| `integration_failed` | runner | an integration's `describe` or `credential` does not start, exits non-zero or answers what its schema refuses |
| `tool_not_started` | runner | a tool exits before it listens, or does not listen in time |
| `tool_unknown` | runner | a tool the machine does not define |
| `tool_invalid` | runner | a tool selected twice, an argument its definition does not provide for, or a host two tools serve |
| `tool_host_denied` | runner | under `enforce`, a tool host the allow list does not cover |
| `image_unknown` | runner | an image the machine does not define |
| `image_invalid` | runner | an image selected without a wall, defined twice, or a daemon without a runtime |
| `start_failed` | runner | any other failure after the ping and before `dev.qory.run.started`, such as the wall, the image or the runtime's launch |
| `secret_value_id_missing` | runner, and the server on save | a reference to a secret with several values without a value id |
| `secret_unresolved` | runner | no provider resolves it, or the sealed list lacks it |
| `secret_hosts_exceeded` | runner | a machine value sent to a host its `hosts` do not cover |
| `secret_value_invalid` | runner | a value that breaks the value rules for where it goes, or a `:` in a basic username |
| `secret_sealed_invalid` | runner | the envelope does not open, an identifier is not the runner's, or the plaintext is malformed |
| `secret_sealed_expired` | runner | `exp` passed by more than 300 s, or more than 900 s ahead |
| `secret_sealed_mismatch` | runner | an extra or repeated value, another digest or another set of connections |
| `variable_reserved` | runner | the run's environment passes a `QORY_` variable, `QORY_ACCESS_KEY_SECRET` among them, or a variable a `secrets.local` value reads into the enclosure; the runner's own `QORY_RUN_ID` and `QORY_RUN_SOCKET` are exempt |
| `placeholder_conflict` | runner | the run passes a value for a placeholder, or a connection other than the runtime's sets a placeholder in a variable the runtime declares or reserves |

## Security considerations

| Threat | What protects | What does not |
|---|---|---|
| A TLS-terminating middlebox between the runner and the server, without the access key secret or the server's signing secret | It cannot read a stored value; it cannot alter the connections, the policy, the variables or the digests, nor replay an older answer; it cannot move a request to another access key, since the key's id is a signed line and one public key belongs to one access key; `no-transform` keeps a proxy from re-coding a signed answer | It reads the document. At the start it can only refuse; during a run, dropping answers keeps the policy in force |
| A proxy between the runner and a destination host, whose authority the machine trusts | For a stored value, `tls.public_roots_only`, on by default: the proxy verifies that host against public roots only, so the authority the machine added receives nothing | It reads a machine value there, and a stored value on a machine that sets `tls.public_roots_only: false`: that leg is then ordinary TLS against the machine's trust store. An integration program's own connections use its own TLS settings |
| The server's logs and answer caches | Ciphertext only; `Cache-Control: no-store` | — |
| A read of the server's database | Values encrypted under a key derived from the instance key; the server stores access keys' public keys only, so a reader of the database cannot act as an access key | A reader with the instance key reads every stored value and, while `APIARY_SIGNING_SECRET` is unset, signs as the server |
| A write to the server's database | Integrity codes over connections, custom definitions, every rendering, every key row and every code, with a per-row version, verified on every request and before sealing: a writer cannot swap an access key's public key, move an access key to another workspace, enable stored secrets, insert a code, or insert or approve an access key; seals taken from the verified rendering's bytes; audit | A writer with the instance key, or a change through the server's own pages |
| A compromised server or operator | — | It reads every stored value, routes it, chooses an integration's argument and settings, sends an observe-everything policy, and learns which `secrets.local` names exist from `secret_unresolved`. The machine's `hosts` bounds, its `arguments` and `settings` bounds, both required for a server-sent integration with a machine value, and the pin, required on every machine, are what remain |
| A workspace administrator, or anyone who may save a custom service and link a secret | In 0.7.0 only owners and administrators may: linking needs `secret.use` on the secret, which only they hold, and only they define custom services, edit variables, create codes and enable stored secrets on an access key | Choosing the host is reading the value |
| A party that can rewrite the administrator's browser session with the server | — | The session is trusted: such a party can show a false pin, fingerprint or code, and can equally approve keys itself. Comparing fingerprints out of band, such as over another channel with the machine's operator, is the operator's option |
| Whoever may edit variables | Only owners and administrators; an unwalled run receives no server variable unless the machine sets `variables.unwalled: accept`; the deny list, the runtime's `denies` and the machine's `variables.deny` leave out what would run code, move a credential or change trust | With `accept`, the deny list matters for unwalled runs, and it cannot be complete |
| A holder of an access key secret, on the path | Every runner pins the server's key, so it forges no answer and no envelope; routing is bound to the document | It signs requests as that key, under any machine id, and opens what is sealed to it, as the next rows say |
| A machine claiming another machine's id | Authorisation rests on the access key alone | Anyone who holds the key can claim any machine id; the id serves display, audit and per-instance events alone |
| A holder of the server's signing secret, on the path | Routing is bound to the document, so real values go only to the hosts the stored rendering names; it holds no access key secret | It forges documents and seals values of its own choosing to every machine that pins the key, until the key is rotated and the pins with it |
| A link removed, or a host moved, while a run starts | A superseded rendering seals a pair only when every listed connection that references it is byte for byte identical in the current rendering, hosts included | — |
| Another runtime's credential | The secrets request lists one runtime connection, the run's own; the server seals nothing for any other | — |
| A server that sends a machine value elsewhere | The machine's own `hosts` on each `secrets.local` entry: `secret_hosts_exceeded` | — |
| A machine, choosing labels | Labels resolve only within the access key's workspace | Repository scope is no boundary against a machine: an access key is scoped to its workspace |
| An agent choosing the next run's labels, such as by rewriting `.git/config`'s origin | A CI or job spec passes labels explicitly; for a local checkout, `qory` pins the labels of its first run the server accepts, in the runner file's directory, which walled agents cannot reach, and a later run whose derived labels differ is `labels_changed` until the user confirms with `--relabel` | Pinning is trust on first use: a checkout's first run, or the same checkout at a new path, pins what the origin says then. An unwalled agent of the same user can rewrite the pin file as easily as `.git/config`. A user who confirms without reading the change |
| An access key secret an unwalled agent read before stored secrets were enabled | Stored values open only with an eligible key, received after the flag's last enabling by the server's sequence; a key received before can neither receive values nor rotate, `key_rotation_required`, whatever other keys the access key holds; only a re-key code from an owner or administrator brings an eligible key; enabling the flag tombstones a pending key; every key command writes the `stored-secrets` marker before it generates the key and refuses while an unwalled run's lock is held; an enrolment retry reuses a secret only for the same code within 15 minutes | A pasted key generated before the flag and pasted after it; the owner pastes a key generated for the purpose. An agent that keeps a process running outside `qory` after its session ends, and so holds no lock |
| An unwalled agent reading `access-key-secret.next` | The key lock: no key command generates a key while an unwalled run's lock is held, and no run starts while a key command runs | An unwalled agent of the same user outside `qory` (Issues, item 4) |
| A stolen code | Single use, valid for at most 15 minutes, bound to one workspace and one access key's settings, or for a re-key code to one access key; until an owner or administrator approves the key, after comparing fingerprints, it waits; the page shows how a pending key arrived, and `qory` tells its user when their code was already used | An approval given without comparing the fingerprint. The access key id is public, so a stolen re-key code works for anyone, and its result is a pending key on an existing access key, eligible when the flag is set |
| A stolen access key secret | Stored secrets only for access keys allowed them; revocation, which cuts off every machine using the key; a re-key code, which outranks a self-signed rotation, after which the administrator ends the old key's window at once; rotation under the current key only, whose new key needs approval after comparing its fingerprint; a second rotation refused while one is pending; the recomputed digest binds values to the document the server rendered | Whoever has it is the access key, on any machine, and receives the stored values sealed to it until it is revoked. Base mode has no forward secrecy: with recorded traffic or the server's logs, the secret opens every past payload sealed to it, so access keys are rotated |
| One public key on two servers | `qory` keeps one secret per server and moves a secret aside before it enrols with another, so a compromise of one server's records involves no key another server trusts | This is a `qory` rule, not a cryptographic guarantee: an administrator who pastes one public key into two servers is outside its reach, and the request string names no server |
| A member of the machine's `docker` group | — | It is root on the machine, with every file and process of the runner |
| Whoever chooses a run's labels, such as a repository's workflow file | — | Labels select the holder, and so whose connections and credentials the run receives |
| An agent reading the machine's configuration, or replacing a program the runner starts | `server_needs_wall`; `qory` refusing unwalled runs while `stored-secrets` exists; `mount_contains_runner_files`; `QORY_ACCESS_KEY_SECRET` and `secrets.local` sources refused in the enclosure | An unwalled agent of the same user outside `qory` (Issues, item 4) |
| A model credential reaching the enclosure | `runtime_secret_conflict`; in a walled run, the runtime's other declared and reserved variables set to empty; `mount_contains_credential_files` | A credential file baked into the image |
| A credential that mints credentials | A declaration's `paths`, `/v1/*` for Claude Code | A minting path inside the allowed paths gives the agent a readable credential; to verify for `api.anthropic.com` |
| The agent in the enclosure | A placeholder in the environment, the value set outside on the kind's hosts only; `TRACE` and `TRACK` refused there | A host that sends a request's headers back returns the value (§Limits); `headers.json` keeps the common echoes out |
| An integration program | Its settings on standard input only; `describe`'s name must match; the machine's `arguments` and `settings` bounds, both required when a server-sent connection references a machine value; its standard error redacted, values, their lines and its credential, before it is reported | It runs as the runner's user and is trusted, and sends the raw value where it chooses; a value it transforms before writing escapes redaction |
| A payload replayed | Run id, access key id, digest and `exp` in `aad`; the recipient's public key in the KEM's context; the timestamp; the reseal window bound to one digest, set and key; a new run id per attempt | — |
| A signed body sent to another endpoint | The request target in the request signature; strict schemas on every endpoint | — |
| The runner's own memory | Unreferenced at run end; optionally `PR_SET_DUMPABLE 0`, `RLIMIT_CORE 0`, `mlock` | A debugger or the kernel of the machine |

## Tests and release gates

- **The API key path is a release gate for 0.7.0**, as the OAuth credential path already
  passes end to end:
  - a proxy unit test that overwrites a session's `X-Api-Key` stand-in with the real value
    on a terminated host;
  - a wall conformance check in `wall/walltest`: the enclosure sends `x-api-key:
    <stand-in>` to a test origin acting as the runtime's host; the origin must receive the
    real value, and the enclosure never sees it;
  - both run as an explicit check in CI.

  - the exact paths Claude Code requests on `api.anthropic.com` with each credential,
    so the declarations' `paths` bound them, that a request outside `/v1/` is refused, and
    whether a path there creates an API key from an OAuth credential.

  A real Claude Code run with a real API key stays a manual check before the release,
  because CI has no Anthropic key.
- **Empty means unset.** A check that Claude Code treats an empty `ANTHROPIC_AUTH_TOKEN`,
  `ANTHROPIC_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN` as unset and uses the chosen stand-in.
- **Fixtures:** `fixtures/sealed/` (Decision 5) with the envelope's Ed25519 `sig`; the
  fixture access key secret with its Ed25519 and X25519 public keys; the request, answer,
  enrolment and rotation signatures; the small-order list; run configurations
  with each kind of connection and invalid ones per refusal the schema can express,
  `runtimes.json` against the descriptors, `headers.json` against its sources, and
  `fixtures/signed/` with answers.
- **Integrations:** a fake program that checks it is started as `<program> <role> --`
  with exactly one argument after `--` for `credential`, the empty string without an
  `argument`, and no flag; that its standard input is one document, `{}` for a connection
  without `settings`, never a terminal, and closed once written; that the document
  arrives fresh on a renewal; that a document over 65536 bytes is refused before the
  program starts, `integration_settings_too_large`; that a program that never reads does
  not stall the run; that no value reaches its arguments or environment; that a value it
  writes to standard error is reported redacted, its credential and every line of a
  multi-line value included; that a program whose `describe` reports another name is
  refused; that an answer claiming hosts above `describe`'s is
  `integration_hosts_exceeded`; and that a server-sent connection with a machine value
  and no `settings` bound runs with `{}` and is refused with any other settings.
- **Refused runs:** every no-run after an accepted ping emits `dev.qory.run.refused` as
  the run's last event, an integration that does not start (`integration_failed`) and a
  tool that does not listen (`tool_not_started`) included.
- **Pin:** a runner with a server and no pinned `apiary_public_key` is refused before
  the first request, `apiary_public_key_missing`; a pin from `QORY_APIARY_PUBLIC_KEY`
  works as one from the runner file; neither it, `QORY_ACCESS_KEY_ID` nor
  `QORY_ACCESS_KEY_SECRET` reaches a tool, an integration or the enclosure.
- **Access key:** the runner's X25519 public key from the fixture seed equals
  `filippo.io/edwards25519`'s `BytesMontgomery` of its Ed25519 public key, and the
  server's conversion gives the same; enrolment refuses every key of the small-order list
  and the fixture access key; `qory` refuses an `access-key-secret` that grants anything to
  the group or others, belongs to another user, or holds the fixture secret; `qory`
  refuses an enrolment or re-key answer that does not verify under the entry the code's
  first fingerprint names, and pins only entries the code's fingerprints name; a new
  access key that awaits approval gets a signed `409` `key_pending` on every signed
  endpoint, discovery and events included, and a pending key beside an approved one gets
  `401`; the old key verifies for 24 hours after the approval whatever requests the new
  key signs, and not after, unless an administrator ends the window earlier; a POST
  signed for one path fails at another, and a request whose access key id or machine id
  line differs from its headers fails to verify.
- **Access keys and machines:** two instances on one access key with different machine
  ids both run, and the server records both ids; `qory` keeps the machine id in
  `machine-id` with the hash of the machine's identity when the directory is writable,
  generates a fresh one per process when not, and generates a new one when the file's id
  fails the pattern or the hash differs; a machine id absent or outside its pattern is
  `400` `bad_request`, signed, after the `429` and before `key_pending`; a known id always
  updates its record, and past 256 new records in 24 hours the answers are unchanged, no
  new record appears and the count on the access key grows; a resent delivery keeps its
  first machine id; a machine name outside its pattern is ignored and the last valid one
  is kept; a public key the index holds is `key_invalid` at enrolment, re-key, paste and
  rotation, with one answer whether another access key holds it or it is a tombstone;
  deleting an access key or its workspace makes its keys tombstones and ends its re-key
  codes; revoking an access key cuts off every instance using it.
- **Locks and the marker:** every key command writes the marker before it generates a
  key, and with an unwalled run's lock held refuses; a run waits while a key command
  holds the key lock; a lock file whose `flock` can be taken is removed; a signed
  discovery without `secrets`, or an answer with `stored_secrets: false`, removes the
  marker, and an unsigned answer leaves it.
- **Re-key:** a re-key code works with the old secret lost and with the runner file lost,
  given `--server` and `--access-key-id`; the proof verifies, and fails under the old
  key; posting the access key's current key, old key or a tombstone is `key_invalid`; a
  re-key while a key is pending is `key_rotation_pending`, and an outstanding re-key code
  makes a rotation `key_rotation_pending`; a code for a revoked access key is `401`; a
  re-key for an access key that awaits approval is `key_pending`; a retry gets the `202`
  again, built afresh; the answer carries `stored_secrets` and the server's keys, and
  installs the pin on a machine without one; `rekey` and `rotate` with the secret in
  `QORY_ACCESS_KEY_SECRET` run only with `--print`; ending the old key's window at once
  retires it.
- **Key checks and enrolment:** enrolment, re-key, paste and rotation each refuse the
  torsion key of Decision 5, `key_invalid`, and with a bad proof answer `key_invalid`
  before any key check; a base64url value with padding, a `+` or `/`, or non-zero spare
  bits is refused; enrolment answers in its own order, with every `401` unsigned; a code
  typed in lower case or with hyphens normalises to the published fixture code, a code
  with two fingerprints is accepted, and the server refuses a code outside the pattern,
  `U` included; a retry with the same code and key gets a `201` for the same access key,
  built afresh with its current `approved`, `stored_secrets` and pin, unless the key has
  since been retired; `qory access-key enrol` reuses an existing secret only while
  `enrolment-pending` holds the same code's hash and is younger than 15 minutes, and
  otherwise moves it aside and generates a fresh one; a `409` `key_invalid` or a `401` to
  a retry moves the secret aside; a secret it moves aside gets a name no existing file
  has; the old key's and the pending key's rotation requests are `401`, a rotation posting
  a key the index holds is `key_invalid`, a second rotation while one is pending is
  `key_rotation_pending`, and a rejected key becomes a tombstone that stays refused when
  posted again; `qory` moves `.next` aside only when signed discovery shows that key
  neither current nor pending, and leaves both files on any unsigned answer.
- **Key commands and codes:** `--print` leaves the marker as it is; a second `rekey` with
  the same code within 15 minutes re-posts the pending key and gets the same `202`, and
  with another code moves `.next` aside; a machine whose new key is pending keeps using
  its current key; a retry of a re-key gets `approved: true` once its key is current and
  `401` once it is retired; with a pin that holds none of a code's fingerprints, `enrol`
  and `rekey` refuse before generating a key; a code whose fingerprints are not the
  server's current and next keys' is `401`, the two-fingerprint known answer included once
  the next key changes; a used code passes for a retry for 15 minutes after its first use;
  a cancelled code is `401`; Settings refuses to enable stored secrets on an access key
  that awaits approval.
- **Stored secrets enabled later:** while the flag is set, the secrets request, and a
  rotation, under a key the server received before the flag's last enabling are
  `key_rotation_required`, whatever other keys the access key holds, the old key of a
  window included, the order being the server's sequence and not the clock; discovery
  lists `key_rotation_required` under every such key; enabling the flag tombstones a
  pending key; a re-key code brings an eligible key; `qory` says to re-key, to approve the
  pending key, or to use the new secret, from `current_key` and `pending_key`; during a
  window the server seals to the key the request verified under, and a reseal under the
  other key is `run_secrets_conflict`.
- **Variants:** an access key without stored secrets receives the rendering with every
  stored-value connection left out and reports them in `connections_withheld`; a secrets
  request with the other variant's digest is `410` `run_configuration_superseded`; labels
  naming a repository the workspace does not hold get the baseline; a holder whose
  connections all reference stored values renders `connections: []` and `withheld` for an
  access key without the flag; a holder without stored-value connections has one rendering
  and one digest for both variants; and the events endpoint answers an access key
  without stored secrets with its own variant's digest, so no reload follows.
- **Variables:** an unwalled run receives no server variable with `variables.unwalled`
  unset or `ignore`, each reported in `variables.unwalled`, and receives them, the deny
  list applied, with `accept`; `GIT_AUTHOR_NAME` and `GIT_COMMITTER_EMAIL` pass while
  `GIT_SSH_COMMAND` is denied, and a `variables.deny` entry of `GIT_AUTHOR_*` denies them
  again, while `GIT_AUTHOR_X` stays denied; each server variable lands in exactly one of
  `names`, `denied` and `unwalled`; a machine-level variable replaces an unlocked variable
  and yields to a locked one, each reported in `policy_applied`; every entry of the
  built-in deny list, in upper and lower case, and a name from `variables.deny`, is left
  out and reported, a locked one included, and the run starts; a name from the runtime's
  `denies` is left out the same way; a name the runtime's `Prepare` sets wins over a
  locked variable, which is reported in `denied`; a `QORY_` variable or a `secrets.local`
  source passed into the enclosure from the run's environment is `variable_reserved`, and
  `QORY_RUN_ID` and `QORY_RUN_SOCKET` pass.
- **Public roots:** a proxy test with a host whose certificate chains only to an
  authority the test adds to the machine's trust store: with `tls.public_roots_only`
  unset or `true`, a stored value stays with the proxy and `dev.qory.run.egress` records
  a refused request with `wall:public-roots`; with `false`, the host receives it; a machine
  value reaches that host under either setting.
- **Labels:** a local checkout's second run with a changed origin is `labels_changed`,
  and runs after `--relabel`; a CI's explicit labels are used as given.
- **Mounts:** a walled run refuses a mount of `runner.yaml`'s directory, with or without
  a server, of an integration program, a tool program, a `secrets.local` file and
  `~/.claude/.credentials.json`, each through a symbolic link too.

## Setting up a machine

What a machine's owner sets up and meets in 0.7.0:

- Connections decide every credential a run sends. The runner file has `connections:`,
  `secrets.providers`, `secrets.local`, `variables.deny`, `variables.unwalled` and
  `machine.name`.
- A run configuration may contain `connections` and `variables`, and may omit
  `security_policy`. Each variable has a value and `locked`; a machine-level variable
  replaces an unlocked one, a locked one keeps the server's value, and a denied one is
  left out. An unwalled run receives the server's variables only with
  `variables.unwalled: accept`, which hands the server code execution as the developer
  and suits only a server its owner trusts as fully as their own shell.
  `dev.qory.run.policy_applied` reports each by name.
- A machine runs with an access key: one secret, `access-key-secret` or
  `QORY_ACCESS_KEY_SECRET`, an Ed25519 key that signs its requests and, converted to
  X25519, opens the values sealed to it; a fleet may share one key. The server stores
  only the public key. `qory access-key enrol` enrols a key with a code;
  `qory access-key create` prints a public key to paste into Settings › Access keys;
  `qory access-key rotate` replaces the key and keeps the access key id; the old key stays
  valid for 24 hours after the approval, or until an administrator ends that window;
  `qory access-key rekey` brings a new key with an administrator's re-key code, the way
  forward after stored secrets are enabled and after a lost secret. Rotation and re-key
  are the operator's commands. Every key command writes the `stored-secrets` marker
  first and waits for unwalled runs to end; the operator of a shared key, or of one held
  in the environment, uses `--print`.
- Each instance has a machine id, kept in `machine-id` with a hash of the machine's
  identity when it can be, for display and audit, and a display name, the host name by
  default; the server's Machines page lists the instances of each access key. A local
  checkout's labels are pinned at its first run the server accepts; `--relabel`
  confirms a change. Everything `qory` keeps lives in the runner file's directory.
- An access key, and every new key of it, needs approval; until then the key waits:
  a new access key gets `key_pending`, and a new key beside an approved one gets
  `401`. Stored values are sealed to an approved key and fetched from
  the secrets endpoint for the connections the run applies.
- Every request is signed with the access key secret, the access key id and the machine
  id among the signed lines, and carries `X-Qory-Access-Key-Id`, `X-Qory-Machine-Id` and
  `X-Qory-Signature-Ed25519`; every answer of the server is signed with the server's key,
  and the runner verifies it.
- A walled run is refused when its environment contains a variable the run's runtime
  declares or reserves; for Claude Code, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` and
  `CLAUDE_CODE_OAUTH_TOKEN`. A walled run whose runtime has a required group and no
  connection that supplies it is refused, `runtime_secret_missing`.
- Every run against a server that lists `secrets` needs a wall, and so does every run on a
  machine with the `stored-secrets` marker. A mount of the runner's configuration
  directory, a program the runner starts, a `secrets.local` file, a directory above any
  of them, or a runtime's credential file, is refused.
- A CI machine takes its secret from `QORY_ACCESS_KEY_SECRET` or a file descriptor, and
  `QORY_ACCESS_KEY_ID` and `QORY_APIARY_PUBLIC_KEY` from plain settings.
- The proxy refuses `TRACE` and `TRACK`, and sets a value only on port 443, on every host
  where it sets one.
- Every machine with a server pins the server's Ed25519 key, `apiary_public_key` in
  `runner.yaml` or `QORY_APIARY_PUBLIC_KEY`, and verifies every answer and every envelope
  with it; a runner with a server and no pin is refused, `apiary_public_key_missing`.
  Enrolment with a code writes the pin.
- The proxy verifies a host that receives a stored value against public roots only;
  `tls.public_roots_only: false` in the runner file verifies it against the machine's
  trust store instead.
- An integration is started as `<program> <role> -- [arguments]` and always receives one
  settings document on standard input, `{}` when empty, at most 64 KiB.
- A value of a multi-valued secret is addressed by `value_id`; a declaration's human name
  is `title`.
- `dev.qory.run.refused` is new, emitted for every no-run after the ping;
  `dev.qory.run.policy_applied` lists connections and reports the variables by name.

## Later: a credentials broker

A future direction, not specified here and not part of 0.7.0, where stored secrets go
only to walled runs. A broker sets credentials on the agent's requests in one of two
forms:

- **A remote broker**, on another machine, sets credentials on the agent's requests, so
  no secret reaches the agent's machine.
- **A local broker**, on the agent's machine, is allowed only when the agent's user has
  no root, no `sudo` and no membership of the `docker` group. The broker runs as another
  user of the system, and a firewall rule lets only that user connect out.

The contract separates which secret goes where, the connections, their hosts and the
seal, from who sets it on a request, the runner's proxy today. A broker replaces only the
second. Issues, item 21, lists what sits with the runner today and would move to a
broker.

## Open questions for the user

None.

**For the server's side:** none open. Answered: the secrets request lists the
connections the run applies, so the server seals for the run's runtime only; the digest
is the SHA-256 of the stored bytes, served as stored; an integration is matched by name
and version, with `describe`'s name required to match.

## Issues found while drafting

1. **Errors quote values.** `santhosh-tekuri/jsonschema/v6` quotes the offending value, and
   `contracts.Decode` (`jsonschema.UnmarshalJSON`) accepts a member name twice, last one
   winning. The run configuration and the plaintext go through `encoding/json/v2` first,
   and no error wraps either decoder's message.
2. **`session.Spec.Env` does not separate what the run sets from what it inherits.**
   The machine's level of variable precedence and `runtime_secret_conflict` need the set
   names, `Prepare`'s included: a new `Spec` field.
3. **Decision 1 relies on the nested Docker fixes**, not on `main` at 9838b7c.
4. **`server_needs_wall` and the secret file reach only runs `qory` starts.** Any
   unwalled agent of the same user outside `qory` reads `runner.yaml` and
   `access-key-secret`.
5. **The digest becomes normative.** The contract calls it opaque today and the runner
   never recomputes it; Decision 6 changes both.
6. **An integration's hosts may contain `*.`**, so the public-suffix check stays, with
   `golang.org/x/net/publicsuffix` as a new dependency of the runner and a list of the
   server's own.
7. **Interactive Claude Code with `ANTHROPIC_API_KEY`** waits for an approval until the
   claude runtime's `Prepare` pre-approves the stand-in; until then, a runtime connection
   with `api_key` works headless only.
8. **`headers.json` from the IANA registry** refuses any registered name a service might
   want; a service that needs one is a change to the file and the contract.
9. **Services have exact hosts only.** A machine credential for every host below a
   domain is an integration whose `describe` lists `*.` hosts, not a service.
10. **Under a server, an integration must be published.** A server-sent integration
    requires `repository` and `version`, so an unpublished in-house adapter, or a
    credential for a whole domain, is usable under a server only once it is published as
    an integration.
11. **`policy_applied`'s schema** changes: `credentials` goes, `connections` comes, and
    `url` and `run_configuration` are allowed with `source` `none`. `qory` decides
    whether `--policy` applies only after the fetch shows whether `security_policy` is
    present.
12. **The runner file's connection ids** use a grammar of their own; the record's
    `connection` field takes either form.
13. **An unsigned `2xx` on an event POST** is retried until the run ends; the runner
    reports it once, not per batch.
14. **The proxy ignores the port today** when it sets a credential
    (`internal/proxy/terminate.go` trims `:443` and sets the credential whatever the
    port); setting values on port 443 only is a change to the proxy.
15. **The request body limit is 32 KiB, not 16.** 16 KiB covers every measured request,
    6.2 to 10.3 KiB, but not 16 labels whose values are escaped byte by byte, about
    26.1 KiB; 32 KiB covers the contract's own label limits.
16. **Validating settings against the program's description** needs a JSON Schema
    validator on the program's `description.json` at run start; the runner has one
    (`santhosh-tekuri/jsonschema/v6`), whose errors quote values, so a settings error
    reports the member only.
17. **Public roots need a root store of the runner's own.** The proxy verifies upstream
    hosts against the machine's roots today (`internal/proxy/terminate.go`); verifying
    stored values' hosts against public roots only adds
    `golang.org/x/crypto/x509roots/fallback`, or a root bundle like it, as a dependency
    of the runner, refreshed with its releases.
18. **The access key's conversion in tests.** The runner derives its X25519 key from the
    seed with `crypto/sha512` and `crypto/ecdh` and needs nothing more for that. Its
    tests and the fixture check the conversion of the Ed25519 public key with
    `filippo.io/edwards25519` `Point.BytesMontgomery`, a new dependency of the runner's
    tests. The server needs the conversion and the small-order check in its own code.
19. **§The server is written for access keys.** `server.schema.json` has `access_key_id`
    and a required `apiary_public_key`; every request, the events POST included, carries
    `X-Qory-Access-Key-Id`, `X-Qory-Machine-Id` and `X-Qory-Signature-Ed25519`; its known
    answers are the Ed25519 ones of Wire format. Every receiver, the reference receiver
    included, verifies Ed25519 requests and signs its answers with a key of its own.
20. **Enrolment, the pasted key, re-key and rotation are `qory` commands**,
    `qory access-key enrol`, `create`, `rekey` and `rotate`. `qory` keeps everything in
    the runner file's directory, which every walled run refuses to mount: the secret and
    `.next`, `machine-id`, the `stored-secrets` marker, `enrolment-pending`, the pinned
    labels under `labels/`, and the per-run lock files and the key lock under `locks/`.
    The runner module takes the access key secret and the machine id through
    `session.Spec` and keeps everything in memory.
21. **Where the setter is tied to the routing.** A broker (Later: a credentials broker)
    replaces who sets a value. Today the following sit with the runner on the agent's
    machine and would move with it: the seal opens with the access key secret, which also
    signs the runner's requests, so a machine that holds it can fetch every stored value;
    `connection_needs_wall` and `server_needs_wall` require the runner's wall for any
    connection or stored value; an integration program runs on the machine, outside the
    wall, and receives raw values; `hosts_denied` and `uses` come from the proxy's own
    decision function; and the proxy applies `tls.public_roots_only`, port 443 only and
    the refusal of `TRACE` and `TRACK`.
