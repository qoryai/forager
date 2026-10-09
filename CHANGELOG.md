# Changelog

Every release of Forager, newest first, in the shape of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 a minor
release may change what an existing document does, and says so under Upgrading.

## [Unreleased]

### Core and contract

#### Upgrading

- `policy.Covers` covers an IP literal by an identical entry alone, as `policy.Match`
  matches it: `*.0.0.1` covers no `10.0.0.1`, under a machine's ceiling as in
  narrowing.
- `session.Policy`'s `Tools` and `Credentials`, and the policy package's, distinguish an
  empty list from none: an empty list is written as `[]`, and as a node's policy beside
  a server's it allows none of the server's tools or credentials.

#### Added

- `dev.qory.run.policy_applied` reports `variables`, one entry per name, sorted: `name`,
  `from`, the source whose value the run applies, `fixed`, `apiary`, `run`, `machine`,
  `harness` or `shell`, and `lost`, each value left out with its source and why,
  `overridden`, `denied`, `fixed` or `unwalled`. Every name the server, the run, the
  machine or the harness's defaults set is listed; a fixed name, and a name the run
  inherits, only beside one of those. Names alone, never a value.
- The node's policy narrows a server's. The mode is `enforce` when either side's is;
  the allow list is the hosts both sides allow; the deny lists add up; a request to a
  host either side holds to paths must match both; the tools and the credentials are
  the server's selection within the node's, when the node's document lists them; the
  image is the one both select or the one a side selects. A tool the narrowing refuses
  is `tool_unknown`, and two different images are `image_unknown`. A reload narrows the
  new policy by the same node policy. `dev.qory.run.policy_applied` reports the
  narrowed lists and `node_policy`: the node policy's `digest`, `sha256=` and the hex
  SHA-256 of its RFC 8785 serialisation, and its `paths`.
- Forager's own refusals are `session.Refusal` values too, with the code, the names
  they concern, never a value, and a sentence in `Detail`: `run_configuration_invalid`,
  `variable_reserved`, `placeholder_conflict`, `tool_unknown`, `image_unknown`,
  `mount_contains_forager_files`, `mount_mode_conflict`, `mount_shared_with_run`,
  `mount_through_link` and `engine_unreachable`.
  `errors.As` finds one in the error `session.Run` returns.
- `contracts/forager/v1/runtimes.json` lists the secrets of every descriptor the contract
  ships, for a server to vendor. `go generate ./contracts` writes it from the
  descriptors, and `go test ./...` fails while the file differs from them.
- Contract `v1` revision 1, amended in place, gains the files of the access key, the
  refused run and the variables that the server vendors:
  `enrolment.schema.json`, the enrolment request and its answer, a `201` that means the
  access key is active, signed with every signed refusal at enrolment under the
  enrolment answers' own domain line, `qory-enrol-answer-ed25519-v1`, once the server
  has checked the key and verified the proof under it; `events/run.refused.schema.json`,
  the data of `dev.qory.run.refused`, which `event.schema.json` lists among its types;
  and `denied-variables.json`, the built-in deny list of variable names and patterns.
  Forager's code is unchanged.
- Fixtures with the known answers of the access key: `fixtures/enrolment/`, two
  enrolment requests and the answer; and `fixtures/known-answers/`, the fixture access
  key and signing keys, the request, enrolment and answer signatures, the discovery body
  an answer covers, and the public keys enrolment refuses. The contracts tests
  recompute every one with Go's standard library: the keys from their seeds, the
  X25519 key from the access key, each signature, and the points of small order with
  integer arithmetic.
- The public package `accesskey` is the access key of the contract, for Forager and
  for qory alike. It generates a key and reads and writes its secret, `qak_` and the
  32-byte Ed25519 seed in base64url; derives the public key, its fingerprint and the
  X25519 key; runs the five checks the contract requires of a public key; builds and
  signs the GET and POST request strings; verifies a signed answer under a pin; builds
  an enrolment request with its normalised code and proof, posts it and verifies the
  answer, a signed `409` `key_limit` or `key_invalid` and a signed `429` `rate_limited`,
  under the key the code names and the enrolment answers' domain line, an unsigned
  `409` or `429` being `answer_unsigned`; and makes the instance id with the two lines of
  its file, the id and a keyed hash of the machine's identity. It verifies under no key
  the key checks refuse, refuses a document that contains a secret with
  `ErrSecretInDocument`, names a secret in no error, and prints a `Key` as its
  fingerprint however it is printed. Its tests reproduce every published known answer
  of the access key, the requests, the answers and enrolment.
- `enrolment.schema.json` defines a signed refusal at enrolment, `$defs/refusal`:
  a `409` `key_invalid` for a key already enrolled or `key_limit`, or a `429`
  `rate_limited` per code, with `apiary_public_key`, the same list in the same order as
  a `201`, so a machine without a pin verifies it as it verifies the `201`. A key the
  checks refuse or a proof that does not verify under it gets an unsigned `409`
  `key_invalid`, before the server signs anything. `fixtures/enrolment/` has the four
  `409`s, with one key and with two, and the `429` with one key, and `signatures.json`
  their signatures under the fixture signing key.
- The reference receiver accepts the public keys its configuration holds, answers in
  the contract's order of refusals, a ping whose `interval_seconds` is outside 1 to 300
  being `invalid_request`, and signs every answer after verification under its own key,
  the `410` of its `Stop` among them. Its new hooks `Closed` and `Admit` close a run with
  `run_closed` and refuse an instance's ping with `instance_limit`.
- `dev.qory.run.started` contains `about` when the caller passes one: what the run is
  about, as the caller passed it, every member optional. `kind` is the kind of run, at
  most 64 bytes; `title` the run's title, at most 256 bytes; `subjects` 1 to 16 objects
  of `type`, an open name of words of `a-z` and `0-9` joined by one space, underscore,
  dot or dash, at most 64 bytes, `ref`, at most 256 bytes, and `url`, an absolute `http`
  or `https` URL of at most 2048 bytes that never carries a user name or password, and
  `title`, with no two of the same `type` and `ref`; `details` a JSON object of at most
  8192 bytes as the event contains it, compacted, with `<`, `>` and `&` written as
  `\u003c`, `\u003e` and `\u0026`, nested at most 4 levels deep, with keys of 1 to 64
  bytes, shown to every reader of the run, so it never holds a secret. No string in it
  contains a control character. Only this event contains it; it is never sent on the
  run configuration request and never selects a policy, and an empty `about` is left
  out. `fixtures/run/about-*.json` holds accepted and refused ones. `session.Spec.About`
  is a `session.About` of `Kind`, `Title`, `Subjects`, each a `session.Subject` of
  `Type`, `Ref`, `URL` and `Title`, and `Details`, a `json.RawMessage`; run.started
  reports `Details` as `CheckAbout` measured them. `session.CheckAbout` holds an
  `About` to these rules and returns the first failure as a `*session.AboutError`, its
  `Field`, such as `about.subjects[0].ref`, and its `Reason`; `session.Run` checks it
  before it contacts the server, and an `About` it refuses is no run.
- Forager reads a run configuration with `encoding/json/v2` first, which refuses a
  member name that appears twice and invalid UTF-8, then against the schema and the
  limits: a variable's value of at most 4096 bytes of UTF-8. The error states where and
  which rule refused the document, and never quotes a value.
- Contract `v1` revision 1, amended in place, defines the gateway's link: §The
  gateway's link, between a session and its gateway, by the protocol toward the server
  on the same paths, discovery, the run configuration, the events endpoint and the `410`
  close, over two transports. The local link is a Unix socket in `qory-link-*`, mode
  `0700`, the socket `0600`, one of Forager's files; the session checks the socket's
  peer is its own user and opens every connection with `QORY-LINK` and the link secret.
  A separate gateway speaks TLS 1.3 alone, with the operator's certificate, which the
  session verifies against the system's roots or `session.gateway.ca_file` and an
  optional pin of its SubjectPublicKeyInfo, and every request carries
  `Authorization: Bearer` and the run credential. Answers on the link are unsigned.
  A run opens with a `POST` of `link-run-request.schema.json`: `run_id`, which the
  session chooses, `labels`, `about` and, behind a separate gateway, a `narrowing` that
  only narrows; the gateway refuses it with `invalid_request`, `run_credential_refused`,
  `run_id_used`, `target_differs_from_credential` or `differs_from_credential`. The
  answer, `link-run-answer.schema.json`, has `run_id`, the policy in force and its
  `digest`, `variables`, the run's `proxy_secret` and, with a wall, its
  `certificate_authority`. Discovery on the link is `link-discovery.schema.json`, with
  no `node_id`, `apiary_public_key` or `secrets`; a batch is `link-batch.schema.json`,
  events without `sequence`, which the gateway numbers. The relay opens its
  connections with `QORY-RELAY` and the run's proxy secret, and without a wall the
  agent's proxy URL carries it as its password. `fixtures/link/` holds the valid
  documents and `fixtures/invalid/link-*` the refused ones. Package `link` has
  `LinkPreamble`, `LinkDirPrefix`, `LinkSocketName`, `LinkDirMode`, `LinkSocketMode`
  and `BearerScheme`.

#### Changed

- The module is a core and three parts over it. The core, at the root, is `contracts`,
  `accesskey`, `receiver`, `policy`, `refusal`, `event`, `sink`, `server`, `program`,
  and `link`, which holds the names the parts agree on.
- Contract `v1` revision 1 is amended in place for a run's variables and a node that
  narrows the server's policy. `run-configuration.schema.json` has `variables`, at most
  128 names of `^[A-Za-z_][A-Za-z0-9_]{0,127}$` with string values without NUL,
  carriage return or line feed, and `security_policy` is optional: without it the
  node's policy is the run's. `events/run.policy_applied.schema.json` has `variables`
  and `node_policy`, and allows `url` and `run_configuration` beside `source` `config`
  or `none`. The README gains §Variables and the narrowing table in §The policy, and
  §The server reads that the launch spec's policy narrows a fetched policy.
  `fixtures/invalid/run-configuration-no-policy.json` is now
  `fixtures/run-configuration/no-policy.json`, `{"version": 1}`; the run configuration
  fixtures gain `variables.json`, and the invalid ones a variable that is no string and
  one with a line feed.
- The README is short. It lists Forager's four jobs: it records the session,
  enforces a policy, walls the agent in with the secrets kept outside, and reports to a
  server. It shows that `qory run` starts Forager, and where a run's policy comes
  from. `docs/` contains the rest, one page per topic.
- Contract `v1` revision 1 is amended in place: §The descriptor has six parts,
  `secrets` among them, defines `title` and the bound on `runtime`, and describes
  `runtimes.json`.
- Contract `v1` revision 1 is amended in place again: §Images lists what `dockerd`
  starts among the programs in the system directories, and §The wall defines the
  daemon's environment, the owners and modes of `/run/qory` and the agent's docker
  configuration, and that a non-empty `DOCKER_CONFIG` of the run's takes the place of
  that configuration.
- `dev.qory.run.started` records `command` and `args` as the runtime prepared them, as
  Forager always did; `run.started.schema.json` and §Sequence now say so. For an
  interactive Claude Code whose API key is a placeholder, `command` is `/bin/sh` and
  `args` hold the script in the run directory, then `claude` and its arguments.
- Contract `v1` revision 1 is amended in place again: a runtime in §The runtime defines
  seven things, the secrets it declares among them, through `runtimes.Secrets` in Go;
  its preparation receives the variables the enclosure gets the placeholder value in,
  and may change the command and the arguments, so it may start the program through a
  script it writes into the run directory. §The descriptor describes Claude Code's
  approval of an API key and the script that pre-approves the placeholder value, and
  §Sequence's steps 6 and 7 list the script.
- Contract `v1` revision 1 is amended in place: Forager signs every request with an
  access key, an Ed25519 key, and verifies every answer under the server's key it pins.
  The server document has `url`, `access_key_id` and the pin `apiary_public_key`, and
  no secret; `session.Server` has the same members, and `session.Spec` and
  `session.ResendSpec` have `AccessKey`, `InstanceID` and `InstanceName`. Every request
  contains `X-Qory-Access-Key-Id`, `X-Qory-Instance-Id`, `X-Qory-Instance-Name` and
  `X-Qory-Signature-Ed25519`, over the request string of a GET or a POST. Every answer
  but a `401` is signed under the server's key and bound to the request's signature,
  and Forager reads its body and headers only once it verifies; during a run an
  answer that does not verify is retried. §The server defines the access key, nodes
  and instances, the pin, the request string, signed answers, the coded refusals and
  their order, and enrolment.
- Discovery lists `node_id` and `apiary_public_key`, both required, and `secrets` for
  an access key allowed stored secrets.
- `dev.qory.ping` contains `interval_seconds`, the run's heartbeat interval, at most
  300; with a server, `session.Spec.Heartbeat` is a whole number of seconds, so the
  ping announces the interval the heartbeats tick at. Heartbeats run from the accepted ping until the final event, and
  `elapsed_seconds` counts from the ping. `dev.qory.run.exited`'s `reason` has
  `run_closed`.
- `fixtures/server/` and `fixtures/signed/` use the fixture access key and Ed25519.
  `fixtures/signed/` has `get-configuration-no-instance-id` and `-header-twice`,
  `batch-unknown-key` in place of `batch-wrong-key`, and
  `expect_code` for a coded refusal. `fixtures/invalid/` has
  `server-no-access-key-id`, `server-no-pin`, `server-secret-member` and
  `event-ping-interval-too-long` in place of `server-no-key`;
  `fixtures/configuration/with-secrets.json` is new; the configuration fixtures list
  `node_id` and `apiary_public_key`; and the pings of `fixtures/batch/ping.json` and
  of the recorded runs contain `interval_seconds`.
- The contract is at `contracts/forager/v1`, and every `$id` and `dataschema` is
  `https://qory.dev/contracts/forager/v1/…`. `dev.qory.ping` and `dev.qory.run.started`
  contain `forager_version`; `dev.qory.run.exited`'s `reason` for a run whose end was
  not recorded is `gateway_lost`; and the refusal code of a mount that holds Forager's
  own files is `mount_contains_forager_files`, `refusal.MountContainsForagerFiles`.
  `accesskey.UserAgent(version)` builds the `User-Agent` of every request to a server,
  `qory-forager/<version>`. The four batch fixtures under `fixtures/signed` are signed
  over their new bodies.
  The module is `github.com/qoryai/forager`, so `go get github.com/qoryai/forager` and
  every import path start with it.

### Gateway

#### Changed

- The gateway is `gateway`, over `gateway/internal/{proxy,credential,tool}`.
- The organization of the run's certificate authority is `Forager gateway, one run
  only`. The gateway's `403` for a link-local address or the machine's own address
  reads "qory: egress to <host>:<port> denied by the gateway: link-local addresses are
  never reached through it, and the gateway's own machine only for a host the policy's
  allow list names", and for an ambiguous path "qory: <method> <host><path> denied by the
  gateway: the path could be read two ways". Package `gateway` holds the names the
  session drives the proxy, the credentials and the tools by.

### Wall

#### Upgrading

- In an image with a Docker of the agent's own, `dockerd` runs with `/usr/local/sbin`,
  `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin` as its whole `PATH`, so
  these directories contain the programs it starts, `containerd`, `runc` and `iptables`
  among them. Of the run's environment it gets the proxy and, when the run has one, the
  run's certificate bundle. `docker:dind` needs no change.
- A link at `/run/qory` or `/run/qory/docker` in an image with a Docker of the agent's
  own stops the run when the wall writes the agent's docker configuration there, which
  it does whenever the run sets no `DOCKER_CONFIG` or an empty one. `wall.Nest` followed
  it before.

#### Added

- `wall.Engined` is a wall whose enclosures are containers of an engine; its `Engine` is a
  `wall.Engine`: the adapter, `docker` whichever command it runs, the command, absolute
  when found in PATH, the variables that select the engine, `DOCKER_HOST`,
  `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`,
  `CONTAINER_HOST`, `CONTAINER_CONNECTION`, `CONTAINERD_ADDRESS` and
  `CONTAINERD_NAMESPACE`, a password in an address left out and an address that cannot be
  read left out whole, `Pinned`, and the engine's id, `info --format {{.ID}}`, when it
  gives one. `Pinned` follows the variables the command reads. For the command named
  podman, it is true when `CONTAINER_HOST` or `CONTAINER_CONNECTION` is set and recorded.
  For any other command, it is true when `DOCKER_HOST` or `DOCKER_CONTEXT` is set and
  recorded; with neither set, it pins the context the command shows, `context show`, and
  `DOCKER_CONFIG`, else `~/.docker`, and a command whose `context show` fails is unpinned.
  A variable of the other kind stays recorded and never makes `Pinned` true. An address
  that cannot be read leaves the selection unpinned, and then neither the context nor the
  id is asked. Every engine command of `wall.Docker`'s, and the agent's container, then
  runs with the recorded selection in place of Forager's own; with an address left out,
  with Forager's own environment. `EngineID` asks the engine's id again through the
  recorded selection; a run whose engine gave none as it started asks once the enclosure
  is prepared, and records the answer. A walled run's registry entry records the engine.
  `wall.RunContainersExist` asks the engine's id again, when one is recorded, and then
  lists a run's containers with `ps --all --quiet --filter label=dev.qory.run=<id>`, with
  the recorded variables in place of Forager's own. It asks a command other than podman
  by its id, through its pinned selection, and refuses one recorded without an id, since
  podman installed under another name reads no `DOCKER_HOST` and every Docker engine gives
  an id; it asks the command named podman by its pinned selection when it gave no id, and
  refuses one recorded with neither.
- `wall.Binder` is a wall, or an enclosure, that binds files and directories of this
  machine of its own; `Binds` lists them as `wall.Bind` values, a `Pattern` for a
  directory the enclosure makes later. `wall.Docker` lists its helper and the pattern
  `wall.TempDirs()` before it prepares an enclosure; its enclosure lists the helper,
  the hook socket's directory and the private directory that holds the run's
  environment files and, with a CA, the `ca-bundle.pem` it binds, which it makes when
  it lists them. The session lists a wall's binds in the registry when the run starts,
  with the pattern of the runs' socket directories, and the enclosure's just before it
  binds them. A place that lies inside a writable directory another run's wall binds
  is `mount_shared_with_run`.

#### Changed

- The wall is `wall`.
- Behind a wall, the enclosure binds the outermost of the places a run lists, the
  mounts and the workspace, each once: a place inside another one of the same mode is
  reached through the outer one. The workspace is the working directory inside, through
  the mount that holds it, and is bound at its own path, writable, only when no mount
  holds it. `wall.Docker` binds `Launch.Mounts` and passes `Launch.Dir` as `--workdir`,
  and refuses a launch whose `Dir` no mount's path holds.

#### Fixed

- In an enclosure with a Docker of the agent's own, the agent's `docker` command reads
  its configuration, so the containers it starts get the proxy. `wall.Nest` made
  `/run/qory` root's with mode 0700, which the agent's user could not pass through: the
  command printed `WARNING: Error loading config file: open
  /run/qory/docker/config.json: permission denied`, and its containers reached nothing.
  `/run/qory` is now root's with mode 0755, whatever the umask, and a `/run/qory`
  already in the image is set to the same owner and mode; `/run/qory/docker` and its
  `config.json` stay the agent's, 0700 and 0600, now also whatever the umask or the
  image made them, and the file is written anew. A link where either directory goes is
  refused. An image that makes `/run/qory` 0755 to work around this may keep doing so.
- `wall.Nest` started `dockerd` with the run's environment, so the daemon looked for
  `containerd`, `runc` and `iptables` on the run's `PATH`, which may list a directory of
  the workspace, and ran what it found there as the enclosure's root; `LD_PRELOAD`,
  `LD_LIBRARY_PATH`, `XTABLES_LIBDIR` and the `DOCKER_` variables reached it the same
  way. The daemon now runs with the system directories as its `PATH`, the proxy
  variables for its pulls and, when the run has a bundle, `SSL_CERT_FILE` pointing at
  it, and with nothing else; the agent keeps the run's environment. The conformance
  suite puts programs of these names first on the run's `PATH`, in the workspace, and
  requires that none of them runs.
- A run that sets `DOCKER_CONFIG` to an empty string gets the agent's docker
  configuration: `wall.Nest` added `DOCKER_CONFIG=/run/qory/docker` after the empty
  entry, the agent's `docker` command read the empty one as unset, and the containers it
  started got no proxy. The agent's environment now contains one `DOCKER_CONFIG`, the
  wall's, when the run's is unset or empty; a non-empty one stays as it is.

### Session

#### Upgrading

- A runtime name is a lower-case letter and then up to 63 lower-case letters, digits
  and dashes: `catalog.Lookup` refuses a longer name, `runtimetest.Conforms` fails a
  runtime that has one, and the descriptor schema holds `runtime` to the same bound.
- `session.Spec.Env` is what the run inherits. The values the harness computes itself go in
  `LaunchFixed`, the values its author wrote as defaults in `LaunchDefaults`, the run's own variables,
  `--env`, in `Variables.Run`, and the machine's, `wall.env`, in `Variables.Machine`, so
  the session tells each source apart and applies the highest that sets a name.
  `HarnessHome` is the harness's home as the agent sees it, an absolute path, and the
  session sets `QORY_HARNESS_HOME` to it. `OnVariables` receives each name, its source
  and the values that lost, once the variables are resolved and before the agent
  starts.
- A walled run refuses to pass into the enclosure a `QORY_` variable other than
  `QORY_RUN_ID` and `QORY_RUN_SOCKET`, or a variable a credential's `Env` names, with
  `variable_reserved`, whether it comes from `Env`, `LaunchFixed`, `LaunchDefaults`,
  `Variables.Run` or `Variables.Machine`. Any run refuses a value from any of them for a
  placeholder, `placeholder_conflict`. Both are checked before the variables are
  resolved. Behind a wall, every variable the runtime declares or reserves that neither
  a placeholder, a source nor the runtime's preparation sets is in the enclosure's
  environment as an empty value, for Claude Code `ANTHROPIC_API_KEY`,
  `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_AUTH_TOKEN`: a value the run passes for one
  reaches the runtime as before.
- With a server whose run configuration has a `security_policy`, `Spec.Policy` narrows
  it, where Forager ignored it before, so a caller may pass a policy of its own
  beside a server.
- The runtime prepares the launch before the tools start, since the names it sets are
  Forager's own when the variables are resolved.

#### Added

- A run configuration's `variables` reach the agent's process: for each name an object
  with its string `value`, as the server resolved it. An attribute beside `value` is
  ignored. For each name the run takes the value of the highest source that sets it: the
  fixed names, those the session, the proxy, the wall, the runtime's preparation and the
  placeholders set and the values the harness computes; then the server's; the run's
  own; the machine's; the harness's written defaults; and what the run inherits. The
  deny list, which is `denied-variables.json`, the runtime's `denies` and
  `Variables.Deny`, matched regardless of case with `*` for any run of characters,
  leaves out a value of the server, the run, the machine or the harness's defaults; its
  built-in entries leave out a value the harness computes too. The server's value of a
  variable the runtime declares or reserves, or of one a credential is read from, is
  left out. A run without a wall takes none of the server's variables unless
  `Variables.Unwalled` is `accept`; the run's own apply with or without a wall. A value
  that loses is left out and the run starts. The variables are fixed when the run
  starts. Tools, the relay, the agent's Docker daemon and the wall's `docker` command
  keep their own environment.
- `runtimes.Secrets` is the optional interface of a runtime that declares the secrets it
  needs; a descriptor's runtime implements it. `wall.Setter` is the optional interface
  of a wall that sets variables in the enclosure itself, and `wall.Docker` implements
  it.
- A runtime descriptor defines the secrets the runtime needs, under an optional
  `secrets`: `declares`, each secret with its id, title, variable, exact hosts, optional
  paths and scheme; `one_of`, groups of declarations of which the runtime needs at most
  one, and exactly one of a required group; `reserves`; `denies`; and
  `credential_files`. Behind a wall, a declared or reserved variable that nothing sets
  goes in empty. It also has an optional `title`. `auth.schema.json` defines the
  scheme, `bearer`, `header` or `basic`. Forager checks the secrets when it reads a
  descriptor.
- The Claude Code descriptor declares its model credential: `ANTHROPIC_API_KEY`, set as
  `x-api-key`, or `CLAUDE_CODE_OAUTH_TOKEN`, set as a bearer, on `api.anthropic.com`
  under `/v1/`, one of the two required. It reserves `ANTHROPIC_AUTH_TOKEN`, denies the
  variables that move its requests, credential, shell, settings or TLS trust, and lists
  `~/.claude/.credentials.json`.
- A runtime declares its secrets in Go through `runtimes.Secrets`, an optional interface
  checked by type assertion, whose `Secrets` method returns `runtimes.Declarations`: the
  declarations, the `one_of` groups, and the reserved, denied and credential-file lists
  of a descriptor's `secrets`. A described runtime implements it with a copy of its
  descriptor's section, empty when the descriptor has none; a runtime without it
  declares nothing. `runtimes.Declaration`, `runtimes.Group` and `runtimes.Auth` are the
  parts.
- `runtimes.Attach` has `Placeholders`: behind a wall, the variables the enclosure gets
  the placeholder value in, a credential's and a tool's. `runtimes.Placeholder` is that
  value.
- Interactive Claude Code runs with an API key behind a wall. On a pseudo-terminal,
  Claude Code waits for a person to approve the key in `ANTHROPIC_API_KEY` unless its
  configuration lists the key's last 20 characters under
  `customApiKeyResponses.approved`. When the session is interactive and
  `ANTHROPIC_API_KEY` is a placeholder of the run, the `claude-settings` installer
  writes `approve-key.sh` into the run directory and starts Claude Code through it with
  `/bin/sh`, which such an image contains: the script adds the placeholder value's
  entry, `utside-the-enclosure`, to `~/.claude.json`, or to the file Claude Code reads
  in its place, inside the enclosure, and then starts Claude Code. A missing file
  becomes one with the entry alone, mode 0600; an empty one gets the entry and keeps its
  mode. A JSON object without `customApiKeyResponses` gets the entry as its first
  member, and keeps every member and the bytes before and after its opening brace,
  ending in one newline. Any other file, and a path that is neither a regular file nor
  missing, stays as it is. The script writes to a temporary file beside the
  configuration first and copies it over, through a link when the configuration is one;
  whatever fails, the configuration keeps its content and Claude Code starts. The OAuth
  credential, and every headless session, start Claude Code as before.
- No tool, credential program or agent receives `QORY_ACCESS_KEY_SECRET`,
  `QORY_ACCESS_KEY_ID` or `QORY_APIARY_PUBLIC_KEY`: the session leaves them out of every
  environment it starts a program with.
- `session.Spec` has `Discovered`, called once the server's signed configuration
  document is read and before the ping, with the access key's `node_id` and whether the
  document lists `secrets`; an error it returns is no run.
- A walled run refuses a mount, or the workspace, that is, contains or lies inside one of
  Forager's files, `mount_contains_forager_files`, before it contacts the server and
  before anything starts, `Local` included. `session.Spec` has `ForagerFiles`, the
  absolute paths the caller lists as its own, such as the directory of qory's
  `runner.yaml`. Beside them the session checks the directory of every credential and tool
  program the machine defines, the file a credential is read from, the private directories
  of every run's tool sockets, record sockets (`qory-run-*`) and Docker wall environment
  files (`qory-wall-*`) in the system's temporary directory, and the files a wall lists
  through the new `wall.Filer`: `wall.Docker` lists the directory of the `docker` command,
  of the helper, and the command's configuration directory. The refusal's `Names` are the
  mount and Forager's file, in that order. `session.Overlap` returns how a mount and a
  path stand, `is`, `contains` or `lies inside`, after symbolic links and by whole
  components, with the filesystem judging which directories are the same, case and bind
  mounts included. A link whose target does not exist yet is followed to the target, a
  path that cannot be resolved is no run, and the check runs again just before the
  enclosure is built.
- No walled run binds from a place a walled agent of the same user can change: no name on
  the way to a bind source is looked up in a writable bind, the run's own or another
  walled run's still going, or in a directory inside one. A walled run is refused with
  `mount_mode_conflict` when a mount, or the workspace, lies inside another one of the
  run's, or is the same, of the other mode; `Names` holds the inner path and the outer
  one, as passed. It is refused with `mount_through_link` when a mount, or the workspace,
  of either mode, goes through a link inside a writable place of the run's and does not
  resolve into it, since the agent that writes the link would choose what is bound;
  `Names` holds the place as passed, the link's path and the writable place as passed. It
  is refused with `mount_shared_with_run` when one of its binds lies inside a writable
  bind of another walled run still going, apart from the same root, or is reached through
  one; when one of its writable binds holds a bind of such a run, or a directory a name on
  the way to one is looked up in; or when one of its binds is, holds or lies inside such a
  run's run directory, whatever the modes. `Names` holds this run's path, the other run's
  id and the other run's path, each as its run passed it. Two runs that bind the same root
  run side by side, and two read-only binds never conflict. A run whose own helper, or
  another directory of Forager's its wall binds, lies inside a writable bind of such a
  run, or is reached through one, does not start. The session keeps the walled runs still
  going in a registry of its own, per user, `$XDG_STATE_HOME/qory-forager/walled`, else
  `~/.local/state/qory-forager/walled`, 0700: a file per run, named by its run id, with
  its process id and its binds, each as passed, as resolved, with the entries its names
  are looked up as, whether writable, and what it is when it is not a place; the file is
  held locked for the run's life and removed when it ends, kept when the wall could not be
  removed. A file whose lock is free is the run of a session that is gone: it is still
  going while the container engine its entry records holds a container labelled with its
  run id, in any state, and is removed when the engine holds none. A run that cannot ask
  that engine, whose engine answers with another id than the one recorded, or that reads
  such an entry that records no id for a command other than podman, neither a pinned
  selection nor an id for podman, no engine, or that cannot be read, is refused with
  `engine_unreachable`; `Names` holds the earlier run's id and then the absolute path of
  its registry entry, and the sentence reads "Docker could not be asked whether the walled
  run <id> is still going, so the run does not start: <the error>". A bind of another
  run's, or a directory on the way to it, that is gone is compared by its names, like a
  part that does not exist yet; any other failure to resolve one stops the run. A run
  checks its binds and adds its own entry under a lock of the registry's, before it
  contacts the server, and again, with its wall's own binds, just before the enclosure
  binds them. `events/run.refused.schema.json` lists the four codes.
- The session passes every bind's path clean, and a run whose working directory lies in
  none of its binds fails.
- A server can close a run with a signed `410` `run_closed` to a delivery: the session
  stops the runtime as at its time limit, records `dev.qory.run.exited` with
  `reason: run_closed` in the file sink and sends nothing further; before
  `dev.qory.run.started` it records `dev.qory.run.refused` with the code `run_closed`.
  A close that keeps the runtime from starting after `dev.qory.run.started` ends the
  run the same way, with exit code -1.
  `session.Result` has `RunClosed`.
- A run refused with a code is a `session.Refusal`, with the code and the server's
  status: `apiary_public_key_missing` for a server without a pin, before any request;
  `unauthorized` for a `401`; `answer_unsigned` for an answer that does not verify; and
  `instance_limit` when the node's live instances are at its limit.

#### Changed

- The session is `session`, with `session/runtimes/…` (from `runtimes/…`) and
  `session/internal/…`.
- `Spec.RunsDir` and the registry of walled runs are among Forager's files, so a
  walled run's mount, or workspace, that is, contains or lies inside either one is
  `mount_contains_forager_files`, and so is a writable one that holds a directory a name
  on the way to one of Forager's files is looked up in, a link say. A walled run's
  run directory lies outside every place it binds and is reached through none, and the
  agent can neither change nor move its record. The default runs directory,
  `.qory/runs` in the workspace, lies inside the workspace, so a walled run passes one
  outside it.
- The check of a walled run's places runs again just before the enclosure binds them,
  the registry included. A place that resolves otherwise than at the start, or whose
  names are looked up in other directories, fails the run with a sentence that says
  which.
- The registry of walled runs is `$XDG_STATE_HOME/qory-forager/walled`, else
  `~/.local/state/qory-forager/walled`. `session.Spec` has `ForagerVersion` and
  `ForagerFiles`. `runtimes.CheckStopSignal` checks a stop signal and
  `runtimes.StopSignal` returns the signal of its name; `session.CheckStopSignal` calls
  the first.

### e2e and CI

#### Upgrading

- An image passed to `e2e.Run` with `Docker` needs the `docker` command as well as
  `dockerd`: the suite starts a container with it as the agent's user.
- `e2e.Options` has `Recorders`: three `e2e.Recorder` values, each the helper
  started with `e2e.RecorderArgs` and `e2e.RecorderEnv()` in a container of
  its own, in this order: the host of a runtime's API key, the host of its OAuth
  credential, then a host the policy allows with no credential. A `Recorder` holds the
  `Host` the proxy reaches it on and a `Recorded` function that returns the content of
  `e2e.RecorderFile` in its container. An adapter's test that passes none skips
  the checks of a runtime's key, `QORY_WALL_REQUIRE` turns those skips into failures,
  and a number other than none or three fails the suite. A recorder prints
  `e2e.RecorderReady` once it listens, and `e2e.AwaitRecorder` waits for that
  line in its container's log, and fails with the log at once when the container stops
  first; a recorder's container started without `--rm` keeps that log. With
  `Recorders`, `e2e.Run` points the roots of the process, and the programs it
  starts within `Run`, at the suite's authority alone, with `SSL_CERT_FILE` and
  `SSL_CERT_DIR`. The process reads its roots once, at its first verification of a
  certificate, so the test binary's first verification must come within `Run`; from
  then on, for the rest of the process, it trusts only the suite's authority.
  `TestDockerConforms` starts the recorders from `busybox:stable`.

#### Added

- The wall's conformance suite checks a runtime's two credentials from inside the
  enclosure, as Claude Code sends them: an API key in `x-api-key` and an OAuth
  credential as a bearer, each a fake key for a recorder that acts as its host. Each key
  reaches its own host once, in its own header and in place of the stand-in; another
  allowed host, plainly and through a tunnel, receives the stand-ins and no key; the
  probe's environment and every `/proc/*/environ` it reads contain the stand-ins and no
  key; and the run's directory, output and reports contain no key, after the
  interactive run as well. The suite points its own process's roots at an authority of
  its own with `SSL_CERT_FILE` and `SSL_CERT_DIR`, so the proxy verifies the
  recorders. The proxy's tests cover both schemes as well, with a request that carries
  both stand-ins.
- `TestDockerClaudeCodeThroughTheWall` runs Claude Code itself behind the Docker
  adapter, with `QORY_WALL_CLAUDE_IMAGE` set to an image with `claude` on its `PATH`:
  `ANTHROPIC_BASE_URL` points it at a recorder that answers as the Messages API, once
  with an API key and once with an OAuth credential. Claude Code prints the recorder's
  answer, each request carries the fake key in the credential's header and no stand-in,
  and the record lists one request through the proxy for each the recorder received,
  each to the recorder.
- `TestDockerClaudeCodeThroughTheWall` also runs Claude Code interactively, on a
  pseudo-terminal with a home of its own whose configuration has the onboarding done and
  the workspace trusted, with the API key and with the OAuth credential. The test types
  a prompt once Claude Code shows its input and leaves with `/exit`; with the API key,
  Claude Code reaches its input with no approval prompt for the key, and the
  configuration then holds the placeholder value's entry and every member it held
  before. Every run sets `ANTHROPIC_AUTH_TOKEN` and the other credential's variable
  empty, and the recorder receives the chosen credential's header alone, so Claude Code
  reads an empty variable as unset and uses the placeholder.

#### Changed

- The wall's conformance suite is package `e2e`, from `wall/walltest`. CI runs gofmt,
  vet, the tests, the build and revive in one job per part, `core`, `gateway`, `wall`,
  `session` and `e2e`; the job named `Go tests` passes when they all pass; and the two
  wall conformance jobs run `./e2e`. A test in `internal/importrules` holds each part's
  imports to the rules: the core imports no part; the gateway and the wall import the
  core; the session imports the core, the wall and package `gateway`; and only `e2e`
  imports the session.

#### Fixed

- The wall's conformance suite missed that the agent's `docker` command could not read
  its configuration: the containers it starts through the Engine API receive the relay's
  address. It also starts one with the image's `docker`
  command, as the agent's user and with no proxy setting of its own, and requires it to
  reach the origin through the proxy and nothing else, so the image of
  `TestDockerNestedConforms` contains the docker command as well as dockerd.

## [0.6.0] - 2026-09-28

### Upgrading

- `golang.org/x/sys` is a direct dependency.

### Added

- Images: `session.Spec.Images` defines the images of the machine's, a name, a
  reference, the container runtime the wall starts it under and whether the agent gets a
  Docker daemon of its own, and a policy's `image` selects one by name, as it selects
  credentials and tools. `Spec.Image` is the default when the policy selects none: the
  name of one of `Images`, or a reference. A name the machine does not define, a
  selection without a wall, an image defined twice and a daemon without a runtime are no
  run; a reload that selects another image is refused, where another image is the one
  the selection resolves to, so selecting the machine's default by name, or dropping
  that selection, is no change.
- `dev.qory.run.started` contains `image_name`, `container_runtime` and `docker`, and
  `dev.qory.run.policy_applied` contains `image`, when they apply; `image` in
  `run.started` is the reference the selection resolves to.
- `wall.Request` has `Runtime` and `Docker`, and `wall.Docker` has `NestArgs`, the
  helper's arguments for the mode that calls `wall.Nest`, beside the one that calls
  `wall.Relay`. The Docker adapter refuses an image with `Docker` when `NestArgs` is
  empty.
- A Docker of the agent's own, experimental because whether the enclosure's root reaches
  the mounts the run lists as the machine's root has not been verified: it may change or
  be withdrawn in a minor release. An image with `Docker` starts under its `Runtime`,
  `sysbox-runc`, whose root is a user of the machine's that is not root. The enclosure
  starts as that root, with `no-new-privileges` and a volume of the run's for the
  daemon's store; `wall.Nest`, the helper in a hidden mode, starts `dockerd` on its Unix
  socket alone with the socket in the agent's group, waits until it answers, writes the
  agent a docker configuration that points the containers it starts at the proxy's
  address, drops every capability, the bounding set included, and executes the launch as
  the agent's user, with the inheritable and ambient sets cleared. It refuses a runtime
  that maps the enclosure's root to the machine's, and looks for `dockerd` only in the
  image's system directories. The daemon's store is a volume of the run's, removed with
  the enclosure and bounded only by the engine's disk, and a daemon that exits stays
  stopped for the rest of the run. Docker in Docker with `--privileged` and the machine's
  socket stay refused.
- IP forwarding is off in the relay's namespace, for IPv4 and IPv6: the relay connects
  the enclosure's network to the ordinary one only through the proxy.
- The wall's conformance suite runs in an enclosure with a Docker of the agent's own,
  `TestDockerNestedConforms`, with the runtime set in `QORY_WALL_RUNTIME`; the CI job
  installs Sysbox and runs it.

- Tools: programs of the machine's that serve hosts, for what a run reaches that needs
  more than a secret in a header. `session.Spec.Tools` defines them, a name, a command
  with `${argument}`, the pattern the argument must match, the hosts the tool serves and
  its placeholders, and a policy's `tools` selects among them, by name and argument, as
  it selects credentials. Behind a wall the runner starts each selected tool outside the
  enclosure before the runtime, with `QORY_TOOL_LISTEN` set to the Unix socket it
  listens on, `QORY_RUN_ID` set to the run's id, and the runner's environment minus the
  variables the machine's credentials are read from, and stops its process group when
  the run ends. The proxy ends the session's TLS for the hosts a tool serves, decides
  the host and the path by the policy, and passes every request it lets through to the
  tool over the socket, streamed, with `Qory-Request-Id` and `Qory-Path-Rule` set,
  `none` for a path observed that no rule covers. Every header and trailer of the
  `Qory-` prefix the session sent, in any case or with an underscore, is taken off, and
  the proxy's headers stay on the request when the session lists them in `Connection`. A
  host a tool serves need not exist: the proxy never dials it, so a service with no host
  of its own, such as an MCP server, serves a name under `.internal`. A selection
  without a wall, a tool that does not listen within a minute, a host a tool and a
  credential both claim, and under enforce a host the allow list does not cover are no
  run; a reload that selects other tools is refused. The runner knows no protocol:
  signing a request to an object store is a tool's, not a scheme's.
- Every request to a tool's host is one `dev.qory.run.egress` with `tool`, the tool's
  name; an allowed one is a tool invocation. `dev.qory.run.policy_applied` lists the
  run's `tools` and their hosts among `terminated`.
- Every egress event that is one request, a plain one or one inside a terminated
  connection, contains `request_id`, the proxy's own id of it, and `status`, the status
  the host or the tool returned, when one returned.
- The wall's conformance suite reaches a tool from inside the enclosure: on its paths it
  receives the proxy's headers and not the ones the probe forged, and off them the proxy
  refuses.
- Each credential use and each tool in `dev.qory.run.policy_applied` contains
  `argument`, the argument the policy passed to the credential or the tool, when it
  passed one, so an audit of the record reads which repositories a secret was minted for
  and what each tool was started for.

### Changed

- Contract `v1` revision 1 is amended in place again, before any server relied on it:
  the policy may contain `tools` and `image`, and the events contain the fields listed
  under Added. The runner sends `X-Qory-Contract-Version: 1` and `contract_version: 1`,
  as before.
- The contract's wording is plainer: the README, the schemas' descriptions and the
  fixtures' notes use plain verbs in the present tense. The runner's behaviour is the
  same; where the text disagreed with the runner it now describes what the runner does.
- A wall points `AWS_CA_BUNDLE` at the run's bundle as well, beside `SSL_CERT_FILE`,
  `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE`.
  The AWS CLI and botocore read `REQUESTS_CA_BUNDLE` only when neither `AWS_CA_BUNDLE`
  nor `ca_bundle` in the image's AWS configuration is set, so an image that sets a
  bundle of its own there did not trust a terminated host. A caller that sets its own
  variables in `Docker.CAEnv` gets those, as before.
- The contract states that a path rule reads the request's path alone: its query,
  headers and body are outside the rule. A subresource in the query, a listing's prefix,
  a copy's source in a header and a GraphQL body are outside what a rule checks.
- A policy's credential and tool `argument` may have up to 4096 characters, where it had
  256, so one argument can list several repositories, `acme/shop,acme/lib`. The cap
  bounds only the size of the run's record: what guards the argument is the definition's
  pattern, which must match it whole, and it reaches the program as one word, with no
  shell.

### Removed

- The paths kept for what a runner before 0.5.1 left: sending a record again no longer
  reads an `ai.qory.` type as `dev.qory.`, and a reap no longer looks for containers and
  networks labelled `ai.qory.run`. No runner or server is in use yet, so there is no
  such record or container to read.

### Fixed

- A request's trailer reaches the host of a terminated connection. The proxy passed on a
  copy of the trailer made before the body was read, which was empty, so a client that
  sent a checksum as a trailer sent none upstream.

## [0.5.1] - 2026-09-24

### Upgrading

- A receiver that matched on `ai.qory.*` matches `dev.qory.*`: every event type is
  renamed, `ai.qory.run.started` to `dev.qory.run.started` and so on, and its data is
  as it was. A server's configuration document names the types it wants in
  `events.types` under the new names, and a descriptor of your own names its session
  types `dev.qory.session.*`; the schemas refuse the old names.
- The contract stays `v1` revision 1, amended in place, and the runner sends
  `X-Qory-Contract-Version: 1` as before. Nothing else changes.

### Changed

- Contract `v1` revision 1 is amended in place again, before any server relied on it:
  every event type starts `dev.qory.`, where it started `ai.qory.`. A CloudEvents type
  is named under the reverse-DNS name of whoever defines it, and qory.dev roots every
  identifier of the contract, as it roots the schema URLs,
  `https://qory.dev/contracts/runner/v1/...`. The schemas, the fixtures and the Claude
  Code descriptor carry the new names, and the signed batch fixtures are signed again
  over their new bodies.
- The containers and the networks of a wall carry the label `dev.qory.run`, where they
  carried `ai.qory.run`.
- Sending again the record of a runner before 0.5.1 reads its `ai.qory.` types as
  `dev.qory.` ones: its `run.exited` is found, so the record is not closed twice, and
  the server gets each event under the type of today. The file keeps what was written.
  The reap that goes with it removes what carries either label.

## [0.5.0] - 2026-09-24

### Upgrading

- A caller in Go that serves the run configuration through `receiver.Handler` changes
  its hook: `RunConfiguration` is `func(labels map[string]string) ([]byte, string, bool)`,
  where it was `func(forge, repository string)`. The map is every label of the run, from
  the request's query or the run's `ai.qory.run.started`, and empty when there were
  none; where a hook read `forge` and `repository`, it reads `labels["forge"]` and
  `labels["repository"]`, which are empty when the run has no such label, as before.
- A server of your own finds every label of a run on the run configuration request,
  where it found `forge` and `repository`. One that reads only those two parameters
  needs no change; one that refused any other parameter accepts them now, or refuses
  the runs that carry more labels. A query of the longest labels is 13,343 bytes, which a front end that
  limits the request line to 8 KiB refuses.
- Nothing changes for the `qory` command, which labels a run with `forge` and
  `repository` and finds its policy chosen by them as before.

### Changed

- Contract `v1` revision 1 is amended in place, before any server relied on it: the run
  configuration request carries every label of the run as its query, one parameter per
  label, sorted by key and percent-encoded,
  `?forge=github.com&issue=77&repository=acme%2Fshop`, where 0.4 sent `forge` and
  `repository` alone. The change adds: a server that reads only those two finds them as
  before. Which labels name what a run works on is the server's to decide; the runner
  reads nothing into them. The contract states the bound, at most 13,343 bytes of query
  from sixteen labels, so a server knows the longest request line it can get. The
  revision stays 1. A signed fixture of the form with every label,
  `fixtures/signed/get-run-configuration-labels-valid.json`, beside the one of two.
- The runner sends the run's labels, all of them, on every run configuration request,
  at the start and at each reload, and a label with an empty value as `key=`.
- `receiver.Handler` reads the run configuration request's query as the run's labels
  and hands them all to `RunConfiguration`, and keeps each run's labels from its
  `ai.qory.run.started` whole, so the digest an answer to a delivery carries is the one
  for all of them. A query that is not labels, a key sent twice, a key outside the
  grammar, a value over 256 bytes or not UTF-8, or more than sixteen, is a `400` once
  the request verifies, and the hook does not see it.
- The rule for labels, `session.CheckLabels` and `session.MaxLabels`, is one definition
  the runner and the receiver share.

## [0.4.1] - 2026-09-21

### Fixed

- A policy reload that landed in the moment between a tunnel's `200 Connection
  Established` and the proxy's own list of open tunnels missed that tunnel, and left it
  open to a host the new policy denies. The tunnel is on the list before the client hears
  200.

## [0.4.0] - 2026-09-21

### Upgrading

- The server replaces the webhook. `session.Spec.Webhook` is gone; `Spec.Server` is a
  `*session.Server` with `Version`, `URL`, `AccessKey` and `Secret`, the document of
  `server.schema.json`: the server's origin and nothing after it, the key the server
  knows the runner by, and the secret that signs. `ResendSpec.Server` likewise. For
  `qory`, the file's `server` section replaces `webhook`, and `QORY_SERVER_SECRET`
  replaces `QORY_WEBHOOK_SECRET`. Where a webhook took an endpoint, a server is an
  origin: the runner fetches `/.well-known/qory-configuration` under it, signed, and
  learns the events URL and the filter there.
- A receiver of your own implements the contract's server section: discovery, the
  events endpoint, and the two headers on every request, `X-Qory-Access-Key` and
  `X-Qory-Contract-Version`. A `GET` is signed over a canonical string with a
  timestamp; a `POST` over its body as before. Every authentication failure is `401`
  with `{"error":"unauthorized"}`. `internal/receiver` is now the public package
  `receiver`; its `Handler` takes `Keys`, a lookup of an access key to its secrets,
  in place of `Secret`, and is replayed against `contracts/runner/v1/fixtures/signed/`.
- The contract is `v1` revision 1: `X-Qory-Contract-Version: 1` on every request and
  `contract_version: 1` in the ping's data, required. A runner that sends neither is
  revision 0.
- `ai.qory.run.policy_applied`: `declared` is renamed `harness_hosts`, and the narrowing
  is gone: `allow` is the policy's list, and a host the harness declared that the policy
  does not cover is denied under `enforce` like any other. `source` gains `fetched`,
  with `url` and `run_configuration`.
- `ai.qory.run.egress` requires `outcome`: `connected`, `dial_failed` or `refused`.
- A name that resolves to the runner's own machine or to the link-local range, through
  a guarded proxy, is now answered `403` and recorded as denied with the rule
  `wall:own-address`; it was a `502` recorded as allowed.
- `runtimes.Runtime` gains `Headless(args []string) bool`, so a `Runtime` of one's own
  adds the method; returning false keeps what the caller asked for.
- A receiver accepts one more type, `ai.qory.run.resized`, with `cols` and `rows`, and
  `terminal`, an object of `cols` and `rows`, on `ai.qory.run.started` when
  `interactive` is true. A receiver that replays the terminal takes the size from
  `run.started` and changes it at each `run.resized`. A receiver that cut the terminal
  stream into lines itself finds a chunk is now a redraw, not a line: it splits on
  nothing, or on what it wants to.

### Added

- The server, `session.Server`: the runner as a client of one server contract. At start
  it fetches the server's configuration document with a signed `GET`, posts the ping and
  every batch to the events URL the document names, with the access key beside the
  signature, and when the document names a `run` section, fetches the run configuration
  for the run's `forge` and `repository` labels and takes its `security_policy` as the
  run's policy, source `fetched`. A fetch that fails, a document the schema refuses or
  a ping not accepted is no run, and the error names the URL and the status. `--local`
  contacts no server.
- Reload. Every answer to a batch may carry `X-Qory-Configuration` and
  `X-Qory-Run-Configuration`; a digest that differs from what the run holds has the
  runner fetch the document again. A new run configuration takes effect for new
  connections at once, the record gets a second `ai.qory.run.policy_applied` at the
  sequence where it took effect, a tunnel open to a host the new policy denies is
  closed and recorded as a denied `ai.qory.run.egress` with `outcome: refused`, and a
  host the new policy terminates TLS for is terminated on its next connection. A new
  configuration document swaps the events URL and the filter for later batches. One
  reload runs at a time; answers during one are coalesced into the next.
- A reload is as strict as a start. The fetched policy's `credentials` are resolved
  again, as at the start, and go to the proxy in one step with the policy; a terminated
  connection whose credential changed is closed, so no later request carries one the
  new policy does not select. What a start refuses, a credential that does not resolve
  or one selected without a wall, fails the reload: it is reported and the policy in
  force stays. A run configuration the server answered is fetched once per answered
  digest: a document that is the one in force changes nothing, and one that was
  refused is not asked for again until the answer changes; a fetch the server did not
  answer is tried again on the next answer.
- The client follows no redirect, its own or a caller's `http.Client` alike: a 3xx is
  a status like any other, no run at discovery and a retry for a delivery, so the
  access key, the signature and the timestamp never reach a host a redirect names.
- `receiver.Handler` serves the three endpoints with `Configuration`,
  `RunConfiguration`, `Now`, `Window`, `EventsPath` and `RunPath`, answers the digest
  headers, verifies in constant time, looks a key up only after its shape is checked
  and logs nothing about the headers.
- The contract: `server.schema.json`, `configuration.schema.json`,
  `run-configuration.schema.json`; fixtures under `fixtures/server/`,
  `fixtures/configuration/`, `fixtures/run-configuration/` and `fixtures/signed/`, the
  last with real signatures under the published key `ak_f1xt0re000000000` and secret
  `fixture-secret-not-a-real-one`; the section §The server with the canonical string,
  its known answers, the failure rule, the documents, the reload rules and the modes
  of a run; `contracts.Revision`.
- The pseudo-terminal's size in the record, so a replay can lay the redraws of a
  full-screen program over each other: `terminal` on `ai.qory.run.started`, the columns
  and rows the runtime started on, the runner's own terminal's when it has one and 80 by
  24 otherwise; and `ai.qory.run.resized` with the new size at the sequence where the
  runner's terminal was resized and the pseudo-terminal followed, so the chunks after it
  were drawn on the new size. Neither on pipes. Behind the docker wall a resize reaches
  the container's terminal: the docker command runs on the runner's pseudo-terminal,
  takes the resize signal and resizes the container's. The schema
  `events/run.resized.schema.json`; the recorded run under `fixtures/run/` carries both.
- `egress.deny` in the policy: hosts the session may not reach, in `allow`'s grammar,
  in either mode. The proxy decides it first, after the wall's guard and before the
  mode and the allow list: a host an entry covers is refused with a `403`, not
  dialled, recorded as denied with the entry as its rule, under `observe` as under
  `enforce`, whatever `allow` says of it; `allow: ["*.example"]` with
  `deny: ["tracker.example"]` denies `tracker.example` and reaches `api.example`.
  Observe records every connection and denies only what `deny` names. A reload
  carries the list and closes an open tunnel to a host the new one names.
  `ai.qory.run.policy_applied` carries `deny` beside `allow`, the policy's entries.
  `session.PolicyEgress.Deny`; `Under` keeps the deny lists of a policy and its
  ceiling both, whatever their modes, since a deny narrows. Fixtures
  `fixtures/policy/observe-deny.yaml` and `fixtures/run-configuration/observe-deny.json`.
  Revision 1 of the contract is amended in place; it had not shipped.
- `headless` in the descriptor: `args`, the arguments that mean the runtime runs
  without an interface. When one of them is among the arguments the runtime is started
  with, the session runs on pipes even at a terminal, exactly as if the caller had
  asked for that: `ai.qory.run.started` carries `interactive: false` and no `terminal`,
  and the descriptor's `output` source is read. A short argument matches the whole
  token, a long one the token or its `--name=value` form, and nothing else is
  inferred; absent, the caller alone decides. Runtimes differ in how they say "no
  interface", so the descriptor defines the inference and not the command. The Claude
  Code descriptor names `-p` and `--print`, so `claude -p "…"` at a terminal is a
  headless session with no flag to say so. `session.Spec.Interactive` keeps its
  meaning, what the caller has; `runtimes.Runtime.Headless` is what the runtime says
  of the arguments, false from a bare runtime. The invalid fixture
  `descriptor-headless-empty.yaml`.

### Changed

- The terminal stream is chunked at 4096 bytes or at a quiet gap of 50 ms after the
  runtime's last write, whichever comes first, never inside a multibyte character, and a
  line break no longer cuts it. A full-screen program redraws on every keypress, and cut
  at line breaks an interactive session was thousands of `ai.qory.run.log` chunks of a
  few bytes each; now one redraw is one chunk. A stream that never pauses is cut at 4096
  bytes, and what is held when the runtime exits is the last chunk. Pipes keep the rule
  of one line or 4096 bytes. `chunk.NewTerminal` is the writer; `chunk.New` is the
  pipes'.

- The proxy records a connection once its outcome is known: an allowed connection when
  the dial succeeded or failed, a denied one at once. A request inside a terminated
  connection is recorded when its response's headers arrive.
- Behind a wall a run with a server always has its authority, made at the start and
  given to the enclosure, so a reload that brings path rules or credentials can
  terminate the hosts concerned. Without a wall the proxy cannot hold path rules: the
  hosts a reloaded policy holds to paths are taken out of its allow list, denied under
  `enforce` and recorded like any other, the event carries no `paths`, and a report
  line says why.
- `receiver.MaxBody` is 2 MiB, twice the size the contract cuts a batch at, since it
  is what the handler reads before it has verified anything; it was 16 MiB.
- The secret of a server document, and the key, never appear in an event or a log; the
  ping and the run's record hold the events URL and the run configuration URL only.

### Removed

- `webhook.schema.json`, `fixtures/webhook/`, `session.Webhook`, `Spec.Webhook`,
  `ResendSpec.Webhook`, `internal/webhook` and `internal/receiver`.
- The narrowing of the allow list by the harness's declared hosts, and
  `policy.Loaded.Narrow`.

## [0.3.0] - 2026-09-19

### Upgrading

- A caller in Go resolves the runtime before the run: `session.Spec.Runtime` is a
  `runtimes.Runtime`, not a name, and `Spec.Descriptors` is gone. Where a spec had
  `Runtime: "claude"` and `Descriptors: dir`, call `catalog.Lookup("claude", dir)` from
  `github.com/qoryai/runner/runtimes/catalog` and give the spec what it returns. A name
  nothing describes was an error and is now a bare runtime, run and recorded with no
  session events.
- A receiver that requires `runtime_version` in `ai.qory.run.started` no longer finds it
  for a bare runtime; for a described one it is there as before.
- Nothing else changes for a run that uses none of what this release adds: a run whose
  policy selects no credential and has no path rule makes no authority and terminates no
  TLS, and the events it produces only gained optional fields.

### Added

- `session.Spec.Timeout`: a time limit for the runtime. At the limit it is stopped as
  the context ending stops it, `ai.qory.run.exited` carries `reason: timeout`, and
  `Result.TimedOut` is set.
- `runtimes.Runtime`: the boundary between the runner and the program it runs, as
  `wall.Wall` is for an enclosure. A runtime says how a launch is prepared, what its
  records mean and how it is asked to leave; the session package knows no program.
  `runtimes.Described` is a runtime written as a descriptor, `runtimes.Bare` a program
  the runner runs and does not read, `runtimes/claude` Claude Code, and
  `runtimes/catalog.Lookup` resolves a name: the machine's descriptor, the contract's,
  or bare, so any program runs behind a wall. `runtimes/runtimetest` is the conformance
  suite, `Conforms` and `Replays`.
- The descriptor's `stop` section, `signal` and `grace`: how a runtime is asked to
  leave. A run's own `StopSignal` and `StopGrace` override it.
- `session.Spec.StopSignal` and `Spec.StopGrace`: how the runner stops a runtime, at the
  limit or when its context ends. The signal is one of SIGTERM, SIGINT, SIGHUP, SIGQUIT,
  SIGUSR1 and SIGUSR2, SIGTERM unless named, since a runtime may close its session on one
  and drop it on another; the grace is the time until SIGKILL, ten seconds unless named.
  `session.CheckStopSignal` is the check.
- `session.Spec.Labels`: the caller's own names for the run, reported as `labels` in
  `ai.qory.run.started` and nowhere else. At most 16, keys of `a-z`, `0-9`, `_`, `.`
  and `-`, values of at most 256 bytes.
- `session.Spec.Limits` and `wall.Limits`: processors, memory, processes and the size
  of `/dev/shm` for the agent's container, as `--cpus`, `--memory`, `--pids-limit` and
  `--shm-size` with the Docker adapter. The relay gets none.
- `session.ReadPolicy` and `Policy.Under`: a command reads a run's own policy file and
  puts it under the machine's, which it can only narrow.

- Credentials the session never holds. `Spec.Credentials` are the machine's: a secret
  from a variable of the runner's environment, from a file, or from an adapter, a
  program of the machine's that knows one kind of host and prints, as
  `credential.schema.json`, the secret, its expiry, and the hosts, the scheme and the
  paths it is for. A policy's new `credentials` selects among them by name, with an
  argument for an adapter, and defines none. Behind a wall the proxy sets each on the
  requests to its hosts; the enclosure gets placeholders, never a secret. An adapter is
  asked again before its secret expires and when a host answers 401.
- Path rules: `egress.paths` in the policy, and the `paths` of a credential. Of a host
  with paths the run reaches those and no other, so a repository's credential does not
  open another organization's on the same host. A path that could be read two ways is
  denied in either mode.
- TLS termination, for the hosts a credential is for and the hosts with path rules, and
  no other: the proxy answers as the host with a certificate of an authority made for
  the run, whose key never leaves the runner's memory. `wall.Launch.CA` gives a wall the
  certificate; the Docker adapter shows the enclosure one bundle, the image's own
  authorities and the run's, and sets `SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE`, or `Docker.CAEnv`.
  `ai.qory.run.policy_applied` lists `credentials`, `paths` and the `terminated` hosts,
  and on a terminated host `ai.qory.run.egress` is one event per request with
  `request_method`, `path`, `path_rule` and `credential`.
- Work in the background, in the Claude Code descriptor: `ai.qory.session.turn_finished`
  and `ai.qory.session.subagent_finished` carry `background_tasks`, the runtime's own
  list of what is still running, each with its id, type, status, description, and a
  shell's command or a subagent's type. A background command's start was already a
  `tool_started` with `run_in_background` in its input. The runtime reports no exit
  status and no duration for such a task, so the record has neither.
- The conformance suite checks, from inside the enclosure, that a host held to paths is
  held to them, that a terminated host is answered with the run's authority and held to
  its credential's paths, that the credential is set outside, and that no secret and no
  key is inside: not in the environment, not in the bundle, not in the record.
- `session.Resend`: completes and delivers the record of a run that is over, for a
  job's last step after a runner that died or a receiver that was away. The run
  directory gains `delivered.log`, a line per accepted batch written as the answer
  comes, and `lock`, held while the runner lives; a run that still goes is
  `ErrRunning`. A record with no `ai.qory.run.exited` gets one with `reason:
  runner_lost`, and the events no accepted batch named are posted in order.
- `wall.Reaper`, and `Docker.Reap`: removes the containers and networks that carry a
  run's label, what a runner that died left behind. `Resend` asks for it.

### Requirements

- The Docker adapter is tested on Linux with Docker Engine 28, in CI, and with Docker
  Engine 29 on OrbStack; the conformance suite passes on both. It may work on an earlier
  engine, and that is not tested. It depends on the bridge option
  `com.docker.network.bridge.inhibit_ipv4`, which is in the engine's source at 24.0 and
  was not looked for before it, and on the `host-gateway` address. On an engine nobody
  has tried, run the suite: `go test ./wall/walltest` with `QORY_WALL_HELPER` naming its
  Linux build.

### Changed

- **Breaking for a caller in Go.** `session.Spec.Runtime` is a `runtimes.Runtime`, not a
  name, and `Spec.Descriptors` is gone: `catalog.Lookup(name, dir)` gives the runtime a
  name and a descriptor directory gave before. A nil `Runtime` is a bare one named after
  the command. A name nothing describes was an error and is now a bare runtime, and
  `runtime_version` in `ai.qory.run.started` is absent for one.
- The contract's limit that the proxy never reads a TLS connection now has its one
  exception, stated in every run's record: a terminated host. A run whose policy selects
  no credential and has no path rule is as before, with no authority made at all.
- Behind a wall the proxy serves the run's relay alone. Its address was reached by
  other containers of the same engine, on a Linux host, and by other processes of the
  machine; the run's policy bounded what they did with it. Now the relay opens every
  connection it forwards with a secret of the run's, `Launch.ProxyToken`, given to the
  relay through a file and to nothing inside the enclosure, and the proxy closes
  unanswered whatever opens otherwise. An adapter of your own passes the secret to its
  relay, which is `wall.Relay` with `QORY_RELAY_TOKEN` in its environment.
- A `Spec.RunID` that is not a UUID in the canonical lower-case form is refused. It
  went unchecked into the run directory's path and into the events' `subject`, which
  the envelope's schema holds to a UUID.
- The Docker adapter refuses a mount that is a socket, or a directory holding a
  container runtime's socket.

### Fixed

- The contract's event table listed `path` in `ai.qory.run.policy_applied`, which no
  schema and no runner has had since the policy became a value, and said every session
  event may carry `agent_id`, which `ai.qory.session.result` cannot.

## [0.2.0] - 2026-09-17

### Added

- The wall, `wall.Wall`: an optional enclosure for the runtime whose only route out
  leads to the session runner's proxy, so a program that ignores the proxy variables
  reaches nothing instead of going unseen. The session runner stays outside with the
  policy and the webhook's secret, and the enclosure sees the run directory read-only. `session.Spec` gains `Wall`, `Image` and `Mounts`;
  under a wall a nil `Env` is nothing, not the process's own, and
  `ai.qory.run.started` carries `wall` and `image`.
- The Docker adapter, `wall.Docker`, through the `docker` command and no library: an
  `--internal` network for the agent whose bridge holds no address of the host's, a relay container on that network and an ordinary
  one, both containers as the caller's user with every capability dropped and no new
  privileges, the workspace at its own path, the runner's settings read-only, the
  environment through a file so no value is on a command line, and everything removed at
  exit. The proxy binds the network's gateway on a Linux host and stays on loopback where
  the engine is in a virtual machine.
- The guard: behind a wall, or with `ProxyBind` set, the proxy refuses the link-local
  range always, and the runner's own machine, loopback and every address it holds,
  unless an allow entry names the host itself, in either mode. The way around the wall
  is not through the proxy, and a local MCP server or model endpoint is reached through
  it when the policy names it. A refused literal address or `localhost` is a denied
  `ai.qory.run.egress` with the rule `wall:own-address`; a name that resolves to one is
  refused when dialled.
- `wall.Relay`, the one peer an enclosure reaches: it copies a fixed port to one address
  fixed when it starts. The caller's binary runs it in a mode of its own and is mounted
  into the enclosure as the relay and the hook forwarder, so the wall needs no image.
- The conformance suite, `wall/walltest`: the contract's guarantees checked from inside
  the enclosure with a real session behind the adapter. CI runs it against Docker on a
  Linux machine, where a skip is a failure; golden files pin the adapter's command lines
  everywhere else.
- `session.Spec.ProxyBind`, the address the proxy listens on, for a caller that builds
  an enclosure of its own; loopback stays the default.
- `session.Spec.Events`, a stream that gets every event as the JSON line `events.jsonl`
  holds: a run with no receiver is followed on standard output.
- The contract gains §The wall: the guarantees, what crosses, the relay, the suite and
  what ships; and under §Limits the three outcomes of a connection, the model credential
  inside the enclosure, the proxy's address on a Linux host, and hooks on an engine in a
  virtual machine.
- `QORY_RUN_SOCKET` is read as an address: a path, or `unix:` and a path, is the local
  socket, and another scheme is a transport the forwarder refuses by name, so a network
  transport can be added without an old forwarder misreading it.

## [0.1.0] - 2026-09-16

### Added

- The runner contract, `contracts/runner/v1/`: the policy document, the webhook
  configuration, the event types with a JSON schema per data type, the batch and
  signature rules, the runtime descriptor schema, and the Claude Code descriptor with its
  fixtures. The `contracts` package embeds the directory and its tests validate every
  fixture against the schemas.
- The session runner, `session.Run`: the policy, given by the caller as a value and
  validated against the schema, pinned with the digest of its canonical JSON, or observe
  with none; the webhook configuration given the same way; the loopback proxy in observe and enforce modes, one `run.egress` event per
  connection and a 403 for a denied one; the session on a pseudo-terminal when
  interactive and on pipes otherwise, its output chunked into `run.log`; the runtime's
  descriptor mapping its JSON lines and its hook calls to session events; the hook
  forwarder installed into the settings the launch passes, reporting over a local
  socket; a heartbeat; `run.exited` as the result; `events.jsonl` and `output.log`
  under `.qory/runs/<id>/`.
- The webhook sink: a ping the receiver must accept before the run starts when a
  webhook is configured, and none when it is not; signed batches with a delivery id;
  retries with backoff; 410 as stop; what is not accepted spooled under `undelivered/`
  and counted at exit.
- `internal/receiver`, the receiving side the tests run the webhook sink against: a
  handler that verifies the signature in constant time, deduplicates on event id and
  appends to a file that remembers its ids across restarts.
- The contract states that no declaration and an empty declaration differ: no list
  leaves the policy's allow list as it is, an empty list under enforce reaches nothing.
  It names the policy's `egress.allow` grammar as the one definition of a declared host,
  which the harness contract copies.

[Unreleased]: https://github.com/qoryai/forager/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/qoryai/runner/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/qoryai/runner/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/qoryai/runner/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/qoryai/runner/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/qoryai/runner/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/qoryai/runner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/qoryai/runner/compare/v0.1.0...v0.2.0
