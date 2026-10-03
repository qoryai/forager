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
variables are fixed when the run starts; a reload never changes them.

A value the server stores is sealed to a key pair of the runner's own (HPKE base mode,
X25519, HKDF-SHA256, AES-256-GCM) and fetched once per run from a new signed endpoint,
for the connections the run applies. A value the machine keeps comes from a provider on
the machine, bounded by the hosts the machine allows it. Every answer of the server is
signed with the access key's secret, bound to the request it answers, and the runner
recomputes the run configuration's digest, so the values it opens are bound to the exact
document that routes them.

From the server to the runner a stored value is end to end: only the runner process
opens it. From the runner to the host it is sent to, the value travels in a TLS
connection that the proxy verifies against public roots only, by default
(`tls.public_roots_only`), so only a host whose certificate chains to a public root
receives it, never one an authority added to the machine answers for. A machine value travels in an ordinary TLS connection verified against the
machine's trust store.

The contract is `v1`, revision 1, and describes the runner as it is; a later change goes
through `X-Qory-Contract-Version`.

## What changed against the 1076-line draft

- **The secrets list is gone.** `secrets` (name, `used_for`, `how`, `argument`, `source`,
  `from`) leaves the run configuration; `how` and `used_for` leave the contract. "Used
  for" is a note in the server, nothing more.
- **Connections replace it**, and the policy's `credentials` with it. Three kinds,
  `runtime`, `integration` and `service`; a connection references a stored value by id
  (`sec_…`) and value id, or a machine value by name. Without a server, the runner file's
  `connections:` has the same shapes: a machine's static credentials are service
  connections, and a machine's adapter is an integration connection.
- **The machine's connections** apply when a run configuration has no `connections`
  member, as the machine's policy applies without `security_policy`; a present
  `connections`, even empty, is the server's whole set.
- **Machine values** live in `secrets.local`, each with `hosts`, the most it may be sent
  to: `secret_hosts_exceeded` beyond them.
- **Variables** are an object, name to value. A value at most 4 KiB, all variables at
  most 64 KiB.
- **The secrets request** lists the connections the run applies; the server seals only
  their values, and the plaintext echoes the set. The plaintext lists values by secret id
  and value id, each once, beside the digest. Routing leaves the seal: the runner recomputes
  the run configuration's digest, which binds the values to the whole document
  (Decision 6).
- **Value rules** depend on where a value goes: header rules for runtime and service
  values, any text for integration values, a PEM key included.
- **Runtimes declare secrets** in their descriptor (`declares`, `one_of` groups that may
  be `required`, `reserves`, optional `paths`). A walled run is refused when its
  environment contains a variable the runtime declares or reserves, or when no connection
  supplies a required group, and the wall sets every such variable the run does not use
  to empty.
- **Integrations** are started as `<program> <role> -- [arguments]` and receive their
  secrets as a settings document on standard input, always one document, `{}` when
  empty, written from a goroutine; anything they write to standard error is reported with every
  value of that document, every line of a multi-line value and the returned credential
  redacted. `describe`'s name must equal the connection's, and its version is checked
  for compatibility.
- **Services** have exact hosts, no argument, and a scheme from the closed set; header
  names are checked against a data file, `headers.json`.
- **A host the policy denies** does not refuse the run: the value is never set there, and
  the host is reported in `hosts_denied`, decided by the proxy's own function.
- **Gone:** the capability header and its `409`, the seventh line of the answer
  signature, every text about earlier runners, and the scope and precedence text: the
  server resolves which connections apply, and the runner sees a flat list. The answer
  vectors and the sealed fixture are recomputed.
- **At rest** is the server's guidance, not contract. The server's integrity codes cover
  connections, service definitions and every stored rendering. Organisation secrets are
  not in 0.7.0.
- **Ids** are `sec_` or `con_` and 16 lower-case Crockford base32 characters, the form of
  an access key.
- **The server's database** is covered: access key and runner key rows have integrity
  codes too, verified before sealing and on registration.
- **The machine keeps more out of the wall:** a mount of a program the runner starts, a
  `secrets.local` file or a runtime's credential file is refused, and a `secrets.local`
  `env:` source never enters the enclosure, a tool or an integration.
- **Integrations** can be bounded by the machine (`arguments`, `settings`), and their
  settings are checked against their own description.
- **Runner keys** may come from a CI's secret store, need approval before the server
  seals to them, fresh approval on every replacement, and registration has a timestamp.
- **A signing pin, required wherever stored secrets are allowed**: the server signs every
  answer and every envelope with Ed25519, and a runner that pins the key in `runner.yaml`
  or `QORY_SIGNING_KEY` verifies both. A run of an access key allowed stored secrets
  without a pin is no run, `signing_key_unpinned`.
- **Public roots for stored values**: the proxy verifies a host that receives a stored
  value against public roots only, `tls.public_roots_only`, on by default.
- **Every no-run after the ping** emits `dev.qory.run.refused`, a tool or an integration
  that does not start included.
- **Who may link**: only owners and administrators link a secret into a connection,
  define a custom service or enable stored secrets on an access key.
- **Value ids and titles**: a value of a multi-valued secret is addressed by `value_id`,
  and a declaration's human name is `title`.
- **Claude Code's declarations** have `paths: [/v1/*]` and `credential_files`.
- **Limits:** request bodies 32 KiB, sealed values 512 KiB per request in an answer of at
  most 5 MiB, settings documents 64 KiB; values set only on port 443.
- **Resolved:** placeholders are the declarations' conventional names; names are
  variable-style and identity is the id; an integration is matched by name and version;
  the server seals only for the connections the run lists; the digest is the SHA-256 of
  the stored bytes.

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
- **Where a value goes** is the kind's, never the reference's:

  | Kind | Hosts | How |
  |---|---|---|
  | `runtime` | the declaration's, in the runtime's descriptor | the declaration's scheme |
  | `integration` | `roles.credential.hosts` of the program's `describe` | the program's answer: scheme and paths |
  | `service` | the definition's exact hosts | the definition's scheme |

- **Where connections come from.** A run configuration's `connections`, when the member
  is present, even as an empty array, is the server's whole set. When the run
  configuration has no `connections` member, or the run has no run configuration (no
  server, `--local`, or a server that offers none), the runner file's `connections:`
  apply, as the machine's policy applies without `security_policy`; `qory` parses them
  and passes them through `session.Spec`. Machine values stay within their `hosts`
  either way.

## Decisions

### 1. Reserved names

**Variables reach the agent's process and nothing else.** The runner adds them to the
launch's environment only: never to a tool, an integration, the relay, the daemon of a
Docker of the agent's own, or the `docker` command the wall runs on the machine. The
nested Docker helper starts `dockerd` with the system `PATH`, the proxy variables and the
bundle only (Issues, item 3).

**Behind a wall**, a variable with a reserved name is no run, `variable_reserved`, with
the variable's name. The runner decides, before the launch, because it knows what it and
the wall set. The list is a data file the server vendors, `reserved-variables.json`, so
it refuses such a variable when it is saved; the names a machine sets through
`Docker.CAEnv` are the machine's, so the server's check is partial.

| Reserved | Why |
|---|---|
| `PATH` | The enclosure resolves the program the launch starts through it; which program runs is the machine's choice (§Images) |
| every name whose lower-case form ends in `_proxy`, in any case | the runner sets the proxy variables (§Sequence step 5), and any other proxy variable routes around them |
| every name starting `QORY_`, compared without case | the runner's own, `QORY_SERVER_SECRET` included |
| `SSL_CERT_FILE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`, and every name the machine's wall configuration sets in their place (`Docker.CAEnv`) | the wall points them at the run's bundle (§The wall) |
| `DOCKER_CONFIG` | the wall sets it for a Docker of the agent's own |
| a placeholder of this run: a declaration's `name` or an integration's | `variable_secret_conflict`: the enclosure gets the placeholder value there; a name the run's runtime declares or reserves is `runtime_secret_conflict`, which wins |
| every variable the run's runtime declares or reserves | `runtime_secret_conflict` (Runtimes) |
| every variable a `secrets.local` value reads (`env:`) | the machine's value, kept outside the enclosure |

`HOME` stays free behind a wall, and so do loader and interpreter variables (`LD_PRELOAD`,
`DYLD_*`, `NODE_OPTIONS`, `BASH_ENV`, `GIT_CONFIG_*`, `GIT_SSH_COMMAND`): inside the
enclosure they affect the agent's own processes only, which the agent can set for itself
anyway.

**Without a wall** a variable such as `NODE_OPTIONS`, `GIT_SSH_COMMAND`, `BASH_ENV`,
`LD_PRELOAD` or a `HOME` in the checkout runs code on the developer's machine. No list of
refusals is complete, so the machine lists what it accepts: `variables.accept` in the
runner file, names only, empty by default. A variable outside it is no run,
`variable_not_accepted`; the reserved list applies as well. An accepted variable replaces
the value the session would inherit (Open question 4).

**A variable the run itself sets** is no run, `variable_conflict`: a name `qory` lists
through `wall.env`, `--env` or the harness's composed launch, or one the runtime's
`Prepare` sets. The runner reads these names from a new `session.Spec` field (Issues,
item 2; Open question 2).

### 2. Names, value ids and identity

- **Identity is the id.** A stored value is selected by its secret's `sec_` id and, for a
  secret with several values, its value id. A machine value is selected by its name and
  value id in `secrets.local`.
- **The name is in the document.** A reference contains the secret's name for display, so
  renaming a secret changes every rendering that links it and gives it a new digest; a
  run already started keeps what it received.
- **Names** are variable-style, `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, for secrets, variables
  and an external reference's lookup key, `secrets.local` names included. A server
  refuses on save, within a workspace, two secrets or two variables whose names differ
  only in case.
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
  id, with its runner key, digest and set of connections. It seals again for that pair
  only with the same runner key, digest and set (else `409` `run_secrets_conflict`), and
  only until the first payload's `exp` (else `409` `run_secrets_expired`). A run whose row
  the server has already closed receives nothing: `410` `run_closed`.
- **A new run id per attempt.** A caller mints a new run id for every attempt to start a
  run, so a retry never meets the reseal window of an earlier attempt.
- **Superseded run configurations.** The server keeps every rendering. It seals for the
  holder's current one, or for one superseded at most 15 minutes ago, and for an older one
  no longer: `410` `run_configuration_superseded`. From a superseded rendering it seals a
  value only when the holder's current rendering still references it through the same
  connection, so removing a link takes effect at once.
- **Reload.** The runner reads `connections` and `variables` from the run-start fetch
  only. A reload's document may contain them, changed or not, or omit them; the runner
  ignores them either way, and each further `dev.qory.run.policy_applied` repeats the
  start's connections with `hosts_denied` recomputed for the policy now in force. A
  change in the server applies from the next run. To cut a running run off a host, the
  server reloads a policy that denies it: the proxy refuses new requests there, closes the
  open connections to it and records each (§The server, Reload, rules 1 and 2). To cut a
  run off entirely: reload with a `deny`, then revoke the access key. An integration's
  credential keeps renewing.
- **Discovery during a run.** A discovery document that starts listing `secrets` or
  `runner_keys` while a run goes on takes effect at the next run.
- **A reload is only as strong as its delivery.** A middlebox that drops answers keeps the
  run on the policy it has. "No run, never a weaker run" applies at the start; during a
  run, the policy in force stays until a signed answer replaces it.

### 4. Runner key lifecycle

- **Who gets one.** A server lists `runner_keys` and `secrets` in discovery only for an
  access key allowed to receive stored secrets, a per-key setting that is off by default
  and that only owners and administrators enable, so discovery is per access key. A
  developer's own key keeps unwalled runs; a CI or shared runner's key receives stored
  secrets, runs walled and pins the server's signing key (Decision 6).
- **Generation.** The first time discovery lists `runner_keys`, the program that hosts the
  runner generates an X25519 key pair and keeps the private key. For `qory`: the file
  `runner-key` next to `runner.yaml`, `$XDG_CONFIG_HOME/qory/runner-key`, else
  `~/.config/qory/runner-key`. One line: the KEM, `x25519`, a space, the private key in
  base64url without padding.
- **On a CI machine** the key comes from the CI's secret store instead: `qory` reads it
  from `QORY_RUNNER_KEY` or from a file descriptor it is given, in the key file's format,
  and writes no key file. A CI system then has one stable key, which approval and the
  key limit work with, however often its machines are replaced. The variable is reserved
  (`QORY_`) and never reaches a tool, an integration or the enclosure: once `qory` has
  read `QORY_RUNNER_KEY`, `QORY_SERVER_SECRET` and `QORY_SIGNING_KEY` (Decision 6), it
  removes them from its own environment, so nothing the run starts inherits them.
- **The key file.** `qory` creates it with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, in a
  directory of mode `0700`, and refuses a key file whose mode grants anything to the
  group or to others, a file or directory owned by another user than the effective one,
  and the published fixture runner key. Keeping the key, and the access key's secret, in
  the system's keychain is a later option; the CI key path above is the one beside the
  key file now.
- **The runner module writes nothing.** It takes the private key through `session.Spec`.
- **Registration.** The runner registers its public key with a signed POST at every run
  start, after the ping and before the run-configuration fetch; the body contains a
  `timestamp` the server accepts within ±300 seconds. The same key always has the same
  id; the runner computes the id itself and refuses an answer with another,
  `runner_key_mismatch`, and `qory` prints the id, so an administrator approves a key by
  comparing it. A refused, unsigned or mismatched registration answer is no run
  when a connection the run applies references a stored value; otherwise the runner
  reports it and the run goes on.
- **What registration refuses.** `409` `runner_key_invalid`: a public key that is not 32
  bytes; a non-canonical encoding, with bit 255 set or a value of at least p = 2^255 − 19;
  a low-order point, by the computed check "X25519 of a fixed non-zero scalar and the key
  is all zero, or the derivation is refused"; and a public key other than the one already
  registered under the same id. `409` `runner_key_revoked`: a key or an id that matches a
  tombstone. `409` `runner_key_limit`: the access key has as many runner keys as the
  server allows.
- **Approval.** Every new runner key needs approval in the server before values are
  sealed to it. The server seals nothing to a key that awaits approval: the secrets
  request answers `409` `runner_key_pending`. A key registered with `replaces` needs
  approval of its own, every time; it never inherits the old key's. Approval always
  applies, so no setting of the server turns it off. The registration's answer contains
  `approved`, `true` or `false`.
- **Scope.** A runner key belongs to one access key; the server keeps a set per access
  key, unique within it, capped. Every rule here applies per access key. The secrets
  request contains the runner key id, which selects the key the server seals to. The
  access keys page lists each access key's runner keys with their last use and revokes
  one.
- **Rotation.** A `qory` command writes the new key to `runner-key.next`, mode `0600`,
  beside `runner-key`. Each run registers the current key and the new one, the new one
  with `replaces`, the current key's id; the runner module takes both through
  `session.Spec`. A `replaces` that names a key of another access key is `409`
  `runner_key_unknown`. A `replaces` alone revokes nothing: the server revokes the old
  key only once the new one is approved, and until then keeps sealing to the old key,
  which the run keeps using; the first run whose registration answers `approved: true`
  seals to the new key, and `qory` then moves `runner-key.next` over `runner-key`. One
  race remains: a run that
  registers both keys before the approval and requests its secrets after it names the
  old key, which the approval has just revoked. It receives `409` `runner_key_revoked`
  and that run alone fails; the next run uses the promoted key.
- **Revocation.** The server seals nothing to a revoked key. A revoked key stays for good
  as a tombstone, its id, its public key and when it was revoked, so neither can be
  registered again. A runner key id the access key never registered is
  `runner_key_unknown`.
- **Expiry of unused keys.** The server removes an unrevoked runner key unused for a
  period it sets; the machine's next run registers it again as new, and it needs
  approval again.
- **What it protects, plainly.** The runner key protects against TLS-terminating
  middleboxes, logs and the server's stored answers. Approval is the control between a
  stolen access key secret and the workspace's stored values: whoever has the secret can
  register a key of their own, and the server seals nothing to it until it is approved.
- **The access key's secret** is generated by the server, with at least 128 bits of
  entropy; the contract requires it.

**Keeping both from the agent.** An agent that reads the access key's secret or the
runner key fetches every value the server stores for that access key.

- *Unwalled runs.* Once a server's signed discovery lists `secrets`, every run against it
  needs a wall: `server_needs_wall`, decided after the ping so the refusal reaches the
  server. Offline, the runner key is the signal: on a machine where `runner-key` exists,
  or where `qory` is given a key through `QORY_RUNNER_KEY` or a file descriptor, `qory`
  refuses every unwalled run, `--local` included (Open question 3).
- *Mounts.* Every walled run, `--local` included, refuses a mount that is, contains or
  lies inside one of the runner's files, resolved through symbolic links:
  `mount_contains_runner_files`, with the path. The runner's files are:
  - the directory of `runner.yaml` and the runner key, when the runner file configures a
    server;
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
  the start and starts it by its file descriptor, so a later change of the path changes
  nothing.
- *The enclosure's environment.* A run that passes `QORY_SERVER_SECRET`, `QORY_RUNNER_KEY`
  or a variable a `secrets.local` value reads (`env:`) into the enclosure is no run,
  `variable_reserved`. `QORY_SIGNING_KEY` holds a public key, and `qory` keeps it out of
  the enclosure all the same, because only the runner needs it.
- *Integrations and tools* run as the runner's user and are trusted. None of them,
  `describe` included, receives `QORY_SERVER_SECRET`, `QORY_RUNNER_KEY`,
  `QORY_SIGNING_KEY`, a variable a `secrets.local` value reads, or the variables a node
  runner passes its spec in. A node
  runner passes the secret and the runner key through a file descriptor.
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
  no `aad`. `NewSender` and `NewRecipient` refuse a low-order point; Go's
  `ecdh.X25519().NewPublicKey` accepts one (both verified), so registration checks
  explicitly.
- **Elixir.** `:crypto` alone implements base mode for this suite. `:crypto.compute_key`
  raises for a low-order point, because OpenSSL's `EVP_PKEY_derive` refuses an all-zero
  result; the sealer checks for an all-zero DH output itself all the same, for a defined
  error independent of the OpenSSL build. Every seal uses a fresh ephemeral key; a seam
  that fixes it exists for the known-answer test only and is compiled out of production
  builds; a test checks that two seals of one plaintext have different `enc`.
- **Encodings.** base64url without padding for every binary value. Registration sends the
  raw 32-byte public key. The runner key id is
  `base64url(SHA-256(kem_id as u16 big-endian || raw public key)[:16])`, 22 characters.
- **Interoperability tests.** Each side checks its implementation against the CFRG
  `test-vectors.json` for this suite, base mode, the file Go vendors as
  `crypto/hpke/testdata/rfc9180.json`; the server's implementation passes it. Each side
  also seals with its own code and the other side's test opens the result.
- **Deliverable: `contracts/runner/v1/fixtures/sealed/`**, a fixed-ephemeral vector. It
  was sealed by an RFC 9180 implementation written for this check, which reproduces the
  server's earlier vector byte for byte, and opened by Go's `crypto/hpke` (verified):

  | Input | Value |
  |---|---|
  | recipient private key | `AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA` (bytes 1 to 32); public key `B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw`; runner key id `3sVqYB9mvRVgaGW-JNlyfw` |
  | ephemeral private key | `ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A` (bytes 33 to 64) |
  | run id, access key, exp | `01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a`, `ak_f1xt0re000000000`, `1700000600` |
  | run configuration | the 583 bytes below, the two connections the plaintext lists; digest `sha256=4a6a9f4309a202d3c8663b8e6ce1d6ffce29afcf1f3516397e79b2ad9987f768` |
  | `info` (hex) | `716f72792073656372657473207631000020000100020016337356715942396d765256676147572d4a4e6c796677`, 46 bytes |
  | `aad` (hex) | `002430313932386634652d376333612d376432652d396231612d3366356536643763386239610013616b5f663178743072653030303030303030300016337356715942396d765256676147572d4a4e6c79667700477368613235363d34613661396634333039613230326433633836363362386536636531643666666365323961666366316633353136333937653739623261643939383766373638000a31373030303030363030`, 168 bytes |
  | plaintext | `{"version":1,"run_configuration":"sha256=4a6a9f4309a202d3c8663b8e6ce1d6ffce29afcf1f3516397e79b2ad9987f768","connections":["con_0b5n6t2r9y4f7j3s","con_7q2m4k9x0d3h8w1c"],"values":[{"secret":"sec_3fz8k2m9q4w7x1d6","value":"fixture-value-not-a-real-one"},{"secret":"sec_9c4r7t2y5b8n1h3e","value_id":"production","value":"-----BEGIN FIXTURE-----\nnot-a-real-key\n-----END FIXTURE-----\n"}]}`, 386 bytes, the `\n` being JSON escapes |
  | `enc` | `WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns` |
  | `ct` | 402 bytes, SHA-256 `475d1d836a0f707942b120933938e44c0cb2a36071fac46e174e9c690909a053` |

  The run configuration:

  ```json
  {"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.anthropic.com","github.com","api.github.com"]}},"connections":[{"kind":"runtime","id":"con_7q2m4k9x0d3h8w1c","name":"claude","secrets":{"oauth_token":{"id":"sec_3fz8k2m9q4w7x1d6","name":"CLAUDE_OAUTH"}}},{"kind":"integration","id":"con_0b5n6t2r9y4f7j3s","name":"qory-github","repository":"github.com/qoryai/qory-github","version":"1.4.0","argument":"acme/shop","settings":{"app_id":"123456"},"secrets":{"private_key":{"id":"sec_9c4r7t2y5b8n1h3e","name":"GITHUB_APP_KEY","value_id":"production"}}}]}
  ```

  `ct`:

  ```
  vWlOGjqntNxqkgdXlQiXxG5i2wUIYkZ_S_CUDYYQHLkxuXtCRP-2oFtTzFQxkdlOltSo0TFbwYHgCgjeLFz-eU7F4LeAN1UwiZUGUG3-rJcRkLEA8mIAjIRzhED05wNZ1nZirqik78fzXsDxTEdXRcIHro6DLtLlCxZKp-IiinXJ7NdElM6np4BIn1Jbo9QFVrsW5N0ht8ECwccpQPNiwKMb4fdcfwB_7s5cCYr8Uue1iat7U0vdp5Vo7BrSuA2OEXr5kYMPKWU20J5Mx1-yRa1Xt4bkzLpDNnQT7unP2x-L9TPR1JF4P4FlKh-6Km53a1YlubL0HU5kXzI9bdlfJgxvFEXUCCoCakQGSTdgc2LHPHAGddD0CytLTCRZ0LH1e-3KuAzc5YNttKhYwrHndudEWrpsNvHS5wnaaU3_ISEMq0ldtPi4yJIlDIMPX8bOI7G_dBtAn5uiUBAlxBCqCoK9_xrez1FRz3MyJ8ahUrWUu16VNCDaaPusMA6Kn2SP89dPUb0mcJowTest1dsptSA1
  ```

  A second case alters `aad` and expects the open to fail.

  The envelope's `sig` (Decision 6), under the fixture signing key, seed bytes 65 to 96,
  `QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A`, public key
  `rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc`: the signed message is 667 bytes, SHA-256
  `05cc542edbab0e6c44553a8f493f5573292c51b2748cb6e2ff7d7ffe80aabd5e`, and `sig` is
  `TXefQcY9H1pHjNXxE2l9scgq4M0-MwNUVKwQ8vtluRbe38uzPyd3W3GZwfxRlgrPExzdxtmAwFnauAcpsDZhDg`.
  Go's `crypto/ed25519` reproduces the server's signature over the previous fixture
  (664 bytes, SHA-256 `034968b4…ded1`), which confirms the framing.
- **Public keys registration refuses**, a test list. The low-order points have five
  u-coordinates: 0, 1, p − 1, and two of order 8. With bit 255 ignored, as X25519 does,
  their encodings are fourteen; Go refuses all of them in the derivation (verified):

  | Value | base64url |
  |---|---|
  | 0 | `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` |
  | 1 | `AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` |
  | order 8 (first) | `4Ot6fDtBuK4WVuP68Z_EatoJjeucMrH9hmIFFl9JuAA` |
  | order 8 (second) | `X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEVc` |
  | p − 1 | `7P_______________________________________38` |
  | p | `7f_______________________________________38` |
  | p + 1 | `7v_______________________________________38` |
  | each of the seven with bit 255 set | `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA`, `AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA`, `4Ot6fDtBuK4WVuP68Z_EatoJjeucMrH9hmIFFl9JuIA`, `X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEdc`, `7P________________________________________8`, `7f________________________________________8`, `7v________________________________________8` |

- **Later.** X25519 is refused under `GODEBUG=fips140=only`. ML-KEM-768 with X25519,
  `0x647a`, is in the same Go package; it becomes another suite value.

### 6. Routing and the seal

**Decided.** Routing leaves the seal. The runner recomputes the run configuration's
digest, and the server seals from the verified rendering for the connections the run
lists. The reasoning follows.

**The question.** Base mode authenticates no sender: anyone with the runner's public key
can seal. An earlier draft therefore put each value's routing inside the seal. Routing
now lives in the connections, inside the signed run configuration whose digest is in
`aad`.

**For keeping routing in the seal.** It binds each value to its hosts under the runner
key, whatever happens to the document. But a connection's routing is no longer a list of
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
it, whoever can sign answers, a holder of the access key's secret on the path, could
serve forged connections under a real digest and have real values routed to a host of
its choosing. It adds protection because such a holder cannot simply register a key of
its own and fetch values directly: every new runner key needs approval (Decision 4).

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
- an integrity code over each access key row: its id, its secret and the previous one
  during a rotation, as bytes the server defines, its workspace, its stored-secrets flag,
  its automatic approval of runner keys when that option exists (Open question 1), and
  whether it is revoked. The secret is already encrypted at rest under the instance key, so a
  reader of the database does not get it; the code stops a writer who moves a ciphertext
  between rows, enables stored secrets or un-revokes a key;
- an integrity code over each runner key row: its public key, its access key, its
  approval and its revocation, so a writer cannot insert or approve a key; approval is
  always required, so there is no switch for a writer to turn off;
- the access key row's code verified on every request's authentication: a row whose code
  fails does not verify, `401`, unsigned, on every endpoint, so a writer cannot
  un-revoke a key for the GET or the events endpoint either, and the server never signs
  with a secret from a row it cannot trust; the runner key row's code on registration
  and before sealing, else `503` `unavailable`;
- a per-row version inside the coded data, with the audit recording the current version
  of each row, so an older row restored over a newer one is detected unless the audit is
  rolled back with it;
- audit of every change with before and after.

All codes use the same key, derived from the instance key with HKDF-SHA256. A connection
or definition whose code fails refuses the render, and the holder keeps its last good
rendering; an access key or runner key row whose code fails seals nothing. None of this
stops a writer who has the instance key, nor a change made through the server's own
pages, which is authorization's matter.

**Who may route a value.** In 0.7.0 only owners and administrators may link a secret into
a connection, define a custom service, or enable stored secrets on an access key. Linking
a secret needs the `secret.use` permission on it, which only owners and administrators
hold. Finer roles are a later release.

**The limit of a shared secret.** Base mode and an answer signature under the access
key's secret leave one thing open: a holder of that secret cannot reroute real values,
but it can forge documents, seal values of its own choosing to the runner and sign the
answers, and the agent then uses those values on the hosts the connections route to. A
pin of the server's signing key closes it, and it is required wherever stored secrets
are allowed:

- The server has an Ed25519 key of the instance: `SIGNING_KEY` when it is set, which
  overrides the default, else one derived from the instance key with HKDF-SHA256 under a
  label of its own, distinct from the integrity key's. The server's documentation
  recommends `SIGNING_KEY` wherever machines pin, so a rotation of the instance key does
  not break the pins. Discovery for every verified access key lists the current public
  key, and during a rotation the next one too, `signing_key: [{"alg": "ed25519",
  "public_key": "<32 bytes, base64url>"}]`, for information only; the access keys page
  shows it. The published fixture signing key is refused as a pin and as the server's
  key, as the fixture runner key is.
- The server signs every answer to a verified request with it, whether or not the
  runner pins it: `X-Qory-Signature-Ed25519: <64 bytes, base64url>`, over the six lines
  of Signed answers with `qory-answer-ed25519-v1` as the first line. An answer to a
  request that did not verify, a `401` or a `400` before verification, is signed by
  neither signature.
- The envelope gains `sig`, the 64-byte signature in base64url, over
  `lp32("qory envelope v1") ‖ lp32(suite) ‖ lp32(runner_key_id) ‖ lp32(run_id) ‖
  lp32(access_key) ‖ lp32(run_configuration) ‖ lp32(exp in canonical decimal) ‖
  lp32(enc, raw) ‖ lp32(ct, raw)`, where `lp32` is a u32 big-endian length, then the
  bytes.
- A runner whose server document pins the key, `signing_key` in `runner.yaml`'s
  `server` section, a list of public keys so the key can rotate, takes the key from the
  pin only, never from discovery. It then requires both: the Ed25519 signature on every
  answer, discovery, the run configuration, registration, the secrets request and every
  event answer, treated as an unsigned answer when it fails (no run at start, a retry
  where today's rules retry); and the envelope's `sig`, verified before opening,
  `envelope_signature_invalid`. An unpinned runner checks neither. The pin is the
  machine's, so nothing on the wire can remove it.
- **The pin is required wherever stored secrets are allowed.** A run is no run,
  `signing_key_unpinned`, when the runner has no pinned `signing_key` and discovery lists
  `secrets` or `runner_keys`, which it does only for an access key allowed stored
  secrets, or a connection the run applies references a stored value. For any other
  access key the pin is optional.
- **How a machine gets the pin.** The pin is a public key, so it needs no secret store.
  It comes through the runner file, baked into the machine's image, or through a plain CI
  variable, `QORY_SIGNING_KEY`, whose value is the same list as `signing_key`, written as
  JSON: `[{"alg": "ed25519", "public_key": "<32 bytes, base64url>"}]`. An ephemeral or CI
  machine sets the variable or carries the runner file in its image. `qory` takes the
  pin from the variable when the runner file's `server` section has no `signing_key`,
  and refuses to start when both are set, so the pin has one source. Unlike
  `QORY_RUNNER_KEY` the variable is not secret, but `qory` still removes it from its own
  environment and keeps it out of the enclosure, because only the runner needs it.

### 7. Machine values and the runner file

- **Providers.** `secrets.providers` in the runner file is the ordered list of providers
  an external reference `{source: external, name, value_id?}` is resolved through; the
  default is `[local]`. The first provider that defines the name, and the value id when one
  is given, resolves it; none is `secret_unresolved`, with the connection and the
  providers tried. Later: `vault`, a cloud's secrets manager, and the like.
- **The `local` provider** is the section `secrets.local`: values by variable-style name,
  each from the runner's environment or a file, or several under value ids, each with `hosts`,
  the most the machine allows it to be sent to, in `egress.allow`'s grammar:

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

- **The policy selects no credential.** `credentials` leaves `policy.schema.json`, and
  with it the run configuration's `security_policy`, `--policy` files and the machine's
  policy: what a run may send where is decided by connections alone. The policy keeps
  `egress`, `tools` and `image`.
- **Connections need a wall**: `connection_needs_wall`. Without one, a program that
  ignores the proxy is bound by nothing.
- **Where it lives.** `qory` parses `runner.yaml`; the runner module takes the providers,
  the local values, the integrations, the runner file's connections and
  `tls.public_roots_only` (Connections at the proxy) through `session.Spec`.

### 8. Contract version and behaviour

- **Revision 1.** Every document here is `v1`, revision 1, and the runner sends
  `X-Qory-Contract-Version: 1`. A later change to what a server may rely on goes through
  that header.
- **Answer signatures are required.** Every runner refuses an answer without a valid
  signature, whatever the runner file contains.
- **`TRACE` and `TRACK`** are refused with a `403`, rule `wall:trace`, on every host where
  the proxy sets a value, because such a request returns its headers to the sender.
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
```

- A declaration's `hosts` are exact DNS names, no wildcard, no IP literal; its `auth` is a
  scheme from the closed set; its optional `paths`, in the policy's path grammar, bound
  the requests its value is set on. A credential that can mint credentials gives the
  agent a readable one if the agent reaches the minting path, so a declaration bounds its
  value with `paths`: Claude Code's are `/v1/*`. A request of the run to
  `api.anthropic.com` outside `/v1/` is refused, not merely sent without the credential,
  as on any host with paths, and the exact paths Claude Code needs are a release-gate
  check. Whether `api.anthropic.com` serves a path that creates an API
  key from an OAuth credential is to verify. Warning about an administrative key on save
  is the server's matter.
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
  placeholder need not look like a key: Claude Code does not check the format. Another
  connection whose placeholder is a variable the run's runtime declares or reserves is
  refused, `placeholder_conflict`: only the runtime connection sets those.
- **Conflicts.** A walled run is refused when its environment, `Spec.Env` with
  `wall.env`, `--env` and the harness's launch, or its variables contain a variable the
  run's runtime declares or reserves: `runtime_secret_conflict`. For Claude Code these
  are `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN`. Claude
  Code reads `ANTHROPIC_AUTH_TOKEN` before `ANTHROPIC_API_KEY` before
  `CLAUDE_CODE_OAUTH_TOKEN`, so a stray value for another alternative would win over the
  stand-in. A model credential from the run's environment never reaches a walled run.
- **Credential files.** `credential_files` lists files in which the runtime keeps a
  credential of its own, for Claude Code `~/.claude/.credentials.json`, `~` being the home
  of the user the runner runs as; for Claude Code the runner also reads
  `CLAUDE_CONFIG_DIR`, and `.credentials.json` in it. A walled run refuses a mount that is
  or contains one, resolved through symbolic links:
  `mount_contains_credential_files`. A file baked into the image is out of the runner's
  reach; that is the image owner's matter.
- **Emptied.** The wall writes every variable the runtime declares or reserves that the
  run does not set a placeholder in, as an empty value in the enclosure's environment
  file, so an image's own `ENV` cannot set one. This relies on Claude Code reading an
  empty value as unset, a check of Tests and release gates.
- **Interactive mode.** With `ANTHROPIC_API_KEY` set, an interactive Claude Code waits for
  the user to approve the key unless its last 20 characters are listed in
  `~/.claude.json` under `customApiKeyResponses.approved`; headless (`-p`) does not.
  Follow-up work: the claude runtime's `Prepare` pre-approves the constant stand-in,
  whose last 20 characters are `utside-the-enclosure`, in the run's copy of the
  configuration.
- **Which runtime.** One runtime connection per runtime name: two are
  `runtime_connection_duplicate`. The runner applies the runtime connection for the run's
  own runtime and sets any other aside: it is not listed in the secrets request, nothing
  is sealed for it, and it is not reported as received.
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
  `session.Spec`, name to program path. The runner never installs anything. A connection
  whose `name` the machine lacks is `integration_missing`.
- **Name and version.** At run start the runner runs `describe` and requires its `name`
  to equal the connection's, else `integration_name_mismatch`, so a program registered
  under another name cannot answer for a connection. When the connection has a
  `version`, which a server's always has, `program_version` must equal it after removing
  one leading `v`; `dev` never matches: `integration_version_mismatch`. This is a
  compatibility check, not identity: `describe` is the program's own report
  about itself. Trust in the program rests on `qory`'s path and ownership checks; matching by
  name and version is enough, and a program digest recorded at install is a later option.
- **Hosts** are `describe`'s `roles.credential.hosts`; a `*.` entry over a public suffix,
  the private section included, is `connection_host_public_suffix`. Scheme and paths come
  from the program's answer, `credential.schema.json`; a claim above the described hosts
  is refused.
- **What the hosts bound.** For an integration, the hosts bound only where the proxy sets
  the credential the program produces. The program runs outside the wall and receives
  the raw value, and where it sends that value is the program's. The server chooses
  `argument` and `settings`, which steer the program.
- **The machine's bounds.** An entry of `integrations:` may bound what a server chooses:
  `arguments`, an RE2 pattern the argument must match whole, else
  `integration_argument_not_allowed`; and `settings`, per member a fixed value or
  `{pattern: <RE2>}`, a member the bound does not list being refused,
  `integration_settings_not_allowed`. A server-sent integration connection that
  references a machine value needs an `arguments` bound; without one it is no run,
  `integration_argument_not_allowed`. Before it writes standard input the runner also
  validates the settings, with the secret values inlined so a required `writeOnly`
  member passes, against the program's own description, else
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
  connection has no `argument`. A program takes no flags for a role, and refuses
  `--settings` as it refuses any unknown flag.
- **Standard input** always carries exactly one JSON document: the connection's
  `settings` with each secret's value inline under its setting's name, a name in both
  being `run_configuration_invalid`. It is `{}` when there is nothing to send, so a
  connection without `settings` runs with `{}`. The runner always connects standard input
  to the document, never to a terminal, writes it whole and closes it. The program reads
  it to its end before any network request, and refuses empty input, a second document
  or trailing data. `describe` reads no standard input.
- **The settings document** is written from memory, from a goroutine (`cmd.Stdin` set to
  a `bytes.Reader`), so a program that never reads cannot stall the runner. It is written
  again on every invocation, renewals included, and never goes to a file, an argument,
  the environment or a log. It is at most 65536 bytes (64 KiB) as encoded; the runner
  refuses a larger one before it starts the program, `integration_settings_too_large`,
  and the server refuses on save a link that would make it larger with a stored value. No
  `${argument}` is replaced inside it.
- **What the program writes to standard error** is reported, in errors and as the
  runner's lines, only after `[redacted]` replaces, matched exactly, every value written
  to its standard input, every line of 8 bytes or more of a value that has several
  lines, and the credential the program returned. Redaction, not dropping, keeps the program's own reason
  readable. It does not catch a value the program transforms before writing it, such as
  an encoded form; that is the program's to avoid.
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
  roots only: the runner's own copy of the public root store
  (`golang.org/x/crypto/x509roots/fallback`), never the machine's trust store. An
  authority added to the machine, such as a TLS-inspecting proxy's, then receives no
  stored value. The runner file switches it explicitly:

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
  stored values. When a host fails verification against public roots, the proxy's
  connection to it fails: `dev.qory.run.egress` records `dial_failed` with the rule
  `wall:public-roots`, the value is never sent, and the run goes on.
- **A host the policy denies** does not refuse the run. The run starts; a request to the
  host is refused by the policy, so the proxy never sets the value there; the host is
  listed in the connection's `hosts_denied`. The list comes from the proxy's own decision
  function, the host lists and the path rules both, so the record and the proxy cannot
  disagree. Under `observe`, every connection host that `deny` does not cover receives the
  value.
- **Nested Docker.** A run with stored values may use a Docker of the agent's own: values
  never enter the enclosure, so the containers the agent starts receive none either.
- **One credential per host.** Two connections, or a connection and a tool, whose hosts
  overlap, one entry covering the other as `*.github.com` covers `api.github.com`, are
  `connection_host_conflict`.
- **Paths.** A service's or runtime declaration's `paths` and an integration's answer
  bound the requests the value is set on; the policy's path rules apply as well, and a
  request passes when every list that exists has an entry that matches.
- **Values.** A value set in a header, for a runtime or a service, follows the header
  rules of Endpoint rules, else `secret_value_invalid`; a value an integration receives
  on standard input is any text.

## Wire format

### The configuration document

```json
{"version": 1,
 "events": {"url": "https://qory.example/v1/events", "types": ["*"]},
 "run": {"url": "https://qory.example/v1/run-configuration"},
 "runner_keys": {"url": "https://qory.example/v1/runner-keys"},
 "secrets": {"url": "https://qory.example/v1/secrets"},
 "signing_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
```

`runner_keys` and `secrets` are optional, each `{url}` with `run.url`'s grammar, listed
only for an access key allowed to receive stored secrets. `signing_key` is listed for
every verified access key, for information: a runner takes the key from its pin only. `run` is listed when the
workspace has a policy, a connection or a variable.

### The run configuration

`version` is required; `security_policy`, `connections` and `variables` are optional, all
covered by the digest. Without `security_policy` the machine's own policy applies, the
policy the command passes, else observe everything: `dev.qory.run.policy_applied` reports
`source` `config` or `none` with `url` and `run_configuration`, a reload that brings a
`security_policy` puts it in force and one that drops it puts the machine's back, and
`--policy` keeps its meaning. Without `connections` the runner file's connections apply;
a present `connections`, even `[]`, is the whole set. The request is the labels, and nothing else, as the query;
labels the contract refuses are `400` `invalid_request` here and on the secrets request
alike, decided by one resolver.

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
 "variables": {"NODE_ENV": "test", "APP_REGION": "eu-west-1"}}
```

`connections` is in the server's order, which the record repeats. Schema sketch:

```json
"connections": {"type": "array", "maxItems": 32, "items": {"oneOf": [
  {"$ref": "#/$defs/runtime"}, {"$ref": "#/$defs/integration"}, {"$ref": "#/$defs/service"}]}},
"variables": {"type": "object", "maxProperties": 128,
  "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_]{0,127}$"},
  "additionalProperties": {"type": "string", "maxLength": 4096, "pattern": "^[^\\u0000\\r\\n]*$"}},
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
`reserves`, variable names; `credential_files`, paths, `~` for the runner's user's home.
Its `runtime` pattern becomes `^[a-z][a-z0-9-]{0,63}$`.

### Contract files the server vendors

All under `contracts/runner/v1`, so one pin covers them:

- `runtimes.json`, generated from the built-in descriptors and checked in CI against
  them: per runtime its `name`, a `title`, its `reserves`, its `credential_files`, its
  declarations with `id`, `title`, `name`, `hosts`, `auth` with its `header`, and `paths`, and its `one_of`
  groups with `id`, `required` and `of`;
- `reserved-variables.json`, the names and prefixes of Decision 1 that do not depend on
  the machine;
- `headers.json`;
- `run-configuration.schema.json` and `policy.schema.json`, without `credentials`;
- `auth.schema.json`;
- `secrets-request.schema.json`, the secrets request's body, and
  `runner-key.schema.json`, the registration's body and its answer, with `approved`
  required;
- `events/run.refused.schema.json` and `events/run.policy_applied.schema.json`, with
  `connections` and `uses`;
- `server.schema.json`, with the optional `signing_key` pin.

### Runner key registration

A signed POST to `runner_keys.url`:

```json
{"version": 1, "suite": "x25519-sha256-aes256gcm",
 "public_key": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw",
 "replaces": "<the old key's id, on rotation only>",
 "timestamp": 1700000000}
```

The server authenticates the request, the access key row's integrity code included, else
`401`; accepts `timestamp` within ±300 seconds, else `401`; verifies the runner key
row's integrity code when the key is already registered, else `503` `unavailable`; and
answers `200` (or `201` the first time):

```json
{"version": 1, "runner_key_id": "3sVqYB9mvRVgaGW-JNlyfw", "approved": false}
```

`approved` is required in `runner-key.schema.json`'s answer: `true` once the key is
approved, `false` while it awaits approval. Otherwise the answer is `409` with
`runner_key_invalid`, `runner_key_revoked`, `runner_key_limit`, or `runner_key_unknown`
for a `replaces` that is not a key of the same access key. A replayed registration is
harmless.

### The secrets request and the envelope

A signed POST to `secrets.url`, once per run, after the run configuration and only when a
connection the run applies references a stored value:

```json
{"version": 1, "run_id": "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a",
 "runner_key_id": "3sVqYB9mvRVgaGW-JNlyfw",
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

1. accepts `timestamp` within ±300 seconds, else `401`;
2. refuses an access key not allowed stored secrets: `409` `secrets_not_allowed`;
3. finds the runner key registered to the access key and not revoked, else `409`
   `runner_key_unknown` or `runner_key_revoked`, and approved, else `409`
   `runner_key_pending`; the runner key row's integrity code must verify, else `503`
   `unavailable` (the access key row's was verified when the request was authenticated);
4. refuses a run whose row it has closed: `410` `run_closed`;
5. resolves the holder the labels select, with the GET's resolver, and requires that
   holder's current rendering, or one superseded at most 15 minutes ago, to have the
   digest, else `410` `run_configuration_superseded`; that rendering's integrity code
   must verify, else `503` `unavailable`, as on the GET;
6. requires `connections` to be connections of that rendering, every one that is not a
   runtime connection and at most one runtime connection, else `409`
   `run_connections_invalid`;
7. applies the reseal rules (`409` `run_secrets_conflict`, `run_secrets_expired`);
8. parses the rendering's stored bytes and collects the distinct pairs of secret id and
   value id that the listed connections reference with an id;
9. for each pair, seals the stored value only when the secret still exists and has that
   value id, and, for a superseded rendering, the holder's current rendering still references
   the pair through the same connection. Any other pair is left out, and the runner
   refuses the run, `secret_unresolved`. The value sealed is the current one;
10. seals with a fresh ephemeral key, `exp` its own time plus 600 seconds.

The answer, `200`:

```json
{"version": 1,
 "sealed": {"suite": "x25519-sha256-aes256gcm",
            "runner_key_id": "3sVqYB9mvRVgaGW-JNlyfw",
            "run_id": "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a",
            "access_key": "ak_f1xt0re000000000",
            "run_configuration": "sha256=<64 hex digits>",
            "exp": 1700000600,
            "enc": "<32 bytes, base64url>",
            "ct": "<ciphertext and tag, base64url>",
            "sig": "<64 bytes, base64url, Ed25519 of Decision 6>"}}
```

A `410` here is no run; it never means the events endpoint's "stop". The runner checks
the envelope's identifiers against its own and `exp` against its clock, then builds
`info` and `aad` from its own values, never from the envelope's. The server keeps its own
record per access key and run id, with the reason for each value it left out; that
record is the server's, and nothing of it reaches the runner.

### Endpoint rules

For `runner_keys.url` and `secrets.url`:

- **Content type** `application/json`, else `415`; every answer `application/json`. A
  request has no `Content-Encoding` (a server answers `415` to one); the runner sends
  no `Accept-Encoding` but `gzip`.
- **Sizes.** A request body at most 32 KiB, else `413`. The largest secrets request has
  16 labels with a 64-byte key and a 256-byte value, at most 1,606 bytes each once every
  byte of a value is escaped as `\u00XX`, 25,696 in all; 32 connection ids, 736 bytes;
  and under 300 bytes besides: about 26.7 KiB. Without escapes it is about 6.3 KiB. The
  secrets answer is at most 5 MiB: 512 KiB of values, every byte escaped at six bytes,
  is 3 MiB of plaintext and 4 MiB in base64url. A refusal body is at most 64 KiB.
- **Members.** A member the schema does not define is refused. A POST's signature covers
  its body and not its path, so a body signed for one endpoint must fail at every other.
  The runner decodes the envelope and the plaintext, and the server the request bodies,
  with `encoding/json/v2` and `RejectUnknownMembers(true)`, since v2 ignores unknown
  members by default; member names are compared with case, never relaxed; a value
  decoded in part before an error is discarded; and `exp` is decoded as an unsigned
  integer, so a negative one is refused.
- **Order of refusals.** `413`; `415`; `400` `bad_request` for a header sent twice; `401`;
  `429`; `400` `unsupported_contract_version`; `400` `invalid_request` for a body that is
  not JSON, fails its schema, has another `version`, an unknown `suite`, a `run_id` that is
  not a canonical lower-case UUID, a malformed digest or labels the labels' rules refuse;
  then each endpoint's own. Everything before `401` is unsigned; everything from `429` on
  is signed.
- **Rate limits** are the server's policy, per access key. A `429` at run start is no
  run, `rate_limited`; an event POST's `429` is retried as today.
- **Answer headers.** Answers of these two endpoints contain neither digest header. Every
  signed answer contains `Cache-Control: no-store, no-transform`.
- **Counts.** At most 32 connections, 16 references per connection, 16 hosts and 32 paths
  per service, 32 distinct stored values and 512 KiB of values per secrets request, and
  a settings document of 64 KiB (65536 bytes) per integration. The server checks the counts per holder
  when it renders.
- **Values.** Every secret value is UTF-8 text, 1 to 16384 bytes, with no NUL; a binary
  secret is stored encoded, base64 for one, as its consumer expects. A value linked to a
  runtime or service connection, which goes into a header, also has no byte
  `0x01`–`0x08`, `0x0A`–`0x1F` or `0x7F` and no leading or trailing space or tab; bytes
  from `0x80` travel as `obs-text`, which some hosts refuse. A value linked only to
  integrations, which goes on standard input, may contain line breaks, such as a PEM key.
  The server checks a value against every link when the value is saved and when a link
  is saved, such as an existing PEM key linked to a service connection; the runner checks
  it where it uses it, `secret_value_invalid`. A variable's value is at most 4 KiB, with no
  NUL, carriage return or line feed; all variables, names and values, at most 64 KiB. A
  runner refuses a document over these limits, `run_configuration_invalid`.

### info and aad

`lp(x)` is `x`'s length as a u16 big-endian, then `x`.

| Input | Bytes |
|---|---|
| `info` | `qory secrets v1` ‖ `0x00` ‖ `0x0020` ‖ `0x0001` ‖ `0x0002` ‖ lp(runner key id) |
| `aad` | lp(run id) ‖ lp(access key) ‖ lp(runner key id) ‖ lp(run configuration digest) ‖ lp(`exp` in canonical decimal) |

With the example values, `info` is 46 bytes and `aad` 168. The set of connections is not
in `aad`: the answer's signature binds the answer to the request that listed it, and the
plaintext echoes it.

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
  pairs those connections reference with an id, each once: a missing pair is
  `secret_unresolved` with the connections that reference it, an extra or repeated one,
  another digest or another set `secret_sealed_mismatch`.
- A value follows the value rules above, for where it is used.
- The runner decodes with `encoding/json/v2` under the options of Endpoint rules; v2
  refuses a member name twice in one object by default (verified on Go 1.27.1):
  `secret_sealed_invalid`. It never wraps that decoder's errors, nor the schema
  validator's, whose messages can quote input.

### Signed answers

Every answer to a request that verified contains `X-Qory-Signature-256: sha256=<hex>`,
the HMAC SHA-256 under the access key's secret of six lines joined by `\n`, with no
newline after the last:

1. `qory-answer-v1`;
2. the status, three decimal digits;
3. the request's `X-Qory-Signature-256` value exactly as sent;
4. the lower-case hex SHA-256 of the body as the server produced it, before any content
   coding;
5. the answer's `X-Qory-Configuration`, or empty;
6. the answer's `X-Qory-Run-Configuration`, or empty.

The server signs in a hook that runs before the answer is sent, with the secret the
request verified under, over every answer to a verified request, `202`, `404` and `503`
included. A `401`, and a `400`, `413` or `415` sent before verification, go out unsigned by
either signature, HMAC or Ed25519. With a pin, the Ed25519 signature of Decision 6 is
required beside this one.
At run start the runner treats an answer without a valid signature as no run,
`answer_unsigned`; registration's answer decides the run only when a stored value is
referenced. During the run an event answer without one is no answer, retried as today,
its headers unread; a reload's fetch without one fails the reload. A code in a body is
reported only from a signed answer; a refusal body over 64 KiB counts as unsigned. The resend
after a runner stops verifies signatures too. Line 3 binds the answer to its request;
two identical GETs in one second, or two retries of one secrets POST, share a signature
and receive the same bytes, so a swap is harmless.

Two known answers, under `fixture-secret-not-a-real-one`, for the request
`GET\n/.well-known/qory-configuration\n1700000000`, signature
`sha256=0c895b2f1c1c62629e6298a59746b975ccae2e5156b01f733d2d7768f6eb55a2`:

- `200`; the discovery body, with `signing_key` as every verified access key's has it,
  170 bytes:

  ```json
  {"version":1,"events":{"url":"https://qory.example/v1/events","types":["*"]},"signing_key":[{"alg":"ed25519","public_key":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
  ```

  SHA-256 `8e153b07d85d603dc269d5f890ca673db4ae9d706dab77af0a470f5d754231e6`;
  `X-Qory-Configuration: sha256=` and the same hex; no run-configuration digest:
  `sha256=6301b305e5eacb4f2bc44d00f7015ffdddfe8832e4269c7cd7e4746430c1a7de`
- `404`, empty body, no digest, unchanged:
  `sha256=040a264ad219396ad1dcee84e93816aa49394b633a5db303818fe1a19a58c9bf`

The Ed25519 answer signature of the `200` above, under the fixture signing key, over the
same six lines with `qory-answer-ed25519-v1` as the first, 236 bytes:
`X-Qory-Signature-Ed25519: 1tCfgMKH-hqX4qveObhEaBQB2Am3EXyTnVZqmS_ko9Y4ZA0fNK5JS8PU8fHAoonNj_QhHdOjDzYAUufifNULBA`.

### Coded refusals

After verification, `409`, `410` (`run_configuration_superseded`, `run_closed`), `429`,
`503` or `400`, `application/json`, signed: `{"error": "<code>", "names": ["…"]}`. `401`
stays `{"error":"unauthorized"}`; `bad_request`, `413` and `415` are unsigned and reported
by status only.

### Values at rest (guidance for the server)

Not part of the contract. The server encrypts each stored value with AES-256-GCM under a
key derived from its instance key with HKDF-SHA256, stored with a key id, and binds as
associated data `lp("qory-secret-v1") ‖ lp(workspace id) ‖ lp(secret id) ‖ lp(value id)`,
so a value moved to another secret or value id no longer decrypts. Access key secrets are
encrypted under the instance key as well. Organisation secrets are
not in 0.7.0. Connections, service definitions and renderings are covered by the
integrity codes of Decision 6.

### Events

**`dev.qory.run.refused`**, new: emitted in place of `dev.qory.run.started` when a run
does not start after the ping, as the run's last event; the runner waits up to fifteen
seconds for its delivery. Data: `code`; `connection`, the connection's id, for every
refusal that concerns one; `names`, never a value; `providers` with `secret_unresolved`;
`status` when the code came from the server. Every no-run after an accepted ping emits
it, whatever stops the run: a refusal of Runner behaviour's checks, the wall check
included, which runs after the ping; an integration whose `describe` or `credential`
does not start or does not answer, `integration_failed`; a tool that does not start or
does not listen in time, `tool_not_started`; and any other failure before
`dev.qory.run.started`, such as the wall, the image or the runtime's launch,
`start_failed`. For these three, `names` contains the integration's or the tool's name
where there is one, and the error the caller receives contains the reason the program
wrote.

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

`secrets` lists the references each connection received, by `id` for a stored value,
name and value id, never a value; `uses` where and how the proxy sets each value;
`hosts_denied` the connection's hosts the policy in force denies, recomputed in every
further `policy_applied`. `dev.qory.run.egress` has `connection`, the id, in place of
`credential`. A top-level `variables` lists the variables' names. With no
`security_policy`, `url` and `run_configuration` are allowed beside `source` `config` or
`none`. No event contains a value.

## Runner behaviour

Order at run start; the steps not listed are §Sequence's.

1. With a server: validate the server document. Every answer's signature is verified
   before its body or headers are read.
2. Discovery. Ping. When discovery lists `secrets` and the run has no wall:
   `server_needs_wall`. When discovery lists `secrets` or `runner_keys` and the runner
   has no pinned `signing_key`: `signing_key_unpinned`.
3. When the configuration lists `runner_keys` and the spec contains a runner key:
   register; keep the outcome.
4. When the configuration lists `run`: fetch the run configuration; recompute its digest;
   decode it with `encoding/json/v2`; validate it against the schema and the limits.
   Without `security_policy`, the machine's policy is the run's; without a
   `connections` member, or without a run configuration, the connections are the runner
   file's.
5. Check the connections: connections without a wall; duplicates; the runtime connection
   for the run's runtime kept and any other set aside; declarations and `one_of`, a
   required group included; hosts and `headers.json`; the mounts against the runner's
   files and the runtime's credential files; for each integration, the machine's
   `arguments` and `settings` bounds.
6. When a connection the run applies references a stored value: no runner key
   (`runner_key_missing`), no `secrets` section in discovery (`secrets_endpoint_missing`),
   no pinned `signing_key` (`signing_key_unpinned`), or a refused, unsigned or
   mismatched registration is no run. Otherwise the secrets request with the applied
   connections; verify the envelope's signature under the pinned `signing_key`; check and
   open the envelope; check the plaintext.
7. Resolve every external reference through the providers in order, and check each
   machine value's `hosts` against where its connection sends it.
8. For each integration connection: find the program, run `describe`, compare its name
   and version, read its hosts, validate the settings against its description. A
   `describe` that does not start or does not answer is `integration_failed`.
9. Check the hosts and the values together: `connection_host_conflict`, the value rules
   for where each value goes; compute `hosts_denied`.
10. Check the variables and the environment: without a wall `variables.accept`; the
    reserved names; `runtime_secret_conflict`; `variable_conflict`; placeholders the run
    passes a value for, `placeholder_conflict`.
11. Run each integration's `credential` with its settings document; check its answer. An
    integration that does not start or does not answer is `integration_failed`.
12. Then §Sequence from the tools on. A tool that does not start or does not listen in
    time is `tool_not_started`; any other failure before the next step, such as the wall,
    the image or the runtime's launch, is `start_failed`. The proxy receives the uses and
    the hosts it verifies against public roots only (`tls.public_roots_only`); the
    launch's environment is the run's, then the variables, then the runner's own, the
    placeholders, and the runtime's other declared and reserved variables as empty.
13. `dev.qory.run.started`, then `dev.qory.run.policy_applied`.

Every no-run after an accepted ping, at steps 2 to 12, emits `dev.qory.run.refused` as
the run's last event, a tool or an integration that does not start included. The caller
receives the error in every case, with or without a ping. Values live in the runner's memory only, never
on disk, in the environment, an event, a log line, an error or a report; at run end they
are unreferenced, since Go cannot wipe a string.

## Refusal codes

| Code | Decided by | When |
|---|---|---|
| `bad_request` | server, `400`, unsigned | a header sent twice |
| `unsupported_contract_version` | server, `400` | `X-Qory-Contract-Version` other than `1` |
| `invalid_request` | server, `400` | a body that is not JSON, fails its schema or has an unknown member; labels the contract refuses |
| `rate_limited` | server, `429` | the access key's rate is exceeded |
| `unavailable` | server, `503` | a stored rendering or a runner key row fails its integrity code, on the GET, registration or the secrets request; a failing access key row is `401` |
| `runner_key_invalid` | server, `409` | not 32 bytes, non-canonical, low-order, or another key under an existing id |
| `runner_key_limit` | server, `409` | as many runner keys as allowed |
| `runner_key_revoked` | server, `409` | the key or its id is a tombstone |
| `runner_key_unknown` | server, `409` | the key id, or `replaces`, is not a key of the access key |
| `runner_key_pending` | server, `409` | the key awaits approval; every new key, and every key registered with `replaces`, does until it is approved |
| `secrets_not_allowed` | server, `409` | the access key is not allowed stored secrets |
| `run_closed` | server, `410` | the server has closed the run's row |
| `run_configuration_superseded` | server, `410` | no rendering of the holder with that digest, current or within 15 minutes |
| `run_connections_invalid` | server, `409` | the listed connections are not those the rendering requires |
| `run_secrets_conflict` | server, `409` | a reseal with another runner key, digest or set of connections |
| `run_secrets_expired` | server, `409` | a reseal after the first payload's `exp` |
| `runner_key_mismatch` | runner | the registration answer's id is not the runner's own |
| `runner_key_missing` | runner | a stored value referenced and no runner key in the spec |
| `secrets_endpoint_missing` | runner | a stored value referenced and discovery lists no `secrets` |
| `envelope_signature_invalid` | runner | an envelope without a valid signature under the pinned `signing_key` |
| `signing_key_unpinned` | runner | discovery lists `secrets` or `runner_keys`, or a connection the run applies references a stored value, and the runner has no pinned `signing_key` |
| `answer_unsigned` | runner | an answer at run start without a valid signature |
| `server_needs_wall` | runner | discovery lists `secrets` and the run has no wall |
| `mount_contains_runner_files` | runner | a mount is, contains or lies inside the runner's configuration directory, the directory of an integration program, a tool program, the wall's `docker` command or helper, the `docker` configuration directory, or a `secrets.local` file |
| `mount_contains_credential_files` | runner | a mount is or contains a file the run's runtime lists in `credential_files` |
| `run_configuration_invalid` | runner | the decoder, the schema or the limits refuse the document |
| `run_configuration_digest_mismatch` | runner | the recomputed digest differs from the header's |
| `connection_needs_wall` | runner | a connection and no wall |
| `connection_duplicate` | runner | two connections with one id |
| `connection_secret_unknown` | runner | a reference under a key the kind does not declare, or an `auth` with an undeclared id |
| `connection_host_invalid` | runner, and the server on save | a service or runtime host that is not an exact DNS name, such as an IP literal |
| `connection_host_public_suffix` | runner | an integration's `*.` host over a public suffix |
| `connection_header_reserved` | runner, and the server on save | a header name `headers.json` refuses |
| `connection_host_conflict` | runner | hosts of two connections, or of a connection and a tool, overlap |
| `runtime_connection_duplicate` | runner | two runtime connections for one runtime |
| `runtime_secret_choice` | runner | more than one declaration of one `one_of` group |
| `runtime_secret_missing` | runner | a walled run with no connection that supplies a required group; reported with the group's id |
| `runtime_secret_conflict` | runner | the environment or the variables contain a variable the runtime declares or reserves |
| `integration_missing` | runner | the machine has no integration of that name |
| `integration_name_mismatch` | runner | `describe`'s `name` differs from the connection's |
| `integration_version_mismatch` | runner | `program_version` differs from the connection's `version` |
| `integration_argument_not_allowed` | runner | the argument does not match the machine's `arguments` pattern |
| `integration_settings_not_allowed` | runner | a setting outside the machine's `settings` bound |
| `integration_settings_invalid` | runner | the settings fail the program's own description |
| `integration_settings_too_large` | runner | the settings document exceeds 65536 bytes (64 KiB), refused before the program starts |
| `integration_failed` | runner | an integration's `describe` or `credential` does not start, exits non-zero or answers what its schema refuses |
| `tool_not_started` | runner | a tool exits before it listens, or does not listen in time |
| `start_failed` | runner | any other failure after the ping and before `dev.qory.run.started`, such as the wall, the image or the runtime's launch |
| `secret_value_id_missing` | runner, and the server on save | a reference to a secret with several values without a value id |
| `secret_unresolved` | runner | no provider resolves it, or the sealed list lacks it |
| `secret_hosts_exceeded` | runner | a machine value sent to a host its `hosts` do not cover |
| `secret_value_invalid` | runner | a value that breaks the value rules for where it goes, or a `:` in a basic username |
| `secret_sealed_invalid` | runner | the envelope does not open, an identifier is not the runner's, or the plaintext is malformed |
| `secret_sealed_expired` | runner | `exp` passed by more than 300 s, or more than 900 s ahead |
| `secret_sealed_mismatch` | runner | an extra or repeated value, another digest or another set of connections |
| `variable_not_accepted` | runner | without a wall, a name outside `variables.accept` |
| `variable_reserved` | runner | a reserved name, or `QORY_SERVER_SECRET`, `QORY_RUNNER_KEY` or a variable a `secrets.local` value reads passed into the enclosure |
| `variable_secret_conflict` | runner | a variable with a placeholder's name |
| `variable_conflict` | runner | a variable the run or the runtime sets |
| `placeholder_conflict` | runner | the run passes a value for a placeholder, or a connection other than the runtime's sets a placeholder in a variable the runtime declares or reserves |

## Security considerations

| Threat | What protects | What does not |
|---|---|---|
| A TLS-terminating middlebox between the runner and the server, without the access key's secret | It cannot read a stored value; it cannot alter the connections, the policy, the variables or the digests, nor replay an older answer; `no-transform` keeps a proxy from re-coding a signed answer | It reads the document. At the start it can only refuse; during a run, dropping answers keeps the policy in force |
| A proxy between the runner and a destination host, whose authority the machine trusts | For a stored value, `tls.public_roots_only`, on by default: the proxy verifies that host against public roots only, so the authority the machine added receives nothing | It reads a machine value there, and a stored value on a machine that sets `tls.public_roots_only: false`: that leg is then ordinary TLS against the machine's trust store. An integration program's own connections use its own TLS settings |
| The server's logs and answer caches | Ciphertext only; `Cache-Control: no-store` | — |
| A read of the server's database | Values encrypted under a key derived from the instance key; access key secrets encrypted under the instance key, so a reader cannot take one, register a runner key and fetch values | A reader with the instance key reads everything |
| A write to the server's database | Integrity codes over connections, custom definitions, every rendering, every access key row and every runner key row, with a per-row version, verified before sealing: a writer cannot move a secret between access keys, enable stored secrets, or insert or approve a runner key; seals taken from the verified rendering's bytes; audit | A writer with the instance key, or a change through the server's own pages |
| A compromised server or operator | — | It reads every stored value, routes it, chooses an integration's argument and settings, sends an observe-everything policy, and learns which `secrets.local` names exist from `secret_unresolved`. The machine's `hosts` bounds, its `arguments` and `settings` bounds and the envelope pin, required wherever stored secrets are allowed, are what remain |
| A workspace administrator, or anyone who may save a custom service and link a secret | In 0.7.0 only owners and administrators may: linking needs `secret.use` on the secret, which only they hold, and only they define custom services and enable stored secrets on an access key | Choosing the host is reading the value |
| A holder of the access key's secret, on the path | Every run of an access key allowed stored secrets pins the server's signing key, so it forges no answer and no envelope there; routing is bound to the document; a runner key it registers receives nothing until it is approved | For an access key not allowed stored secrets, on an unpinned machine, it can forge documents: the policy, the variables, and connections that route machine values within their `hosts` |
| A link removed while a run starts | A superseded rendering seals only what the current rendering still references through the same connection | — |
| Another runtime's credential | The secrets request lists one runtime connection, the run's own; the server seals nothing for any other | — |
| A server that sends a machine value elsewhere | The machine's own `hosts` on each `secrets.local` entry: `secret_hosts_exceeded` | — |
| A machine with the access key, choosing labels | — | Repository scope is no boundary against a machine: an access key is workspace-wide |
| A stolen access key secret | Stored secrets only for access keys allowed them; approval of every new runner key, a replacement included; revocation; the recomputed digest binds values to the document the server rendered | Whoever has it registers a key, which receives future stored values once someone approves it; automatic approval, if it is offered (Open question 1), would give them those values |
| A thief of the runner key file with recorded traffic or the server's logs | Rotation and revocation | Base mode has no forward secrecy: the key opens every past payload sealed to it, so keys are rotated |
| A member of the machine's `docker` group | — | It is root on the machine, with every file and process of the runner |
| Whoever chooses a run's labels, such as a repository's workflow file | — | Labels select the holder, and so whose connections and credentials the run receives |
| An agent reading the machine's configuration, or replacing a program the runner starts | `server_needs_wall`; `qory` refusing unwalled runs where `runner-key` exists; `mount_contains_runner_files`; `QORY_SERVER_SECRET`, `QORY_RUNNER_KEY` and `secrets.local` sources refused in the enclosure | An unwalled agent of the same user outside `qory` (Issues, item 4) |
| A model credential reaching the enclosure | `runtime_secret_conflict`; the runtime's other declared and reserved variables set to empty; `mount_contains_credential_files` | A credential file baked into the image |
| A credential that mints credentials | A declaration's `paths`, `/v1/*` for Claude Code | A minting path inside the allowed paths gives the agent a readable credential; to verify for `api.anthropic.com` |
| The agent in the enclosure | A placeholder in the environment, the value set outside on the kind's hosts only; `TRACE` and `TRACK` refused there | A host that sends a request's headers back returns the value (§Limits); `headers.json` keeps the common echoes out |
| An integration program | Its settings on standard input only; `describe`'s name must match; the machine's `arguments` and `settings` bounds; its standard error redacted, values, their lines and its credential, before it is reported | It runs as the runner's user and is trusted, and sends the raw value where it chooses; a value it transforms before writing escapes redaction |
| A payload replayed | Run id, access key, runner key id, digest and `exp` in `aad`; the timestamp; the reseal window bound to one key, digest and set; a new run id per attempt | — |
| A signed body sent to another endpoint | Strict schemas on every endpoint | — |
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
- **Fixtures:** `fixtures/sealed/` (Decision 5) with the envelope's Ed25519 `sig`, the
  Ed25519 answer signature, the low-order list, run configurations
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
  multi-line value included; and that a program whose `describe` reports another name is
  refused.
- **Refused runs:** every no-run after an accepted ping emits `dev.qory.run.refused` as
  the run's last event, an integration that does not start (`integration_failed`) and a
  tool that does not listen (`tool_not_started`) included.
- **Signing pin:** a run whose discovery lists `secrets` or `runner_keys` without a pinned
  `signing_key` is refused, `signing_key_unpinned`; a pin from `QORY_SIGNING_KEY` works as
  one from the runner file, and the variable reaches no tool, integration or enclosure.
- **Public roots:** a proxy test with a host whose certificate chains only to an
  authority the test adds to the machine's trust store: with `tls.public_roots_only`
  unset or `true`, a stored value is never sent there and `dev.qory.run.egress` records
  `dial_failed` with `wall:public-roots`; with `false`, the host receives it; a machine
  value reaches that host under either setting.
- **Mounts:** a walled run refuses a mount of an integration program, a tool program, a
  `secrets.local` file and `~/.claude/.credentials.json`, each through a symbolic link
  too.

## Upgrading

0.7.0, as facts for the changelog:

- Connections decide every credential a run sends; the policy has no `credentials`. The
  runner file has `connections:`, `secrets.providers`, `secrets.local` and
  `variables.accept`.
- A run configuration may contain `connections` and `variables`, and may omit
  `security_policy`.
- Stored values are sealed to a runner key that `qory` creates the first time discovery
  lists `runner_keys`, once the server has approved it, and fetched from the secrets
  endpoint for the connections the run applies. A replacement key needs approval of its
  own.
- Every answer of the server is signed, and the runner verifies it.
- A walled run is refused when its environment contains a variable the run's runtime
  declares or reserves; for Claude Code, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` and
  `CLAUDE_CODE_OAUTH_TOKEN`. A walled run whose runtime has a required group and no
  connection that supplies it is refused, `runtime_secret_missing`.
- Every run against a server that lists `secrets` needs a wall, and so does every run on a
  machine with `runner-key`. A mount of the runner's configuration directory, a program
  the runner starts, a `secrets.local` file, a directory above any of them, or a
  runtime's credential file, is refused.
- A CI machine may take its runner key from `QORY_RUNNER_KEY` or a file descriptor.
- The proxy refuses `TRACE` and `TRACK`, and sets a value only on port 443, on every host
  where it sets one.
- A machine pins the server's Ed25519 signing key in `runner.yaml` or through
  `QORY_SIGNING_KEY`; a pinned runner verifies every answer and every envelope with it.
  The pin is required for an access key allowed stored secrets, `signing_key_unpinned`,
  and optional otherwise.
- The proxy verifies a host that receives a stored value against public roots only;
  `tls.public_roots_only: false` in the runner file verifies it against the machine's
  trust store instead.
- An integration is started as `<program> <role> -- [arguments]` and always receives one
  settings document on standard input, `{}` when empty, at most 64 KiB.
- A value of a multi-valued secret is addressed by `value_id`; a declaration's human name
  is `title`.
- `dev.qory.run.refused` is new, emitted for every no-run after the ping;
  `dev.qory.run.policy_applied` lists connections and variables' names.

## Open questions for the user

1. Ephemeral machines, a new machine per job, generate a new runner key at every start,
   which manual approval cannot follow. Either (a) the CI's secret store supplies one
   stable key through `QORY_RUNNER_KEY` or a file descriptor, which keeps approval
   meaningful; or (b) a per-access-key option, "approve runner keys from this access key
   automatically", administrators only and off by default, at the cost that a thief of
   that access key's secret receives values.
   (b) is the server's side's option, and the weaker one: a thief of that access key's
   secret then receives values.
   Reviewer's safer answer: (a), the stable CI key, only.
   The user is considering a single machine key pair in place of the access key's secret
   and the runner key.
2. `variable_conflict` against the names the run sets: refuse (proposed), or let the
   server's value win, or the run's?
   Reviewer's safer answer: refuse.
   The user wants flexibility here without refusals.
3. `server_needs_wall`, scoped per access key as the server's side proposes, with `qory`
   refusing every unwalled run where `runner-key` exists: accept?
   Reviewer's safer answer: accept; `qory`'s error states that deleting `runner-key`
   restores unwalled runs.
   The user wants an alternative in which no secret reaches the machine at all: a
   credentials broker outside the machine.
4. `variables.accept`: the server's side accepts it as drafted, names only. Agree?
   Reviewer's safer answer: agree, and add a built-in list the machine can never accept:
   `LD_*`, `DYLD_*`, `NODE_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHONSTARTUP`, `PERL5OPT`,
   `RUBYOPT`, `GIT_*`, `*_PROXY`, `HOME`. Leaving such a variable out and reporting it,
   instead of refusing the run, is equally safe.
   The user wants it treated like policy.

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
   `variable_conflict`, `variables.accept` and `runtime_secret_conflict` need the set
   names, `Prepare`'s included: a new `Spec` field.
3. **Decision 1 relies on the nested Docker fixes**, not on `main` at 9838b7c.
4. **`server_needs_wall` and the key file reach only runs `qory` starts.** Any unwalled
   agent of the same user outside `qory` reads `runner.yaml` and the key file.
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
    26.7 KiB; 32 KiB covers the contract's own label limits.
16. **Validating settings against the program's description** needs a JSON Schema
    validator on the program's `description.json` at run start; the runner has one
    (`santhosh-tekuri/jsonschema/v6`), whose errors quote values, so a settings error
    reports the member only.
17. **Public roots need a root store of the runner's own.** The proxy verifies upstream
    hosts against the machine's roots today (`internal/proxy/terminate.go`); verifying
    stored values' hosts against public roots only adds
    `golang.org/x/crypto/x509roots/fallback`, or a root bundle like it, as a dependency
    of the runner, refreshed with its releases.
