# Proposal: secrets and variables

Status: draft. Nothing here is part of the contract until it is merged into
`contracts/runner/v1/README.md` and its schemas. Section references (§) are to that
README.

## Summary

A secret is a name and a value, or several values each with a label. What needs a secret
is one of three kinds, and each kind defines how and where its secrets are sent:

- a **runtime**, such as Claude Code, through its descriptor;
- an **integration**, a program that implements the integrations contract;
- a **service**, a definition of exact hosts, an authentication scheme and the secrets it
  needs.

A **connection** links each secret a kind needs to a secret. Connections are the only
way a run sends a credential anywhere: the policy selects no credential. With a server, a
run's connections come from its run configuration, beside an optional `security_policy`
and optional `variables`, all covered by the digest; without one, from the machine's
runner file in the same shapes. Connections and variables are fixed when the run starts;
a reload never changes them.

A value the server stores is sealed to a key pair of the runner's own (HPKE base mode,
X25519, HKDF-SHA256, AES-256-GCM) and fetched once per run from a new signed endpoint,
for the connections the run applies. A value the machine keeps comes from a provider on
the machine, bounded by the hosts the machine allows it. Every answer of the server is
signed with the access key's secret, bound to the request it answers, and the runner
recomputes the run configuration's digest, so the values it opens are bound to the exact
document that routes them.

From the server to the runner a stored value is end to end: only the runner process
opens it. From the runner to the host it is sent to, the value travels in an ordinary TLS
connection verified against the machine's trust store, so a proxy whose authority the
machine trusts reads it there.

The contract is `v1`, revision 1, and describes the runner as it is; a later change goes
through `X-Qory-Contract-Version`.

## What changed against the 1076-line draft

- **The secrets list is gone.** `secrets` (name, `used_for`, `how`, `argument`, `source`,
  `from`) leaves the run configuration; `how` and `used_for` leave the contract. "Used
  for" is a note in the server, nothing more.
- **Connections replace it**, and the policy's `credentials` with it. Three kinds,
  `runtime`, `integration` and `service`; a connection references a stored value by id
  (`sec_…`) and label, or a machine value by name. Without a server, the runner file's
  `connections:` has the same shapes: a machine's static credentials are service
  connections, and a machine's adapter is an integration connection.
- **Machine values** live in `secrets.local`, each with `hosts`, the most it may be sent
  to: `secret_hosts_exceeded` beyond them.
- **Variables** are an object, name to value. A value at most 4 KiB, all variables at
  most 64 KiB.
- **The secrets request** lists the connections the run applies; the server seals only
  their values, and the plaintext echoes the set. The plaintext lists values by secret id
  and label, each once, beside the digest. Routing leaves the seal: the runner recomputes
  the run configuration's digest, which binds the values to the whole document
  (Decision 6).
- **Value rules** depend on where a value goes: header rules for runtime and service
  values, any text for integration values, a PEM key included.
- **Runtimes declare secrets** in their descriptor (`declares`, `one_of`, `reserves`,
  optional `paths`). A walled run is refused when its environment contains a variable
  the runtime declares or reserves, and the wall sets every such variable the run does
  not use to empty.
- **Integrations** receive their secrets as a settings document on standard input,
  written from a goroutine; anything they write to standard error is reported with every
  value of that document redacted. `describe`'s name must equal the connection's, and its
  version is checked for compatibility.
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
- **Resolved:** placeholders are the declarations' conventional names; names are
  variable-style and identity is the id; an integration is matched by name and version;
  the server seals only for the connections the run lists; the digest is the SHA-256 of
  the stored bytes.

## The model

- **A secret** is a name, `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, and either one value without a
  label or several values, each with a label unique within the secret,
  `^[a-z0-9][a-z0-9_.-]{0,63}$`. A stored secret's identity is its id, `sec_` and 16
  lower-case Crockford base32 characters; the name is what people read.
- **A declaration** is what a kind needs: an id unique within the kind,
  `^[a-z][a-z0-9_]{0,63}$`, a label for people, and optionally `name`, the conventional
  variable a program reads it from, which becomes the run's placeholder.
- **A connection** links a kind's declarations to secrets: `id`, the kind and what
  identifies it, and `secrets`, a map from a declaration's id to a reference. In a run
  configuration its id is `con_` and 16 lower-case Crockford base32 characters; in the
  runner file, a name the machine chooses, `^[a-z0-9][a-z0-9_-]{0,63}$`. The server
  decides which connections apply to a run and sends them as one flat list; it refuses on
  save two connections that would apply to one run for the same runtime, the same
  integration name or overlapping hosts.
- **A reference** is `{"id": "sec_…", "name": "…", "label": "…"}` for a value the server
  stores, where the id is the identity and the name is for display; or
  `{"source": "external", "name": "…", "label": "…"}` for a value a provider on the
  machine resolves, where the name is the lookup key. `label` selects one value of a
  secret with several; a reference to such a secret without one is refused,
  `secret_label_missing`. The runner file's connections contain external references only.
- **Where a value goes** is the kind's, never the reference's:

  | Kind | Hosts | How |
  |---|---|---|
  | `runtime` | the declaration's, in the runtime's descriptor | the declaration's scheme |
  | `integration` | `roles.credential.hosts` of the program's `describe` | the program's answer: scheme and paths |
  | `service` | the definition's exact hosts | the definition's scheme |

- **Where connections come from.** A run whose policy comes from a server's run
  configuration takes that document's `connections`; any other run, without a server,
  with `--local`, or against a server that offers no run configuration, takes the runner
  file's `connections:`, which `qory` parses and passes through `session.Spec`.

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
| a placeholder of this run: a declaration's `name` or an integration's | `variable_secret_conflict`: the enclosure gets the placeholder value there |
| every variable the run's runtime declares or reserves | `runtime_secret_conflict` (Runtimes) |

`HOME` stays free behind a wall, and so do loader and interpreter variables (`LD_PRELOAD`,
`DYLD_*`, `NODE_OPTIONS`, `BASH_ENV`, `GIT_CONFIG_*`, `GIT_SSH_COMMAND`): inside the
enclosure they affect the agent's own processes only, which the agent can set for itself
anyway.

**Without a wall** a variable such as `NODE_OPTIONS`, `GIT_SSH_COMMAND`, `BASH_ENV`,
`LD_PRELOAD` or a `HOME` in the checkout runs code on the developer's machine. No list of
refusals is complete, so the machine lists what it accepts: `variables.accept` in the
runner file, names only, empty by default. A variable outside it is no run,
`variable_not_accepted`; the reserved list applies as well. An accepted variable replaces
the value the session would inherit.

**A variable the run itself sets** is no run, `variable_conflict`: a name `qory` lists
through `wall.env`, `--env` or the harness's composed launch, or one the runtime's
`Prepare` sets. The runner reads these names from a new `session.Spec` field (Issues,
item 2).

### 2. Names, labels and identity

- **Identity is the id.** A stored value is selected by its secret's `sec_` id and, for a
  secret with several values, its label. A machine value is selected by its name and
  label in `secrets.local`.
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
- **Empty lists.** A server omits an empty `connections` or `variables`; a runner reads
  an empty one as absent.

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
  open connections to it and records each (§The server, Reload, rules 1 and 2). An
  integration's credential keeps renewing.
- **Discovery during a run.** A discovery document that starts listing `secrets` or
  `runner_keys` while a run goes on takes effect at the next run.
- **A reload is only as strong as its delivery.** A middlebox that drops answers keeps the
  run on the policy it has. "No run, never a weaker run" applies at the start; during a
  run, the policy in force stays until a signed answer replaces it.

### 4. Runner key lifecycle

- **Who gets one.** A server lists `runner_keys` and `secrets` in discovery only for an
  access key allowed to receive stored secrets, a per-key setting that is off by default,
  so discovery is per access key. A developer's own key keeps unwalled runs; a CI or
  shared runner's key receives stored secrets and runs walled.
- **Generation.** The first time discovery lists `runner_keys`, the program that hosts the
  runner generates an X25519 key pair and keeps the private key. For `qory`: the file
  `runner-key` next to `runner.yaml`, `$XDG_CONFIG_HOME/qory/runner-key`, else
  `~/.config/qory/runner-key`. One line: the KEM, `x25519`, a space, the private key in
  base64url without padding.
- **The key file.** `qory` creates it with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, in a
  directory of mode `0700`, and refuses a key file whose mode grants anything to the
  group or to others, a file or directory owned by another user than the effective one,
  and the published fixture key. Optionally it keeps the key, and the access key's
  secret, in the system's keychain instead (Open question 8).
- **The runner module writes nothing.** It takes the private key through `session.Spec`.
- **Registration.** The runner registers its public key with a signed POST at every run
  start, after the ping and before the run-configuration fetch. The same key always has
  the same id; the runner computes the id itself and refuses an answer with another,
  `runner_key_mismatch`. A refused, unsigned or mismatched registration answer is no run
  when a connection the run applies references a stored value; otherwise the runner
  reports it and the run goes on.
- **What registration refuses.** `409` `runner_key_invalid`: a public key that is not 32
  bytes; a non-canonical encoding, with bit 255 set or a value of at least p = 2^255 − 19;
  a low-order point, by the computed check "X25519 of a fixed non-zero scalar and the key
  is all zero, or the derivation is refused"; and a public key other than the one already
  registered under the same id. `409` `runner_key_revoked`: a key or an id that matches a
  tombstone. `409` `runner_key_limit`: the access key has as many runner keys as the
  server allows.
- **Scope.** A runner key belongs to one access key; the server keeps a set per access
  key, unique within it, capped. Every rule here applies per access key. The secrets
  request contains the runner key id, which selects the key the server seals to. The
  access keys page lists each access key's runner keys with their last use and revokes
  one.
- **Rotation.** A `qory` command writes a new key file and keeps the old key's id in
  `runner-key.replaces` beside it, mode `0600`. The next run registers the new key with
  `replaces`; the server revokes the old key when it belongs to the same access key (else
  `409` `runner_key_unknown`), and `qory` removes `runner-key.replaces` once the
  registration succeeds.
- **Revocation.** The server seals nothing to a revoked key. A revoked key stays for good
  as a tombstone, its id, its public key and when it was revoked, so neither can be
  registered again. A runner key id the access key never registered is
  `runner_key_unknown`.
- **Expiry of unused keys.** The server removes an unrevoked runner key unused for a
  period it sets; the machine's next run registers it again as new.
- **What it protects, plainly.** Anyone with the access key's secret can register a key
  of their own and receive every future value that access key's runs receive. The runner
  key protects against TLS-terminating middleboxes, logs and the server's stored answers.
  A stolen access key secret is outside what it protects (Open question 1).
- **The access key's secret** is generated by the server, with at least 128 bits of
  entropy; the contract requires it.

**Keeping both from the agent.** An agent that reads the access key's secret or the
runner key fetches every value the server stores for that access key.

- *Unwalled runs.* Once a server's signed discovery lists `secrets`, every run against it
  needs a wall: `server_needs_wall`, decided after the ping so the refusal reaches the
  server. Offline, the key file is the signal: on a machine where `runner-key` exists,
  `qory` refuses every unwalled run, `--local` included.
- *Mounts.* On a machine whose runner file configures a server, every walled run,
  `--local` included, refuses a mount that is, contains or lies inside the directory of
  `runner.yaml` and the runner key, resolved through symbolic links:
  `mount_contains_runner_config`. The runner module takes the paths through
  `session.Spec`.
- *The enclosure's environment.* A run that passes `QORY_SERVER_SECRET` into the
  enclosure is no run, `variable_reserved`.
- *Integrations and tools* run as the runner's user and are trusted. Neither receives
  `QORY_SERVER_SECRET` nor the variables a node runner passes its spec in. A node runner
  passes the secret and the runner key through a file descriptor.
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
  | digest | `sha256=6629797938f27cafa91774f5095aded55cdde5843d35dd26df5747e845a805e5`, the SHA-256 of `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}}` |
  | `info` (hex) | `716f72792073656372657473207631000020000100020016337356715942396d765256676147572d4a4e6c796677`, 46 bytes |
  | `aad` | 168 bytes, as Wire format defines, starting `0024` |
  | plaintext | `{"version":1,"run_configuration":"sha256=6629797938f27cafa91774f5095aded55cdde5843d35dd26df5747e845a805e5","connections":["con_0b5n6t2r9y4f7j3s","con_7q2m4k9x0d3h8w1c"],"values":[{"secret":"sec_3fz8k2m9q4w7x1d6","value":"fixture-value-not-a-real-one"},{"secret":"sec_9c4r7t2y5b8n1h3e","label":"production","value":"-----BEGIN FIXTURE-----\nnot-a-real-key\n-----END FIXTURE-----\n"}]}`, 383 bytes, the `\n` being JSON escapes |
  | `enc` | `WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns` |
  | `ct` | 399 bytes, SHA-256 `c294c94cf658e4bc8e79065b2be487bc7f9af05946d21314d4974999fa655abe` |

  ```
  vWlOGjqntNxqkgdXlQiXxG5i2wUIYkZ_S_CUDYYQHLkxuXtCRP-2oFtRm1Bpn4ZNnNep1jFckIS1CAnZLVioJx7DuufQNwYy2sMABjD6_8xDkrMA8jdSjYsgh0L6sQZdintu96fy7ZT-XsDxTEdXRcIHro6DLtLlCxZKp-IiinXJ7NdElM6np4BIn1Jbo9QFVrsW5N0ht8ECwccpQPNiwKMb4fdcfwB_7s5cCYr8Uue1iat7U0vdp5Vo7BrSuA2OEXr5kYMPKWU20J5Mx1-yRa1Xt4bkzLpDNnQT7unP2x-L9TPR1JF4P4FlKh-6Km53a1YlubL0HU5kXzI9bdlfJgxvFEXUCCoCakQGSTdgc2LHPHAGddD0CytLTCRZ0Kv1df3DxV-at8sgoK9U0q3rbKwHFu4hePLWqUadZlrwISFjwyNWv5-3z-o3EIkeJ7mmI7HON1hzhdisCU8hiA7iAIvpyBGKvhJRzxtRTqOpX82Gp1SETF-yaPvdcwGrrDtC-XCUI0eYkATiegsh6crp
  ```

  A second case alters `aad` and expects the open to fail.
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
  by id and label, nothing else; the runner checks both against what it sent.

That binds every value to the whole document: connections, policy and variables. Without
it, whoever can sign answers, a holder of the access key's secret on the path, could
serve forged connections under a real digest and have real values routed to a host of
its choosing. It adds protection where such a holder cannot simply register a key of its
own and fetch values directly, which is when a new runner key needs approval (Open
question 1).

**A write to the server's database.** Whoever can edit a service definition's hosts, a
connection's link to a secret, or a stored rendering, in the server's database, reroutes
a real value: the server serves it, signs it and seals for it. The server's obligations,
whose exact bytes the server defines:

- an integrity code, an HMAC under a key derived from the instance key, over the whole
  canonical connection row and over each custom service definition, never a field list;
  a built-in definition lives in the server's release and has no code, and the
  rendering records the definitions it was rendered from;
- an integrity code over each stored rendering, its body bytes and its digest, checked
  when serving the GET (a failure is a `503`, no run) and again before sealing;
- a per-row version inside the coded data, so an older row restored over a newer one
  fails;
- audit of every change with before and after.

A connection or definition whose code fails refuses the render, and the holder keeps its
last good rendering. None of this stops a writer who has the instance key, nor a change
made through the server's own pages, which is authorization's matter.

### 7. Machine values and the runner file

- **Providers.** `secrets.providers` in the runner file is the ordered list of providers
  an external reference `{source: external, name, label?}` is resolved through; the
  default is `[local]`. The first provider that defines the name, and the label when one
  is given, resolves it; none is `secret_unresolved`, with the connection and the
  providers tried. Later: `vault`, a cloud's secrets manager, and the like.
- **The `local` provider** is the section `secrets.local`: values by variable-style name,
  each from the runner's environment or a file, optionally labelled, each with `hosts`,
  the most the machine allows it to be sent to, in `egress.allow`'s grammar:

  ```yaml
  secrets:
    providers: [local]
    local:
      SENTRY_AUTH:
        env: SENTRY_AUTH                # read once at run start
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
  A server can therefore never send a machine value further than the machine allows.
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
      declares: [{id: auth, label: Sentry auth, name: SENTRY_AUTH}]
      secrets: {auth: {source: external, name: SENTRY_AUTH}}
    - kind: integration
      id: github
      name: qory-github
      argument: acme/shop
      secrets: {private_key: {source: external, name: GITHUB_APP_KEY, label: production}}
  ```

- **The policy selects no credential.** `credentials` leaves `policy.schema.json`, and
  with it the run configuration's `security_policy`, `--policy` files and the machine's
  policy: what a run may send where is decided by connections alone. The policy keeps
  `egress`, `tools` and `image`.
- **Connections need a wall**: `connection_needs_wall`. Without one, a program that
  ignores the proxy is bound by nothing.
- **Where it lives.** `qory` parses `runner.yaml`; the runner module takes the providers,
  the local values, the integrations and the runner file's connections through
  `session.Spec`.

### 8. Contract version and behaviour

- **Revision 1.** Every document here is `v1`, revision 1, and the runner sends
  `X-Qory-Contract-Version: 1`. A later change to what a server may rely on goes through
  that header.
- **Answer signatures are required.** A runner refuses an answer without a valid
  signature. An exemption for a plain receiver, if there is one (Open question 5), is a
  setting of the runner file, never inferred from an answer, and a run configuration with
  connections or variables under it is no run.
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
      label: Anthropic API key
      name: ANTHROPIC_API_KEY
      hosts: [api.anthropic.com]
      auth: {scheme: header, header: x-api-key}
    - id: oauth_token
      label: Claude OAuth credential
      name: CLAUDE_CODE_OAUTH_TOKEN
      hosts: [api.anthropic.com]
      auth: {scheme: bearer}
  one_of:
    - [api_key, oauth_token]
  reserves: [ANTHROPIC_AUTH_TOKEN]
```

- A declaration's `hosts` are exact DNS names, no wildcard, no IP literal; its `auth` is a
  scheme from the closed set; its optional `paths`, in the policy's path grammar, bound
  the requests its value is set on. Warning about an administrative key on save is the
  server's matter.
- A runtime connection supplies exactly one declaration of each `one_of` group, and every
  declaration in no group: else `runtime_secret_choice`. A key that is no declaration of
  the runtime is `connection_secret_unknown`.
- **The stand-in.** The runner sets the placeholder value only in the chosen
  declaration's variable, and the proxy sets the value on its hosts by its scheme. The
  placeholder need not look like a key: Claude Code does not check the format.
- **Conflicts.** A walled run is refused when its environment, `Spec.Env` with
  `wall.env`, `--env` and the harness's launch, or its variables contain a variable the
  run's runtime declares or reserves: `runtime_secret_conflict`. For Claude Code these
  are `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN`. Claude
  Code reads `ANTHROPIC_AUTH_TOKEN` before `ANTHROPIC_API_KEY` before
  `CLAUDE_CODE_OAUTH_TOKEN`, so a stray value for another alternative would win over the
  stand-in. A model credential reaches a walled run only through a connection.
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
  compatibility check, not identity: `describe` reports what the program says about
  itself. Trust in the program rests on `qory`'s path and ownership checks; matching by
  name and version is enough, and a program digest recorded at install is a later option.
- **Hosts** are `describe`'s `roles.credential.hosts`; a `*.` entry over a public suffix,
  the private section included, is `connection_host_public_suffix`. Scheme and paths come
  from the program's answer, `credential.schema.json`; a claim above the described hosts
  is refused.
- **Invocation.** `<program> credential --settings - -- <argument>`, the argument as one
  word after `--`. Standard input contains exactly one JSON document: the connection's
  `settings` with each secret's value inline under its setting's name, a name in both
  being `run_configuration_invalid`. The program reads it to its end before any network
  request, and refuses empty input, a second document or trailing data.
- **The settings document** is written from memory, from a goroutine (`cmd.Stdin` set to
  a `bytes.Reader`), so a program that never reads cannot stall the runner; standard input
  is then closed. It is written again on every invocation, renewals included, and never
  goes to a file, an argument, the environment or a log. At most 64 KiB, refused before
  the program starts: `integration_settings_too_large`. No `${argument}` is replaced
  inside it.
- **What the program writes to standard error** is reported, in errors and as the
  runner's lines, only after every value written to its standard input is replaced by
  `[redacted]`, matched exactly. Redaction, not dropping, keeps the program's own reason
  readable. It does not catch a value the program transforms before writing it, such as
  an encoded form; that is the program's to avoid.
- **A program that does not read `--settings -`** fails under the credential-failure rule
  (§Credentials). The integrations contract adds no description member announcing it
  (Open question 10).
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
  username and contains no `:` (`secret_value_invalid`). `auth.secret` is the declaration
  whose value is sent.
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

- **Termination.** Every host of a connection is terminated.
- **A host the policy denies** does not refuse the run. The run starts; a request to the
  host is refused by the policy, so the proxy never sets the value there; the host is
  listed in the connection's `hosts_denied`. The list comes from the proxy's own decision
  function, the host lists and the path rules both, so the record and the proxy cannot
  disagree. Under `observe`, every connection host that `deny` does not cover receives the
  value.
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
 "secrets": {"url": "https://qory.example/v1/secrets"}}
```

`runner_keys` and `secrets` are optional, each `{url}` with `run.url`'s grammar, listed
only for an access key allowed to receive stored secrets. `run` is listed when the
workspace has a policy, a connection or a variable.

### The run configuration

`version` is required; `security_policy`, `connections` and `variables` are optional, all
covered by the digest. Without `security_policy` the machine's own policy applies, the
policy the command passes, else observe everything: `dev.qory.run.policy_applied` reports
`source` `config` or `none` with `url` and `run_configuration`, a reload that brings a
`security_policy` puts it in force and one that drops it puts the machine's back, and
`--policy` keeps its meaning. The request is the labels, and nothing else, as the query;
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
    "secrets": {"private_key": {"id": "sec_9c4r7t2y5b8n1h3e", "name": "GITHUB_APP_KEY", "label": "production"}}},
   {"kind": "service", "id": "con_5h1k8m3p6r0t4w9x", "name": "Sentry",
    "hosts": ["sentry.io"], "paths": ["/api/0/*"],
    "auth": {"scheme": "bearer", "secret": "auth"},
    "declares": [{"id": "auth", "label": "Sentry auth", "name": "SENTRY_AUTH"}],
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
                    "name": {"$ref": "#/$defs/name"}, "label": {"$ref": "#/$defs/label"}}},
    {"type": "object", "additionalProperties": false, "required": ["source", "name"],
     "properties": {"source": {"const": "external"},
                    "name": {"$ref": "#/$defs/name"}, "label": {"$ref": "#/$defs/label"}}}]},
  "name": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,127}$"},
  "label": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_.-]{0,63}$"},
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
        "type": "object", "additionalProperties": false, "required": ["id", "label"],
        "properties": {"id": {"$ref": "#/$defs/declared"}, "label": {"type": "string", "minLength": 1, "maxLength": 128},
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

`descriptor.schema.json` gains `secrets`: `declares`, a list of `{id, label, name, hosts,
paths?, auth}`; `one_of`, a list of groups of declared ids, each id in at most one group;
`reserves`, variable names. Its `runtime` pattern becomes `^[a-z][a-z0-9-]{0,63}$`.

### Contract files the server vendors

All under `contracts/runner/v1`, so one pin covers them:

- `runtimes.json`, generated from the built-in descriptors and checked in CI against
  them: per runtime its `name`, a `label`, its `reserves`, its declarations with `id`,
  `label`, `name`, `hosts`, `auth` with its `header`, and `paths`, and `one_of`;
- `reserved-variables.json`, the names and prefixes of Decision 1 that do not depend on
  the machine;
- `headers.json`;
- `run-configuration.schema.json` and `policy.schema.json`, without `credentials`;
- `auth.schema.json`.

### Runner key registration

A signed POST to `runner_keys.url`:

```json
{"version": 1, "suite": "x25519-sha256-aes256gcm",
 "public_key": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw",
 "replaces": "<the old key's id, on rotation only>"}
```

answered `200` (or `201` the first time) `{"version": 1, "runner_key_id":
"3sVqYB9mvRVgaGW-JNlyfw"}`, or `409` with `runner_key_invalid`, `runner_key_revoked`,
`runner_key_limit`, or `runner_key_unknown` for a `replaces` that is not a key of the same
access key. A replayed registration is harmless.

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
   `runner_key_unknown` or `runner_key_revoked`;
4. refuses a run whose row it has closed: `410` `run_closed`;
5. resolves the holder the labels select, with the GET's resolver, and requires that
   holder's current rendering, or one superseded at most 15 minutes ago, to have the
   digest and a valid integrity code, else `410` `run_configuration_superseded`;
6. requires `connections` to be connections of that rendering, every one that is not a
   runtime connection and at most one runtime connection, else `409`
   `run_connections_invalid`;
7. applies the reseal rules (`409` `run_secrets_conflict`, `run_secrets_expired`);
8. parses the rendering's stored bytes and collects the distinct pairs of secret id and
   label that the listed connections reference with an id;
9. for each pair, seals the stored value only when the secret still exists and has that
   label, and, for a superseded rendering, the holder's current rendering still references
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
            "ct": "<ciphertext and tag, base64url>"}}
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
- **Sizes.** A request body at most 4 KiB, else `413`. The secrets answer at most 1 MiB,
  a refusal body at most 64 KiB.
- **Members.** A member the schema does not define is refused. A POST's signature covers
  its body and not its path, so a body signed for one endpoint must fail at every other.
- **Order of refusals.** `413`; `415`; `400` `bad_request` for a header sent twice; `401`;
  `429`; `400` `unsupported_contract_version`; `400` `invalid_request` for a body that is
  not JSON, fails its schema, has another `version`, an unknown `suite`, a `run_id` that is
  not a canonical lower-case UUID, a malformed digest or labels the labels' rules refuse;
  then each endpoint's own. Everything before `401` is unsigned; everything from `429` on
  is signed.
- **Rate limits** are the server's policy, per access key. A `429` at run start is no
  run, `rate_limited`; an event POST's `429` is retried as today.
- **Answer headers.** Only discovery's `200` contains `X-Qory-Configuration`, only a run
  configuration's `200` contains `X-Qory-Run-Configuration`, and event answers may contain
  either. Every signed answer contains `Cache-Control: no-store, no-transform`.
- **Counts.** At most 32 connections, 16 references per connection, 16 hosts and 32 paths
  per service, 32 distinct stored values per secrets request. The server checks the count
  per holder when it renders.
- **Values.** Every secret value is UTF-8 text, 1 to 16384 bytes, with no NUL; a binary
  secret is stored encoded, base64 for one, as its consumer expects. A value linked to a
  runtime or service connection, which goes into a header, also has no byte
  `0x01`–`0x08`, `0x0A`–`0x1F` or `0x7F` and no leading or trailing space or tab; bytes
  from `0x80` travel as `obs-text`, which some hosts refuse. A value linked only to
  integrations, which goes on standard input, may contain line breaks, such as a PEM key.
  The server checks a value against every current link on save; the runner checks it
  where it uses it, `secret_value_invalid`. A variable's value is at most 4 KiB, with no
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
   {"secret": "sec_9c4r7t2y5b8n1h3e", "label": "production", "value": "<the value>"}]}
```

- `run_configuration` equals the digest the runner computed, and `connections`, sorted,
  equals the set it sent. The pairs of `secret` and `label` are exactly the distinct
  pairs those connections reference with an id, each once: a missing pair is
  `secret_unresolved` with the connections that reference it, an extra or repeated one,
  another digest or another set `secret_sealed_mismatch`.
- A value follows the value rules above, for where it is used.
- The runner decodes with `encoding/json/v2`, which refuses a member name twice in one
  object by default (verified on Go 1.27.1): `secret_sealed_invalid`. It never wraps that
  decoder's errors, nor the schema validator's, whose messages can quote input.

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
included. A `401`, and a `400`, `413` or `415` sent before verification, go out unsigned.
At run start the runner treats an answer without a valid signature as no run,
`answer_unsigned`; registration's answer decides the run only when a stored value is
referenced. During the run an event answer without one is no answer, retried as today,
its headers unread; a reload's fetch without one fails the reload. A code in a body is
reported only from a signed answer; a body over 64 KiB counts as unsigned. The resend
after a runner stops verifies signatures too. Line 3 binds the answer to its request;
two identical GETs in one second, or two retries of one secrets POST, share a signature
and receive the same bytes, so a swap is harmless.

Two known answers, under `fixture-secret-not-a-real-one`, for the request
`GET\n/.well-known/qory-configuration\n1700000000`, signature
`sha256=0c895b2f1c1c62629e6298a59746b975ccae2e5156b01f733d2d7768f6eb55a2`:

- `200`; body `{"version":1,"events":{"url":"https://qory.example/v1/events","types":["*"]}}`,
  SHA-256 `ed0f5b284ef81c9277ee50cf30d91662056274028f226533a6e59ce51be4ce56`;
  `X-Qory-Configuration: sha256=` and the same hex; no run-configuration digest:
  `sha256=3104ba0fa44df9d05c101b29a4383be2abdff143830e1c008b2799955f856016`
- `404`, empty body, no digest:
  `sha256=040a264ad219396ad1dcee84e93816aa49394b633a5db303818fe1a19a58c9bf`

### Coded refusals

After verification, `409`, `410` (`run_configuration_superseded`, `run_closed`), `429`,
`503` or `400`, `application/json`, signed: `{"error": "<code>", "names": ["…"]}`. `401`
stays `{"error":"unauthorized"}`; `bad_request`, `413` and `415` are unsigned and reported
by status only.

### Values at rest (guidance for the server)

Not part of the contract. The server encrypts each stored value with AES-256-GCM under a
key derived from its instance key with HKDF-SHA256, stored with a key id, and binds as
associated data `lp("qory-secret-v1") ‖ lp(workspace id) ‖ lp(secret id) ‖ lp(label)`,
so a value moved to another secret or label no longer decrypts. Organisation secrets are
not in 0.7.0. Connections, service definitions and renderings are covered by the
integrity codes of Decision 6.

### Events

**`dev.qory.run.refused`**, new: emitted in place of `dev.qory.run.started` when a run
does not start after the ping, as the run's last event; the runner waits up to fifteen
seconds for its delivery. Data: `code`; `connection`, the connection's id, for every
refusal that concerns one; `names`, never a value; `providers` with `secret_unresolved`;
`status` when the code came from the server. The wall check runs after the ping, so
every no-run after an accepted ping is reported this one way.

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
name and label, never a value; `uses` where and how the proxy sets each value;
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
   `server_needs_wall`.
3. When the configuration lists `runner_keys` and the spec contains a runner key:
   register; keep the outcome.
4. When the configuration lists `run`: fetch the run configuration; recompute its digest;
   decode it with `encoding/json/v2`; validate it against the schema and the limits.
   Without `security_policy`, the machine's policy is the run's. Without a run
   configuration, the connections are the runner file's.
5. Check the connections: connections without a wall; duplicates; the runtime connection
   for the run's runtime kept and any other set aside; declarations and `one_of`; hosts
   and `headers.json`; protected mounts.
6. When a connection the run applies references a stored value: no runner key, no
   `secrets` section, or a refused, unsigned or mismatched registration is no run.
   Otherwise the secrets request with the applied connections; check and open the
   envelope; check the plaintext.
7. Resolve every external reference through the providers in order, and check each
   machine value's `hosts` against where its connection sends it.
8. For each integration connection: find the program, run `describe`, compare its name
   and version, read its hosts.
9. Check the hosts and the values together: `connection_host_conflict`, the value rules
   for where each value goes; compute `hosts_denied`.
10. Check the variables and the environment: without a wall `variables.accept`; the
    reserved names; `runtime_secret_conflict`; `variable_conflict`; placeholders the run
    passes a value for, `placeholder_conflict`.
11. Run each integration's `credential` with its settings document; check its answer.
12. Then §Sequence from the tools on. The proxy receives the uses; the launch's
    environment is the run's, then the variables, then the runner's own, the
    placeholders, and the runtime's other declared and reserved variables as empty.
13. `dev.qory.run.started`, then `dev.qory.run.policy_applied`.

A refusal at steps 2 to 11 is `dev.qory.run.refused` when the ping was accepted, and the
error the caller receives in every case. Values live in the runner's memory only, never
on disk, in the environment, an event, a log line, an error or a report; at run end they
are unreferenced, since Go cannot wipe a string.

## Refusal codes

| Code | Decided by | When |
|---|---|---|
| `bad_request` | server, `400`, unsigned | a header sent twice |
| `unsupported_contract_version` | server, `400` | `X-Qory-Contract-Version` other than `1` |
| `invalid_request` | server, `400` | a body that is not JSON, fails its schema or has an unknown member; labels the contract refuses |
| `rate_limited` | server, `429` | the access key's rate is exceeded |
| `unavailable` | server, `503` | a stored rendering fails its integrity code |
| `runner_key_invalid` | server, `409` | not 32 bytes, non-canonical, low-order, or another key under an existing id |
| `runner_key_limit` | server, `409` | as many runner keys as allowed |
| `runner_key_revoked` | server, `409` | the key or its id is a tombstone |
| `runner_key_unknown` | server, `409` | the key id, or `replaces`, is not a key of the access key |
| `secrets_not_allowed` | server, `409` | the access key is not allowed stored secrets |
| `run_closed` | server, `410` | the server has closed the run's row |
| `run_configuration_superseded` | server, `410` | no valid rendering of the holder with that digest, current or within 15 minutes |
| `run_connections_invalid` | server, `409` | the listed connections are not those the rendering requires |
| `run_secrets_conflict` | server, `409` | a reseal with another runner key, digest or set of connections |
| `run_secrets_expired` | server, `409` | a reseal after the first payload's `exp` |
| `runner_key_mismatch` | runner | the registration answer's id is not the runner's own |
| `runner_key_missing` | runner | a stored value referenced and no runner key in the spec |
| `answer_unsigned` | runner | an answer at run start without a valid signature |
| `server_needs_wall` | runner | discovery lists `secrets` and the run has no wall |
| `mount_contains_runner_config` | runner | a mount is, contains or lies inside the runner's configuration directory |
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
| `runtime_secret_choice` | runner | not exactly one declaration per `one_of` group, or a required one missing |
| `runtime_secret_conflict` | runner | the environment or the variables contain a variable the runtime declares or reserves |
| `integration_missing` | runner | the machine has no integration of that name |
| `integration_name_mismatch` | runner | `describe`'s `name` differs from the connection's |
| `integration_version_mismatch` | runner | `program_version` differs from the connection's `version` |
| `integration_settings_too_large` | runner | the settings document exceeds 64 KiB |
| `secret_label_missing` | runner, and the server on save | a reference to a secret with several values without a label |
| `secret_unresolved` | runner | no provider resolves it, or the sealed list lacks it |
| `secret_hosts_exceeded` | runner | a machine value sent to a host its `hosts` do not cover |
| `secret_value_invalid` | runner | a value that breaks the value rules for where it goes, or a `:` in a basic username |
| `secret_sealed_invalid` | runner | the envelope does not open, an identifier is not the runner's, or the plaintext is malformed |
| `secret_sealed_expired` | runner | `exp` passed by more than 300 s, or more than 900 s ahead |
| `secret_sealed_mismatch` | runner | an extra or repeated value, another digest or another set of connections |
| `variable_not_accepted` | runner | without a wall, a name outside `variables.accept` |
| `variable_reserved` | runner | a reserved name, or `QORY_SERVER_SECRET` passed into the enclosure |
| `variable_secret_conflict` | runner | a variable with a placeholder's name |
| `variable_conflict` | runner | a variable the run or the runtime sets |
| `placeholder_conflict` | runner | the run passes a value for a placeholder |

## Security considerations

| Threat | What protects | What does not |
|---|---|---|
| A TLS-terminating middlebox between the runner and the server, without the access key's secret | It cannot read a stored value; it cannot alter the connections, the policy, the variables or the digests, nor replay an older answer; `no-transform` keeps a proxy from re-coding a signed answer | It reads the document. At the start it can only refuse; during a run, dropping answers keeps the policy in force |
| A proxy between the runner and a destination host, whose authority the machine trusts | — | It reads the value there: that leg is ordinary TLS against the machine's trust store (Open question 7) |
| The server's logs and answer caches | Ciphertext only; `Cache-Control: no-store` | — |
| A read of the server's database | Values encrypted under a key derived from the instance key | A reader with the instance key reads everything |
| A write to the server's database | Integrity codes over connections, custom definitions and every rendering, with a per-row version; seals taken from the verified rendering's bytes; audit | A writer with the instance key, or a change through the server's own pages |
| A link removed while a run starts | A superseded rendering seals only what the current rendering still references through the same connection | — |
| Another runtime's credential | The secrets request lists one runtime connection, the run's own; the server seals nothing for any other | — |
| A server that sends a machine value elsewhere | The machine's own `hosts` on each `secrets.local` entry: `secret_hosts_exceeded` | — |
| A machine with the access key, choosing labels | — | Repository scope is no boundary against a machine: an access key is workspace-wide |
| A stolen access key secret | Stored secrets only for access keys allowed them; revocation; the recomputed digest binds values to the document the server rendered | Whoever has it registers a key and receives future stored values (Open question 1) |
| An agent reading the machine's configuration | `server_needs_wall`; `qory` refusing unwalled runs where `runner-key` exists; `mount_contains_runner_config`; `QORY_SERVER_SECRET` refused in the enclosure | An unwalled agent of the same user outside `qory` (Issues, item 4) |
| A model credential reaching the enclosure | `runtime_secret_conflict`; the runtime's other declared and reserved variables set to empty | — |
| The agent in the enclosure | A placeholder in the environment, the value set outside on the kind's hosts only; `TRACE` and `TRACK` refused there | A host that sends a request's headers back returns the value (§Limits); `headers.json` keeps the common echoes out |
| An integration program | Its settings on standard input only; `describe`'s name must match; its standard error redacted before it is reported | It runs as the runner's user and is trusted; a value it transforms before writing escapes redaction |
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

  A real Claude Code run with a real API key stays a manual check before the release,
  because CI has no Anthropic key.
- **Empty means unset.** A check that Claude Code treats an empty `ANTHROPIC_AUTH_TOKEN`,
  `ANTHROPIC_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN` as unset and uses the chosen stand-in.
- **Fixtures:** `fixtures/sealed/` (Decision 5), the low-order list, run configurations
  with each kind of connection and invalid ones per refusal the schema can express,
  `runtimes.json` against the descriptors, `headers.json` against its sources, and
  `fixtures/signed/` with answers.
- **Integrations:** a fake program that checks its standard input is one document, that
  it arrives fresh on a renewal, that a program that never reads does not stall the run,
  that no value reaches its arguments or environment, that a value it writes to
  standard error is reported redacted, and that a program whose `describe` reports
  another name is refused.

## Upgrading

0.7.0, as facts for the changelog:

- Connections decide every credential a run sends; the policy has no `credentials`. The
  runner file has `connections:`, `secrets.providers`, `secrets.local` and
  `variables.accept`.
- A run configuration may contain `connections` and `variables`, and may omit
  `security_policy`.
- Stored values are sealed to a runner key that `qory` creates the first time discovery
  lists `runner_keys`, and fetched from the secrets endpoint for the connections the run
  applies.
- Every answer of the server is signed, and the runner verifies it.
- A walled run is refused when its environment contains a variable the run's runtime
  declares or reserves; for Claude Code, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY` and
  `CLAUDE_CODE_OAUTH_TOKEN`.
- Every run against a server that lists `secrets` needs a wall, and so does every run on a
  machine with `runner-key`. A mount of the runner's configuration directory, or of a
  directory above it, is refused.
- The proxy refuses `TRACE` and `TRACK` on every host where it sets a value.
- `dev.qory.run.refused` is new; `dev.qory.run.policy_applied` lists connections and
  variables' names.

## Open questions for the user

1. Does a newly registered runner key need approval in the server before values are
   sealed to it? It is the one control between a stolen access key secret and the
   workspace's stored values, and the case where the recomputed digest matters.
2. `variable_conflict` against the names the run sets: refuse (proposed), or let the
   server's value win, or the run's?
3. `server_needs_wall`, scoped per access key as the server's side proposes, with `qory`
   refusing every unwalled run where `runner-key` exists: accept?
4. `variables.accept`: the server's side accepts it as drafted, names only. Agree?
5. A runner-file exemption from answer signing for a plain receiver: offer one, or none?
6. Should other no-runs after the ping, such as a tool that does not start, also emit
   `dev.qory.run.refused`?
7. Build the optional setting that verifies destination hosts against public roots only?
8. Keychain storage for the access key's secret and the runner key: now, or later?
9. Routing out of the seal, with the digest recomputed and the server sealing from the
   verified rendering (Decision 6): the server's side agrees. Agree?
10. Integrations: add a description member announcing support for `--settings -`, so a
    program without it is refused by name rather than by its failure?
11. For a later release, with organisation secrets: who may link a secret into a
    connection? The server's side prefers a permission on the secret at the level that
    owns it, and, until then, the right to enable stored secrets on an access key held by
    administrators.

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
10. **`policy_applied`'s schema** changes: `credentials` goes, `connections` comes, and
    `url` and `run_configuration` are allowed with `source` `none`. `qory` decides
    whether `--policy` applies only after the fetch shows whether `security_policy` is
    present.
11. **The runner file's connection ids** use a grammar of their own; the record's
    `connection` field takes either form.
12. **An unsigned `2xx` on an event POST** is retried until the run ends; the runner
    reports it once, not per batch.
