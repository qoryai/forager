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
- **Variables** are an object, name to `{value, locked}`. A value at most 4 KiB, all
  variables at most 64 KiB. Levels resolve from organisation to machine, the more
  specific winning unless a level above locks the variable; two sources for one name
  never refuse a run (Decision 1).
- **A deny list replaces `variables.accept`.** A machine accepts every variable except a
  built-in list and its own `variables.deny`; a denied variable is left out and reported,
  never a refusal. `variable_conflict`, `variable_not_accepted` and
  `variable_secret_conflict` are gone.
- **Stored secrets go only to walled runs** in 0.7.0; a credentials broker is a later
  direction, not specified here.
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
  supplies a required group; a server variable with such a name is left out, and the
  wall sets every such variable the run does not use to empty.
- **Integrations** are started as `<program> <role> -- [arguments]` and receive their
  secrets as a settings document on standard input, always one document, `{}` when
  empty, written from a goroutine; anything they write to standard error is reported with every
  value of that document, every line of 8 bytes or more of a multi-line value and the
  returned credential redacted. `describe`'s name must equal the connection's, and its
  version is checked for equality.
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
- **Ids** are `sec_`, `con_` or `ak_` and 16 lower-case Crockford base32 characters.
- **The server's database** is covered: access key rows have integrity codes too,
  verified on every request.
- **The machine keeps more out of the wall:** a mount of a program the runner starts, a
  `secrets.local` file or a runtime's credential file is refused, and a `secrets.local`
  `env:` source never enters the enclosure, a tool or an integration.
- **Integrations** can be bounded by the machine (`arguments`, `settings`), and their
  settings are checked against their own description. A server-sent integration that
  references a machine value needs both bounds.
- **One secret per access key.** The HMAC secret and the runner key give way to one
  access key secret, `QORY_ACCESS_KEY_SECRET` or the file `access-key-secret`: an Ed25519
  key that signs every request and, converted to X25519, opens sealed values. The server
  stores only its public key, so no HMAC remains, and reading the server's database no
  longer lets anyone act as an access key. A key enrols with a single-use code or by an
  administrator pasting its public key; registration at every run start is gone. The
  server seals nothing to a key before approval, a rotation keeps the access key id, and
  a fleet may share one key (Decision 4).
- **Machines are instances.** A machine id, generated per instance and signed into every
  request under the key, serves display, audit and per-instance events; it is never part
  of authorisation. One public key belongs to exactly one access key.
- **Names say what they are.** A name ending in `_SECRET` is never shown; one ending in
  `_PUBLIC_KEY` or `_ID` is safe to show. The runner has `QORY_ACCESS_KEY_ID`,
  `QORY_ACCESS_KEY_SECRET` and `QORY_APIARY_PUBLIC_KEY`; the server has
  `APIARY_ENCRYPTION_SECRET` and `APIARY_SIGNING_SECRET`. Third-party names, such as
  `ANTHROPIC_API_KEY`, keep theirs.
- **A pin of the server's key on every runner**: the server signs every answer and
  every envelope with Ed25519, and every runner with a server pins the key,
  `apiary_public_key` in `runner.yaml` or `QORY_APIARY_PUBLIC_KEY`, and verifies both.
  A runner with a server and no pin is no run, `apiary_public_key_missing`. Enrolment
  with a code installs the pin.
- **Public roots for stored values**: the proxy verifies a host that receives a stored
  value against public roots only, `tls.public_roots_only`, on by default.
- **Every no-run after the ping** emits `dev.qory.run.refused`, a tool or an integration
  that does not start included.
- **Who may link**: only owners and administrators link a secret into a connection,
  define a custom service, edit variables or enable stored secrets on an access key.
- **Enabling stored secrets forces a rotation**: the server seals only to a key it
  received after the flag was last enabled, so a key an earlier unwalled agent could
  have read never receives a stored value (Decision 4).
- **An access key without stored secrets** receives the holder's rendering with every
  connection that references a stored value left out, and the runner reports them by
  name (Decision 6).
- **One workspace per access key** in 0.7.0.
- **Server variables reach unwalled runs only when the machine opts in**:
  `variables.unwalled`, `ignore` by default (Decision 1).
- **`GIT_AUTHOR_*` and `GIT_COMMITTER_*` are allowed**: the deny list gains an `except`
  member for them (Decision 1).
- **Runtimes deny names**: a descriptor's `denies` lists variables the server may never
  set for that runtime, such as Claude Code's endpoint and shell variables.
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

**Variables reach the agent's process and nothing else.** The runner adds them to the
launch's environment only: never to a tool, an integration, the relay, the daemon of a
Docker of the agent's own, or the `docker` command the wall runs on the machine. The
nested Docker helper starts `dockerd` with the system `PATH`, the proxy variables and the
bundle only (Issues, item 3).

**Precedence.** A variable is set at levels, the more specific winning: the organisation
(in the commercial editions), the workspace, the repository, all three resolved by the
server, then the machine. There is no level per kind of run.

- The server sends each variable with its value and `locked`. A level that locks a
  variable stops every level below it from overriding it; the server's resolution
  honours locks among its own levels, and the runner honours `locked` for the machine's.
- `locked` is true when any server level of the chain locks the name, and the value sent
  is then the topmost locking level's. A lock always carries a value. Whether a lower
  level may still save a value under a lock is the server's to decide.
- The machine's level is what the run sets on the machine: `wall.env` in `runner.yaml`,
  `--env`, the harness's composed launch and what the runtime's `Prepare` sets, the names
  a new `session.Spec` field lists (Issues, item 2).
- A machine value replaces an unlocked variable. Where a value from `wall.env` or `--env`
  meets a locked one, the server's value wins. A name the runtime's `Prepare` or the
  harness's launch sets wins even over a locked variable, because the runtime needs it;
  the server's variable is then left out and reported in `denied`.
- Two sources for one name never refuse a run. `dev.qory.run.policy_applied` reports, by
  name only, every variable a machine value replaced and every locked one that kept the
  server's value against a machine value (Events).

**Unwalled runs.** The runner file's `variables.unwalled` decides whether an unwalled run
receives the server's variables: `ignore`, the default, or `accept`. With `ignore`, an
unwalled run receives none of them; they are left out and reported by name in
`policy_applied`'s `variables.unwalled`, and the run is never refused. With `accept`,
the deny list below still applies. A walled run receives them as this decision
describes, whatever the setting.

**Denied names.** A machine accepts every variable the server sends except the names of a
deny list: the built-in list below, the run's runtime's `denies` (Runtimes), and the
names the machine's owner adds in the runner file, `variables.deny: [NAME, PREFIX_*]`.

- A denied variable is left out of the run and reported by name. The run is never
  refused, and that holds for a locked variable too.
- An entry is a name or a pattern, `^[A-Za-z0-9_*]{1,128}$` with at least one character
  other than `*`. It matches a whole name: `*` matches any run of characters, the empty
  run included, anywhere in the entry. Matching ignores case, because programs read
  `http_proxy` and `HTTP_PROXY` alike.
- The list applies to the server's variables only, never to what the machine sets
  itself, and it applies with and without a wall.
- The reason: in an unwalled run that accepts the server's variables, a server-sent
  `LD_PRELOAD` runs code as the developer,
  and in a walled one these names would undo the wall's own set-up: its proxy, its trust
  bundle, its Docker configuration and the program the launch starts.
- No such list is complete; a machine's owner extends it with `variables.deny`.
- **Exceptions.** `GIT_AUTHOR_*` and `GIT_COMMITTER_*` are allowed although `GIT_*` is
  denied: they set a commit's name, email and date, and run nothing, and teams set them
  so an agent's commits carry a bot identity. A name is denied when it matches an entry
  of the built-in `names` or `patterns` and no entry of `except`. `except` applies to the
  built-in list only: the runtime's `denies` and the owner's `variables.deny` always win.
- The server vendors the built-in list as `denied-variables.json`,
  `{"version": 1, "names": [...], "patterns": [...], "except": ["GIT_AUTHOR_*", "GIT_COMMITTER_*"]}`,
  under the same matching rule. It
  holds every row of the table except two, which depend on the machine and the run: the
  names `Docker.CAEnv` sets, and the runtime's `declares`, `reserves` and `denies`, which
  come from `runtimes.json`. The server refuses a name the file covers when it is saved,
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
| Start-up, Java | `JAVA_TOOL_OPTIONS` | options every JVM reads, `-javaagent` included |
| Start-up, Java | `_JAVA_OPTIONS` | the same, read by HotSpot |
| Start-up, Java | `JDK_JAVA_OPTIONS` | the same, read by the `java` launcher |
| Start-up, .NET | `DOTNET_STARTUP_HOOKS` | assemblies .NET runs before `Main` |
| Start-up, .NET | `CORECLR_*` | `CORECLR_ENABLE_PROFILING` with `CORECLR_PROFILER_PATH` loads a native profiler |
| Start-up, Erlang | `ERL_AFLAGS`, `ERL_ZFLAGS`, `ERL_FLAGS` | flags for every `erl`, `-eval` included |
| Start-up, Erlang | `ERL_LIBS` | where Erlang finds applications |
| Start-up, build tools | `GOFLAGS` | `-toolexec` runs a program for every step of a Go build |
| Start-up, build tools | `GOENV` | a Go environment file, which can set `GOFLAGS` |
| Start-up, build tools | `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER` | Cargo runs it in place of the compiler |
| Start-up, build tools | `CARGO_TARGET_*_RUNNER` | Cargo runs it to start every program and test it builds |
| Start-up, build tools | `CARGO_TARGET_*_LINKER` | Cargo runs it to link |
| Start-up, build tools | `CC`, `CXX` | the compiler make, cgo and build scripts start |
| Start-up, build tools | `MAKEFLAGS` | options and variable assignments for every make, `SHELL` among them |
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
| Git and SSH | `GIT_*`, except `GIT_AUTHOR_*` and `GIT_COMMITTER_*` | `GIT_SSH_COMMAND`, `GIT_EXEC_PATH`, `GIT_ASKPASS` and `GIT_CONFIG_*` start programs or change configuration, and `GIT_SSL_CAINFO` the trust |
| Git and SSH | `SSH_AUTH_SOCK` | points ssh and git at an agent holding keys |
| Docker | `DOCKER_*` | `DOCKER_HOST` and `DOCKER_CONFIG` choose the daemon and its credentials; the wall sets `DOCKER_CONFIG` for a Docker of the agent's own |
| Routing and trust | `*_PROXY` | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `FTP_PROXY`: the runner sets the proxy variables (§Sequence step 5), and any other routes around them |
| Routing and trust | `SSL_CERT_FILE`, `SSL_CERT_DIR` | the trust store of OpenSSL and of Go; the wall points them at the run's bundle (§The wall) |
| Routing and trust | `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE` | the trust of curl, Python Requests, Node and the AWS SDKs, which the wall sets the same way |
| Routing and trust | `NODE_TLS_REJECT_UNAUTHORIZED` | `0` turns off certificate checks in Node |
| Routing and trust | `GODEBUG` | its settings turn insecure TLS and X.509 behaviour back on in every Go program |
| Routing and trust | `PYTHONHTTPSVERIFY` | `0` turns off certificate checks in Python builds that honour it (PEP 493) |
| Routing and trust | `OPENSSL_CONF` | an OpenSSL configuration, which can load engines and providers and change trust |
| Routing and trust | `OPENSSL_ENGINES`, `OPENSSL_MODULES` | where OpenSSL loads engines and providers from |
| Routing and trust | `CURL_HOME` | where curl reads `.curlrc`, which can set a proxy or turn off verification |
| Routing and trust | `WGETRC` | the same for wget |
| Routing and trust | `HOSTALIASES` | a file of host aliases the glibc resolver reads |
| Routing and trust | `RES_OPTIONS`, `LOCALDOMAIN` | resolver options and search domains, which change where a short name leads |
| Cloud configuration | `KUBECONFIG` | a kubeconfig, whose `exec` entries start credential programs and whose clusters receive credentials |
| Cloud configuration | `AWS_CONFIG_FILE` | an AWS configuration, whose `credential_process` starts a program |
| Cloud configuration | `AWS_SHARED_CREDENTIALS_FILE` | which credentials AWS tools send |
| Package managers | `npm_config_node_options` | Node options for the scripts npm runs |
| Package managers | `npm_config_script_shell` | the shell npm runs scripts with |
| Package managers | `npm_config_userconfig`, `npm_config_globalconfig` | which npm configuration file is read, and it can set every other npm setting |
| Package managers | `npm_config_strict_ssl`, `npm_config_cafile`, `npm_config_ca` | npm's trust |
| Package managers | `PIP_CONFIG_FILE` | which pip configuration file is read |
| Package managers | `PIP_CERT` | pip's trust store |
| Package managers | `PIP_TRUSTED_HOST` | hosts pip reaches without verifying their certificates |
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
Package-manager settings that only choose a mirror, such as `PIP_INDEX_URL` or
`npm_config_registry`, stay allowed: a team sets them for a mirror, and the egress policy
bounds where they lead. Settings that run a program, load a configuration file or change
trust are denied, as the table lists. The list cannot be complete, and a machine's owner
extends it with `variables.deny`.

**Also left out, the same way:** a server variable with the name of a placeholder of this
run, a declaration's `name` or an integration's, where the placeholder wins; and one a
`secrets.local` value reads (`env:`), whose machine value stays outside the enclosure.
A lock never overrides a denied or reserved name: the reserve wins, and the variable is
left out and reported.

**The machine's own environment** keeps three refusals, because they keep the machine's
secrets and the stand-ins out of the enclosure. A run whose environment passes a `QORY_`
variable, or a variable a `secrets.local` value reads, into the enclosure is no run,
`variable_reserved`. `QORY_RUN_ID` and `QORY_RUN_SOCKET`, which the runner itself sets
for the session, are exempt. One whose environment contains a variable the run's runtime declares
or reserves is `runtime_secret_conflict` (Runtimes). One that passes a value for a
placeholder is `placeholder_conflict`.

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
  run, so a retry never meets the reseal window of an earlier attempt.
- **Superseded run configurations.** The server keeps every rendering. It seals for the
  holder's current one, or for one superseded at most 15 minutes ago, and for an older one
  no longer: `410` `run_configuration_superseded`. From a superseded rendering it seals a
  value only when the holder's current rendering still references it through the same
  connection, so removing a link takes effect at once. A holder has two renderings at a
  time, one per variant (Decision 6), and these rules apply to each.
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

**The access key is the credential.** A machine is an instance that runs with it.

- **One secret per access key.** An access key is an Ed25519 key. It signs every request
  the runner sends, and the same key, converted to X25519, opens what the server seals
  to it. The server stores only the public key. The access key id, `ak_` and 16
  lower-case Crockford base32 characters, is assigned by the server when the key enrols
  and is sent on every request. The key is enrolled, approved and rotated once, and a
  fleet may share it: ten ephemeral instances on one key are one access key.
- **On the key row.** Approval, the stored-secrets flag, the workspace, the rate limits,
  rotation and the integrity code all belong to the access key's row, and seals bind to
  the key. Revoking a key cuts off every machine that uses it.
- **A machine is an instance.** The runner reports a machine id as a signed line of every
  request under the key, for display, audit and per-instance events only. The machine
  id is never part of authorisation: the seal, the variant and the rate bucket are all
  per key, and anyone who holds the key can claim any machine id.
  - The id matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. `qory` generates `m_` and 16
    random bytes in base64url, 24 characters, once per instance. It keeps the id in the
    file `machine-id` beside `runner.yaml` when that directory is writable; otherwise the
    id lives for the process only, which suits an ephemeral instance. The runner module
    takes it through `session.Spec`.
  - An optional display name, `machine.name` in `runner.yaml`, defaults to the host name
    and travels in `X-Qory-Machine-Name`, for display only.
  - The server keeps at most 256 distinct machine ids per access key in a rolling
    24 hours. It never refuses a request for exceeding that, which would break a fleet
    mid-run: past the bound it creates no new machine record and counts the excess on
    the key. The answer is unchanged, and the runner learns nothing.
  - The server's live Machines page shows each machine of a key: when it was last seen,
    its runs and its events. Events carry the machine id as reported.
- **Names.** A name ending in `_SECRET` is never shown; one ending in `_PUBLIC_KEY` or
  `_ID` is safe to show. `QORY_ACCESS_KEY_ID` is the access key id,
  `QORY_ACCESS_KEY_SECRET` the key's only secret, and `QORY_APIARY_PUBLIC_KEY` the pin of
  the server's key (Decision 6). Apiary's server has `APIARY_ENCRYPTION_SECRET`, the
  instance key, and `APIARY_SIGNING_SECRET`, its signing key. Third-party names, such as
  `ANTHROPIC_API_KEY`, are never renamed.
- **The secret.** One line: `qak_` and the 32-byte Ed25519 seed in base64url without
  padding, 47 characters. The prefix lets secret scanners recognise it. `qory` generates
  the seed from the system's random source and reads the secret from a file descriptor
  it is given, else from `QORY_ACCESS_KEY_SECRET`, else from the file `access-key-secret`
  next to `runner.yaml`: `$XDG_CONFIG_HOME/qory/access-key-secret`, else
  `~/.config/qory/access-key-secret`. The variable wins over the file.
- **The file.** `qory` creates it with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, in a
  directory of mode `0700`, and refuses a file whose mode grants anything to the group or
  to others, a file or directory owned by another user than the effective one, and the
  published fixture secret (Decision 5). Keeping the secret in the system's keychain is a
  later option.
- **On a CI machine** the secret comes from the CI's secret store instead, through
  `QORY_ACCESS_KEY_SECRET` or a file descriptor, and `qory` writes no file.
  `QORY_ACCESS_KEY_ID` and `QORY_APIARY_PUBLIC_KEY` are plain settings of the CI; only the
  secret goes to its secret store. The variables are reserved (`QORY_`) and never reach a
  tool, an integration or the enclosure: once `qory` has read them, it removes them from
  its own environment, so nothing the run starts inherits them.
- **The runner module writes nothing.** It takes the secret and the machine id through
  `session.Spec`.
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
  same way. Signatures and HPKE use distinct domain strings: every message the access
  key signs starts with a line of its own, `qory-request-ed25519-v1`,
  `qory-enrol-ed25519-v1` or `qory-rotate-ed25519-v1`, and HPKE derives its keys under
  its own labels. Two costs: the signing key and the opening key cannot be rotated apart,
  and a hardware key store that does not expose the scalar cannot open envelopes, which
  matters when keychain storage comes. A post-quantum KEM key, later, is derived from the
  same seed with HKDF-SHA256 under a label of its own, so the key keeps one secret.
- **Enrolment** gives an access key its id, in one of two ways.
  - (a) **An enrolment code.** An owner or administrator creates a code in Settings ›
    Access keys: single use, valid for minutes, bound to a workspace and to the key's
    settings, and carrying the fingerprint of the server's public key. On the machine,
    `qory access-key enrol <server> <code>` generates the secret, keeps it as above,
    prints its fingerprint, and posts the enrolment request (Wire format): the public
    key, a name for the key, a timestamp, the code, and a proof of possession, an Ed25519
    signature under the new key. When `access-key-secret` exists, `qory` first moves it
    to `access-key-secret.old`, replacing an earlier one. The answer is signed with the
    server's key; `qory` verifies it against the key whose fingerprint the code carries,
    then writes `access_key_id` and `apiary_public_key` into `runner.yaml`'s `server`
    section. The answer contains the access key id, `approved: false` and
    `stored_secrets`, the key's stored-secrets flag; when the flag is set, `qory` writes
    the `stored-secrets` marker (below). The key awaits approval, and an owner or
    administrator compares the fingerprint `qory` printed with the one Settings › Access
    keys shows, and sees the settings the key will get, before approving it.
    `qory access-key enrol --print` writes no file and prints `QORY_ACCESS_KEY_ID`,
    `QORY_ACCESS_KEY_SECRET` and `QORY_APIARY_PUBLIC_KEY` for a CI's settings.
  - (b) **A pasted key.** `qory access-key create` generates the secret, keeps it as
    above, and prints the public key and its fingerprint; with `--print` it writes no
    file and prints `QORY_ACCESS_KEY_SECRET` as well. An owner or administrator adds the
    key in Settings › Access keys by pasting the public key, with its settings, and the
    key is approved at once, since an administrator entered it. The page then shows
    `QORY_ACCESS_KEY_ID` and the pin, which the machine sets in `runner.yaml` or its
    environment.

  A fingerprint is `base64url(SHA-256(raw public key)[:16])`, 22 characters, for the
  access key and the server's key alike.
- **A code and the server's key.** The server answers an enrolment under the key whose
  fingerprint the code carries while it still holds that key. A change of the server's
  key ends every outstanding code. The server keeps only the SHA-256 of a code; with 130
  random bits a fast hash is enough.
- **One public key, one access key.** A public key belongs to exactly one access key. The
  server keeps a global unique index over every key row's current key, pending key, old
  key in its window and every tombstone, checks it at enrolment, paste and rotation, and
  keeps it beyond the deletion of a workspace. A key another access key holds is `409`
  `key_invalid`; a tombstone is `409` `key_revoked`. An enrolment retry is exempt for
  its own row.
- **What enrolment refuses.** The server checks every public key it is given, enrolled,
  pasted or sent for rotation, the pasted key included, which has no proof of
  possession:
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
  retired: by revocation, by rotation or by the rejection of a pending key. It outlives
  the deletion of its workspace and organisation, so the key never enrols again and the
  id is never reused.
- **Approval.** Every access key needs approval, and every new key of it needs approval
  before it is used. Until then every signed endpoint answers a request under that key
  with a signed `409` `key_pending`, discovery included, and the events endpoint accepts
  nothing: a key that awaits approval receives no run configuration, no variable and no
  stored value, and posts no event. A key enrolled with a code awaits approval; a pasted
  key is approved as it is entered. Approval always applies, so no setting of the server
  turns it off.
- **Key settings.** What the server sets per key row: whether the key may receive stored
  secrets, off by default and enabled only by owners and administrators, with when it
  was last enabled; its rate limits; and its workspace. In 0.7.0 an access key belongs to
  exactly one workspace in every edition, and a fleet that serves several workspaces
  holds one key per workspace. Discovery is per key and lists `secrets` only for a key
  allowed stored secrets. A developer's own key keeps unwalled runs; a CI or shared key
  receives stored secrets and runs walled.
- **Enabling stored secrets forces a rotation.** A secret an earlier unwalled agent read
  must never unlock stored values, so the server seals only to a key it received, by
  enrolment, paste or rotation, after the access key's stored-secrets flag was last
  enabled. The key row holds that time and the time it received each key it holds,
  current, pending and old, all under its integrity code. Enabling the flag also rejects
  any pending key, which becomes a tombstone, because it was received before.
  - An access key whose current key is older gets `409` `key_rotation_required` on the
    secrets request. Signed discovery lists `secrets` and `key_rotation_required: true`
    to the current key only, and only while no eligible key is pending; otherwise the
    member is omitted.
  - When the secret is held in a file, `qory` then writes the `stored-secrets` marker
    before it generates the new key, so no unwalled run can see that key, and rotates as
    below; a `key_rotation_pending` answer to that rotation is no error. With the secret
    in `QORY_ACCESS_KEY_SECRET` or a file descriptor, `qory` reports
    `key_rotation_required` and the operator rotates with `--print`, as for a fleet.
  - `qory access-key rotate` also writes the marker before it generates a key whenever
    discovery lists `secrets`.
  - A key enrolled or pasted while the flag is set is received after it and needs no
    rotation. The server cannot know when a pasted key was generated, so the owner pastes
    a key `qory access-key create` generated for that purpose.
  - The variant follows the flag alone, by intent. A key with the flag and no eligible
    key receives the full rendering and is refused at the secrets request,
    `key_rotation_required`, which discovery has already announced, so the failure is
    explicit rather than a run quietly missing its connections.
- **Rotation.** `qory access-key rotate` generates a new secret, writes it to
  `access-key-secret.next`, mode `0600`, beside `access-key-secret`, prints the new key's
  fingerprint, and posts the new public key with a proof of possession by the new key,
  signed under the current secret (Wire format). The new key needs approval, given after
  comparing that fingerprint with the one Settings › Access keys shows; until then the
  current key keeps working.
  - Only the current key may rotate: the old key of an open window and the pending key
    each get `401` there. A rotation that posts a key this access key holds or held, its
    current key, the old key of an open window or one of its own tombstones, is
    `key_invalid`, as is a key another access key holds. A second rotation while a new
    key awaits approval is `409` `key_rotation_pending`; a repeat of the pending key's
    own request is answered as the first was. An owner or administrator can reject a
    pending key without revoking the access key, and a rejected key becomes a tombstone.
  - On approval the old key stays valid for a fixed window of 24 hours, whatever the
    machines do, and then becomes a tombstone; a request under the new key does not end
    it. An owner or administrator can end the window early in Settings › Access keys, for
    example once a CI's secret store holds the new secret. An access key has at most one
    old key: approving a new key ends any window still open, and that old key becomes a
    tombstone. The access key id stays.
  - Before each run while `access-key-secret.next` exists, `qory` sends a discovery
    request signed under the new key: a signed `409` `key_pending` means the key awaits
    approval, and the run uses the current secret; a signed `200` means it is approved,
    and `qory` moves `access-key-secret.next` over `access-key-secret` and the run uses
    it. Any other answer leaves both files as they are.
  - `qory` rotates by itself only when the secret is held in a file. A key a fleet
    shares, or one held in `QORY_ACCESS_KEY_SECRET`, is rotated by its operator with
    `--print`, and the 24-hour window covers the whole fleet.
  - A planned rotation therefore has no gap and no failing run: every run or job started
    under the old key finishes within the window. The one case left is a run longer than
    24 hours that began before the approval. Revocation, the action for a compromised
    key, is immediate and separate.
- **Rotation of a shared key.** The operator runs `qory access-key rotate --print` with
  the current secret, which posts the new key, writes no file and prints the new
  `QORY_ACCESS_KEY_SECRET`; approves the new key in Settings › Access keys; within
  24 hours, puts the new secret in the fleet's secret store; then, optionally, ends the
  window. Instances sign with the old key until the store changes and with the new one
  after, and both keys verify throughout the window, so runs keep working. The order
  matters: an instance that signs with the new key before its approval is answered
  `key_pending` and does not run.
- **Revocation.** An owner or administrator revokes an access key in Settings › Access
  keys. Its requests then do not verify, `401`, from every machine that uses it, so the
  server seals nothing to it, and the runner reports the `401` as `unauthorized`. Its
  keys become tombstones.
- **Unused keys.** The server may revoke an access key unused for a period it sets; the
  machine then enrols again with a new key, since the old one is a tombstone.
- **What it protects, plainly.** The server stores public keys only, so reading its
  database no longer lets anyone act as an access key; writing to it could swap a public
  key, and the key row's integrity code stops that (Decision 6). The access key protects
  stored values against TLS-terminating middleboxes, logs and the server's stored
  answers. Approval is the control between a stolen enrolment code and the workspace:
  whoever uses the code enrols a key of their own, and every endpoint answers it
  `key_pending` until it is approved. Whoever holds an access key's secret is that key,
  on any machine, under any machine id.
- **The secret** is 32 bytes from the system's random source; the contract requires it.

**Keeping the secret from the agent.** An agent that reads the access key secret fetches
every value the server stores for that key.

- *Unwalled runs.* Once a server's signed discovery lists `secrets`, every run against it
  needs a wall: `server_needs_wall`, decided after the ping so the refusal reaches the
  server. Offline, a marker is the signal: when signed discovery lists `secrets`, `qory`
  writes an empty file `stored-secrets` next to `runner.yaml`, and while it exists `qory`
  refuses every unwalled run, `--local` included, with the same code,
  `server_needs_wall`; deleting the file restores unwalled runs. In 0.7.0 stored secrets
  go only to walled runs; a credentials broker is a later direction (Later: a
  credentials broker).
- *Mounts.* Every walled run, `--local` included, refuses a mount that is, contains or
  lies inside one of the runner's files, resolved through symbolic links:
  `mount_contains_runner_files`, with the path. The runner's files are:
  - the directory of `runner.yaml`, `access-key-secret` and `machine-id`, whether or not
    the runner file configures a server;
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
  low-order point; the server never meets one, because enrolment refuses an Ed25519 key
  of small order, and only such a key converts to a low-order u.
- **Elixir.** `:crypto` alone implements base mode for this suite. The sealer converts the
  access key's Ed25519 public key to its u-coordinate itself (Decision 4). `:crypto.compute_key`
  raises for a low-order point, because OpenSSL's `EVP_PKEY_derive` refuses an all-zero
  result; the sealer checks for an all-zero DH output itself all the same, for a defined
  error independent of the OpenSSL build. Every seal uses a fresh ephemeral key; a seam
  that fixes it exists for the known-answer test only and is compiled out of production
  builds; a test checks that two seals of one plaintext have different `enc`.
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
  `key_invalid`, and the fixture signing key as a pin and as its own key.
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

**The question.** Base mode authenticates no sender: anyone with the access key's public key
can seal. An earlier draft therefore put each value's routing inside the seal. Routing
now lives in the connections, inside the signed run configuration whose digest is in
`aad`.

**For keeping routing in the seal.** It binds each value to its hosts under the access
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
- an integrity code over each key row: its id, its public key, and during a rotation
  the new key that awaits approval, or after the approval the old key and the end of its
  window, the time the server received each of those keys, its workspace, its
  stored-secrets flag and when it was last enabled, its rate limits, its approval and
  whether it is revoked. The server stores no secret of the key, so reading the
  database no longer lets anyone act as an access key; writing to it could swap a public
  key for one of the writer's own, and the code stops that, as it stops a writer who
  moves a key to another workspace, enables stored secrets, approves a key or un-revokes
  one. Approval is always required, so there is no switch for a
  writer to turn off;
- the key row's code verified on every request, before the signature: a row whose
  code fails does not verify, `401`, unsigned, on every endpoint, so a writer cannot
  swap a key or un-revoke an access key for the GET or the events endpoint either;
- an integrity code over each enrolment code row: the code's SHA-256, its workspace, the
  settings the key will get, its expiry and who issued it, so a writer cannot insert a
  code that creates a key of its choosing;
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
  as a pin and as the server's key, in `APIARY_SIGNING_SECRET_NEXT` too, as the fixture
  access key secret is.
- **Rotating the server's key.**
  1. The operator sets `APIARY_SIGNING_SECRET_NEXT`. The current key keeps signing, and
     discovery and the enrolment answer list both public keys, current then next, so a
     machine enrolled now pins both.
  2. The operator adds the next public key to every other machine's pin out of band: in
     `runner.yaml`, the image or the CI variable. A pin is a list, so both fit. The
     runner never takes a key from discovery, because a stolen signing secret could
     otherwise make itself permanent.
  3. The switch: `APIARY_SIGNING_SECRET` takes the next value, and
     `APIARY_SIGNING_SECRET_NEXT` is unset.
  4. A code carries the fingerprint of the key that was signing when the code was made,
     and every outstanding code ends at the switch.
  5. A machine whose pin lacks the new key gets `answer_unsigned` until its pin is
     updated.
- The server signs every answer to a verified request with it, and every answer to an
  enrolment whose code it accepted: `X-Qory-Signature-Ed25519: <64 bytes, base64url>`,
  over the six lines of Signed answers. Every `401` is unsigned, wherever it falls, and
  so is a `400` before verification.
- The envelope gains `sig`, the 64-byte signature in base64url, over
  `lp32("qory envelope v1") ‖ lp32(suite) ‖ lp32(access_key_id) ‖ lp32(run_id) ‖
  lp32(run_configuration) ‖ lp32(exp in canonical decimal) ‖ lp32(enc, raw) ‖
  lp32(ct, raw)`, where `lp32` is a u32 big-endian length, then the bytes.
- The pin is `apiary_public_key` in `runner.yaml`'s `server` section, a list of public
  keys so the key can rotate. The runner takes the key from the pin only, never from
  discovery, and requires both: the signature on every answer, discovery, the run
  configuration, the secrets request, rotation and every event answer, treated as an
  unsigned answer when it fails (no run at start, a retry where today's rules retry);
  and the envelope's `sig`, verified before opening, `envelope_signature_invalid`. The
  pin is the machine's, so nothing on the wire can remove it.
- **Every machine needs the pin.** Every runner requires answer signatures, with no
  exemption (Decision 8), and only the server's key signs them, so the pin is required on
  every machine with a server, not only on access keys allowed stored secrets. A runner
  with a server and no pinned `apiary_public_key` is no run,
  `apiary_public_key_missing`, decided before the first request.
- **How a machine gets the pin.** Enrolment with a code installs it verifiably: the code
  carries the key's fingerprint, and `qory` writes the pin only after the signed answer
  verifies under that key. For a pasted key, Settings › Access keys shows the pin. The pin is
  a public key, so it needs no secret store: it comes through the runner file, baked into
  the machine's image, or through a plain CI variable, `QORY_APIARY_PUBLIC_KEY`, whose
  value is the same list as `apiary_public_key`, written as JSON: `[{"alg": "ed25519",
  "public_key": "<32 bytes, base64url>"}]`. `qory` takes the pin from the variable when
  the runner file's `server` section has no `apiary_public_key`, and refuses to start
  when both are set, so the pin has one source. `qory` removes the variable from its own
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
  signature under its pinned `apiary_public_key`, whatever the runner file contains.
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
  denies: [ANTHROPIC_BASE_URL, ANTHROPIC_BEDROCK_BASE_URL, ANTHROPIC_BEDROCK_MANTLE_BASE_URL,
           ANTHROPIC_VERTEX_BASE_URL, ANTHROPIC_FOUNDRY_BASE_URL, ANTHROPIC_AWS_BASE_URL,
           ANTHROPIC_CUSTOM_HEADERS, CLAUDE_CODE_USE_BEDROCK, CLAUDE_CODE_USE_VERTEX,
           CLAUDE_CODE_USE_FOUNDRY, CLAUDE_CODE_USE_ANTHROPIC_AWS, CLAUDE_CODE_SHELL,
           CLAUDE_CODE_SHELL_PREFIX, CLAUDE_ENV_FILE, CLAUDE_CONFIG_DIR,
           CLAUDE_CODE_CLIENT_CERT, CLAUDE_CODE_CLIENT_KEY, CLAUDE_CODE_CERT_STORE]
```

- **`denies`** lists variables the server may never set for the runtime; the runner leaves
  such a variable out and reports it (Decision 1). For Claude Code, each name is checked
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
  `wall.env`, `--env` and the harness's launch, contains a variable the run's runtime
  declares or reserves: `runtime_secret_conflict`. A server variable with such a name is
  left out and reported (Decision 1). For Claude Code these
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
  one leading `v`; `dev` never matches: `integration_version_mismatch`. This is a check
  for equality, not of identity: `describe` is the program's own report
  about itself. Trust in the program rests on `qory`'s path and ownership checks; matching by
  name and version is enough, and a program digest recorded at install is a later option.
- **Hosts** are `describe`'s `roles.credential.hosts`; a `*.` entry over a public suffix,
  the private section included, is `connection_host_public_suffix`. Scheme and paths come
  from the program's answer, `credential.schema.json`; a claim above the described hosts
  is refused, `integration_hosts_exceeded`.
- **What the hosts bound.** For an integration, the hosts bound only where the proxy sets
  the credential the program produces. The program runs outside the wall and receives
  the raw value, and where it sends that value is the program's. The server chooses
  `argument` and `settings`, which steer the program.
- **The machine's bounds.** An entry of `integrations:` may bound what a server chooses:
  `arguments`, an RE2 pattern the argument must match whole, else
  `integration_argument_not_allowed`; and `settings`, per member a fixed value or
  `{pattern: <RE2>}`, a member the bound does not list being refused,
  `integration_settings_not_allowed`. A server-sent integration connection that
  references a machine value needs both bounds: without an `arguments` bound it is no
  run, `integration_argument_not_allowed`, and without a `settings` bound its `settings`
  must be `{}`, else `integration_settings_not_allowed`. Before it writes standard input the runner also
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
 "secrets": {"url": "https://qory.example/v1/secrets"},
 "access_key": {"url": "https://qory.example/v1/access-key"},
 "apiary_public_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
```

`secrets` is optional, `{url}` with `run.url`'s grammar, listed only for an access key allowed
to receive stored secrets. `access_key`, the same shape, is where the runner posts a new
key (Rotation); it and `apiary_public_key` are listed for every verified access key, the key
for information: a runner takes the key from its pin only. `key_rotation_required: true`
is listed, beside `secrets`, for an access key whose key is older than its stored-secrets
flag (Decision 4). `run` is listed when the workspace has a policy, a connection or a
variable in force, its own or from a level above.

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
does not hold, get the workspace's baseline, as today. The
server stores a rendering, with its digest, per holder and variant. There are two
variants: the full rendering, and one with every connection that references a stored
value left out. The server picks the variant from the key row's stored-secrets flag
alone: the full one for an access key allowed stored secrets, the other for any other
key. No request member selects it, so a machine can never ask for the other one.
On every answer that carries them, the GET's and the events endpoint's alike,
`X-Qory-Run-Configuration` is the digest of the access key's variant, and
`X-Qory-Configuration` that of the discovery document for the access key and the key the
request verified under, so an access key without stored secrets reloads only when its own
variant changes. The variant without stored values lists what it left out in `withheld`,
by `id`, `kind` and `name`, and omits `withheld` when it left nothing out, so a holder
without stored-value connections has one rendering, and one digest, for both variants.
It keeps `connections`, even `[]`, whenever the full rendering has it, since an absent
member would put the runner file's connections in force. The runner
reports them in `policy_applied` as `connections_withheld`, and they raise no
`connection_needs_wall` or `secrets_endpoint_missing`. When leaving them out leaves a
required group of the run's runtime unmet, `runtime_secret_missing` applies as usual.

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
`reserves`, variable names; `denies`, variable names the server may never set for the
runtime; `credential_files`, paths, `~` for the runner's user's home.
Its `runtime` pattern becomes `^[a-z][a-z0-9-]{0,63}$`.

### Contract files the server vendors

All under `contracts/runner/v1`, so one pin covers them:

- `runtimes.json`, generated from the built-in descriptors and checked in CI against
  them: per runtime its `name`, a `title`, its `reserves`, its `denies`, its `credential_files`, its
  declarations with `id`, `title`, `name`, `hosts`, `auth` with its `header`, and `paths`, and its `one_of`
  groups with `id`, `required` and `of`;
- `denied-variables.json`, the built-in deny list of Decision 1, names and patterns;
- `headers.json`;
- `run-configuration.schema.json` and `policy.schema.json`, without `credentials`;
- `auth.schema.json`;
- `secrets-request.schema.json`, the secrets request's body;
  `secrets-answer.schema.json`, its answer, the envelope; `sealed-plaintext.schema.json`,
  the plaintext the envelope opens to; `enrolment.schema.json`, the enrolment's body and
  its answer, with `approved` and `stored_secrets` required; and
  `access-key.schema.json`, the rotation's body;
- `events/run.refused.schema.json` and `events/run.policy_applied.schema.json`, with
  `connections` and `uses`;
- `server.schema.json`, with `access_key_id` and the required `apiary_public_key` pin, and
  no secret.

### The access key and signed requests

§The server's identity and request signing are the access key's. The server document,
`server.schema.json` and `runner.yaml`'s `server` section, becomes:

```yaml
version: 1
url: https://qory.example
access_key_id: ak_f1xt0re000000000     # ak_ and 16 lower-case Crockford base32 characters
apiary_public_key:
  - {alg: ed25519, public_key: rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc}
```

The runner file's `machine` section is separate: `machine.name`, the optional display
name (Decision 4).

The access key secret lives outside this document: `qory` reads it from a file
descriptor, `QORY_ACCESS_KEY_SECRET` or `access-key-secret`, in that order (Decision 4),
and passes it through `session.Spec` with the machine id. `qory` takes `access_key_id`
from `QORY_ACCESS_KEY_ID` when the section has none, and refuses to start when both are
set, as for the pin.

- **On every request** `X-Qory-Access-Key-Id` carries the access key id and
  `X-Qory-Machine-Id` the machine id; `X-Qory-Machine-Name` carries the display name when
  the runner file sets one.
- **Every request is signed** with Ed25519 under the access key secret:
  `X-Qory-Signature-Ed25519: <64 bytes, base64url>`. The signed message is §The server's
  canonical string with three lines first: the domain line, the access key id and the
  machine id, exactly as the headers carry them. Lines are joined by `\n`, with no
  newline after the last:
  - a GET, with `X-Qory-Timestamp` as before: `qory-request-ed25519-v1`, the access key
    id, the machine id, the method in upper case, the request target exactly as sent, the
    timestamp as sent;
  - a POST: `qory-request-ed25519-v1`, the access key id, the machine id, `POST`, the
    request target exactly as sent, then the raw request body. A POST's signature covers
    its path and its body, so a body signed for one endpoint fails at every other; the
    secrets and rotation bodies contain a timestamp of their own.
- **Verification.** The server checks the access key id's shape, looks the key up,
  verifies the key row's integrity code (Decision 6), then builds the message from the
  two headers and verifies the signature under the stored public key, cofactorless
  (Decision 5). Every failure is `401` with `{"error":"unauthorized"}`, as §The server
  describes, a revoked key's request included; the runner reports it as `unauthorized`.
  After the `401`, a machine id outside `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` is `400`
  `bad_request`, signed. A request under a key that awaits approval verifies, and every
  signed endpoint answers it with a signed `409` `key_pending`, discovery and the events
  endpoint included (Decision 4). During a rotation's 24-hour window the server verifies
  under either key, except at `access_key.url`, which takes the current key only.
- **The machine id is never authorisation.** The seal, the variant and the rate bucket are
  per access key. The server records the machine id as reported, for display, audit and
  per-instance events, and anyone who holds the key can claim any machine id.
- **Unsigned headers.** The signature covers the access key id, the machine id, and the
  method, the target and the timestamp of a GET, or the method, the target and the body
  of a POST. `User-Agent`, `Content-Type`, `X-Qory-Contract-Version`,
  `X-Qory-Machine-Name`, `X-Qory-Delivery` and `X-Qory-Run-Configuration` are unsigned.
  The server decides nothing from them that the signed lines or body do not carry: the
  contract version only lets the server refuse a revision it does not implement, the
  display name is shown and nothing more, and the delivery id and the run-configuration
  digest of an events POST are hints the signed events repeat. `X-Qory-Access-Key-Id`
  selects the key the signature must verify under, and is signed as well.
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
signature; the code and the proof authenticate it:

```json
{"version": 1,
 "code": "qec_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg",
 "name": "build-01",
 "public_key": "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
 "timestamp": 1700000000,
 "proof": "<64 bytes, base64url>"}
```

- `code` is `qec_`, 26 Crockford base32 characters, 130 random bits, then `.` and the
  fingerprint of the server's public key (Decision 4). `qory` sends it, and the proof
  covers it, in its normalised form: the 26 characters in upper case, `I` and `L` read as
  `1`, `O` as `0`, and hyphens removed, so a person may type it in either case and in
  groups; `U` and every character outside Crockford's alphabet are refused, never
  mapped. The fingerprint is base64url and is never changed. The schema's pattern is
  `^qec_[0-9A-HJKMNP-TV-Z]{26}\.[A-Za-z0-9_-]{22}$`, so the server refuses a code not in
  normalised form, `400` `invalid_request`, and builds the proof's second line from the
  code as sent. Settings › Access keys may show a code in groups, `qec_F1XT-0RE0-…`, because
  `qory` normalises.
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
4. `401` for a code it did not issue, or that is used or expired, the whole code compared,
   fingerprint included; then `401` for a `timestamp` outside ±300 seconds. A used code
   passes this step for a retry with the same public key while the code is valid;
5. `429` per code;
6. `409` `key_invalid` or `key_revoked` for the key (Decision 4), then `409`
   `key_invalid` for a `proof` that does not verify;
7. `201`: the server creates the key row with the code's workspace and settings, the
   code is used, and the answer is

```json
{"version": 1, "access_key_id": "ak_f1xt0re000000000", "approved": false,
 "stored_secrets": false,
 "apiary_public_key": [{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
```

Steps 1 to 4 go out unsigned; from step 5 on every answer is signed as Signed answers
describes, line 3 being the request's `proof` exactly as sent. A retry still passes steps
5 and 6, so a key since rejected, revoked or retired is `409` `key_revoked`; it then
receives a `201` for the same access key, built afresh, with the server's current
`apiary_public_key` and `approved: false`, signed with the retry's own proof as line 3,
so a machine whose answer was lost still learns the key's id. Any other use of a used code is
`401`. `qory` verifies the answer under the key of
`apiary_public_key` whose fingerprint the code carries, and refuses an answer that lists
no such key or does not verify under it; only then does it write `access_key_id` and
`apiary_public_key`.

Known answers, under the fixture access key secret and the fixture signing key: the five
lines of the body above are 139 bytes, and `proof` is
`stcDcwasYMSLUxHX7A9AH-LXGRsRfpbHpMwGKd5ND6LI1WRsH10Rt4dhp8VmIYEau2sj31kCJSUzsDkSlCV8AQ`.
The answer above, without spaces, is 190 bytes, SHA-256
`106d9ddca5e1f8e624b902a0b975592a92f4a69c01238bbefd291b0611271517`; its six lines are 180
bytes, and `X-Qory-Signature-Ed25519` is
`yCgKNLXJxfaPS0yTNhHiwYbLrTPc09nYkuGBJX4COykQZEgd-NIjBGbo5s87fBJNYBZoRZxwlZK4joHgI4ZDBQ`.

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
verifies under the access key's current key only; the old key of an open window and the
pending key each get `401`. After the endpoint rules' order, the server refuses, in
order: a `timestamp` outside ±300 seconds, `401`; a new key while another awaits
approval, `409` `key_rotation_pending`, unless the request repeats that pending key with
a `proof` that verifies, which is answered as the first request was; a key the checks
refuse (Decision 4), `409` `key_invalid`; a key this access key already holds or
held, its current key, the old key of an open window or one of its own tombstones,
`409` `key_invalid`; a key another access key holds, `409` `key_invalid`; another
tombstone, `409` `key_revoked`; a `proof` that does not verify, `409` `key_invalid`. It
keeps the key as the access key's pending key, with the time it received it, and answers
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
   value id, and, for a superseded rendering, the holder's current rendering still references
   the pair through the same connection. Any other pair is left out, and the runner
   refuses the run, `secret_unresolved`. The value sealed is the current one;
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

A `410` here is no run; it never means the events endpoint's "stop". The runner checks
the envelope's identifiers against its own and `exp` against its clock, then builds
`info` and `aad` from its own values, never from the envelope's. The server keeps its own
record per access key and run id, with the reason for each value it left out; that
record is the server's, and nothing of it reaches the runner.

### Endpoint rules

For the enrolment path, `access_key.url` and `secrets.url`:

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
- **Order of refusals**, on every endpoint but enrolment (Enrolment has its own),
  discovery, the run-configuration GET and the events endpoint included: `413`; `415`;
  `400` `bad_request` for a header sent twice; `401`; `429`; `409` `key_pending`;
  `400` `unsupported_contract_version`; `400` `invalid_request` for a body that is not
  JSON, fails its schema, has another `version`, a `run_id` that is not a canonical
  lower-case UUID, a malformed digest or labels the labels' rules refuse; `401` for a
  `timestamp` outside ±300 seconds; then each endpoint's own. Every `401` is unsigned,
  wherever it falls; every other answer from `429` on is signed.
- **Rate limits** are the server's policy, per access key, never per machine id, and on
  the enrolment path per
  code and per source address. A `429` at run start is no
  run, `rate_limited`; an event POST's `429` is retried as today.
- **Answer headers.** Answers of these three endpoints contain neither digest header.
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
  `secret_sealed_invalid`. It never wraps that decoder's errors, nor the schema
  validator's, whose messages can quote input.

### Signed answers

Every answer to a request that verified, and every answer to an enrolment whose code the
server accepted, contains `X-Qory-Signature-Ed25519: <64 bytes, base64url>`, the Ed25519
signature under the server's signing key, `APIARY_SIGNING_SECRET` (Decision 6), of six
lines joined by `\n`, with no newline after the last:

1. `qory-answer-ed25519-v1`;
2. the status, three decimal digits;
3. the request's `X-Qory-Signature-Ed25519` value exactly as sent, or for an enrolment
   the body's `proof`;
4. the lower-case hex SHA-256 of the body as the server produced it, before any content
   coding, which for an empty body is the SHA-256 of the empty string;
5. the answer's `X-Qory-Configuration`, or empty when the answer has none;
6. the answer's `X-Qory-Run-Configuration`, or empty when the answer has none.

The server holds no secret shared with the access key, so this is the only answer
signature. The server signs in a hook that runs before the answer is sent, over every
answer to a verified request, `202`, `404` and `503` included. Every `401` goes out
unsigned, wherever it falls, and so does a `400`, `413` or `415` sent before
verification. Every signed answer contains `Cache-Control: no-store, no-transform`. Every
runner verifies the signature under its pinned `apiary_public_key`, so every machine
with a server needs the pin (Decision 6).
At run start the runner treats an answer without a valid signature as no run,
`answer_unsigned`. During the run an event answer without one is no answer, retried as
today, its headers unread; a reload's fetch without one fails the reload. A code in a
body is reported only from a signed answer; a refusal body over 64 KiB counts as
unsigned. The resend after a runner stops verifies signatures too. Line 3 binds the
answer to its request, and through the request's signature to the access key and the
machine id that sent it.
Ed25519 signatures are deterministic, so two identical GETs in one second share a request
signature and receive the same bytes. Two retries of one secrets POST share a request
signature too, and each answer seals afresh, so their bytes differ; either answer is
bound to that request, and a swap between them is harmless.

Two known answers under the fixture signing key, for the GET of discovery signed
`q7tv_FdWMid18PivX9Z3doioUEWHq1dRfB0cWDnVrxs5i1K0k6S7JB4269_m_JPT6PwXCCrZc-ndMIhN9ZjWCA`
under the fixture access key secret (The access key and signed requests):

- `200`; the discovery body as every verified access key's has it, 234 bytes:

  ```json
  {"version":1,"events":{"url":"https://qory.example/v1/events","types":["*"]},"access_key":{"url":"https://qory.example/v1/access-key"},"apiary_public_key":[{"alg":"ed25519","public_key":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]}
  ```

  SHA-256 `1698b8f76bcbe2cbfeeefdac4c157f4910c1624fd580ad9b6b93fa3aed61131b`;
  `X-Qory-Configuration: sha256=` and the same hex; no run-configuration digest. The six
  lines are 251 bytes:
  `X-Qory-Signature-Ed25519: AwfjyU3KGScM06nV8JTY321sAOGEga7dUjHkoKr2pr3Ie6OXs2PMN1ugfmAgbkTuWyXAVabFVp8cyE5D5Ig7CQ`
- `404`, empty body, no digest, 180 bytes:
  `X-Qory-Signature-Ed25519: NOGTucKY0qKpLV23wlSkyLthtXLrilzBrta6pDdFVKh6eykIboIapfBPWR4HmdtvCB2BIePL9GBrby0VSS8dDw`

### Coded refusals

After verification, `409`, `410` (`run_configuration_superseded`, `run_closed`), `429`,
`503` or `400`, `application/json`, signed: `{"error": "<code>", "names": ["…"]}`. Every
`401` is `{"error":"unauthorized"}`, unsigned, and the runner reports it as
`unauthorized`; `bad_request`, `413` and `415` are unsigned and reported by status only.

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
`credential`. A top-level `variables` reports the variables by name, never a value:

```json
"variables": {"names": ["APP_REGION", "NODE_ENV"],
              "overridden": ["NODE_ENV"],
              "locked": ["APP_REGION"],
              "denied": ["LD_PRELOAD"],
              "unwalled": []}
```

`names` lists the server's variables the run applies; `overridden` those, unlocked, whose
value a machine value replaced; `locked` those, locked, that kept the server's value
against a machine value; `denied` the server's variables left out: a denied name, a
reserved name, a placeholder's name, one a `secrets.local` value reads, or one the
runtime's `Prepare` or the harness sets; `unwalled` the server's variables an unwalled
run left out because `variables.unwalled` is `ignore`, in which case `names` is empty.
Each list is sorted and may be empty. A
top-level `connections_withheld` lists, by `id`, `kind` and `name`, the connections the
server left out of the variant for an access key without stored secrets (The run
configuration), and is empty otherwise. With no
`security_policy`, `url` and `run_configuration` are allowed beside `source` `config` or
`none`. No event contains a value.

## Runner behaviour

Order at run start; the steps not listed are §Sequence's.

1. With a server: validate the server document; without a pinned `apiary_public_key`,
   `apiary_public_key_missing`, before any request. Every request is signed with the
   access key secret. Every answer's signature is verified under the pin before its body or
   headers are read.
2. Discovery: a signed `409` `key_pending` is no run, `key_pending`; a `401` is
   no run, `unauthorized`. Ping. When discovery lists `secrets` and the run has no wall:
   `server_needs_wall`. When it lists `secrets`, or `key_rotation_required`, the runner
   reports that to its caller, and `qory` writes the `stored-secrets` marker and, for
   `key_rotation_required` with a file-held secret, rotates; otherwise it reports that
   the operator rotates (Decision 4).
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
    runner's own, the placeholders, and the runtime's other declared and reserved
    variables as empty.
12. `dev.qory.run.started`, then `dev.qory.run.policy_applied`.

Every no-run after an accepted ping, at steps 2 to 11, emits `dev.qory.run.refused` as
the run's last event, a tool or an integration that does not start included. The caller
receives the error in every case, with or without a ping. Values live in the runner's memory only, never
on disk, in the environment, an event, a log line, an error or a report; at run end they
are unreferenced, since Go cannot wipe a string.

## Refusal codes

| Code | Decided by | When |
|---|---|---|
| `bad_request` | server, `400` | a header sent twice, unsigned; after verification, a machine id outside its pattern, signed |
| `unsupported_contract_version` | server, `400` | `X-Qory-Contract-Version` other than `1` |
| `invalid_request` | server, `400` | a body that is not JSON, fails its schema or has an unknown member; labels the contract refuses |
| `rate_limited` | server, `429` | the access key's rate, or the enrolment path's, is exceeded |
| `unavailable` | server, `503` | a stored rendering fails its integrity code, on the GET or the secrets request; a failing key row is `401` |
| `key_invalid` | server, `409` | at enrolment, paste or rotation: a public key that is not a canonical encoding of a point on the curve, is of small order or not of prime order, has y = 1, is the published fixture access key or, a key another access key holds; at rotation, a key this access key holds or held: its current key, the old key of an open window or one of its own tombstones; or a proof of possession that does not verify |
| `key_revoked` | server, `409` | at enrolment, paste or rotation: the public key is a tombstone, whether it was retired by revocation, rotation or rejection; at rotation, another access key's |
| `key_pending` | server, `409` | on every signed endpoint, discovery and events included, after `429`: a request under an access key, or a new key of it, that awaits approval |
| `key_rotation_pending` | server, `409` | a rotation while another new key awaits approval |
| `key_rotation_required` | server, `409` | the secrets request under a key the server received before the access key's stored-secrets flag was last enabled |
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
| `server_needs_wall` | runner, and `qory` offline | discovery lists `secrets` and the run has no wall; or, decided by `qory`, an unwalled run, `--local` included, while the `stored-secrets` marker exists |
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
| A read of the server's database | Values encrypted under a key derived from the instance key; the server stores access keys' public keys only, so reading the database no longer lets anyone act as an access key | A reader with the instance key reads every stored value and, while `APIARY_SIGNING_SECRET` is unset, signs as the server |
| A write to the server's database | Integrity codes over connections, custom definitions, every rendering, every key row and every enrolment code, with a per-row version, verified on every request and before sealing: a writer cannot swap an access key's public key, move a machine to another workspace, enable stored secrets, insert a code, or insert or approve a machine; seals taken from the verified rendering's bytes; audit | A writer with the instance key, or a change through the server's own pages |
| A compromised server or operator | — | It reads every stored value, routes it, chooses an integration's argument and settings, sends an observe-everything policy, and learns which `secrets.local` names exist from `secret_unresolved`. The machine's `hosts` bounds, its `arguments` and `settings` bounds, both required for a server-sent integration with a machine value, and the pin, required on every machine, are what remain |
| A workspace administrator, or anyone who may save a custom service and link a secret | In 0.7.0 only owners and administrators may: linking needs `secret.use` on the secret, which only they hold, and only they define custom services, edit variables and enable stored secrets on a machine | Choosing the host is reading the value |
| Whoever may edit variables | Only owners and administrators; an unwalled run receives no server variable unless the machine sets `variables.unwalled: accept`; the deny list, the runtime's `denies` and the machine's `variables.deny` leave out what would run code, move a credential or change trust | With `accept`, the deny list matters for unwalled runs, and it cannot be complete |
| A holder of an access key secret, on the path | Every runner pins the server's key, so it forges no answer and no envelope; routing is bound to the document | It signs requests as that key, under any machine id, and opens what is sealed to it, as the next rows say |
| A machine claiming another machine's id | — | Nothing: the machine id is never authorisation, and anyone who holds the key can claim any machine id. It serves display, audit and per-instance events only |
| A holder of the server's signing secret, on the path | Routing is bound to the document, so real values never go to a host it chooses; it holds no access key secret | It forges documents and seals values of its own choosing to every machine that pins the key, until the key is rotated and the pins with it |
| A link removed while a run starts | A superseded rendering seals only what the current rendering still references through the same connection | — |
| Another runtime's credential | The secrets request lists one runtime connection, the run's own; the server seals nothing for any other | — |
| A server that sends a machine value elsewhere | The machine's own `hosts` on each `secrets.local` entry: `secret_hosts_exceeded` | — |
| A machine, choosing labels | Labels resolve only within the access key's workspace | Repository scope is no boundary against a machine: an access key is scoped to its workspace |
| An access key secret an unwalled agent read before stored secrets were enabled | Enabling the flag forces a rotation: the server seals only to a key it received after it, `key_rotation_required`; enabling it tombstones a pending key; `qory` writes the `stored-secrets` marker before it generates the new key | A pasted key generated before the flag and pasted after it; the owner pastes a key generated for the purpose |
| A stolen enrolment code | Single use, valid for minutes, bound to one workspace and one key's settings; until an owner or administrator approves the key, after comparing fingerprints, every endpoint answers it `key_pending`: no discovery, no run configuration, no variable, no stored value, no event accepted | An approval given without comparing the fingerprint |
| A stolen access key secret | Stored secrets only for access keys allowed them; revocation, which cuts off every machine using the key; rotation under the current key only, whose new key needs approval after comparing its fingerprint; a second rotation refused while one is pending; the recomputed digest binds values to the document the server rendered | Whoever has it is the access key, on any machine, and receives the stored values sealed to it until it is revoked. Base mode has no forward secrecy: with recorded traffic or the server's logs, the secret opens every past payload sealed to it, so access keys are rotated |
| A member of the machine's `docker` group | — | It is root on the machine, with every file and process of the runner |
| Whoever chooses a run's labels, such as a repository's workflow file | — | Labels select the holder, and so whose connections and credentials the run receives |
| An agent reading the machine's configuration, or replacing a program the runner starts | `server_needs_wall`; `qory` refusing unwalled runs while `stored-secrets` exists; `mount_contains_runner_files`; `QORY_ACCESS_KEY_SECRET` and `secrets.local` sources refused in the enclosure | An unwalled agent of the same user outside `qory` (Issues, item 4) |
| A model credential reaching the enclosure | `runtime_secret_conflict`; the runtime's other declared and reserved variables set to empty; `mount_contains_credential_files` | A credential file baked into the image |
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
  refuses an enrolment answer that does not verify under the key the code's fingerprint
  names; every signed endpoint, discovery and events included, answers an access key, or
  a new key of it, that awaits approval with a signed `409` `key_pending`; rotation promotes
  `access-key-secret.next` only after a signed `200` to a request under the new key; the
  old key verifies for 24 hours after the approval whatever requests the new key signs,
  and not after, unless an administrator ends the window earlier; a POST signed for one
  path fails at another, and a request whose access key id or machine id line differs
  from its headers fails to verify.
- **Access keys and machines:** two instances on one key with different machine ids both
  run, and the server records both ids; `qory` keeps the machine id in `machine-id` when
  the directory is writable and generates a fresh one per process when not; a machine
  id outside its pattern is `400` `bad_request` after verification; past 256 distinct
  ids in 24 hours the answers are unchanged and no new machine record appears; a public
  key another access key holds, or held, is refused at enrolment, paste and rotation;
  revoking a key cuts off every instance using it.
- **Key checks and enrolment:** enrolment, paste and rotation each refuse the torsion
  key of Decision 5, `key_invalid`; a base64url value with padding, a `+` or `/`,
  or non-zero spare bits is refused; enrolment answers in its own order, with every
  `401` unsigned; a code typed in lower case or with hyphens normalises to the published
  fixture code, and the server refuses a code outside the pattern, `U` included; a retry
  with the same code and key gets a `201` for the same access key, built afresh, unless
  the key has since been retired; the old key's and the pending key's rotation requests
  are `401`, a rotation posting a key the access key holds or held is `key_invalid`, a
  second rotation while one is pending is `key_rotation_pending`, and a rejected key becomes a tombstone.
- **Stored secrets enabled later:** the secrets request under a key the server received
  before the flag is `key_rotation_required`, even when that key was approved after it;
  enabling the flag tombstones a pending key; discovery lists `key_rotation_required` to
  the current key only and only while no eligible key is pending; `qory` writes the
  marker before it generates the new key, and rotates by itself only from a file; during
  a window the server seals to the key the request verified under, and a reseal under
  the other key is `run_secrets_conflict`.
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
  again; a machine value replaces an unlocked variable and yields to a locked one, each
  reported in `policy_applied`; every entry of the built-in deny list, in
  upper and lower case, and a name from `variables.deny`, is left out and reported, a
  locked one included, and the run starts; a name from the runtime's `denies` is left
  out the same way; a name the runtime's `Prepare` sets wins over a locked variable,
  which is reported in `denied`; a `QORY_` variable or a `secrets.local` source passed
  into the enclosure from the run's environment is `variable_reserved`, and
  `QORY_RUN_ID` and `QORY_RUN_SOCKET` pass.
- **Public roots:** a proxy test with a host whose certificate chains only to an
  authority the test adds to the machine's trust store: with `tls.public_roots_only`
  unset or `true`, a stored value is never sent there and `dev.qory.run.egress` records
  `dial_failed` with `wall:public-roots`; with `false`, the host receives it; a machine
  value reaches that host under either setting.
- **Mounts:** a walled run refuses a mount of `runner.yaml`'s directory, with or without
  a server, of an integration program, a tool program, a `secrets.local` file and
  `~/.claude/.credentials.json`, each through a symbolic link too.

## Setting up a machine

What a machine's owner sets up and meets in 0.7.0:

- Connections decide every credential a run sends; the policy has no `credentials`. The
  runner file has `connections:`, `secrets.providers`, `secrets.local`,
  `variables.deny`, `variables.unwalled` and `machine.name`.
- A run configuration may contain `connections` and `variables`, and may omit
  `security_policy`. Each variable has a value and `locked`; a machine value replaces an
  unlocked one, a locked one keeps the server's value, and a denied one is left out. An
  unwalled run receives the server's variables only with `variables.unwalled: accept`.
  `dev.qory.run.policy_applied` reports each by name.
- A machine runs with an access key: one secret, `access-key-secret` or
  `QORY_ACCESS_KEY_SECRET`, an Ed25519 key that signs its requests and, converted to
  X25519, opens the values sealed to it; a fleet may share one key. The server stores
  only the public key. `qory access-key enrol` enrols a key with a code;
  `qory access-key create` prints a public key to paste into Settings › Access keys;
  `qory access-key rotate` replaces the key and keeps the access key id; the old key stays
  valid for 24 hours after the approval, or until an administrator ends that window.
  Enabling stored secrets on a key requires a new key, which `qory` creates itself from a
  file-held secret; the operator of a shared key rotates it with `--print`.
- Each instance has a machine id, kept in `machine-id` when it can be, for display and
  audit; the server's Machines page lists the instances of each key.
- An access key, and every new key of it, needs approval; until then every endpoint
  answers it `key_pending`. Stored values are sealed to an approved key and fetched from
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
    answers are the Ed25519 ones of Wire format. Every receiver, the reference receiver included,
    verifies Ed25519 requests and signs its answers with a key of its own.
20. **Enrolment, the pasted key and rotation are `qory` commands**, `qory access-key enrol`,
    `qory access-key create` and `qory access-key rotate`, with the `stored-secrets`
    marker and the `machine-id` file; the runner module takes the access key secret and
    the machine id through `session.Spec` and writes nothing.
21. **Where the setter is tied to the routing.** A broker (Later: a credentials broker)
    replaces who sets a value. Today the following sit with the runner on the agent's
    machine and would move with it: the seal opens with the access key secret, which also
    signs the runner's requests, so a machine that holds it can fetch every stored value;
    `connection_needs_wall` and `server_needs_wall` require the runner's wall for any
    connection or stored value; an integration program runs on the machine, outside the
    wall, and receives raw values; `hosts_denied` and `uses` come from the proxy's own
    decision function; and the proxy applies `tls.public_roots_only`, port 443 only and
    the refusal of `TRACE` and `TRACK`.
