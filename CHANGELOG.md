# Changelog

Every release of Forager, newest first, in the shape of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 a minor
release may change what an existing document does, and says so under Upgrading.

## [Unreleased]

### Core and contract

#### Upgrading

- A configuration document whose `run.url` contains `qak_` or `qrk_` in any case is
  refused: `server.Client.Discover` returns a `*server.DocumentError`, and no run
  starts. Before, the document was read and `run.policy_applied` sent `run.url` as it
  was.
- Set `HOME` in the image, as `ENV HOME`, if a run set it through the server's
  variables, `--env`, `wall.env` or the harness's defaults: the session now leaves that
  value out. A run that set `NODE_OPTIONS`, `LD_PRELOAD` or `BASH_ENV` that way gets
  no value for them from those sources either, and a sealed credential needs another
  placeholder than one of the four.
- Return an empty digest from a `receiver.Handler.RunConfiguration` hook, or `sha256=`
  and the lower-case hex SHA-256 of the document's bytes. The reference receiver
  computes the digest itself. For any other digest from the hook, it answers a signed
  `500` in place of the registration's, the attach's or the reload's answer, and no
  digest on a batch's answer. Before, the receiver served the hook's digest as it was.
- A walled run whose gateway holds credentials for it, and whose runtime's descriptor
  lists model keys in `model.keys`, needs a model key: without a model key from the
  control plane or forager.yaml, and without a value of a model key's variable from the
  run, the machine, the harness, the runtime's preparation or what the run inherits, it
  is `model_key_missing`. A setup whose walled Claude Code run has only a forge
  credential and finds its model key in a mount, the image, its settings or a login
  inside the run now stops: pass the key in the machine's variables, or define a model
  key in forager.yaml. A run whose run answer has no `credential_hosts` starts as
  before.
- Rewrite a forager.yaml model credential as a model key: replace `hosts`, `paths` and
  `placeholders` with `format` and `endpoint`, such as `{env: MODEL_API_KEY, format:
  anthropic-messages, endpoint: https://api.anthropic.com, auth: {scheme: bearer,
  oauth: true}}`. A credential without `format` whose `placeholders` list a variable the
  runtime reads a model key from, such as `ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`, now stops the run, `run_configuration_invalid`.
- A placeholder of the machine's credentials or tools that the runtime's descriptor
  denies, lists in its model `overrides` or reads its model endpoint from, such as
  `CLAUDE_CONFIG_DIR` or `ANTHROPIC_MODEL` for Claude Code, now stops the run,
  `run_configuration_invalid`, and so does a tool's placeholder in a variable the
  runtime reads a model key from, such as `ANTHROPIC_API_KEY`. Remove the placeholder
  from forager.yaml.
- `runtimes.json`: the claude runtime's `reserves`, `declares` and `one_of` are `[]`,
  and its `model` has `keys`, the three variables Claude Code reads a model key from:
  `ANTHROPIC_API_KEY` for the header `x-api-key`, `ANTHROPIC_AUTH_TOKEN` for a bearer,
  and `CLAUDE_CODE_OAUTH_TOKEN` for a bearer with `oauth`. A server that offered a
  runtime's declarations to choose a model key reads `model.keys` instead.
- `dev.qory.run.refused` and the link's batches take the code `model_key_missing`, and
  the session's `dev.qory.run.policy_applied` may have `credential_variables`. A
  separate gateway older than the session refuses both: upgrade the gateway first.
- A run without a wall whose policy selects credentials now starts, and the gateway
  sets the credentials: before, it was `wall_required`. The agent's environment gets
  each credential's placeholder, and the run trusts the gateway through `ca-bundle.pem`
  in the run directory (Session, Added). A run without a wall on a machine with none of
  `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
  `/etc/ssl/ca-bundle.pem` and `/etc/ssl/cert.pem` now stops when the gateway gives it
  an authority: install a CA bundle at one of those paths. Without a wall, the agent
  can read every credential the machine already holds; run a brokered run on a machine
  that holds none.
- A run without a wall whose gateway holds credentials for it now gets the rules a
  walled run gets: the start key's variable and endpoint, the endpoint rule and
  `credential_variables` in `dev.qory.run.policy_applied`. A Claude Code run without a
  wall and without a model key starts, and Claude Code can use the machine's Claude
  login.

#### Added

- A descriptor's `model` may list `keys`, 1 to 32 variables the runtime reads a model
  key from, each `{format, auth, variable}`. The session refuses a descriptor whose key
  is read from `HOME`, `LD_PRELOAD`, `NODE_OPTIONS` or `BASH_ENV` in any letter case,
  whose format is not in `formats`, whose pair of format and auth appears twice, whose
  variable is in `denies` or `overrides` or is the endpoint's variable, or whose
  variable has another auth in `secrets.declares`. A `secrets.declares` name may not be one of those four
  variables either. The Claude Code descriptor lists `ANTHROPIC_API_KEY`,
  `ANTHROPIC_AUTH_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN`, and `runtimes.json` lists them.
- `auth.schema.json` has `oauth`, `true` and beside `bearer` alone: the value is an
  OAuth token, such as a Claude subscription login's. The proxy sets it as any bearer,
  and the session reads it to pick the runtime's variable.
- The session gives the start key, the model key the runtime starts with, to the
  runtime: of the descriptor's `model.keys`, the key whose format is the start key's
  and whose auth has its scheme, its header's name, case ignored, and its `oauth`. The
  key's variable is set to the start key's placeholder and joins the start key's
  placeholders and the run's, so a value the run passes for it is
  `placeholder_conflict`. The session sets the runtime's model endpoint variable,
  `ANTHROPIC_BASE_URL` for Claude Code, to the start key's endpoint, and leaves out
  every other value of it as `fixed`. The runtime's other model-key variables get no
  value: one from any source, the inherited environment included, is left out as
  `fixed`, and behind a wall the name is unset inside. A descriptor without a `model` section, a format
  it lists no key for, and an auth no key of that format has are
  `run_configuration_invalid`.
- A model key's placeholder contains its name: `qory-`, the name and
  `-sets-the-credential-outside-the-enclosure`, such as
  `qory-model-sets-the-credential-outside-the-enclosure`, `link.KeyPlaceholder` in Go.
  It ends as the stand-in does, so Claude Code's approval script covers it.
- A placeholder goes only into a variable for a credential. The session refuses,
  `run_configuration_invalid`, a placeholder of a host credential from the server that
  the runtime's descriptor denies, lists in its model `overrides` or `reserves`, reads
  its model `endpoint` from or reads a model key from; a host credential of the
  machine's with a model key's variable among its placeholders; and one of the run
  answer's `placeholders` that the descriptor denies, overrides or reads its endpoint
  or a model key from, or that the runtime declares or reserves and no credential has.
  A tool's placeholder, such as `GITHUB_TOKEN`, passes.
- The link's run answer's `credential_hosts` has `auth` for a credential from the
  server and for a model key of the machine's, and `format` and `endpoint` for a model
  key from either. The run answer has `model_credential`, the start key's name.
  `server.LinkCredentialHosts` has `Auth`, `Format` and `Endpoint`, and
  `server.LinkRunAnswer` has `ModelCredential`.
- `dev.qory.run.policy_applied`: behind a wall `credential_variables` lists the
  variable each credential's placeholder is in, `{credential, name}`, with a name's
  phrase in place of a credential's name or a variable that contains `qak_` or `qrk_`.
  The gateway leaves `credential_variables`
  out of the members it matches.
- The refusal `model_key_missing`, in `refusal.Decides`: a run whose run answer has
  `credential_hosts`, behind a wall or, without one, with a credential whose placeholder
  is a model key's variable, whose runtime's `model` section has `keys`, and that has
  no model key, as the contract's §Variables, A model key, says. Its names are the
  model keys' variables.

- The link's run answer has `credential_hosts`: the hosts and placeholders of each
  credential the gateway holds for the run, so the session can tell which hosts the run's
  credentials cover. `server.LinkRunAnswer.CredentialHosts` contains it, and is empty for
  a gateway that sends none.
- `api-format.schema.json`, the fixed list of model API formats: `anthropic-messages`,
  `openai-responses`, `openai-chat` and `gemini`. A schema that uses the list refers to
  the whole file with `$ref`.
- A runtime descriptor may have `model`: the API formats the runtime sends, and where a
  composer writes a run's model id, effort value and model endpoint, each in a flag, a
  setting or a variable, the endpoint in a variable only. The Claude Code descriptor
  has one, and `runtimes.json` lists it. In Go, a described runtime implements
  `runtimes.Model`, whose `Model` method returns the section.
- A descriptor's `model` may list `overrides`, the variables that would override the
  model id or effort value a composer writes. Behind a wall the session leaves out the
  server's, the run's, the machine's and the harness's value of each, the harness's
  computed value included, records it as `denied`, and unsets the name inside when
  nothing else sets it; without a wall nothing changes. The Claude Code descriptor
  lists 12, among them `ANTHROPIC_MODEL` and `CLAUDE_CODE_EFFORT_LEVEL`.
- `server.ShownLabels` and `server.ShownAbout`: a run's labels and what it is about as
  Forager sends them to Qory Apiary. A label's key or value, and `about`'s `kind`,
  `title` and a subject's `title`, that contains `qak_` or `qrk_` in any case is `(a
  name that contains an access key secret)`, or `(a name that contains a run key)` when
  it contains `qrk_` and no `qak_`. Of two labels whose keys become the same phrase, the
  one whose key sorts first is kept. A subject whose `type` or `ref` contains a prefix
  is left out, and so is a subject's `url` that contains one. In `details`, a string is
  `(a value that contains …)` and a member name the name's phrase; of two members whose
  names become the same, the first is kept, and details that grow past 8192 bytes are
  left out. `accesskey.ShownError` takes nil and returns it.

- `dev.qory.run.started` has `preparation`, the run's preparation as the caller gave it,
  when the run has one.
- The server's variables may set `QORY_RUN_SYSTEM` and `QORY_RUN_REPOSITORIES`, the
  system and the repositories a run's preparation may use: the built-in `QORY_*` deny
  entry leaves the server's values of these two names in, by these names exactly. Set
  by any other source, they stay reserved as any `QORY_` name.
- `dev.qory.run.policy_applied` has `ceiling_paths`: the path rules of each ceiling a
  run's policy file was put under with `gateway.Policy.Under`, by host, one object per
  ceiling that has any. The link's `applied` carries it too.
- A policy's `image` may name an image by its reference pinned by digest,
  `NAME@sha256:` and 64 lower-case hexadecimal digits, as well as select one of the
  machine's by name. A reference with a tag, without a digest or in upper case is
  `run_configuration_invalid`, in a node's policy file and in a run configuration alike.
  `policy.CheckImage`, `policy.CheckImagePrefix` and `policy.ImageAllowed` hold the
  grammar and the prefix rule.
- `policy.EndpointHost` reads the host of an `https` base URL, such as
  `ANTHROPIC_BASE_URL`'s value, in the form `policy.Host` gives. `policy.CredentialFor`
  reports whether a credential's hosts are for a host, by the rule the gateway's proxy
  picks a request's credential by.
- A run configuration's `image`: the image a run starts in, named by digest beside its
  `security_policy` and run only under the machine's `images.allow`.
- The refusals `image_not_allowed`, a reference under none of the machine's
  `images.allow` prefixes, and `image_user_root`, an image whose user is root, both in
  `refusal.Decides`.
- `dev.qory.run.started` has `image_fetch_ms`, how long the wall took to find an image by
  reference: its fetch included unless the engine holds it by that digest.
- The link's run request has `images.allow`; its answer has `relay_image`, the image the
  relay starts from, and `reference: true` on an `image` the policy names by reference.
- A run configuration's `credentials`: at most 8 credentials whose values the server
  stores for the run, with no value. An API credential, a model key, is `{name,
  format, endpoint, auth, key_prefixes}`: the gateway sets its value on every path of
  the endpoint's host alone. `endpoint` is `https`, with a host, an optional port and
  path, and no user, query or fragment. A host credential is `{name, hosts, paths,
  auth, placeholders}`, with exact hosts. Forager checks the member against
  `run-configuration.schema.json`, and refuses a name twice, an `auth.header` that
  frames the request or that the proxy sets, a placeholder that
  `denied-variables.json` covers, and an endpoint from which `policy.EndpointHost`
  reads no host, each `run_configuration_invalid`. `server.RunCredential` has `Format`,
  `Endpoint` and `KeyPrefixes`, and `Applies` returns the hosts and paths a value is
  set on.
- `key_prefixes`, on an API credential, optional: 1 to 4 literal prefixes, each 1 to 32
  characters of printable ASCII without a space. The gateway refuses a stored value
  that starts with none of them, `run_configuration_invalid`, without printing the
  value.
- A run configuration's `model_credential`: the name of the start key, the model key
  the runtime starts with, an API credential of `credentials` or a model key of the
  machine's. A run with two or more model keys, the server's and the machine's
  together, needs it; with one, that one is the start key. A name of a host
  credential, of no model key of the run, and none beside two or more model keys are
  `run_configuration_invalid`. A reload that names another fails, and the policy in
  force stays. A reload whose start key differs from the run's fails too, with or
  without `model_credential`: `start a new run to change the model key it starts
  with`. `server.RunConfiguration` has `ModelCredential`, and
  `server.CheckCredentials` takes it.
- The gateway sets a run configuration's `credentials`, with or without a wall. When the run
  starts it sends one secrets request under the access key, for the digest it computes of
  the document's bytes, opens the answer with `sealed.Open`, and the proxy sets each value
  in place of a credential of the machine's that claims one of its hosts, of the same
  name or another. Without `secrets` in discovery, with a fixture pin or access
  key, or with a value a header cannot hold, it is `run_configuration_invalid`. A reload with other `credentials` fails, and the policy
  in force stays. A `TRACE` or `TRACK` to a host that gets one is denied with the rule
  `wall:echo-method`. A run configuration without `credentials` runs as before.
- The secrets request, `secrets-request.schema.json`, a signed `POST` to discovery's
  `secrets.url` for the values of a run configuration's `credentials`; its answer, the
  envelope of `secrets-answer.schema.json`, sealed with HPKE base mode, X25519,
  HKDF-SHA256 and AES-256-GCM, to the access key and signed under the server's key; and
  the plaintext it opens to, `sealed-plaintext.schema.json`. `fixtures/sealed/` contains a
  sealed answer with its vectors and an envelope refused at each step.
- The reference receiver serves the secrets endpoint, at `receiver.DefaultSecretsPath`,
  `/v1/secrets`, or `Handler.SecretsPath`, when the hook `Handler.Secrets` is set:
  `func(run receiver.Run, credentials []string) (values [][]byte, refusal
  *receiver.Refusal)`, one value for each credential of the run configuration in force.
  It seals the values to the access key the request verified under with `sealed.Seal`,
  signs the answer under the receiver's key and overwrites the values with zeros; it
  logs and stores none. `receiver.AccessKey.StoredSecrets` allows a key stored secrets,
  and discovery lists the configuration's `secrets` for such a key alone. A request is
  refused in the contract's order, then as a reload of the run would be; a digest that
  is not the one in force, or not one the run was answered with, is a signed `410`
  `run_configuration_superseded`, and a `credentials` list other than the run
  configuration's names in its order a signed `409` `credentials_differ`.
  `receiver.MaxSecretsBody` is the bound of a request's body, 32 KiB.
- Package `sealed`: `sealed.Open` checks a secrets answer in the contract's order and
  opens it with an access key, returning the values by credential name as bytes that
  `Values.Clear` overwrites. A `Values`, a `Value` or a `Sealing` prints no value with
  any format verb, also as a field of a struct printed by reflection; `sealed.Seal`
  seals and signs an answer, for a receiver and the tests. Each refusal is one of the
  package's errors, and no error contains a value.

#### Changed

- `wall_required` has the names `tools`, `paths` and `image=<name>`, never
  `credentials`. Its message for tools and path rules reads "run it with a wall: the
  policy selects tools or has path rules, and without a wall a program that ignores
  the proxy is bound by neither". The run answer's `certificate_authority` is present
  with or without a wall, whenever the gateway reads inside HTTPS for the run, and
  always with a server. The `wall:` rules of `dev.qory.run.egress` keep their names,
  and `wall:echo-method` and `wall:ambiguous-path` now appear in the records of runs
  without a wall too.
- The built-in deny list, `denied-variables.json`, has `NODE_OPTIONS`, `LD_PRELOAD`,
  `BASH_ENV` and `HOME`. A value of one of them from the server, the run, the machine,
  the harness's defaults or the harness's computed values is left out and recorded as
  `denied`; the value the run inherits applies. A run configuration's credential with
  one of them as a placeholder is `run_configuration_invalid`.
- Behind a wall, the session keeps a value of the runtime's model endpoint variable,
  `ANTHROPIC_BASE_URL` for Claude Code, of the server, the run, the machine or the
  harness's defaults, when its host is a host of the run's model credential in the
  run answer's `credential_hosts`, and leaves any other value out in place of the
  runtime's `denies`. The harness's computed value of it, which reached the runtime
  whatever its host, is left out too when uncovered. The value the run inherits is not
  checked. `dev.qory.run.policy_applied`'s `variables` records a kept value with
  `kept`, and a value left out as `endpoint_uncovered` or `endpoint_unreadable`.
  Without a wall nothing changes. In a run with a start key, the session sets the
  variable to the start key's endpoint instead, and the endpoint rule does not apply.
- A run configuration's digest, `X-Qory-Run-Configuration`, is `sha256=` and the
  lower-case hex SHA-256 of the exact bytes of the document as the server sends it; the
  contract called it opaque before.
- The registration bodies, `server.Registration.Body` and
  `server.GatewayRegistration.Body`, send the labels and about as `server.ShownLabels`
  and `server.ShownAbout` give them, and so do `run.started` and the gateway's
  `run.registered`. A separate gateway's selection reads the labels the attach answers
  with, so a label value that contains `qak_` or `qrk_` gives no credential argument
  (Gateway, Upgrading). `run.started.schema.json` admits the two name phrases as a
  label's key, and `server.CheckLabels` takes them. The reference receiver keeps a
  registration's labels and about as the two functions give them, and answers an
  attach with that copy. `server.ShownAbout` keeps `details` byte for byte when no
  string or member name in them contains a prefix, and the receiver keeps an about
  without a prefix as the body has it.

- `server.Client.Discover` refuses a configuration document whose `run.url` contains
  `qak_` or `qrk_` in any case, as a document the schema refuses: `run.policy_applied`
  sends `run.url` as a URI, and no phrase is one.

- The Claude Code descriptor declares no secret and requires none: its `secrets` have
  no `declares` and no `one_of` group, and in `runtimes.json` its `declares` and
  `one_of` are `[]`, no longer `api_key` and `oauth_token` and the required group
  `model_key` of both. Its model keys are in `model.keys`, and the run's model key is a
  model key from the server or the machine. A descriptor may still define `declares`
  and `one_of` groups.
- Enrolment: an access key can belong to an adapter, `node_kind` `adapter` with an
  `na_` id.
- Enrolment: an enrolment code's prefix names the kind of key it enrols, `qecn_` a
  node's, `qecp_` a node pool's, `qecg_` a gateway's and `qeci_` an integration's
  (node_kind `adapter`), in place of `qec_`, which is refused. `accesskey.CodeKind`
  reads the kind, and `EnrolmentRequest.VerifyAnswer` refuses a `201` of another kind
  with an `accesskey.KindError`.
- A new instance id is `i_` and 26 lower-case Crockford base32 characters, no longer 22
  base64url characters, so it can no longer contain an access key's or a run key's
  prefix by chance.
- The `credentials` merge row: behind a separate gateway, a walled run gets the
  gateway's selection when the server's selects none.
- `dev.qory.run.policy_applied`'s `credentials` carry, as the argument, the value of the
  run's label a gateway's selection took it from.

#### Fixed

- The server package printed a value as written in these messages, and now prints `(a
  value that contains an access key secret)` or `(a value that contains a run key)` in
  place of a value that contains `qak_` or `qrk_` in any case: a server document's name
  and error; a URL in a request's or an answer's error, and the transport's error; the
  decoder's and the schema's error of a document Qory Apiary answered; a pointer or a
  member name in an answer's refusal; the gateway's proxy address, its certificate
  authorities' file and its URL behind a separate gateway; the text of a gateway's
  refusal; and an outcome's state. A variable's name, an image and a label's key print
  the name's phrase. `accesskey.Refusal.Error` prints its names as
  `accesskey.ShownNames` gives them. A run answer and a local link, as `fmt`,
  `encoding/json` and `log/slog` print them, show the phrases in place of labels,
  variables, documents, placeholders, reserved names, images, the socket and the files'
  paths. An outcome's `reason` is sent as the name's phrase. `policy.Error`,
  `internal/jcs`'s number error and the sink's reports print the value's phrase. A fixed
  reason that names a prefix, such as a run key's "it does not start with qrk_", prints
  as it is.

- `json.Marshal` of a run answer whose `policy` or `applied` contains `qak_` or `qrk_`
  failed, and a prefix written with an escape, such as `q\u0061k_`, printed as it was.
  A string or member name in either document is now read decoded, and the document
  prints as the value's phrase, a JSON string. A delivery's transport error, to the
  server and over the link, a via's errors, the dial of a separate gateway and the
  reference receiver's store file errors print the value's phrase in place of one that
  quotes a URL, an address or a path with a prefix. They still wrap the error, so
  `errors.Is` and `errors.As` find it. So do `link.Local.DialContext`'s error and the
  reference receiver's `File.Close`.

- A pin whose key contains `qak_` or `qrk_` in any case, about one key in 27,000, is
  read: `server.Parse` and `accesskey.ParsePin` leave each entry's `public_key` that is
  one valid key out of the secret check, written in a form
  `accesskey.SecretInPinDocument` lists; the check still covers `alg`, the entry's
  other members, a key that starts with `qak_` or `qrk_` in any case, and the rest of
  the document. `accesskey.SecretInPinDocument` and `accesskey.SecretInPinEntry` hold
  the rule.

### Gateway

#### Upgrading

- A credential's selection gives no argument for a label whose value is `(a name that
  contains an access key secret)` or `(a name that contains a run key)`, whatever its
  `pattern` admits, `.+` among them. A separate gateway reads the labels from the
  attach answer, where a value that contains `qak_` or `qrk_` in any case is that
  phrase, so a label such as `repository=acme/qrk_x` gave its value as the argument
  before and gives none now. The run's user is told the label is no argument.
- A separate gateway refuses a run key whose instance id contains `qak_` or `qrk_` in
  any case: the attach is answered `run_key_invalid`, 400. Before, the run attached and
  `run.registered` sent the instance id as it was.

#### Added

- A model key of the machine's: a `gateway.Credential` with `Format`, `Endpoint`,
  `OAuth` and `KeyPrefixes` in place of `Hosts`, `Paths` and `Placeholders`, in
  forager.yaml `{env|file|adapter, format, endpoint, auth: {scheme, header, username,
  oauth}, key_prefixes}`. The gateway sets it on every path and on any port of the endpoint's host.
  `Check` refuses a definition that cannot be one. A token from `env` or an adapter
  that starts with none of `key_prefixes` stops the run, and a `file` token read again
  that starts with none of them is not taken. An adapter's answer for a model key sets
  it with the definition's scheme and lists no placeholders.
- The gateway holds every model key of a run and its proxy sets only the start key,
  on a request to the key's endpoint host that carries the key's placeholder in the
  key's header or scheme. Two model keys may claim one host. Under `enforce`, the
  run's allow list must cover a model key's endpoint host.
- `gateway.Config.Selects`: behind a separate gateway, when the server's policy selects
  no credential, a run, with or without a wall, gets the gateway's selection, a credential that takes an
  argument taking it from a label of the run whose value matches the pattern named, for
  a run whose `forge` label is the one named.
- The gateway decides an image a policy names by reference: refused with
  `image_not_allowed` under none of the request's `images.allow`, and otherwise the
  run's image under the default's runtime. The answer carries `relay_image`, the
  default's reference, for every walled run on a machine with a default image.
- The gateway reads a run configuration's `image`, `server.RunConfiguration.Image`, as
  the policy's image: the server's policy and the node's must name the same wherever
  they name one, else `image_unknown`, and a reload that names another, or none in its
  place, is refused. `server.CheckConfigurationImage` holds its rule.

#### Changed

- A reload that brings tools, path rules or an image to a run without a wall fails, and
  the policy in force stays. Before, a reload's path rules for such a run were dropped
  from the policy, and its credentials failed it.
- Behind a wall, and behind a separate gateway, only the node's policy opens the
  gateway's machine: the guard reaches the machine's addresses only for an
  `egress.allow` entry of `gateway.Config.Policy` that names the host itself and that
  the run's policy allows, at the start and at each reload. An entry of a server's
  `security_policy`, such as `localhost` or a name that resolves to `127.0.0.1`, no
  longer opens it: list the host in the node's policy. With no server's policy the
  node's policy opens what it names, as before.
- Two messages start with the step that fixes them. The guard's `403` for a link-local
  address or the machine's address reads "qory: egress to <host>:<port> denied by the
  gateway: to reach the gateway's machine, list the host itself, not a *. pattern, in
  the allow list of the node's policy, and allow it in the run's policy; the gateway
  reaches its machine only for such a host, and never a link-local or cloud metadata
  address". Two credentials that claim one host are refused with "claim <host> in only
  one of the credentials <a> and <b>; both claim it, and a host has one".
- The proxy sets a credential on a private host only through a `hosts` entry equal to
  the host, never through a `*.` pattern. A private host is an IP literal in
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `fc00::/7`, a name of one label,
  or a name that ends in `.local`, `.internal` or `.home.arpa`. A `forager.yaml`
  credential whose hosts are `["*.local"]` no longer sets its key on `litellm.local`:
  list `litellm.local` in the credential's hosts. `policy.CredentialFor` holds the rule.
  `dev.qory.run.policy_applied`'s `terminated` leaves out a credential's `*.` pattern
  that is for no host under the rule, such as `*.local`.
- Behind a wall or behind a separate gateway, the gateway's proxy refuses the cloud
  metadata addresses outside `169.254.0.0/16` and `fe80::/10`, as it refuses
  `169.254.169.254`: `100.100.100.200` (Alibaba Cloud), `192.0.0.192` (Oracle Cloud
  Compute Classic), `fd00:ec2::254` (AWS over IPv6), `fd20:ce::254` (Google Cloud
  over IPv6), `168.63.129.16` (Azure WireServer), `fd00:ec2::23` (AWS EKS Pod
  Identity Agent over IPv6), `fd00:a9fe:a9fe::1` (Akamai over IPv6) and `fd00:42::42`
  (Scaleway over IPv6), and an IPv6 address that contains one of these IPv4 addresses
  in its last 32 bits (`::/96`, `::ffff:0:0:0/96`, `64:ff9b::/96`). An exact
  `egress.allow` entry of the node's policy does not open them. The guard's error for
  one reads "Use another host: the gateway refuses the cloud metadata address
  <address>". The errors for a host that does not read as an address, for a
  link-local address and for the machine's address end "the gateway refuses it",
  where they ended "the wall refuses it", and the error for the machine's address
  reads "no allow entry lists the host by name", where it read "no allow entry names
  the host". A `403` page for a refused
  address ends "the gateway reaches its machine only for such a host, and never a
  link-local or cloud metadata address". The private ranges `10/8`, `172.16/12`,
  `192.168/16` and `100.64/10` stay open. Before, a request to `100.100.100.200` was
  dialled.
- A run holds a copy of the path rules `gateway.Policy.Under` adds, taken and checked
  when it starts: the proxy and `ceiling_paths` keep them for the run whatever the
  caller's `Policy` holds afterwards.
- The gateway holds a copy of its `Config`'s credentials and tools, taken at `Start`
  and checked there: every run keeps them whatever the caller's `Config` holds
  afterwards.

#### Fixed

- More of the gateway's messages and event members printed or sent a value as written,
  and now print or send a phrase in place of one that contains `qak_` or `qrk_` in any
  case. The name's phrase: an image in `image_unknown` and `image_not_allowed`, their
  names included, in the refusal of an image that needs a wall, in a reload whose image
  moved, and in the machine's image definitions; a selection's label and forge. The
  value's phrase: a tool's program, the lines it writes, its start's error and a host
  its definition gives; a path an adapter's answer claims, the decoder's and the
  schema's error of the answer, and a definition's scheme and hosts; the run
  configuration's URL; the proxy's answers to the run for an upstream error, a host
  outside the form, a port, and a request's method and path; the record's, the server's
  and the events' reports; the gateway's address and TLS files; a reload's failure;
  `run.egress`'s `host`, `path`, `path_rule` and `request_method`; and
  `run.policy_applied`'s `paths`, `ceiling_paths`, a credential's `hosts` and `paths`,
  and `terminated`. The server's codes are sent as the server sent them.

- More of the gateway's answers and errors sent or printed a value as written, and now
  send or print a phrase in place of one that contains `qak_` or `qrk_` in any case.
  The name's phrase: the `names` of a refusal on the link, `wall_required`'s
  `image=<name>` among them, and a selection's pattern error. The value's phrase: the
  errors of the gateway's address, its link socket and its directory, of a run's record
  files, locks and resend, and of an enrolment's request. A separate gateway refuses a
  run key whose instance id contains a prefix as `run_key_invalid`, as a registration's
  is refused, since `run.registered` sends the instance id as it is.

- Eight of the gateway's credential messages printed a credential's name or a
  placeholder as written, so a secret pasted in place of one reached the error: the two
  about the policy's selection, a name the machine does not define and a name selected
  twice; the token that cannot be read; the allow-list check; and `Definition.Check`'s
  name, source, argument and placeholder checks. In these eight, a name or placeholder
  that contains `qak_` in any case now prints as `(a name that contains an access key
  secret)`, and one that contains `qrk_` and no `qak_` as `(a name that contains a run
  key)`. The rest of each message prints as before, and so does a name with neither.
  This fix left the reason quoted after the name, such as an adapter's error output or
  a regular expression's error, as it was. `accesskey.ShownName` holds the rule.
- More of the gateway's and the session's messages, and three event members, printed a
  name, an argument or a label's value as written. Each now prints `(a name that
  contains an access key secret)` when it contains `qak_` in any case, and `(a name that
  contains a run key)` when it contains `qrk_` and no `qak_`: the credential messages
  about two credentials that claim one host, an adapter with a scheme, an argument for
  env or file, env or file without hosts, and an argument the credential does not take
  or the machine does not provide for, its name and the argument; the two lines a
  renewal reports; the refusals of `Config.Selects`; the link's phrases for a
  credential's program directory and file and a tool's program directory; the lines a
  run is told when a selection entry gives it no credential, the entry's name, the run's
  forge and the label's value among them, and the refusal of a selection the node's
  policy does not list; the tool messages, a tool's name, argument and placeholder in
  `Definition.Check`, `Choose` and `Check`, a tool that does not start, a tool that
  exits while the run goes on, and the lines a tool writes; the refusals of a server's
  tools and credentials that the node's policy does not list; the credential's name in
  the tool check of a host a credential is for; a `placeholder_conflict` refusal's
  detail and names, the gateway's for a credential's or a tool's placeholder and the
  session's; `run.policy_applied`'s `credentials` `name` and `argument` and its
  `variables` `name`; and the names of a `placeholder_conflict`'s `run.refused`. A
  refusal's names, and a list of names in a message the `tool_unknown` and
  `placeholder_conflict` refusals and the server's credentials refusal give, contain
  each phrase once. Five parts that may quote a secret print `(a value that contains an
  access key secret)` or `(a value that contains a run key)` in place of the whole part:
  in the message of an adapter that fails, its path, its error and the first line of its
  error output; the adapter's path in the other messages about its answer; the error of
  a credential's file that cannot be read; the regular expression error of a
  credential's or a tool's argument pattern and of a `Selects` pattern; and the error of
  a server's `security_policy` that does not read as a policy. The rest of each message
  prints as before, and so does a value with neither prefix.
  `run.policy_applied.schema.json` admits the two name phrases as a variable's name.
  `accesskey.ShownValue` holds the rule for a value, `accesskey.ShownError` for an
  error's text, and `accesskey.ShownNames` for a list of names.
- More run events sent a value of the run's as written, and now send `(a name that
  contains an access key secret)` in place of one that contains `qak_` in any case, and
  `(a name that contains a run key)` in place of one that contains `qrk_` and no `qak_`:
  `run.policy_applied`'s `tools` `name` and `argument` and its `image`; `run.egress`'s
  `credential` and `tool`; the `names` of a `run.refused` of every code, each phrase
  once; and `run.started`'s `image`, `image_name`, each label's value, and `about`'s
  `kind`, `title` and each subject's `title`. `run.started`'s `dir` is the value's
  phrase, `(a value that contains …)`. `run.started.schema.json` admits
  the two phrases as `image_name`, and `run.policy_applied.schema.json` as `image`. The
  gateway accepts `run.started` labels as they are or as `server.ShownLabels` gives
  them, and records and sends them as `server.ShownLabels` gives them. It phrases every
  other member of a `run.started` that a session phrases too, `dir`, `command`, `args`,
  `image` and `about` among them, so a session that sends a value as it is passes none
  through; a `run.started` without such a value is sent byte for byte. The wall and the
  agent get every value as it is.

### Wall

#### Added

- `wall.Request.Pull`: `wall.Docker` pulls the image before it makes any network, unless
  the engine holds it by that digest, under a timeout, and refuses with `image_user_root`
  an image whose user is root, a uid of 0 or a name its `/etc/passwd` maps to uid 0, or a
  name it cannot map. A pull that fails leaves no container or network. `wall.Fetcher`
  reports how long finding the image took, the pull included when there was one.
- `wall.AuthoritySetter`, a wall's names it sets only for a run with an authority:
  `wall.Docker`'s CA names, which a run without one has unset when it denies them.
- `wall.Mount.Target`, the path a mount is shown at inside; `wall.Docker` refuses one
  that is not absolute or that overlaps `/qory`.

#### Changed

- The relay now starts from the machine's default image, never from the run's, when the
  machine has a default image.

#### Fixed

- `wall.Docker`, the engine check, the nest and the relay printed a value as written in
  their errors, and now print a phrase in place of one that contains `qak_` or `qrk_` in
  any case: the name's phrase for a run id, an image, a container runtime, a user, a
  group and a variable's name, the image's in an `image_user_root` refusal's detail and
  names; the value's phrase for a path, a mount and its target, a limit, the helper, the
  docker command, its output and its error, the engine's ids, the proxy and a relay's
  forward. The engine command's error and the start of a command's output print the
  value's phrase too, and so do the errors of making, writing and removing the
  directory of a run's environment files.


### Session

#### Added

- A run without a wall gets its credentials' placeholders, set after the environment it
  inherits, so a placeholder wins over an inherited value, which is then no
  `placeholder_conflict`. The variables the machine's credentials are read from, the run
  answer's `reserved`, are left out of what it inherits. When the gateway gives it an
  authority, the session writes `ca-bundle.pem` into the run directory, the machine's
  authorities and then the run's certificate, and points the names of
  `session.Spec.CAEnv`, or `wall.DefaultCAEnv` when it is nil, at it.
  `wall.BundleFiles` lists the files the machine's authorities are read from.
- Claude Code's `approve-key.sh` runs behind a wall alone: without a wall, an
  interactive Claude Code shows its approval prompt for the placeholder of
  `ANTHROPIC_API_KEY`, once, and the approval stays in your configuration.
- `session.Exec`, the helper's `exec`: `--unset NAME …`, then `--` and the program and
  its arguments. It unsets the names and executes the program, found in `PATH`; a name
  outside a variable's grammar exits 2, a program it does not find, or finds only
  through `.` or an empty entry of `PATH`, 127 and one it cannot execute 126. A walled
  run's launch starts through it when the run has names to unset, in front of the
  preparation and the runtime's approval script, and `dev.qory.run.started` reports the
  launch without it.
- `session.Spec.ImagesAllow`, the machine's `images.allow`: the prefixes of the
  references a policy may name its image by. A run in an image by reference starts
  under the default's runtime, with no nested Docker, its workspace at `/workspace`
  and the paths the session puts inside written there.
- `session.Spec.Preparation`, a run's preparation: the program and then its arguments,
  which the session runs inside the wall before the runtime, after the runtime's
  preparation, with the runtime's environment and through the run's proxy, from
  `preparation.sh` in the run directory. The runtime starts once it exits 0; one that
  exits otherwise is the run's exit status. A spec with a preparation and no `Wall` is
  refused.
- `session.Spec.Written`, the places of this machine the caller records as writable by a
  walled run: the workspaces and the writable mounts of the walled runs it starts.
- `runtimes.Attach.Readable`, which a runtime asks of a file of this machine, by its
  absolute path, before `Prepare` reads it, and which the session sets: it returns where
  the path resolves through every link, the file `Prepare` may read, and refuses a file
  a walled run could have written and a path with a `..` name.
- `runtimes.Attach.ReadableDir`, which a runtime asks of a directory of this machine
  before `Prepare` passes it to the program, and which the session sets: it refuses
  what `Readable` refuses, and a directory that is or contains, as given or resolved,
  by whole names and regardless of case, a place a walled run could have written.
  `Readable` and `ReadableDir` refuse a path for such a place with a
  `*runtimes.WrittenError`, whose `How` is `lies in`, `is reached through` or
  `contains`, and whose `Place` is the place; its text is as before.
- `session.RunsBinding(ctx, d, p)`, the walled runs still going on this machine whose
  writable binds overlap p, an absolute path, by the registry's rule, each a
  `session.WalledRun` of its run id and the absolute path of its entry. A bind overlaps
  p when it is p, holds p or lies inside p, or when a name on the way to either is
  looked up in the other, compared as written and as resolved through links, a `..` in
  p after a link resolved from the link's target. An entry is asked after only when one
  of its writable binds overlaps p, or one cannot be resolved now: the entry of such a
  run that is over is removed, and an engine that cannot be asked is
  `engine_unreachable`, naming the run and its entry, as is an entry whose lock is free
  that cannot be read, with `EntryUnreadable` set on the refusal, in a sentence that
  counts the run as still going, and a relative p is an error. The engine of an entry
  is asked through d, the caller's `*wall.Docker`, by
  `(*wall.Docker).RunContainersExist`, with the recorded command and selection;
  `wall.RunContainersExist` is that method of a Docker with no field set, which a nil d
  asks through. A run's check against the registry asks through its wall when it is a
  `*wall.Docker`.

#### Fixed

- More of the session's messages and `run.started`'s members printed or sent a value as
  written, and now print or send a phrase in place of one that contains `qak_` or `qrk_`
  in any case. In `run.started`, `runtime`, `host`, `wall` and `container_runtime` are
  the name's phrase; `dir`, `command`, each argument, `runtime_version` and each word
  of `preparation` the value's; a label's key the name's; and `about` as
  `server.ShownAbout` gives it. The paths in a mount's refusal,
  `mount_contains_forager_files`, `mount_mode_conflict`, `mount_through_link` and the
  checks of other walled runs, print the name's phrase in the names and the value's
  phrase in the detail. The value's phrase is printed for the paths and errors of the
  registry of walled runs, the written places, the variables' settings,
  the images, `exec`, the descriptors, the socket, the runtimes, the catalog and the
  Claude settings, and the reports of removing the wall, the socket and closing the
  sinks. A `variable_reserved` refusal's detail and names print the name's phrase, its
  names sorted.

- `run.policy_applied`'s `harness_hosts` sent a host as written, and now sends the
  value's phrase in place of one that contains `qak_` or `qrk_` in any case. These
  errors print the value's phrase in place of one that quotes a path with a prefix,
  and still wrap the error: the resend's, the run directory's files and lock, the
  preparation script, the socket, the walk of the registry of walled runs, a wall's
  binds and its wrap, `sink.File` and `sink.Delivered`, a hook's forward to the socket,
  and `claude.Settings`' writes of the settings file and the approval script.
  `run.started` sends `args` as
  `[]` for a run with no arguments, where it sent `null`, which its schema refuses.
  `run.started` sends `about` whenever the caller passed one that is not empty, as
  `{}` when `server.ShownAbout` leaves out every member.

- The `claude-settings` installer read the settings file the launch passes with
  `--settings` through links, wherever it lay, and copied it into the run directory,
  where the enclosure reads it: a walled run could put a link to any JSON file of this
  machine in its workspace, in place of the settings a later run is passed, and hand
  that file to the agent. The session now refuses a settings file whose path, as given
  or through links, is or lies inside, or is reached through, a place of
  `Spec.Written` or, behind a wall, a writable bind of the run's, the workspace among
  them; one whose path has a `..` name; one whose last part is a link; and one that is
  not a regular file or is larger than 1 MiB. The path is made absolute once and that
  path is checked and opened. The open does not follow a link as the path's last part,
  and the file opened must be the one the path resolved to when it was checked. The run
  then stops before the runtime starts, with "runtime claude: ", the fix, and the
  reason, such as "Pass the path of the file that <path> links to. This launch passes
  --settings <path>, and that file is a link, so the run does not start." Settings
  passed as a document are not checked, as before. The places also hold the writable
  binds of the other walled runs in the registry, with or without a wall for this run,
  and are worked out only when a settings file is to be read.
- The `claude-settings` installer copied and checked only the first `--settings` of a
  launch, and Claude Code reads only the last: a walled launch that passed two started
  without Forager's hooks and with a file the session had not checked. A walled launch
  that passes `--settings` more than once, in either form and anywhere in its
  arguments, now does not start, with "runtime claude: Pass one --settings file. This
  launch passes --settings more than once, and Claude Code reads only the last one, so
  the run does not start." In a walled launch whose last argument is a bare
  `--settings`, the session gives that flag the path of the run's settings, so the
  launch passes one `--settings`. `runtimes.Attach.Walled` is set for a walled run. An
  unwalled launch starts as before.
- The `claude-settings` installer passed a walled launch's `--mcp-config`, `--agents`,
  `--plugin-dir`, `--plugin-dir-no-mcp` and `--add-dir` to Claude Code unchecked, so
  Claude Code could load servers, agents, plugins or settings that an agent of a walled
  run had written, and start the programs they name. In a walled launch, a path value
  of these flags that starts with `~`, is relative or has a `..` part now does not
  start, with "runtime claude: Replace ~/ref with an absolute path. This launch passes
  --add-dir ~/ref, and inside the wall ~ is the home of the wall's user, which Forager
  cannot check, so the run does not start." and the texts for the other two. An `--mcp-config` or
  `--agents` file is checked as the `--settings` file is and passed as a copy in the run
  directory, `mcp-config-<n>.json` or `agents-<n>.json`; a value Claude Code takes as
  JSON passes unchanged. A text shows a value of `--mcp-config`, `--agents` or
  `--settings` that contains `{` or `[`, or starts with white space or a format
  character such as U+FEFF, as `(an --mcp-config value)`, `(an --agents value)` or `(a
  --settings value)`, and the reason after "failed:" as `it is no file`, `it cannot be
  read` or `it is no JSON object`, because such a value may be JSON with a token in it;
  for `--settings` in an unwalled launch too. A `--plugin-dir` or `--plugin-dir-no-mcp` directory that lies
  in, is reached through or contains a place a walled run can write, that holds a link
  leading into one or a file with more than one name, or that has more than 10,000
  entries, does not start; a `.zip` is checked as a file. An `--add-dir` directory is
  checked the same way, with only `<dir>/.claude` and `<dir>/CLAUDE.md` read. Each text
  starts with the fix, and the wall docs, § "No file read from a place an agent can
  write", have each text. An unwalled launch starts as before.
- Claude Code loads plugin directories from `CLAUDE_CODE_PLUGIN_DIRS` and adds
  directories from `CLAUDE_RELAUNCH_SESSION_ADD_DIRS`, so a value set for a run went
  past the checks of `--plugin-dir` and `--add-dir`. The Claude descriptor's `denies`
  now lists both, and `contracts/forager/v1/runtimes.json` with it: a value of the
  server's, the run's or the machine's no longer reaches the run, and a walled run has
  them unset.
- `CLAUDE_CODE_PLUGIN_SEED_DIR`, `CLAUDE_CODE_PLUGIN_CACHE_DIR` and
  `CLAUDE_CODE_MANAGED_SETTINGS_PATH` lead Claude Code's plugin and settings loaders to
  a directory or a file no check covers; the Claude descriptor now denies them too.
- A walled run bound a mount or a workspace through a link that an agent of an earlier
  walled run, already ended, had left in a place it could write: the engine followed
  the link, so the run could bind any directory of this machine, writable. A place whose
  path goes through a link inside a place of `Spec.Written` and does not resolve into
  it is now no run, `mount_through_link`, with the place, the link and the written place
  as its names, as for a link inside a writable place of the run's.
- `catalog.Lookup` read a descriptor in `dir` through a link, of any size. It now reads
  one only when its last part is no link, it is a regular file and it holds at most
  1 MiB, and refuses one otherwise with "Make the runtime descriptor <path> a readable regular file of at most 1 MiB, or remove it. It could not be read: " and the reason.
- A `--settings` file whose content is `null` stopped the session with a panic. It now
  does not start, with "runtime claude: Make the file /a/settings.json a JSON object.
  The check of --settings /a/settings.json failed: it is null", as other settings that
  are no JSON object.
- A walled launch's `--add-dir` passed with a regular file, though Claude Code adds
  only a directory. It now does not start, with "runtime claude: Pass an --add-dir path
  to a directory. This launch passes --add-dir /home/notes.md, and that file is not a
  directory, so the run does not start." A FIFO or other file that is not a regular
  one, and a link to such a file or to a regular file, now get the same text. Before,
  they were refused with "that file is not a regular file" or "that file is a link".

#### Changed

- A walled Claude Code launch checks and copies the files of `--system-prompt-file`,
  `--append-system-prompt-file` and `--append-subagent-system-prompt-file`, as it does
  `--settings`, and does not start with `--project-config-root`.
- A walled run needs `session.Spec.Exec`, the command that makes the caller's binary
  run `session.Exec` inside the enclosure, `{wall.HelperPath, "exec"}` for a binary that
  runs it in its `exec` mode; a `Wall` without one is refused before the run starts.
- Behind a wall, the runtime's declared and reserved variables that nothing sets are
  unset inside, where they went in empty, which a program may read as set; and so is
  every name the runtime denies or the node's `Variables.Deny` removes, by its exact
  name, that nothing sets, so an image's `ENV` cannot set one, with one exception: with
  nested Docker, `DOCKER_CONFIG` is never unset, and a non-empty value, the image's
  included, takes the place of the wall's docker configuration, as the contract's
  §The wall says. A name Forager, the wall or the preparation sets is never unset.
- A bind in the registry of walled runs whose `writable` field is missing or null is
  taken as writable, by a run's check against other runs, by the places a walled run
  could have written and by `session.RunsBinding`.
- The `engine_unreachable` sentence of a walled run now reads "The check for a
  container of the walled run <id> failed, so this run does not start: <the error>",
  and, for `session.RunsBinding`, "… so the run counts as still going: …".

### e2e and CI

#### Added

- The conformance suite checks that a run's preparation runs inside, before the runtime,
  through the proxy.
- The conformance suite checks a run in an image by reference: refused outside
  `images.allow` and for a root user, leaving no container or network, its relay from
  the machine's default, its workspace at `/workspace`, and a name its image's `ENV`
  sets that the runtime denies unset. The Docker adapter's test pushes the images to a
  registry it starts on the machine.

#### Changed

- The conformance suite passes the launch's settings file from outside the workspace,
  since the session refuses a settings file in it.

## [0.7.0] - 2026-10-12

### Core and contract

#### Upgrading

- The module is `github.com/qoryai/forager`, no longer `github.com/qoryai/runner`, so
  `go get github.com/qoryai/forager` and every import path start with it.
- `link.Local.Files` is a list of `link.File`, each path with what it is, the phrase a
  refused mount names it by.
- `policy.Covers` covers an IP literal by an identical entry alone, as `policy.Match`
  matches it: `*.0.0.1` covers no `10.0.0.1`, under a machine's ceiling as in
  narrowing.
- `session.Policy`'s `Tools` and `Credentials`, and the policy package's, distinguish an
  empty list from none: an empty list is written as `[]`, and as a node's policy beside
  a server's it allows none of the server's tools or credentials.
- `dev.qory.run.started` requires `opened_by`, whose one value is `session`, and
  `dev.qory.run.exited` no longer requires `exit_code`. Forager writes `exit_code` on
  every `dev.qory.run.exited`; a receiver reads a record that lacks it as one written
  before.
- `dev.qory.run.exited`'s `state` is required on every `dev.qory.run.exited`, and has
  `cancelled` beside `succeeded` and `failed`: the run was stopped before it said how it
  went. A run stopped at its time limit, `timeout`, is `cancelled`, and so is
  `session.Result.State`; so is a session's run stopped from where it was started,
  `interrupted`, a Ctrl-C or a signal to the program that runs the session, with the
  runtime's `exit_code` and `signal`; such a run was recorded `failed`, or not at all
  when the runtime exited 0 at the stop. Its `reason` is an open code,
  `^[a-z][a-z0-9_]{0,63}$`, with no list: Forager's codes, or the run's starter's,
  carried as given. A receiver reads the state from `state`, and shows a reason it does
  not know as it is.
- `server.Ended` returns a `server.RunEnd`, the code, who ended the run, and the state
  and the reason of that end, in place of the code alone, and `sink.Config.OnEnded`
  takes a `server.RunEnd` in place of the code and who ended it.
- A run registers with the server with one signed `POST` to the discovery's `run.url`,
  in place of the ping and the run configuration `GET` with the labels as its query. The
  body, `run-registration.schema.json`, holds the run's id, its labels, what it is
  about, `forager_version`, `contract_version`, `interval_seconds`, `events` and `time`.
  The labels no longer travel in a URL, and what a run is about never selects a policy.
  The answer is the run's run configuration, a signed `200` with
  `X-Qory-Run-Configuration`. A reload fetches it again by the run's id, a signed
  `GET <run.url>/<run_id>`. A `time` more than 300 seconds from the server's clock is an
  unsigned `401`. A registration the server accepted with the same bytes under any
  active key of the node or node pool that registered it gets the same answer again; one
  whose run id it accepted from another node, even with the same bytes, or with other
  bytes, is a `409` `run_id_used`. This is the direct shape of the body; a run through a
  gateway registers with the second (Added, below).
- Discovery's `run` is required, and `run.url` has no trailing slash, query or
  fragment; a document without `run` is refused. A server serves the run endpoint even
  with no policy, and answers every registration `{"version":1}`.
- `dev.qory.ping` is gone, with `events/ping.schema.json`, and nothing is posted in its
  place. Once the server accepts the registration, the gateway writes
  `dev.qory.run.registered` as line 1 of its record, with these members, each required:
  `workspace`, the one workspace discovery lists; discovery's `node_id`; `instance_id`,
  the instance id the registration was signed with, as its `X-Qory-Instance-Id` carried
  it; and the registration's `forager_version`, `events`, `contract_version` and
  `interval_seconds`. Behind a separate gateway the gateway writes it once the server
  accepts the run's attach: `workspace`, `node_id` and `instance_id` are the run key's,
  which name the starter's registration, the other four the attach's, and `labels` and
  `about`, optional, are those of the starter's registration, as the attach's answer
  gives them back, each absent when it had none. It is the record's alone and never
  posted. `event.RunRegistered` names it. The gateway's `delivered.log` begins
  `registered <seq>`. Heartbeats run from the accepted registration until the final
  event.
- A server's `409` to the registration reads `register <run.url>: <code> (status 409)`,
  such as `register https://apiary.example/v1/runs: instance_limit (status 409)`, in
  place of `ping <events URL>: …`. `server.ErrNotAccepted` reads "the server did not
  accept the run", and a signed `410` to the registration "register <run.url>: status
  410: the server did not accept the run". `gateway.ResendNotOpened` reads "the run never
  opened at the server; nothing is sent", reported only by a resend to a server.
- `receiver.Handler` serves the run endpoint at `receiver.DefaultRunPath`, `/v1/runs` in
  place of `/v1/run-configuration`: a run's registration, and its reload by id. Its
  `RunConfiguration` hook is
  `func(run receiver.Run) (document []byte, digest string, refusal *receiver.Refusal)`:
  a `receiver.Run` holds the access key id, the instance id, the run id, the labels,
  `about`, and the run's placement from its registration, `Node`, `Workspace` and
  `Gateway`, and a `*receiver.Refusal` is a signed answer of its `Status`, with its
  `Code` or no body. Without a hook every run gets `receiver.NoPolicy`, `{"version":1}`.
  `Admit` is asked at the registration. The handler answers a reload only for a run its
  node registered, under any of the node's active keys, or for the gateway node that
  attached it, and `404` otherwise.
- `json.Marshal` of `server.RegistrationAnswer` and `server.Attach` writes `run_key`
  redacted, and of `server.LinkRunAnswer` `proxy_secret`; `Attach.Body` is the wire form.
- A policy whose `allow`, `deny` or `paths` entry naming a host is neither a host name
  nor an IPv4 address in canonical form is refused when it is read, as one the schema
  refuses, with "egress.<list> holds <entry>, which is neither a host name nor an IPv4
  address in canonical form".

#### Added

- `event.OpenedBySession`, the value of `opened_by`, and `event.ReasonTimeout`,
  `ReasonInterrupted`, `ReasonRunClosed`, `ReasonGatewayLost`, `ReasonSessionLost`,
  `ReasonStopped` and `ReasonBatchRefused`, Forager's reasons of `dev.qory.run.exited`;
  `interrupted` ends a session's run stopped from where it was started, `cancelled`;
  `stopped` ends a run whose starter ended it and gave no outcome, `cancelled`;
  `batch_refused` is the gateway's `410` to a session whose batch it refused, the reason
  of the gateway's `dev.qory.run.exited`, `failed`, and the reason the session records
  in the session's record after it. The session's `dev.qory.run.started` contains
  `opened_by` `session`. `event.StateSucceeded`, `StateFailed` and `StateCancelled` are
  the states of `dev.qory.run.exited`, and `event.IsState` says whether a string is one;
  `event.Reserved` says whether a reason is one of Forager's reserved codes, the old
  names among them, and `event.StarterReason` whether it may be a starter's: a code of
  the pattern of `reason` that is not reserved.
- Contract `v1` revision 1, amended in place, lets the run's starter say how a run
  ended, and carries it to the end of the run: the starter posts its outcome to the
  server (the outcome, below), the server hands it to the gateway as the `end` member of
  its signed `2xx` to a batch of the run, and the gateway ends the run with it (Gateway,
  Added). With no outcome the run ends `cancelled` with `stopped`, and a reason that is
  one of Forager's reserved codes, or no code, is dropped and the outcome kept.
  Forager's codes are reserved: `timeout`, `interrupted`, `stopped`, `session_lost`,
  `gateway_lost`, `batch_refused` and `run_closed`; and so are seven old names, which
  Forager never writes, kept so that records written before still validate: `quiet`,
  `credential_expired`, `credential_check_unreachable`, `credential_check_invalid`,
  `run_ended_at_issuer`, `issuer_unreachable` and `issuer_answer_invalid`. A
  `dev.qory.run.exited` with the old `quiet` contains `quiet_seconds`, and no other
  does. A `410` that ends a run on the link carries the `state` and the `reason` of that
  end, new optional members of `link-refusal.schema.json`. The README's §The events, How
  a run ends, gives the state of each of Forager's endings. `fixtures/` has a session's
  run that the gateway ends `cancelled` with `stopped`, two session batches whose
  `dev.qory.run.exited` is `cancelled` with `interrupted`, one with the runtime's exit
  status and one with its signal, `410`s with a `state` and a `reason`, the starter's
  `failed` and `checks_failed` among them, and refused ones: a `dev.qory.run.exited`
  without `state`, with a state of no kind it names, with a reason that is no code or
  `gateway_lost` and `cancelled`, a session's with `timeout` and `succeeded`, with
  `interrupted` and `failed` or with the old name `run_ended_at_issuer`, two marked
  beyond the schema, which only the gateway refuses, and refusals with a state of no
  kind it names.
- `go test ./contracts -run TestSignedFixtures -update-signed` signs the batches under
  `fixtures/signed/` again under the fixture access key secret, after a change to a
  body; the same test without the flag checks them.
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
- Forager's refusals are `session.Refusal` values too, with the code, the names they
  concern, never a value, and a sentence in `Detail`: `run_configuration_invalid`,
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
  enrolment answers' domain line, `qory-enrol-answer-ed25519-v1`, once the server has
  checked the key and verified the proof under it; `events/run.refused.schema.json`, the
  data of `dev.qory.run.refused`, which `event.schema.json` lists among its types; and
  `denied-variables.json`, the built-in deny list of variable names and patterns.
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
  fingerprint however it is printed. It treats a run key, `qrk_` in any case, as it
  treats `qak_`: a server URL, a name or an instance id that holds one is refused, the
  value never quoted, and a document or a pin that holds one is
  `ErrRunKeyInDocument`, which `errors.Is` reports as `ErrSecretInDocument`;
  `SecretInDocument` tells the two apart, and `server.Parse` returns either.
  `WithoutVariables` leaves out of an environment the access key's three variables and
  `QORY_RUN_KEY`, `EnvRunKey`. Its tests reproduce every published known answer of the
  access key, the requests, the answers and enrolment.
- `enrolment.schema.json` defines a signed refusal at enrolment, `$defs/refusal`:
  a `409` `key_invalid` for a key already enrolled or `key_limit`, or a `429`
  `rate_limited` per code, with `apiary_public_key`, the same list in the same order as
  a `201`, so a machine without a pin verifies it as it verifies the `201`. A key the
  checks refuse or a proof that does not verify under it gets an unsigned `409`
  `key_invalid`, before the server signs anything. `fixtures/enrolment/` has the four
  `409`s, with one key and with two, and the `429` with one key, and `signatures.json`
  their signatures under the fixture signing key.
- The reference receiver accepts the public keys its configuration holds, answers in
  the contract's order of refusals, a registration whose `interval_seconds` is outside
  1 to 300 being `invalid_request`, and signs every answer after verification under the
  receiver's key, the `410` of its `Stop` among them. Its new hook `Admit` refuses an
  instance's registration with `instance_limit`.
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
  contains a control character. Toward the server, only this event and the run's
  registration contain it; it never selects a policy, and an empty `about` is left
  out. `fixtures/run/about-*.json` holds accepted and refused ones. `session.Spec.About`
  is a `session.About` of `Kind`, `Title`, `Subjects`, each a `session.Subject` of
  `Type`, `Ref`, `URL` and `Title`, and `Details`, a `json.RawMessage`; run.started
  reports `Details` as `CheckAbout` measured them. `session.CheckAbout` holds an
  `About` to these rules and returns the first failure as a `*session.AboutError`, its
  `Field`, such as `about.subjects[0].ref`, and its `Reason`; `session.Run` checks it
  before it contacts the server, and an `About` it refuses is no run.
- Contract `v1` revision 1, amended in place, gains `run_id_used`, a gateway's refusal
  of a run request whose `run_id` already names a run at this gateway, with no names.
  `events/run.refused.schema.json` lists it, and the refusals of a separate gateway over
  the run key, `run_key_invalid`, `run_attached`, `run_key_expired` and `wrong_gateway`,
  which the session records with no `status`, and the server's `workspace_not_served`,
  which the session records with its `status`, and says that a run request the gateway
  refuses opens no run at the gateway: the session records the refusal it received only
  in the session's record, and nothing reaches the server for it. A gateway's `410`
  before the runtime starts is recorded the same way, as `dev.qory.run.refused` with the
  `410`'s code and `status` `410`: the schema's codes include `session_lost`,
  `batch_refused` and `stopped`, and the server's `not_found`, a signed `404` to a run's
  registration, `accesskey.CodeNotFound`. A code without `status` is held to the
  schema's list; a code of the server's, with its `status`, is kept as the server sent
  it, one the list does not hold included, and a receiver shows a code it does not know
  as it is. `fixtures/batch/` has `refused-not-found.json` and
  `refused-unlisted-server-code.json`. A session that fails after the run answer and
  before its process starts posts its `dev.qory.run.refused` on the link, and the
  gateway delivers it; `refusal.RunIDUsed` is the code in Go, and
  `refusal.GatewayDecides` reports a gateway's code.
- Forager reads a run configuration with `encoding/json/v2` first, which refuses a
  member name that appears twice and invalid UTF-8, then against the schema and the
  limits: a variable's value of at most 4096 bytes of UTF-8. The error states where and
  which rule refused the document, and never quotes a value.
- Contract `v1` revision 1, amended in place, defines the gateway's link: §The gateway's
  link, between a session and its gateway, by the protocol toward the server, discovery,
  the run configuration, the events endpoint and the `410` close, over two transports.
  The local link is a Unix socket in `qory-link-*`, mode `0700`, the socket `0600`, one
  of Forager's files, on the paths toward the server. Before it sends anything the
  session checks that the socket's peer is the session's user, by the peer's uid, and
  the gateway serves only a peer of the gateway's user, by the same check, and closes
  any other connection unanswered before it reads anything of it; a connection carries
  HTTP/1.1 from its first byte, with no preamble and no secret of the link. The socket's
  peer uid is the whole of the local link's trust: a process of the same user that
  reaches the socket and knows a local run's id can post a batch into the run, fetch its
  configuration again, or end it. A session in the same process as the gateway, as
  `qory` runs them on one machine, reaches the link in memory, with the same bytes, and
  never dials the socket's path, where another process of the same user could stand in
  for the gateway. `gateway.Config.NoLinkSocket`, which `qory run` sets, makes no link
  directory and no socket: the link is served in memory alone, which no other process
  reaches, `LocalLink()` has no `Socket`, and its `Files` leave out the link directory
  and keep every other entry, the pattern of every gateway's link among them. A separate
  gateway, the one the run's run key names, speaks TLS 1.3 alone on its one address,
  with the operator's certificate, whose chain the session verifies for the host name of
  the run key's `gateway_url` against the system's roots; every connection there opens
  with the binding, every request carries the run key, and every path is under
  `/qory-link/` (a run through a gateway, below). Answers on the local link are
  unsigned, and behind a separate gateway signed under a key the run key names; both
  carry the digest headers of a reload. A coded refusal on the link is
  `link-refusal.schema.json`, `error`, `names`, `from`, required, `gateway` or `apiary`,
  the server's refusal passed on with its code and status, and `message`, on every
  refusal of the link, the `500` `internal` of a run that fails to open without a code
  among them: the text the session gives the user as the run's error, today's word for
  word, Qory Apiary's URL in it for the server's, optional, a session that reads none
  using the code, up to 8192 characters that may span lines, tab and newline its only
  control characters, with no other C0 control character, no DEL and no C1 control
  character, which holds no secret or image reference; every `410` on the link is one. A
  reload is a `GET` of `<run.url>/<run_id>`, answered with
  `link-reload-answer.schema.json`, the policy in force, its `digest`, `variables`,
  `placeholders`, `reserved`, `image` and `applied`, never the proxy secret or the
  certificate authority; on the local link it names its run by its path alone, the
  socket's peer being what lets it in, and an unknown `run_id` is `400`
  `invalid_request`; behind a separate gateway its run key's run must be the `run_id`,
  else `400` `run_key_invalid`. A run opens with a `POST` of
  `link-run-request.schema.json`: `run_id`, which the session chooses, `wall`, on the
  local link alone `labels` and `about`, `passes`, the names of the variables the run
  passes a value for, never a value, `images`, the session's `default` and
  `definitions`, each with `name`, `ref`, `runtime` and `docker`, whose references the
  gateway never logs or reports since one may carry a registry's credentials, and,
  behind a separate gateway, a `narrowing` that only narrows; the request is one-shot
  per `run_id`. The gateway refuses the request in order with `invalid_request`, a
  `narrowing` on the local link among it, and on the local link `run_id_used`; behind a
  separate gateway the run key is decided before the body is read, and then a `run_id`
  that is not the run key's is `run_key_invalid`, `labels` or `about` in the request
  `invalid_request`, and a run the gateway holds or is opening, live or ended, or holds
  a record of, `409` `run_attached`. With `passes` and `images` the gateway decides the
  run, and each reload, as the session decides it today and in the same order, before it
  sets anything: the policy in force, what needs a wall, the image, `image_unknown`, the
  credentials and the tools, and `placeholder_conflict` for a placeholder the run passes
  a value for. A refused start is a `403` with the session's code of `refusal.Decides`
  and `from: gateway`, while the server's refusals pass through with the server's status
  and `from: apiary`; a start that fails without a code is a `500` `internal` from
  `gateway` whose `message`, the error's text, the session returns as its error. The
  gateway tries the server's registration up to 3 times, 1 second and then 2 seconds
  apart, starting a try again only within 6 seconds of the run request: after no answer,
  a `5xx`, signed or not, and a signed `429` `rate_limited`, every try with the same
  bytes, and recorded once; once the tries are spent the last answer is the session's,
  as without them. A `404` does not fetch the configuration document again. A signed
  answer at run start with no code is a `server.AnswerError`, with its status. A refused
  reload leaves the policy in force: behind a separate gateway it is answered as a
  refused start is, and on the local link it stays off the link. A start without a wall
  whose policy selects what needs one is `wall_required`, a `403` from `gateway` and a
  code of the link alone, named `credentials`, `tools`, `paths` or `image=<name>`: the
  session turns it back into today's error and writes no event for it, so it is not in
  `refusal.Decides` or in `dev.qory.run.refused`'s codes. On the local link the gateway
  applies a reload itself and reports every failed one, with a code or without, with
  today's text, and the reload answers the policy in force with its digest unchanged.
  The session still checks its image table and runtime before it sends the request, and
  leaves out of `passes` a name outside the variable-name grammar. The answer,
  `link-run-answer.schema.json`, has `run_id`, on the local link `labels`, the run's
  labels as the gateway holds them, the run request's, the policy in force and its
  `digest`, `variables`, `placeholders`, the variables the agent sees in place of a
  credential or a tool's secret, `reserved`, the variables the machine's credentials are
  read from, which a walled run that passes one is refused for, `variable_reserved`, and
  whose value an unwalled run has left out, `image`, the image the run gets when it has
  a wall, `applied`, required, the members of `dev.qory.run.policy_applied` the gateway
  decides, every one but `variables` and `harness_hosts`, which the session adds to
  write the session's `dev.qory.run.policy_applied`, on the local link the run's
  `proxy_secret`, and its `certificate_authority` when `wall` is true and the gateway
  reads inside HTTPS for the run, for a credential, a tool or a path rule, and behind a
  wall with a server always; the session's `dev.qory.run.started` contains exactly those
  labels, and behind a separate gateway none. Discovery on the link,
  `GET /.well-known/qory-configuration` on the local link and
  `GET /qory-link/configuration` behind a separate gateway, is
  `link-discovery.schema.json`, with `events.interval_seconds`, the gateway's heartbeat
  interval, `proxy.address`, the gateway's proxy as `host:port`, on loopback on one
  machine, and no `node_id`, `workspaces`, `apiary_public_key` or `secrets`; a batch is
  `link-batch.schema.json`, events without `sequence`, which the gateway numbers. On the
  local link every batch names its run in `X-Qory-Run-Id`, and one with no
  `X-Qory-Run-Id`, with two, or with the id of no run of this gateway's is `400`
  `invalid_request`, and ends no run; behind a separate gateway a batch is of its run
  key's run. A session writes no event the gateway decides: the gateway refuses a batch,
  `400` `invalid_request`, nothing of it numbered, with an event of another run; a
  `dev.qory.run.registered` or a `dev.qory.run.egress`, which the gateway writes; a
  `dev.qory.run.started` not opened by the session, whose `labels` differ from the run's
  as the gateway holds them, none behind a separate gateway, or a second one; an event
  after the run's `dev.qory.run.exited` or `dev.qory.run.refused`, or a
  `dev.qory.run.refused` after its `dev.qory.run.started`; a `dev.qory.run.exited` with
  a `reason` other than `timeout` and `interrupted`, both `cancelled`, since the gateway
  writes the event of every other reason itself; a `dev.qory.run.policy_applied` that is
  not the `applied` of an answer of this run with the session's `harness_hosts` and
  `variables` added, any policy the gateway has put in force for the run matching, so a
  batch in flight during a reload is not refused; or a `dev.qory.run.refused` whose code
  is not one of `refusal.Decides`, or with a name `<member>=<value>`. The schema states
  the types, `opened_by`, `timeout` and `interrupted` as the ones of Forager's reasons
  and the codes and names of `dev.qory.run.refused`. A batch whose body does not arrive
  whole, its client gone before the end, is `400` `invalid_request` too, and ends no
  run. Any other `400` `invalid_request` to a batch ends its run at the gateway: the
  gateway writes `dev.qory.run.exited`, `failed` with `batch_refused`, refuses the run's
  proxy secret, or behind a separate gateway its run key on a proxy connection, and
  answers the session's further requests with a `410` `batch_refused`; the session stops
  the runtime and writes the session's `dev.qory.run.exited`, `failed` with
  `batch_refused`, as the gateway's, in the session's record and never posted.
  `dev.qory.run.policy_applied` is the session's, from the run answer and a reload
  answer whose digest changed; into a session's run the gateway merges the gateway's
  `dev.qory.run.egress`, every one after a reload's switch held until the session's
  `dev.qory.run.policy_applied` of the new policy is numbered, and, when it ends the
  run, its `dev.qory.run.exited`. A walled agent never reaches the local link's socket;
  an unwalled one runs as the session's user and can, so without a wall enforcement is
  cooperative. A session's heartbeats are its run's, and a session silent for 3 × the
  interval ends the run, `session_lost`. When the gateway ends a session's run, with
  `session_lost`, `batch_refused`, or `stopped` with the starter's outcome, it writes
  the run's `dev.qory.run.exited` itself, with the state of that end and `-1`, and
  delivers it toward the server. It answers the session's next request and every one
  after it with a `410`, and the session writes the session's `dev.qory.run.exited`,
  with the state and the reason that `410` gives, as the gateway's, in the session's
  record and never posted, and posts nothing more. The `410`'s code is, from `gateway`,
  `stopped` after the starter's outcome, `session_lost` after a silent session, or
  `batch_refused` after a refused batch. Every `410` on the link carries `from`, and the
  gateway's `410` `run_closed` to a request of a run already ended is unchanged. A
  server's signed `410`, with any code or none, stops delivery: the gateway sends no
  further batch for the run and marks its record `stopped`, and the run goes on, its
  record keeping every event. A `410` to the registration, signed or not, is no run, and
  no refusal: no server's `410` crosses the link. On one machine the relay opens its
  connections with `QORY-RELAY` and the run's proxy secret; behind a separate gateway
  the session's forwarder opens each, bound, with `QORY-RELAY` and the run key, over TLS
  1.3 (Session, Added). `fixtures/link/` holds the valid documents, the discovery of a
  separate gateway and a run answer behind one, without labels and `proxy_secret`, among
  them, refusals from `gateway` and from `apiary`, most with today's text as their
  `message`, the gateway's with the `: <code>: <names>` tail, `run_key_invalid` and
  `run_attached` from `gateway`, and the signed `409` `instance_limit` to the
  registration and `run_key_expired` to the attach from `apiary` with the server's
  `run.url` in it, and `fixtures/invalid/link-*` the refused ones, a discovery without
  `proxy`, a run request that passes a value with a name or whose image has no `ref`, a
  run answer without `applied` or whose image has no `ref`, a reload answer whose
  `applied` holds `variables`, a refusal without `from` or with a control character
  other than tab and newline in its `message`, a C1 one among them, and a batch with a
  `dev.qory.run.egress`, a `dev.qory.run.started` whose `opened_by` is not `session`, a
  `dev.qory.run.exited` with each of Forager's reasons but `timeout` and `interrupted`,
  and a `dev.qory.run.refused` with a code a gateway decides, `run_id_used` among them,
  `run_closed`, a code of the server's or a name `<member>=<value>`. Package `link` has
  `LinkDirPrefix`, `LinkSocketName`, `LinkDirMode` and `LinkSocketMode`.
- `link.Local` is what a session needs of a gateway on the same machine: its link
  socket, its proxy address, the files a walled run must not mount and the variables it
  reserves. The one `(*gateway.Gateway).LocalLink()` hands out reaches the gateway in
  memory, `Local.IsInMemory`; `Local.DialContext` opens a connection in memory when it
  has that way, `Local.InMemory`, and to the socket otherwise, and `server.NewLocalLink`
  dials that way alone. `server.ErrLinkPeer`, "the socket's peer is another user;
  nothing is sent", is a socket whose peer is another user. `link.RelayLine` writes the
  relay's preamble, `QORY-RELAY`, a space, a secret and a newline, and
  `link.ReadRelayPreamble` reads it, compared in constant time in a read of exactly its
  length, beside `link.PreambleWait`, `link.MaxSecret` and `link.ToolDirPrefix`.
- `server.NewRemoteLink(runKey, server.RemoteTLS{CAFile, CertificateSHA256}, userAgent, digests)`
  is the client of a separate gateway's link, with the local link's `Discover`,
  `OpenRun`, `Reload` and `Deliver` and their refusals: the run key read as a runner
  reads one, unverified, `runkey.Parse`, its `gateway_url` the one address it is ever
  sent to and its `gateway_public_key` the keys the gateway must prove it holds; TLS 1.3
  alone, with HTTP/2 not offered; the chain checked for the host name of `gateway_url`
  against the system's roots, the zero `RemoteTLS`, or the CA file's authorities in
  their place, and the pin, when one is set, after the chain; no proxy of the
  environment and no redirect; on every connection the binding before the run key is
  sent, and on every request `Authorization: Bearer` and the run key, never in an error
  or a print; and every answer signed under a key the run key names, for that connection
  and request, else no answer, a `*server.GatewayKeyError` with the gateway's `URL` and
  `Unproven`, true when the binding failed. Its discovery must list URLs of the
  gateway's origin under `/qory-link/` alone and name its one address as the proxy.
  `Link.DialProxy` opens a bound connection to that address with `QORY-RELAY` and the
  run key, and `Link.ProxyAddress` names it.
- `server.Delivery` has `Refusal`: on the link, a coded answer other than a `2xx` as the
  `*accesskey.Refusal` it is, with its code, status, names, who refused and its
  message.
- `server.RunEnd` is how a run ended at the gateway, as the link says it: `Code`, one of
  `server.EndCodes`, `run_closed`, `stopped`, `session_lost` and `batch_refused`,
  `From`, and `State` and `Reason`, the state and the reason a `410` that ends a run
  carries, each held to `run.exited.schema.json`'s, and both empty for a `410` that
  carries none, `run_closed`, or one the schema refuses. `server.Ended` returns it from
  a `410` of the link, and `server.Delivery` has `State` and `Reason` beside `End` and
  `From`, and `Delivery.RunEnd` returns all four. On a link sink,
  `(*sink.Server).Resend` takes a line of the session's record and posts it without its
  sequence. `(*sink.Server).RunEnded` records that an answer the sink did not read
  itself, a reload's `410`, ended the run: nothing more is sent, `RunClosed` reports
  true, and `delivered.log` says `stopped`.
- `accesskey.Refusal` has `From`: `accesskey.FromApiary` for a code read from the
  server's signed answer and for its `401` `unauthorized` at run start,
  `accesskey.FromGateway` for one a gateway decides, made by `refusal.ByGateway`, and
  empty for one Forager decides, `answer_unsigned` or `apiary_public_key_missing`; its
  text is unchanged.
- Contract `v1` revision 1, amended in place, defines the run key,
  `run-key.schema.json`: one string of at most 2048 characters and no white space,
  `qrk_`, the payload in base64url without padding, `.`, and the signature in base64url
  without padding, 64 bytes of Ed25519 under Qory Apiary's server key over the domain
  line `qory-run-key-ed25519-v1`, a line feed and the exact payload bytes Qory Apiary
  signed, which nobody re-serialises. The payload has every member required and no
  other: `version`, `1`; `signer`, the fingerprint of the server key that signed it, so
  the server's key can rotate inside a live run; `run_id`; `workspace`, the run's
  workspace; `node_id`, the node or node pool that registered the run; `gateway`, the
  gateway the node's choice resolved to at the registration, `ng_`; `gateway_url`, an
  `https` origin, the only address the run key is ever sent to; `gateway_public_key`,
  the gateway's live keys, one or two, current then next; `instance_id`, the
  registration's signed instance id; `issued`; and `attach_by`, the end of the attach
  window. A gateway and Qory Apiary verify a run key under their pin; a runner pins no
  server key and only parses one, takes only `run_id`, `gateway_url` and
  `gateway_public_key` of it, and never checks `issued` or `attach_by`. The public
  package `runkey` is both readings: `runkey.Verify` under a pin, whose `Key` reports
  `Verified`, and `runkey.Parse`, whose `Key` never does; `Key.Sign` makes one under a
  server key. Its errors, a `*runkey.Error`, name the part that is wrong,
  `its signature does not verify` say, and never contain the run key.
  `fixtures/invalid/run-key-*` holds refused payloads.
- Contract `v1` revision 1, amended in place, lets a run go through a gateway (§The
  server, Through a gateway). Each node or node pool records one of three choices,
  `direct`, `default` or a named gateway, `ng_`, which the server resolves at every
  registration from the access key's record, never from the body: `direct` answers as a
  direct registration does; a named gateway is that gateway, if it may still serve the
  node's workspace; `default` is the workspace's default, else its organisation's, else
  its operator's. A change of choice or of default applies to new registrations only.
  `run-registration.schema.json` has a second shape, which a starter, or a keyed
  machine's `qory` behind a gateway, sends: `version`, `run_id` and `time`; `labels` and
  `about`, information alone; and `attach_seconds`, the attach window the run asks for,
  absent for the server's default, 600 seconds, clamped to its ceiling, 3600 seconds,
  below 1 or not an integer `invalid_request`; without `forager_version`,
  `contract_version`, `interval_seconds` and `events`, which move to the attach. Its
  answer is a signed `200`, `run-registration-answer.schema.json`, the run's id and its
  run key, `{"version": 1, "run_id": "…", "run_key": "qrk_…"}`, with no run
  configuration, so the starter never receives the run's policy, and no
  `X-Qory-Run-Configuration` or `ETag`. The run endpoint's refusals of a registration
  gain, after the stored answer and the `410`, in order: `409` `gateway_key`, a
  gateway's key, which registers no run; `409` `node_is_direct`, the gateway shape from
  a key whose choice is `direct`, or `node_uses_gateway`, the direct shape from a key
  whose choice resolves to a gateway; `409` `no_default_gateway`, the choice is the
  default and none resolves; `409` `gateway_not_serving`, the named gateway may no
  longer serve the node's workspace; and `409` `gateway_without_key`, the resolved
  gateway has no active access key; all before `instance_limit`, so a run that can go
  nowhere never takes a slot. A node pool's instance slot frees when the run ends, or at
  `attach_by` if the run never attached. `server.GatewayRegistration` builds the body,
  its `Body` setting `time` from the clock when it is left empty, and
  `Client.RegisterThroughGateway` posts it and takes the answer only when its `run_id`
  is the registration's and its `run_key` reads as one of that run and it carries
  neither `X-Qory-Run-Configuration` nor `ETag`, refusing one that does,
  `registration answer <run.url>: the answer carries X-Qory-Run-Configuration or ETag;
  a registration through a gateway carries no run configuration`; a refusal reads
  `register <run.url>: <code> (status 409)`, such as
  `register <run.url>: gateway_key (status 409)`, and no error contains the run key. A
  `server.RegistrationAnswer` prints and logs its run key as `[redacted]`, however it is
  printed.
  `fixtures/run-registration/` has two bodies of the gateway shape, and
  `fixtures/invalid/` refused ones of either shape.
- The attach, `POST <run.url>/<run_id>/attach`, signed by the gateway's access key, with
  which the gateway the run key names takes the run on: its body,
  `run-attach.schema.json`, every member required, holds `run_key`, `interval_seconds`,
  `events`, `forager_version`, `contract_version` and `time`. The answer is a signed
  `200`, `run-attach-answer.schema.json`: the run's run configuration with
  `X-Qory-Run-Configuration` and `ETag`, and `labels` and `about` as the starter's
  registration gave them, information alone, each absent when it had none; a reload's
  answer stays a plain run configuration. Its refusals, after the shared order, in
  order: `409` `not_a_gateway`; `400` `run_key_invalid`, a run key that does not verify
  or whose `run_id` is not the path's; the stored answer to the same gateway node, under
  any of its active keys, attaching the same live run again while the gateway still
  serves the run's workspace; `410`, the run has ended; `409` `run_key_expired`, past
  `attach_by` and never attached; `409` `wrong_gateway`, the run key names another
  gateway; `409` `workspace_not_served`; and `409`
  `run_attached`, another gateway node attached the run. After the attach a run's
  reloads, batches and heartbeats are accepted from the active keys of one node alone:
  for a run behind a gateway the gateway node that attached it, a batch from any other
  key a signed `409` `wrong_gateway`; for a direct run the node or node pool that
  registered it, a batch from another node's key a signed `409` `wrong_node`; a reload
  from any other key is `404`. A run behind a gateway counts as live from its attach, by
  the attach's `interval_seconds`, and one never attached is lost at `attach_by`.
  `server.Attach` builds the body and `Client.Attach` posts it, returning the run
  configuration with its digest, the labels and `about`; it takes an answer only with
  one `ETag`, the `X-Qory-Run-Configuration` digest in quotes, and refuses any other,
  `attach answer <run.url>/<run_id>/attach: the ETag header is not the
  X-Qory-Run-Configuration digest in quotes`; a refusal reads
  `attach <run.url>/<run_id>: <code> (status <status>)`, such as
  `attach <run.url>/<run_id>: run_key_expired (status 409)`, and a signed `410` is no
  run. A `server.Attach` prints and logs its run key as `[redacted]`, however it is
  printed. `fixtures/run-attach-answer/` has two answers, and `fixtures/invalid/` refused
  attaches and answers.
- Qory Apiary answers a run's batch or reload with a signed `410` `workspace_not_served`
  once the gateway that attached the run may no longer serve its workspace, decided as at
  the attach, and the reference receiver answers the same.
- The starter's outcome, `POST <run.url>/<run_id>/outcome`, signed by any active key of
  the node or node pool that registered the run, sent directly or through a gateway's
  relay: its body, `run-outcome.schema.json`, holds an optional `state`, `succeeded`,
  `failed` or `cancelled`, an optional `reason`, a code, and `time`, held to the window
  of a registration's. With no `state` the outcome is `cancelled` with `stopped`, and a
  reason that is one of Forager's reserved codes, or no code, is dropped and the outcome
  kept. The outcome sets the run's state whenever it arrives while the run's record is
  kept, before or after `dev.qory.run.exited`, whose exit code, signal and reason stay
  on record beside it. Each run gets one outcome: the same bytes, or the same state and
  reason under any of those keys, get the stored answer, a signed `200` with
  `{"version": 1}`, `run-outcome-answer.schema.json`; a different one is a signed `409`
  `outcome_given`, and a run the node did not register, or whose record is gone, a
  signed `404` `not_found`. `server.Outcome` and `Client.PostOutcome` send it: an empty
  `State` sends neither `state` nor `reason`, a `Reason` without a `State` is refused
  before anything is sent, a `Time` left empty is the clock's now, and a refusal reads
  `outcome <run.url>/<run_id>: <code> (status <status>)`, such as
  `outcome <run.url>/<run_id>: outcome_given (status 409)`. `fixtures/run-outcome/` has
  three outcomes, and `fixtures/invalid/` refused ones.
- The `end` member: a signed `2xx` to a batch may carry a body,
  `batch-answer.schema.json`,
  `{"end": {"state": "succeeded", "reason": "all_checks_passed"}}`, covered by the
  answer's signature, the outcome the run's starter gave, `reason` absent when it has
  none; an empty body, or one without `end`, means no end. Once the server has recorded
  the outcome it sends `end` on every `2xx` for the run until the run's
  `dev.qory.run.exited` arrives, and a signed `410` carries none. `server.ReadEnd` reads
  it against the schema, from a signed `2xx` alone, as `Delivery.ServerEnd`, a
  `server.ServerEnd`: a body the schema refuses is no end, and a reserved reason is
  dropped and the state kept. `sink.Config.OnServerEnd` gets each one.
  `fixtures/batch-answer/` has an `end` with a reason, one without and none, and
  `fixtures/invalid/` refused ones.
- A gateway enrols as a node does: the enrolment answer's `node_kind` has `gateway`,
  paired with an `ng_` `node_id`, and `accesskey.CheckNodeID` takes `ng_`. Discovery for
  a gateway's key lists its `ng_` `node_id` and no `workspaces` (Changed, below); there
  is no member that names the key's kind. The fixture gateway key,
  `ak_f1xt0re00000000g`, its seed bytes 97 to 128, is in `keys.json`, among the
  published fixture keys every side refuses as its key and as a pin;
  `fixtures/enrolment/` has a gateway's request under it and the answer,
  `fixtures/configuration/gateway.json` a gateway key's discovery, with no `workspaces`,
  and `fixtures/invalid/configuration-gateway-workspaces.json` one that has them.
- The server document has `via`, `server.schema.json`: `url`, required, an `https`
  origin, `ca_file` and `certificate_sha256`, the gateway a keyed machine or a starter
  reaches the server through. With `via` set, Forager sends every request to the server,
  the enrolment, discovery, the registration and the outcome, to `via.url`'s origin with
  the target, the path and the query, unchanged, discovery's absolute `run.url` rebased
  on it too, and the gateway passes each answer back byte for byte, so each signature is
  the server's; `url` stays the server's, so records and texts name the real server. A
  `via` connection is TLS 1.3 alone, its chain always checked for `via.url`'s host name
  against the system's roots, or the authorities of `ca_file` in their place, with
  `certificate_sha256`, the SHA-256 of the certificate's DER SubjectPublicKeyInfo in
  standard base64 with padding, as a pin besides. `server.Config.Via`, a `*server.Via`,
  holds it; `Via.Check` refuses one Forager cannot send through, and `Via.Transport` is
  its transport, with no proxy of the environment. A `server.Client` whose `HTTP` sets a
  transport keeps that transport's `DialContext` under `via` and drops its
  `DialTLSContext` and `DialTLS`, which would skip the chain check and the pin. The
  gateway a request is relayed through sees the registration answer's run key, so `via`
  names a gateway trusted at least as much as the run's gateway.
  `accesskey.EnrolmentRequest.PostVia`
  sends an enrolment through it, with a client the caller builds from that transport,
  and verifies the answer as `Post` does. `fixtures/server/via.yaml` has one, and
  `fixtures/invalid/server-via-*` refused ones.
- Package `link` has the binding of a connection to a separate gateway, `BindWord` and
  `BindLine`, `QORY-BIND`, `BoundLine`, `BindingMessage` and `BindingLabel`, the TLS
  exporter label `EXPERIMENTAL-qory-link-binding`; `AnswerRequest`, the third line of a
  separate gateway's signed answer, the hash of the connection's exporter value, the
  method, the target and the body, and `AnswerRequestHash`, its SHA-256 holding
  everything before the body, which a body is written to as it arrives for the same
  line; and `RemotePathPrefix`, `/qory-link/`, and
  `RemoteDiscoveryPath`. `accesskey.LinkAnswerDomain`, `qory-link-answer-ed25519-v1`, is
  the domain line of a separate gateway's answers, `accesskey.Answer.Link` marks one,
  and `accesskey.PublicKey.VerifyAnswer` verifies an answer's signature under a public
  key.
- `fixtures/known-answers/through-gateway.json` holds, under the fixture keys, the run
  key of `run-key-payload.json` with its signed message and its signature, and the
  requests and answers of a run through a gateway, line by line with their signatures:
  the registration through a gateway and its answer, which carries that run key, the
  attach, signed under the fixture gateway key, and its answer, and the outcome and its
  answer. For a fixed exporter value, the 32 bytes counting up from 129, it holds the
  binding, the three lines the gateway signs under the fixture gateway key, the
  signature and the `QORY-BOUND` line, and one answer of the gateway on its link, a
  `202` with no body to the batch `fixtures/link/link-batch.json` posted to
  `/qory-link/events`, with the lines whose SHA-256 is its third line, its six lines
  under `qory-link-answer-ed25519-v1` and its signature. `go generate ./runkey` writes
  them, and the module's tests fail while they differ, or while the session's side and
  the gateway's make other bytes of them.
- The reference receiver serves a run through a gateway. `receiver.Handler` has `Nodes`,
  `Workspaces`, `Organisations` and `Gateways`, records by id: a `receiver.Node`, its
  workspace and its choice, `receiver.Direct`, `receiver.Default` or a named gateway; a
  `receiver.Workspace` and a `receiver.Organisation`, each with its default gateway; and
  a `receiver.Gateway`, its URL, the workspace or organisation it lives at and its
  access keys. `receiver.AccessKey` has `Node`, what the key belongs to, and a key with
  none is a separate node, which reports directly. It answers a gateway key's discovery
  with its `ng_` `node_id` and no `workspaces`, resolves each registration's gateway at
  the workspace and the organisation, with no operator level, in the run endpoint's
  order of refusals, and issues each run through a gateway its run key under the
  receiver's key, its `attach_by` by `attach_seconds`, `receiver.AttachWindow`, 600
  seconds, when it asks for none, and `receiver.AttachCeiling`, 3600 seconds, at most.
  It serves the attach and its refusals in order, accepts a run's reloads and batches
  from one node alone, a signed `404` and `409` `wrong_node` or `wrong_gateway`
  otherwise, takes the starter's outcome once per run, and carries it as the `end`
  member of every `2xx` to a batch of the run until the batch that carries the run's
  `dev.qory.run.exited`. A batch whose events are not all of one run is `400`
  `invalid_request`. The `RunConfiguration` hook is asked at the registration, at the
  attach and at each reload.

#### Changed

- The module is a core and three parts over it. The core, at the root, is `contracts`,
  `accesskey`, `receiver`, `policy`, `refusal`, `event`, `sink`, `server`, `program`,
  `runkey`, and `link`, which holds the names the parts agree on.
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
- The docs and the contract's README name qory's `~/.config/qory/forager.yaml` and its
  `session`, `gateway` and `wall` sections: the machine's policy is `gateway.egress`, and
  the server `gateway.server`.
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
  no secret; `gateway.Server` has the same members, and `AccessKey`, `InstanceID` and
  `InstanceName`, which `session.Server` and `session.Spec` had until a session spoke
  to a gateway alone (Session, Upgrading). Every request
  contains `X-Qory-Access-Key-Id`, `X-Qory-Instance-Id`, `X-Qory-Instance-Name` and
  `X-Qory-Signature-Ed25519`, over the request string of a GET or a POST. Every answer
  but a `401` is signed under the server's key and bound to the request's signature,
  and Forager reads its body and headers only once it verifies; during a run an
  answer that does not verify is retried. §The server defines the access key, nodes
  and instances, the pin, the request string, signed answers, the coded refusals and
  their order, and enrolment.
- Discovery lists `node_id` and `apiary_public_key`, each required, `workspaces` for a
  node's or a node pool's key, and `secrets` for an access key allowed stored secrets.
  `node_id` is the id of the access key's node, node pool or gateway,
  `^n[dpg]_[0-9a-hjkmnp-tv-z]{16}$`, and the `ng_` prefix alone says the key is a
  gateway's. `workspaces` holds ids of `ws_` and 16 lower-case Crockford base32
  characters, Qory Apiary's workspaces and not the directory a run works in: for a
  node's or a node pool's key exactly one, the workspace the node or node pool belongs
  to. A gateway's key has none: a gateway takes each run's workspace from the run's run
  key. A document of a node's or a node pool's key without `workspaces` or with two, or
  of a gateway's key with `workspaces`, is refused. `server.Configuration` has
  `Workspaces`.
- The registration's `interval_seconds` is the run's heartbeat interval, a whole number
  of seconds from 1 to 300, `gateway.Config.Heartbeat`, which the heartbeats tick at.
  `elapsed_seconds` counts from the session's discovery of its gateway's link.
  `dev.qory.run.exited`'s `reason` has `run_closed`.
- `fixtures/server/` and `fixtures/signed/` use the fixture access key and Ed25519.
  `fixtures/signed/` has `get-configuration-no-instance-id` and `-header-twice`,
  `batch-unknown-key` in place of `batch-wrong-key`, and
  `expect_code` for a coded refusal. `fixtures/invalid/` has
  `server-no-access-key-id`, `server-no-pin`, `server-secret-member` and
  `event-registered-interval-too-long` in place of `server-no-key`;
  `fixtures/configuration/with-secrets.json` is new; the configuration fixtures list
  `node_id` and `apiary_public_key`, and `workspaces` but for a gateway's key; and the
  `dev.qory.run.registered` of the recorded runs contains `workspace`, `node_id`,
  `instance_id` and `interval_seconds`. `fixtures/invalid/` has
  `configuration-no-workspaces`, `configuration-two-workspaces`,
  `event-registered-no-workspace` and `link-discovery-workspaces`, and the discovery
  known answer, its body, digest and signature, is recomputed.
- The contract is at `contracts/forager/v1`, and every `$id` and `dataschema` is
  `https://qory.dev/contracts/forager/v1/…`. `dev.qory.run.registered` and
  `dev.qory.run.started` contain `forager_version`; `dev.qory.run.exited`'s `reason` for a run whose end was
  not recorded is `gateway_lost`; and the refusal code of a mount that holds Forager's
  files is `mount_contains_forager_files`, `refusal.MountContainsForagerFiles`.
  `accesskey.UserAgent(version)` builds the `User-Agent` of every request to a server,
  `qory-forager/<version>`. The four batch fixtures under `fixtures/signed` are signed
  over their new bodies.
- Contract `v1` revision 1 is amended in place for the end of a session's run at the
  gateway. `dev.qory.run.started` has `opened_by`, required, whose one value is
  `session`, and requires `runtime`, `command`, `args`, `dir` and `interactive`.
  `forager_version` is the session's, and `host` is the agent's machine's.
  `dev.qory.run.exited`'s `reason` has `session_lost`, the session was silent,
  `batch_refused`, the gateway refused a batch from the run's session, and `stopped`,
  which the gateway writes, beside `timeout`, `interrupted`, `run_closed` and
  `gateway_lost`; when the gateway ends a session's run it writes the run's
  `dev.qory.run.exited`, and the
  session writes the session's, with the state and the reason of the gateway's `410`, in
  the session's record and never posted. `exit_code` is optional in the schema, and
  Forager writes it on every `dev.qory.run.exited`: `-1` with `gateway_lost` and in
  every `dev.qory.run.exited` the gateway writes for a session's run, `session_lost`
  included. `state` is required on every `dev.qory.run.exited`, `failed` with
  `gateway_lost`; the schema fixes `exit_code` to `-1` with `gateway_lost` when it is
  present. The README's events table, §The events and §Fixtures say so. Every
  `run.started` in the fixtures contains `opened_by`, and the four batches under
  `fixtures/signed` are signed over their new bodies. `fixtures/invalid/` has a
  `run.started` without `opened_by`, one whose `opened_by` is of no kind it names, and a
  session's without `command`.
- The server judges a run's liveness by its heartbeats' `time`, corrected by the run's
  clock offset, with a tolerance of 300 seconds and never later than their arrival, and
  a delivery id is never used again for other events.

### Gateway

#### Upgrading

- Package `gateway` exports `gateway.Start`, its `Config` and the `Gateway` it returns,
  with `Addr`, `LocalLink`, `Close` and `Wait`, and `String`, `Format`, `GoString` and
  `LogValue`, which never print a secret; `gateway.Resend`, its `ResendConfig`,
  `Delivery` and `ErrRunning`; and the types their fields need: `Server`, `TLS`,
  `Policy` with `Under`, `ReadPolicy`, `PolicyEgress`, `PolicyCredential`, `PolicyTool`,
  `Credential`, `Tool`, `Discovery` and `Image`. `Proxy`, `Decision`, `CA`,
  `ProxyCredential`, `ProxyTool`, `CredentialDefinition`, `HeldCredentials`,
  `ToolDefinition`, `ChosenTool`, `Tools`, `Listen`, `NewCA`, `ResolveCredentials`,
  `ChooseTools`, `CheckTools`, `ToolPlaceholders`, `StartTools` and `ToolSocketDirs` are
  removed: `gateway.Start` starts the one proxy every run shares, and for each run a
  session opens on its link resolves the credentials and starts the tools the run's
  policy selects among `gateway.Config`'s `Credentials` and `Tools`. A test in
  `internal/importrules` fails on any other export.
- `gateway.TLS` is `{CertFile, KeyFile}`, in place of `{Certificate, Key}`, and
  `gateway.Config` has `Listen` and `TLS`. `Start` with `Listen` empty serves the local
  link alone, as before, and refuses a `TLS` without a `Listen`.

#### Added

- `gateway.Config.Listen`, a separate gateway's one address, in place of its local link:
  a gateway with `Listen` serves the sessions of other machines alone, and makes no
  local link, in memory or on a socket, and no proxy listener on loopback; a session on
  the gateway's machine that dials its `LocalLink` gets "the gateway serves other
  machines on its address, and runs no sessions". Every connection is routed by its
  first bytes after the TLS handshake, served with ALPN `http/1.1`: one that opens with
  `QORY-BIND` is an edge's, the session's or its forwarder's, which the gateway binds to
  its TLS with its `QORY-BOUND` line, signed under its access key over the connection's
  TLS exporter value, and then serves the link, or, after `QORY-RELAY` and a run key,
  that run's proxy, with at most 2048 characters of run key; any other is the relay of
  the server's endpoints (below). It reads the edge's next line within the ten seconds
  of a preamble, each line at most 8 KiB, and closes a connection that sends neither in
  time unanswered.
- The one address verifies each request's run key, its one `Authorization: Bearer`,
  under the server's pin before it reads the request's body, in this order, from
  `gateway`: `400` `run_key_invalid`, its message "the gateway refused the run:
  run_key_invalid", for no single `Authorization` of the Bearer scheme or a value that
  is not a run key that verifies; `409` `run_key_expired`, past its `attach_by` plus a
  skew of 300 seconds by the gateway's clock, for a run the gateway holds nothing of,
  not open, not opening, not kept after its end and not recorded, a run key within the
  skew going on as one before `attach_by`, the server deciding its attach; and `409`
  `wrong_gateway`, its `gateway` not the `node_id` the gateway's discovery lists. Each
  `409`'s message is the line of the server's refusal of the attach,
  `attach <run.url>/<run_id>: <code> (status 409)`, `run.url` the server's. A run key
  that passes names the request's run: a run request or a reload of another `run_id` is
  `run_key_invalid`. The gateway verifies the run key on every request of the run and on
  every proxy connection, not only the first: once the gateway restarts with a server
  key out of its pin, a run whose run key that key signed gets `run_key_invalid` on its
  next request, and a new proxy connection of it is closed unanswered. On the run
  request the gateway attaches the run at the server under the gateway's access key,
  `server.Client.Attach`, with the tries of a registration, and writes the record's
  first event, `dev.qory.run.registered`, from the run key and the attach's answer; a
  refusal of the attach reaches the session with its code, its status and
  `from: apiary`. A run request for a run the gateway holds or is opening, live or
  ended, or holds a record of, is `409` `run_attached`, its message
  `attach <run.url>/<run_id>: run_attached (status 409)`. A gateway that stopped between
  the attach and marking the run's record `answered` leaves a record that holds
  `dev.qory.run.registered` alone, which the run request that comes again removes before
  the gateway attaches the run again; one that stopped after it keeps the record, and
  the run request that comes again is `409` `run_attached`; a gateway that cannot write
  `answered` answers the run request `500`, `run <id>: marking its record answered:
  <error>`; an attach that failed leaves nothing of the run, and the run request that
  comes again asks for the attach again. A run that was open at a gateway that stopped
  is over: the gateway that starts again answers its reloads and batches `410`
  `run_closed` and its run request `409` `run_attached`. A run the gateway let go of
  answers its later requests with the `410` of its end for 15 minutes after its record
  is flushed, and `run_closed` after, as long as the gateway still has the run's record.
  Every answer on a bound connection, a refusal and a `410` included, is signed under
  the gateway's access key, `X-Qory-Signature-Ed25519` over the six lines of a signed
  answer under `qory-link-answer-ed25519-v1`, its third line the hash of the
  connection's exporter value and the request, the body hashed as it arrives,
  `link.AnswerRequestHash`, with no copy of it kept. An answer of the server whose
  `X-Qory-Configuration` differs from the one in force makes the gateway read its
  discovery again and put it in force for every run. The gateway delivers each run's
  events toward the server under the gateway's access key, and fetches a reload of the
  run at the run endpoint, as a direct node's gateway does. A session's narrowing is
  accepted on the one address and narrows the run's policy, at its start and on each
  reload; it opens none of the gateway's addresses, which only the policy before it
  opens, when it enforces and names the host itself. Its `dev.qory.run.policy_applied`
  has the `source` of the policy it narrows, with the narrowed policy's `digest`, and
  `source` `config` for a narrowing of no policy.
- The one address bounds what a peer holds there before its run key is admitted. Every
  connection, the relay's among them, counts against at most 4096 such connections at
  once, 64 of one source, an IPv4 address or an IPv6 /64, and 256 of one IPv6 /48,
  until its run key is admitted: on its first request of the link answered `2xx` for
  its live run, a run request, a reload or a batch, or in its relay preamble of a live
  run. One more closes the oldest such connection whose run key has not verified, of
  its source when that is full, else of its /48, else of all, and is taken; when none
  can be closed, it is closed as it is accepted, unanswered. An admitted connection
  counts against none of them. On a bound connection a request of the link
  arrives whole, its body included, within 60 seconds, and its request line and fields
  within 16 KiB, the 4 KiB net/http allows past that aside: a longer head is net/http's
  `431`, unsigned. Every request goes through the run key's check, `OPTIONS *` among
  them, and one refused for its run key is answered once, with `Connection: close`,
  after the gateway reads at most 64 KiB of its body, which the refusal's signature
  covers, within 10 seconds; a body declared or sent longer, or one slower, closes the
  connection unanswered. Every answer other than a `2xx` to a request whose run key
  passed, a `409` or a `410` among them, carries `Connection: close`, and the gateway
  closes the connection after it. A request answered other than `2xx` whose body does
  not come whole within 10 seconds of the answer closes the connection unanswered.
- A separate gateway forgets a run it stops keeping, 15 minutes after its record is
  flushed, its run id and its record's flush error with it, so neither grows with the
  runs it has served. `Close`'s error keeps the first 16 such errors, in the order the
  runs were let go of, then those of the runs it still keeps, and counts any others in
  one line, "and <n> more runs' records could not be closed", or "and 1 more run's
  record could not be closed".
- A gateway ends a run with the outcome its starter gave when the server's signed `2xx`
  to a batch of the run carries `end`, a direct node's gateway and a separate gateway
  alike: the first `end` ends the run, code `stopped`, from `gateway`, and the gateway's
  `dev.qory.run.exited` of it has the outcome's `state` and `reason` and `exit_code`
  `-1`; an `end` `cancelled` with no reason gives the reason `stopped`. The gateway
  still numbers the run's last events and its `dev.qory.run.exited` and delivers them,
  and ignores any later `end`. The session's next request is the `410` `stopped` with
  that state and reason, its message "the run has ended: <state>, <words>": the reason's
  words, `no outcome given` for `stopped`, and any other reason with spaces for its
  underscores, "the run has ended: failed, checks failed" for `checks_failed`; with no
  reason, "the run has ended: <state>". A refused batch is `failed` with `batch_refused`
  in the gateway's record, as in the session's.
- `gateway.Delivery` has `ClosedReason`, the code of the gateway's `410` of the first
  run that ended at the gateway, in place of `Reason`, and `State` and `Reason`, how
  that run ended, the state and the reason of the gateway's `dev.qory.run.exited` of
  it; for a resend that completes the record, `failed` and `gateway_lost`.
  `Delivery.ClosedBy` is removed: it always said `gateway`.
- Each line the gateway reports of a run's end reads `run <id>: <what happened>; the run
  ends: <state>`: "its session sent nothing for 1m30s; the run ends: failed", or "the
  gateway refused a batch from the run's session, <why>; the run ends: failed". The
  server's signed `410` is "the server wants no more events of this run; the run goes
  on".
- A run's certificate authority keeps at most 1024 hosts' certificates, the least
  recently used going first.
- A run's end closes every tunnel of its proxy, at both ends, and the connections whose
  TLS the proxy ends, so no connection relays past the run.
- `gateway.Config.TLS`, the operator's certificate and key: the one address speaks TLS
  1.3 alone, and its exporter binds every connection of the link there. `Start` refuses
  a `Listen` that is not `host:port`; a `Listen` without `TLS`, "the gateway's address
  <address> needs TLS, a certificate and its key: every connection of the link there is
  bound to its TLS", or without a `Server`, "the gateway's address <address> needs a
  server and a gateway's access key: the gateway attaches each run there"; certificate
  and key files it cannot read or that do not match; and, once discovery is read, an
  access key whose node is not a gateway's, "the access key's node <node id> is not a
  gateway, ng_: the gateway's address <address> needs a gateway's access key".
- `gateway.Start` refuses a gateway's access key without an address: the access key's
  node <node id> is a gateway, ng_: a gateway without an address needs a node's access
  key, nd_ or np_.
- The discovery on the one address, `GET /qory-link/configuration`, lists every URL on
  the origin the session reached, by its `Host`, under `/qory-link/`, and
  `proxy.address` that same address.
- The proxy of every run served through the one address is guarded, whatever its wall:
  the machine's addresses are refused unless the policy's allow list names the host, as
  for a walled run.
- `gateway.Delivery.NotOpened` says a resend to a server sent nothing, and left the
  record as it is, since the run never opened at that server: its registration was
  refused, or it had no server. With no server it is never set: the resend completes
  every record, and leaves one that holds no event as it is, with no error. `gateway.ResendNotOpened` and `gateway.ResendNoServer` are the lines the
  resend reports then, which a caller that reports `NotOpened` itself may leave out,
  and `gateway.ResendTorn` the one for lines of the record that are not whole events,
  a format of their count and the record's path. `gateway.Delivery.Stopped` says the
  server answered a signed `410` and wants no more events of the run: during the run,
  so the resend sent nothing, or during the resend, with `Sent` what the server
  accepted before it and `Undelivered` what was not sent, which stays in the record's
  `events.jsonl`, none under `undelivered/`.
- A connection to the one address that does not open with the binding is the relay's:
  HTTP/1.1, for a keyed machine or a starter whose server document holds `via`. The
  relay forwards four endpoints alone to the origin of the gateway's server document,
  with the target unchanged, the path it matched, which holds no escaped byte, and a
  discovery's query as it came, in origin form when it came in absolute form: the
  enrolment, `POST /.well-known/qory-enrolment`; discovery,
  `GET /.well-known/qory-configuration`; a registration, a `POST` to the path of the
  `run.url` of the gateway's discovery; and an outcome, a `POST` to that path, a slash,
  a run's id and `/outcome`. It drops the fields of one connection, those its
  `Connection` names among them, and the fields that name a source, `X-Forwarded-For`,
  `Forwarded` and `X-Real-IP`, asks for no compression, and passes the server's answer
  back byte for byte, its status and its fields but those of one connection, so each
  request's signature and each answer's stay the server's. It relays nothing else, the
  attach above all, and answers none of them itself. Its limits, each answered by the
  relay itself with no body, in this order: `429` past 60 requests a minute from one
  source, in bursts of at most 20, or past 240 a minute from one IPv6 /48, in bursts of
  at most 80; `404` a path other than the four; `405` one of the four paths, its escapes
  decoded, with another method; `404` one of the four with its method, but a path with
  an escaped byte or a query on a `POST`; `413` a body over 16 KiB for the enrolment,
  64 KiB for a registration or 4 KiB for an outcome; `503` 64 requests
  with the server already; `502` the server not reached, or its answer over 1 MiB; and
  `504` no answer from the server within 10 seconds. A source is the connection's IPv4
  address or IPv6 /64, never a field the request carries, and the relay lets go of one
  idle for 20 seconds, the time its burst takes to come back whole, at its sweep every
  20 seconds. The relay follows at most 65,536 sources; a new one past that lets go of
  the one idle longest. Of one IPv6 /48 it follows at most 256 sources; a new one past
  that lets go of that /48's source idle longest. A connection of the relay reads a
  request whole, its body included, within 30 seconds, and writes its answer within 30
  seconds, or is closed; a request's line and fields are within 16 KiB, the 4 KiB
  net/http allows past that aside, and a longer head is net/http's `431`, which counts
  toward no rate.
- A separate gateway's calls to the server, the attach and the relay among them, use
  the proxy of the environment, `HTTPS_PROXY` and `NO_PROXY`, `HTTP_PROXY` never, since
  a server over http is on loopback, which Go never proxies: a proxy that ends their TLS
  with a certificate the gateway's machine trusts sees the run keys they carry.
- `gateway.Config.Discovered`, when not nil, is called once the server's signed
  configuration document is read and verified, before `gateway.Start` returns, with a
  `gateway.Discovery`: the access key's `node_id`, `NodeID`, and whether the document
  lists `secrets`; an error it returns is no gateway.

#### Changed

- A run request whose session gives up waiting for its run answer, ten seconds, opens
  no run: once its connection goes, the gateway asks Qory Apiary nothing more for it,
  its registration among it, and removes what it recorded of the run, so the same
  `run_id` sent again opens the run instead of `run_id_used`. Within 150 seconds of its
  `time`, with
  every member of the registration but `time` the same, the gateway sends the server
  the same registration bytes again, which a server that accepted them answers the
  same; after that, or with other labels or another `about`, the server answers
  `run_id_used`. Before,
  the run opened and ended `session_lost` after three heartbeat intervals. A session
  that goes while the run answer is on its way may still leave such a run.
- The gateway is `gateway`, over `gateway/internal/{proxy,credential,tool}`.
- The organization of the run's certificate authority is
  `Forager gateway, one run only`. The gateway's `403` for a link-local address or the
  machine's address reads "qory: egress to <host>:<port> denied by the gateway:
  link-local addresses are never reached through it, and the gateway's machine only for
  a host the policy's allow list names", and for an ambiguous path "qory: <method>
  <host><path> denied by the gateway: the path could be read two ways".
- The proxy answers a host's `101 Switching Protocols` to a request that asked for no
  upgrade with `502`, `upstream: the host answered 101 Switching Protocols to a request
  that asked for no upgrade`, and closes the host's connection and the client's.
- The proxy refuses a request to a host that is not a name of ASCII letters, digits,
  hyphens and dots, or an IP address in canonical form, whatever the mode, with the rule
  `wall:host-form` and a `403` that reads "qory: egress to "<host>":<port> denied by the
  gateway: the host is neither a name of ASCII letters, digits, hyphens and dots nor an
  IP address in canonical form". It decides a name lower-case and without a trailing
  dot, and an IPv6 address lower-case.
- The gateway resolves a host name exactly as decided, with no search domain added: a
  name of one label is reached at the addresses the hosts file gives it, and any other
  name only as it is written.
- The proxy refuses a request to an IPv6 address in `::/96` (except `::1`),
  `::ffff:0:0/96`, `::ffff:0:0:0/96` or `64:ff9b::/96`, whatever the mode, with the rule
  `wall:host-form`.
- The wall judges an IPv6 address with a zone by the address alone.
- The wall also judges an address in `::/96` (other than `::1` and `::`),
  `::ffff:0:0:0/96` or `64:ff9b::/96` by the IPv4 address in its last 32 bits.

#### Fixed

- `gateway.Resend` reads on past a line of `events.jsonl` that holds no whole event, a
  write the gateway did not finish, on a full disk: it skips those bytes, and keeps and
  sends every event the gateway wrote after them, one the next write put on the same
  line too, the object that ends the line, never one inside the bytes before it. When
  those bytes are themselves exactly one whole event, a write that lost its newline
  alone, it is kept too. A whole event numbered at or below the one before it is
  skipped. Before, it cut the file at that line, and every event after it was lost. A
  last line without its newline that is a whole event is kept, and gets its newline
  before `gateway_lost` follows it; any other is cut off, as before. The resend
  reports "<n> lines of <file> are not whole events and are not sent". `gateway_lost`
  is numbered after the highest sequence of the whole events or of `delivered.log`,
  since an event whose line was not finished may have reached the server whole, and the
  file is changed only when `gateway_lost` is added.
- `gateway.Resend` to a server sends nothing of a record with no
  `dev.qory.run.registered`, no `delivered.log` and no `dev.qory.run.started`, of a run
  that never opened there. Nothing is added to its `events.jsonl`, the `Delivery` says
  `NotOpened`, nothing sent, and the resend reports "the run never opened at the
  server; nothing is sent". Before, its ping and events were posted, which reported a
  run that never opened. The same holds of a record with neither mark and a
  `dev.qory.run.started`, of a run that had no server, sent to a server: it never
  opened there, and the resend reports "the run had no server; nothing is sent".
  Before, its events were posted without a ping. A record with a
  `dev.qory.run.registered` or a `delivered.log` is sent. With no server, the resend
  completes every record as any other, without a word, and leaves one that holds no
  event as it is, with no error.
- Of a policy's path rules, the one for the most specific host pattern that matches
  applies: an exact host before a wildcard, a longer suffix before a shorter.
- `gateway.Policy.Under` keeps each side's path rules apart, as beside a server's
  policy: a request to a host either side holds to paths must match an entry of each
  side that lists it, and the run's mode decides a miss.

### Wall

#### Upgrading

- In an image with nested Docker, `dockerd` runs with `/usr/local/sbin`,
  `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin` as its whole `PATH`, so
  these directories contain the programs it starts, `containerd`, `runc` and `iptables`
  among them. Of the run's environment it gets the proxy and, when the run has one, the
  run's certificate bundle. `docker:dind` needs no change.
- A link at `/run/qory` or `/run/qory/docker` in an image with nested Docker stops the
  run when the wall writes the agent's docker configuration there, which it does
  whenever the run sets no `DOCKER_CONFIG` or an empty one. `wall.Nest` followed it
  before.
- A wall with nested Docker needs the docker command and Docker Engine 28 or later;
  another engine is refused before anything is made.

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
  runs with the recorded selection in place of Forager's; with an address left out, with
  Forager's environment. `EngineID` asks the engine's id again through the recorded
  selection; a run whose engine gave none as it started asks once the enclosure is
  prepared, and records the answer. A walled run's registry entry records the engine.
  `wall.RunContainersExist` asks the engine's id again, when one is recorded, and then
  lists a run's containers with `ps --all --quiet --filter label=dev.qory.run=<id>`,
  with the recorded variables in place of Forager's. It asks a command other than podman
  by its id, through its pinned selection, and refuses one recorded without an id, since
  podman installed under another name reads no `DOCKER_HOST` and every Docker engine gives
  an id; it asks the command named podman by its pinned selection when it gave no id, and
  refuses one recorded with neither.
- `wall.Binder` is a wall, or an enclosure, that binds extra files and directories of
  this machine, beyond the launch's mounts; `Binds` lists them as `wall.Bind` values, a
  `Pattern` for a directory the enclosure makes later. `wall.Docker` lists its helper
  and the pattern `wall.TempDirs()` before it prepares an enclosure; its enclosure lists
  the helper, the hook socket's directory and the private directory that holds the run's
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
  the mount that holds it, and is bound at the same path as on the machine, writable,
  only when no mount holds it. `wall.Docker` binds `Launch.Mounts` and passes
  `Launch.Dir` as `--workdir`, and refuses a launch whose `Dir` no mount's path holds.
- With nested Docker, the wall's inside network has an IPv6 subnet in Docker's isolated
  gateway mode, and its relay listens on its address in it.

#### Fixed

- In an enclosure with nested Docker, the agent's `docker` command reads its
  configuration, so the containers it starts get the proxy. `wall.Nest` made `/run/qory`
  root's with mode 0700, which the agent's user could not pass through: the command
  printed `WARNING: Error loading config file: open /run/qory/docker/config.json:
  permission denied`, and its containers reached nothing. `/run/qory` is now root's with
  mode 0755, whatever the umask, and a `/run/qory` already in the image is set to the
  same owner and mode; `/run/qory/docker` and its `config.json` stay the agent's, 0700
  and 0600, now also whatever the umask or the image made them, and the file is written
  anew. A link where either directory goes is refused. An image that makes `/run/qory`
  0755 to work around this may keep doing so.
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
- The engine ran the agent's image's health check in the relay's container, as the
  relay's user, where it could read the run's proxy secret from the relay's environment
  and reach what the relay reaches. `wall.Docker` now creates the relay and the agent's
  container with `--no-healthcheck`.
- Without nested Docker, `wall.Docker` creates the inside network with no IPv6 subnet,
  and the agent's container starts with no IPv6 address but loopback's `::1`.
- The relay listened on every address of its container, so whatever reached its address
  on its ordinary network, another container of the engine or a process of the machine,
  had its connections forwarded to the proxy opened with the run's proxy secret. The
  relay now listens on its address on the wall's inside network alone: `wall.Docker`
  gives it that network's subnets in `QORY_RELAY_INSIDE`, and `wall.Relay` refuses to
  start when the variable names none, or a subnet that holds no address of the relay's,
  or several. `wall.Relay` takes a connection only from an address in those subnets.

### Session

#### Upgrading

- A session speaks to a gateway alone, over the gateway's link. `session.Spec` gains
  `Gateway`, an interface: `session.LocalGateway(l link.Local)` from the link
  `(*gateway.Gateway).LocalLink()` hands out, or a `session.RemoteGateway` (Added,
  below), and a `session.Gateway` prints and logs by its socket or, behind a separate
  gateway, the URL its run key names, never the run key. A spec without one, a nil
  `Gateway`, is no run. `Spec.Policy`, `Server`, `Local`, `AccessKey`, `InstanceID`,
  `InstanceName`, `Discovered`, `Credentials`, `Tools`, `Events`, `Heartbeat` and
  `ProxyBind` are removed, with `session.Policy`, `PolicyEgress`, `PolicyCredential`,
  `PolicyTool`, `Credential`, `Tool`, `Server`, `Discovery`, `ReadPolicy`,
  `(*Policy).Under`: the policy, the credentials, the tools and the server are
  `gateway.Config`'s, the stream that follows every event is `gateway.Config.Events`,
  the heartbeat interval is `gateway.Config.Heartbeat`, which the link's discovery
  announces, and the resend of the run's stream is the gateway's, `gateway.Resend`. What
  the entries below say of these members holds of the gateway's.
- `session.Resend` sends a run's record again to the separate gateway the run spoke to
  (Added, below). `ResendSpec` has `Gateway`, the run's `session.RemoteGateway`, `Dir`,
  `ForagerVersion` and `Report`, and no `Server`, `Wall` or `RunnerVersion`: a record on
  one machine is `gateway.Resend`'s, and what a wall left is the caller's to remove,
  `(*wall.Docker).Reap`. `Resend` returns a `ResendResult` value with `Sent`,
  `Undelivered`, `RunClosed`, `ClosedReason`, `State`, `Reason` and `NotOpened`, and no
  `RunID`, `Closed` or `Reaped`: the session completes no record.
- `session.Result.ClosedBy` and `session.ResendResult.ClosedBy` are removed: with
  Forager's gateway they always said `gateway`. `ResendResult.ClosedReason` is the code
  of the gateway's `410`, which `ResendResult.Reason` held before, and
  `ResendResult.Reason` is now the reason of how the run ended, as `Result.Reason` is.
- The session's record is `session.jsonl` and `output.log` in the run directory; the
  gateway writes the run's numbered stream, `events.jsonl`, and its delivery state
  toward the server. Behind a separate gateway, the session's run directory on the
  session's machine also holds `delivered.log`, what the gateway accepted of
  `session.jsonl` by the session's sequence, and `stopped` when the gateway ended the
  run; `undelivered/`, the session's batches the gateway did not accept; and
  `separate-gateway`, an empty file, `session.GatewayMark`, the mark of a session's
  record behind a separate gateway. None holds the run key. `Result.Undelivered` counts
  the session's events the gateway did not accept.
- A refusal the gateway or the server answers the run request with is a
  `*session.Refusal` with `From`, `gateway` or `apiary`, whose `Error` is the refusal's
  `message`, the text the run always returned; the gateway's `wall_required` is the
  error a run without a wall always had, word for word. A run the gateway could not open
  for a reason without a code is the error its answer's `message` says, word for word.
  `server.LinkRefusal` has `Message`, and the link's client sets a refusal's
  `accesskey.Refusal.Text` from it.
- A runtime name is a lower-case letter and then up to 63 lower-case letters, digits
  and dashes: `catalog.Lookup` refuses a longer name, `runtimetest.Conforms` fails a
  runtime that has one, and the descriptor schema holds `runtime` to the same bound.
- `session.Spec.Env` is what the run inherits. The values the harness computes itself go in
  `LaunchFixed`, the values its author wrote as defaults in `LaunchDefaults`, the run's
  variables, `--env`, in `Variables.Run`, and the machine's, `wall.env`, in
  `Variables.Machine`, so the session tells each source apart and applies the highest
  that sets a name. `HarnessHome` is the harness's home as the agent sees it, an
  absolute path, and the session sets `QORY_HARNESS_HOME` to it. `OnVariables` receives
  each name, its source and the values that lost, once the variables are resolved and
  before the agent starts.
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
  it, where Forager ignored it before, so a caller may pass its policy beside a server.
- The runtime prepares the launch before the tools start, since the names it sets are
  among Forager's fixed names when the variables are resolved.
- Without a wall on one machine, the agent's proxy URL carries a password,
  `http://qory:<password>@127.0.0.1:<port>`, where it was the forwarder's address alone.
  The session makes, holds and checks the password as behind a separate gateway (Added,
  `session.RemoteGateway`), and the forwarder closes a connection whose first request
  does not carry it unanswered, before anything reaches the gateway's proxy, so a
  process of another user that reaches the port reaches nothing. Without a wall, here
  and behind a separate gateway, a connection to the forwarder carries one request, a
  `CONNECT` and its tunnel or one plain HTTP request and its reply, which the forwarder
  passes on with `Connection: close`, or with `Connection: Upgrade` when it asks for an
  upgrade, a `101` reply making the connection a tunnel, so each request's password is
  checked and taken off before the request is passed on. A program that sends
  its proxy URL's user name and password as `Proxy-Authorization`, and opens a new
  connection after a reply with `Connection: close`, reaches the proxy as before.
- Without a wall, the forwarder checks the request line of each request the password
  lets in, and itself answers one it refuses with a `400`, `Connection: close`, before
  anything reaches the gateway's proxy: `the proxy takes HTTP/1.0 or HTTP/1.1` for a
  line that is not a method, a target and `HTTP/1.0` or `HTTP/1.1`, each after a single
  space; `CONNECT takes host:port` for a `CONNECT` whose target is not `host:port` with
  a port from 1 to 65535; and `the proxy takes an absolute-form request target` for any
  other method without an absolute-form target. It reads the proxy's reply head to an
  upgrade up to 64 KiB, and closes the connection at the first byte the agent sends
  before the reply to an upgrade. At most 128 connections at once wait to show the
  password or the hop line; one more closes the one that has waited longest.

#### Added

- `session.RemoteGateway{RunKey}`, a separate gateway on a separate machine, by the
  run's run key, the one Qory Apiary answered the run's registration with, which the
  caller passes from `QORY_RUN_KEY`, `session.EnvRunKey`; the session reads no variable
  itself. It reads the run key as a runner does, unverified, `runkey.Parse`: its
  `gateway_url` is the one address the run key is ever sent to, and its
  `gateway_public_key` the keys the gateway must prove it holds. A run key it cannot
  read is no run, "QORY_RUN_KEY is not a run key: " and the part that is wrong, never
  the run key; the run's id is the run key's `run_id`, and a `Spec.RunID` that is
  another is no run, "the run id <run id> is not the one QORY_RUN_KEY names, <its run
  id>". The session reaches the gateway's one address over TLS 1.3 alone, verifies the
  chain for the host name of `gateway_url` against the system's roots, and on every
  connection, the link's and the proxy's, sends `QORY-BIND` and sends the run key only
  once the gateway's `QORY-BOUND` proves, over the connection's TLS exporter value, that
  it holds a key the run key names. A gateway that fails the proof is "the gateway at
  <url> could not prove it holds a key the run key names", and an answer under a key the
  run key does not name, or under none, "the gateway at <url> answered under a key the
  run key does not name", a `*server.GatewayKeyError` whose `Unproven` tells the two
  apart: before the run starts the run does not start with that text, and once it runs
  such an answer is no answer, and nothing of it is applied. A `RemoteGateway` holds no
  access key, and prints as the URL its run key names, `(no run key)` or
  `(not a run key)`, never the run key. The discovery's proxy is the gateway's one
  address; the run request carries no labels, no `about` and no narrowing, the run's
  labels and what it is about being the starter's registration's, so `Spec.Labels` and
  `Spec.About` are neither sent nor reported there; the run answer has no labels and no
  proxy secret, and the session's `dev.qory.run.started` has no labels and no `about`.
  The gateway's refusals of the run key, `400` `run_key_invalid`, and `409`
  `wrong_gateway`, `run_key_expired` and `run_attached`, return a `*session.Refusal`
  with the gateway's message as its text. Agent traffic goes through the session's
  forwarder to the gateway's one address over TLS, each connection bound and opened with
  `QORY-RELAY` and the run key. Without a wall the agent's proxy URL is the forwarder on
  loopback, `http://qory:<password>@127.0.0.1:<port>`, the password a secret the session
  makes for the run's forwarder alone, 32 bytes from the system's random source in
  base64url, which lives as long as the run and is never logged or recorded: the first
  request of every connection must carry it in its one `Proxy-Authorization`, Basic, the
  user name ignored, compared in constant time. The forwarder reads at most 16 KiB of
  that request's head, 8 KiB a line and 100 lines, before its password, takes the header
  off, and closes a connection without it, or with a longer head, unanswered, before
  anything reaches the gateway. Behind a wall the relay opens every connection with
  `QORY-RELAY` and a hop secret of the run's forwarder alone, 256 bits from the system's
  random source, `wall.Launch.ProxyToken`, which the forwarder compares in constant time
  and takes off, closing a connection without it unanswered. The run key is in no file
  and no agent's environment: the session takes `QORY_RUN_KEY` out of every agent's
  environment, the one it inherits among them. On one machine an unwalled agent's proxy
  URL carries a password of the run's forwarder as well, made and checked the same way
  (Upgrading, above).
- `session.Resend(ctx, session.ResendSpec)` sends a separate gateway what a run's
  session did not deliver to it, from the run directory on the session's machine,
  through the run's `RemoteGateway` with its run key, which the caller passes from
  `QORY_RUN_KEY`, since the run directory never holds it. Every event of `session.jsonl`
  the link takes that `delivered.log` does not name is posted in order, in the link's
  batches, until the gateway accepts it or the context ends, and what it does not accept
  is under `undelivered/` again, unless the gateway ended the run; the events the
  session records only in the session's record are not sent. A record that owes nothing
  is sent nothing, with no request and no run key needed, and the result is the zero
  `ResendResult`. A record with no `delivered.log`, of a run that never opened at the
  gateway, a run refused at its run request say, is `NotOpened`, left as it is and sent
  nothing, with no request. A record that owes something is refused before any request
  without a run key, "resend <dir>: the run key is needed to send to its gateway; set
  QORY_RUN_KEY", with one it cannot read, "QORY_RUN_KEY is not a run key: " and the part
  that is wrong, and with the run key of another run, "resend <dir>: QORY_RUN_KEY names
  the run <run id>, not this one". A run the gateway has ended answers with its `410`:
  `RunClosed`, with `ClosedReason`, and nothing more is sent. Once something was sent,
  `State` and `Reason` say how the run ended where that is known: the state and the
  reason the gateway's `410` says, as the session records them, else those of the
  record's `dev.qory.run.exited`. The `dev.qory.run.exited` the session posted is sent
  again; the one it records after the gateway ended the run is the session's alone, and
  is never sent: `delivered.log` says `stopped` before it, whether the `410` answered a
  batch or a reload. A refusal of the run key the gateway passes on, `400`
  `run_key_invalid`, or `409` `wrong_gateway`, `run_key_expired` or `run_attached`, at
  the discovery or at a batch, is a `*session.Refusal` from `gateway`, its code, status
  and text the gateway's, and stops the resend with the events left under
  `undelivered/`; so does a `401` `unauthorized`, which the gateway does not send, so a
  resend never sends again into one. Any other refusal of a batch is sent again. The
  record is never completed: the gateway writes the end of a run whose session was lost.
  A record its session holds is `session.ErrRunning`, and a directory with
  `events.jsonl` is a gateway's record. After a gateway restart, the gateway's resend
  completes the run `gateway_lost`.
- `session.BehindGateway(dir)` reports whether a run directory holds a session's record
  behind a separate gateway, which `session.Resend` sends: whether it holds
  `separate-gateway`, `session.GatewayMark`, as a regular file, not followed if it is a
  symbolic link, whatever else it holds and wherever the directory is; an error other
  than a missing name is returned. The session writes the mark, an empty file, as it
  creates `session.jsonl` behind a separate gateway, and no other writer of a run
  directory writes it.
- `Result.RunClosed` and `Result.ClosedReason`: a run the gateway closed, by a `410` on
  the gateway's link or the gateway's `400` to a batch, says with what code,
  `run_closed`, `stopped`, `session_lost` or `batch_refused`. The runtime is stopped as
  at its time limit, and the session's record has `dev.qory.run.exited` with the state
  and the reason the `410` says, such as `cancelled` and `no_longer_needed`, and the
  runtime's exit status: `batch_refused` as the reason after a refused batch, and
  `failed` with the code as the reason when the `410` carries no state, or one the
  schema refuses. A run the gateway closed before its runtime started is a
  `*session.Refusal` with the code, status `410` and the text
  `the run did not start: it has ended already`, and records `dev.qory.run.refused` as
  before.
- `Result.State` and `Result.Reason` say how the run ended, as the session's
  `dev.qory.run.exited` does. A runtime that exits by itself is decided by its exit,
  `succeeded` on 0 and `failed` otherwise, with no reason. Once the runtime has exited,
  the caller's context ending does not cut the record short: `dev.qory.run.exited` is
  still written and posted, and `Run` returns after it, within its bounds. A run whose
  caller's context had ended when the runtime's exit was observed, a Ctrl-C or a signal
  to the caller, is `cancelled` with `interrupted`, in the record, on the link and in
  the result, with the runtime's `exit_code` and `signal`, whatever they are. At the
  time limit the run is `cancelled` with `timeout`, `Result.TimedOut`, when the
  session's stop signal reached the runtime before its exit was observed; a runtime that
  exited by itself before it is decided by its exit, whatever its status. A runtime that
  exits 0 at the session's stop, at the context's end or at the limit, has exited 0:
  `session.Run` records its `dev.qory.run.exited` and returns its result, where it
  returned the context's error and recorded no `dev.qory.run.exited`.
  `Result.Cancelled`, beside `Result.TimedOut`, says the caller's context had ended when
  the session observed the runtime's exit, whoever stopped the runtime; a context that
  ends after the exit, while the sinks close, leaves it false, as do the time limit,
  `Result.TimedOut`, a run the gateway closed first, `Result.RunClosed`, and a signal
  from elsewhere: it is never true with either. When it is true, `dev.qory.run.exited`
  is `cancelled` with `interrupted`.
- The session fetches the run's configuration from the gateway again whenever the
  gateway's answers carry a new run-configuration digest, and records it in another
  `dev.qory.run.policy_applied`.
- A run configuration's `variables` reach the agent's process: for each name an object
  with its string `value`, as the server resolved it. An attribute beside `value` is
  ignored. For each name the run takes the value of the highest source that sets it: the
  fixed names, those the session, the proxy, the wall, the runtime's preparation and the
  placeholders set and the values the harness computes; then the server's; the run's;
  the machine's; the harness's written defaults; and what the run inherits. The deny
  list, which is `denied-variables.json`, the runtime's `denies` and `Variables.Deny`,
  matched regardless of case with `*` for any run of characters, leaves out a value of
  the server, the run, the machine or the harness's defaults; its built-in entries leave
  out a value the harness computes too. The server's value of a variable the runtime
  declares or reserves, or of one a credential is read from, is left out. A run without
  a wall takes none of the server's variables unless `Variables.Unwalled` is `accept`;
  the run's variables apply with or without a wall. A value that loses is left out and
  the run starts. The variables are fixed when the run starts. Tools, the relay, the
  agent's Docker daemon and the wall's `docker` command keep their environment.
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
- No program Forager starts on the machine receives `QORY_ACCESS_KEY_SECRET`,
  `QORY_ACCESS_KEY_ID`, `QORY_APIARY_PUBLIC_KEY` or `QORY_RUN_KEY`, whatever brought
  them: not the `docker` command a wall runs or the credential helpers it starts, not a
  gateway's credential programs and tools, and not an agent, walled or not.
  `accesskey.WithoutVariables` leaves all four out, `accesskey.EnvRunKey` names the run
  key's, and `session.EnvRunKey` keeps its name and value.
- A walled run refuses a mount, or the workspace, that is, contains or lies inside one of
  Forager's files, `mount_contains_forager_files`, before it contacts the server and
  before anything starts, `Local` included. `session.Spec` has `ForagerFiles`, the
  absolute paths the caller lists as Forager's files, such as the directory of qory's
  `forager.yaml`. Beside them the session checks the directory of every credential and
  tool program the machine defines, the file a credential is read from, the private
  directories of every run's tool sockets, record sockets (`qory-run-*`) and Docker wall
  environment files (`qory-wall-*`) in the system's temporary directory, the pattern of
  every gateway's link directories there (`qory-link-*`), whatever the run's gateway, so
  a walled run behind a separate gateway refuses a mount that reaches one as a run on a
  local gateway does, and the files a wall lists
  through the new `wall.Filer`: `wall.Docker` lists the directory of the `docker` command,
  of the helper, and the command's configuration directory. The refusal's `Names` are the
  mount and Forager's file, in that order. `session.Overlap` returns how a mount and a
  path stand, `is`, `contains` or `lies inside`, after symbolic links and by whole
  components, with the filesystem judging which directories are the same, case and bind
  mounts included. A link whose target does not exist yet is followed to the target, a
  path that cannot be resolved is no run, and the check runs again just before the
  enclosure is built.
- No walled run binds from a place a walled agent of the same user can change: no name
  on the way to a bind source is looked up in a writable bind, the run's or another
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
  run side by side, and two read-only binds never conflict. A run whose helper, or
  another directory of Forager's its wall binds, lies inside a writable bind of such a
  run, or is reached through one, does not start. The session keeps the walled runs
  still going in a separate registry, per user, `$XDG_STATE_HOME/qory-forager/walled`,
  else `~/.local/state/qory-forager/walled`, 0700: a file per run, named by its run id,
  with its process id and its binds, each as passed, as resolved, with the entries its
  names are looked up as, whether writable, and what it is when it is not a place; the
  file is held locked for the run's life and removed when it ends, kept when the wall
  could not be removed. A file whose lock is free is the run of a session that is gone:
  it is still going while the container engine its entry records holds a container
  labelled with its run id, in any state, and is removed when the engine holds none. A
  run that cannot ask that engine, whose engine answers with another id than the one
  recorded, or that reads such an entry that records no id for a command other than
  podman, neither a pinned selection nor an id for podman, no engine, or that cannot be
  read, is refused with `engine_unreachable`; `Names` holds the earlier run's id and
  then the absolute path of its registry entry, and the sentence reads "Docker could not
  be asked whether the walled run <id> is still going, so the run does not start: <the
  error>". A bind of another run's, or a directory on the way to it, that is gone is
  compared by its names, like a part that does not exist yet; any other failure to
  resolve one stops the run. A run checks its binds and adds its entry under a lock of
  the registry's, before it contacts the server, and again, with its wall's extra binds,
  just before the enclosure binds them. `events/run.refused.schema.json` lists the four
  codes.
- The session passes every bind's path clean, and a run whose working directory lies in
  none of its binds fails.
- A run refused with a code is a `session.Refusal`, with the code and the server's
  status: `apiary_public_key_missing` for a server without a pin, before any request;
  `unauthorized` for a `401`; `answer_unsigned` for an answer that does not verify; and
  `instance_limit` when the node's live instances are at its limit.
- `session.Spec.SocketGrace` sets how long the run socket keeps accepting after the
  runtime exits; zero keeps 200 ms. It is for tests.

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
- `e2e.Options` has `Recorders`: three `e2e.Recorder` values, each the helper started
  with `e2e.RecorderArgs` and `e2e.RecorderEnv()` in a separate container, in this
  order: the host of a runtime's API key, the host of its OAuth credential, then a host
  the policy allows with no credential. A `Recorder` holds the `Host` the proxy reaches
  it on and a `Recorded` function that returns the content of `e2e.RecorderFile` in its
  container. An adapter's test that passes none skips the checks of a runtime's key,
  `QORY_WALL_REQUIRE` turns those skips into failures, and a number other than none or
  three fails the suite. A recorder prints `e2e.RecorderReady` once it listens, and
  `e2e.AwaitRecorder` waits for that line in its container's log, and fails with the log
  at once when the container stops first; a recorder's container started without `--rm`
  keeps that log. With `Recorders`, `e2e.Run` points the roots of the process, and the
  programs it starts within `Run`, at the suite's authority alone, with `SSL_CERT_FILE`
  and `SSL_CERT_DIR`. The process reads its roots once, at its first verification of a
  certificate, so the test binary's first verification must come within `Run`; from
  then on, for the rest of the process, it trusts only the suite's authority.
  `TestDockerConforms` starts the recorders from `busybox:stable`.

#### Added

- The wall's conformance suite checks a runtime's two credentials from inside the
  enclosure, as Claude Code sends them: an API key in `x-api-key` and an OAuth
  credential as a bearer, each a fake key for a recorder that acts as its host. Each key
  reaches its host once, in its header and in place of the stand-in; another allowed
  host, plainly and through a tunnel, receives the stand-ins and no key; the probe's
  environment and every `/proc/*/environ` it reads contain the stand-ins and no key; and
  the run's directory, output and reports contain no key, after the interactive run as
  well. The suite points its process's roots at a separate authority with
  `SSL_CERT_FILE` and `SSL_CERT_DIR`, so the proxy verifies the recorders. The proxy's
  tests cover both schemes as well, with a request that carries both stand-ins.
- `TestDockerClaudeCodeThroughTheWall` runs Claude Code itself behind the Docker
  adapter, with `QORY_WALL_CLAUDE_IMAGE` set to an image with `claude` on its `PATH`:
  `ANTHROPIC_BASE_URL` points it at a recorder that answers as the Messages API, once
  with an API key and once with an OAuth credential. Claude Code prints the recorder's
  answer, each request carries the fake key in the credential's header and no stand-in,
  and the record lists one request through the proxy for each the recorder received,
  each to the recorder.
- `TestDockerClaudeCodeThroughTheWall` also runs Claude Code interactively, on a
  pseudo-terminal with a separate home whose configuration has the onboarding done and
  the workspace trusted, with the API key and with the OAuth credential. The test types
  a prompt once Claude Code shows its input and leaves with `/exit`; with the API key,
  Claude Code reaches its input with no approval prompt for the key, and the
  configuration then holds the placeholder value's entry and every member it held
  before. Every run sets `ANTHROPIC_AUTH_TOKEN` and the other credential's variable
  empty, and the recorder receives the chosen credential's header alone, so Claude Code
  reads an empty variable as unset and uses the placeholder.
- `session`'s tests run a real session behind a real separate gateway, end to end,
  against the test's server: the session, given the run key alone, binds every
  connection to the gateway's one address and checks every answer's signature; the
  gateway attaches the run and writes its record's first line with the labels the attach
  gave back; the session's batches are numbered and reach the server; and a change of
  the run's configuration during the run reaches the session as a reload, recorded in a
  second `dev.qory.run.policy_applied`, which the gateway numbers and the server
  receives.

#### Changed

- The wall's conformance suite is package `e2e`, from `wall/walltest`. CI runs gofmt,
  vet, the tests, the build and revive in one job per part, `core`, `gateway`, `wall`,
  `session` and `e2e`; the job named `Go tests` passes when they all pass; and the two
  wall conformance jobs run `./e2e`. A test in `internal/importrules` holds each part's
  imports to the rules: the core imports no part; the gateway and the wall import the
  core; the session imports the core and the wall, and its tests package `gateway`,
  using only its surface; and only `e2e` imports the session.

#### Fixed

- The wall's conformance suite missed that the agent's `docker` command could not read
  its configuration: the containers it starts through the Engine API receive the relay's
  address. It also starts one with the image's `docker` command, as the agent's user and
  with no proxy setting passed to it, and requires it to reach the origin through the
  proxy and nothing else, so the image of `TestDockerNestedConforms` contains the docker
  command as well as dockerd.

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

[Unreleased]: https://github.com/qoryai/forager/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/qoryai/forager/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/qoryai/runner/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/qoryai/runner/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/qoryai/runner/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/qoryai/runner/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/qoryai/runner/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/qoryai/runner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/qoryai/runner/compare/v0.1.0...v0.2.0
