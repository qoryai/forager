# Credentials

Forager keeps its credentials out of the session. Behind a wall, it keeps the run's
credentials outside the container too. Its proxy sets each credential on the way out.

The gateway sets every credential, with or without a wall. A wall also makes a
connection around the proxy fail.

Without a wall, Forager gives the run only placeholders, but the agent can read every credential the machine already holds; run a brokered run on a machine that holds none.

## Without a wall

- The agent's environment gets the placeholders. A placeholder wins over a value the
  run inherits, and the variables the machine's credentials are read from are left out.
- The run trusts the gateway through `ca-bundle.pem` in the run directory: the
  machine's authorities, then the run's certificate. `SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `AWS_CA_BUNDLE`
  point at it, or the names the caller gives in `OpenSpec.CAEnv`. `qory` is to give them
  from `wall.ca_env`.
- Forager reads the machine's authorities from the first of
  `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
  `/etc/ssl/ca-bundle.pem` and `/etc/ssl/cert.pem` that contains a certificate. On a
  machine with none of them the run does not start.
- A program that ignores the proxy sends only the placeholder, and its connection is
  not recorded.
- Without a model key, the run starts, and Claude Code can use the machine's Claude
  login. With one, Claude Code gets the model key's placeholder and endpoint (see
  [Model keys](#model-keys)).
- In an interactive run, Claude Code shows its approval prompt for the placeholder of
  `ANTHROPIC_API_KEY` once; approve it. Behind a wall the session approves it inside
  the container.

## What goes into the container

Behind a wall, the container gets only what the run lists of the machine's environment:

- `wall.env` is the whole of the node's environment that goes in, by name.
- A model key's variable, such as `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` or
  `CLAUDE_CODE_OAUTH_TOKEN`, and a forge token's, such as `GH_TOKEN` or `GITLAB_TOKEN`,
  listed in `wall.env` is left out: the built-in deny list,
  `denied-variables.json`, lists them in `model_keys` and `forge_tokens`, and the run
  reports `Move <NAME> to the gateway's credentials in forager.yaml: the run leaves out
  the value that wall.env passes, ...`. Define the credential under
  `gateway.credentials` instead.
- A credential defined under `gateway.credentials`, and selected by the run's policy,
  stays outside instead.

For a credential that stays outside:

- The proxy sets it on the requests to its hosts, such as `git.example`, or to a
  model key's endpoint host, such as `api.model.example`.
- The container gets a placeholder, such as `GITHUB_TOKEN` or `ANTHROPIC_API_KEY`,
  that is no credential.

## How it works

The machine defines credentials. A run's policy selects among them by name, and defines
none. A run configuration from Qory Apiary may also list credentials whose values Qory
Apiary stores; see [From Qory Apiary](#from-qory-apiary).

A credential's secret comes from one of three sources:

| Source    | The secret is                                 |
| --------- | --------------------------------------------- |
| `env`     | a variable of Forager's environment           |
| `file`    | a file's content, read again on each use      |
| `adapter` | what a program of the machine's prints        |

- The gateway keeps each secret in memory, outside the container.
- For the hosts a credential is for, the proxy ends the container's TLS itself. It uses
  an authority made for the run. The authority's key never leaves the gateway.
- A request that carries a credential goes to its host over HTTP/1.1, so no HTTP/2
  header table (HPACK) keeps a copy of the secret. Other requests may use HTTP/2.
- When the run ends, the gateway closes every idle connection to a credential's host.
  While the run goes on, a connection idle for 90 seconds closes.
- A placeholder has the value `qory-sets-the-credential-outside-the-enclosure`. A model
  key's placeholder contains the key's name, such as
  `qory-model-sets-the-credential-outside-the-enclosure` for the key `model`. The proxy
  replaces what the program sends.
- The record lists each credential the run uses, by name. No event contains a
  credential's secret.
- When an adapter fails, the gateway reports the first line it wrote to standard error,
  with `***` in place of text in the shape of a known key (`mask.Shapes`) and, for a
  renewal, of the token the gateway holds for that credential. When an adapter's output
  fails `credential.schema.json`, the gateway reports `Fix the output of the adapter
  <PATH> to match credential.schema.json: /apply/0/header fails pattern; ...`: each
  failing location and keyword, at most 5 and then how many more, with no value, and no
  member name other than the schema's. A tool's lines on standard error have `***` in place of
  the shapes too.
- The route to the caller, `http://host.qory.invalid` in `QORY_HOST_URL`, sets no
  credential. The session's forwarder takes every header off a request but
  `Content-Type`, `Proxy-Authorization` among them, adds `Qory-Session`, the number of
  the session that sent the request, and passes the request only to the handler the
  caller gave in `OpenSpec.QoryRoute`. Behind a wall, the agent's proxy URL then has a
  password of the session's launch alone, which the run's masker replaces in the
  output. The forwarder serves the route only to a request with that password from the
  address of the session's agent container, which the wall's relay writes for each
  connection. The setup container never reaches the handler, also with the password.
  See [Forager from Go](go.md#the-route-to-the-caller).

In `qory`, the `gateway.credentials` section of `forager.yaml` defines them. See
[qory's docs][qory-credentials].

[qory-credentials]: https://github.com/qoryai/qory/blob/main/docs/run.md#credentials-the-agent-never-has

## What the agent gets back

A host can send back what it received: the answer to a `TRACE`, a debug endpoint, an
error page. The proxy replaces a credential's value with its placeholder in every answer
from a host that gets the credential, before the answer reaches the agent.

- Send each request to such a host as `https://` through `CONNECT`, as an HTTPS client
  behind a proxy does. If the policy allows the host, a plain request, `http://` or an
  absolute-form `https://` sent without `CONNECT`, gets a `403` from the gateway and
  never reaches the host, in either mode, with the rule `wall:plain-request`.
- A `TRACE` or `TRACK` through `CONNECT` to such a host gets a `405` from the gateway
  and never reaches the host, in either mode, with the rule `wall:echo-method`. Use
  another method.
- The proxy replaces the value in the answer's headers, those of a `1xx` and the
  trailer included, in their names and values in any case, and in the body as it
  streams.
- For a `basic` credential, the proxy also replaces the base64 of the username and the
  value, as the header has it, with or without its padding.
- The proxy also looks for each form percent-encoded and JSON-escaped. For a key of
  letters, digits, `-`, `_`, `.` and `~`, such as an API key, these forms are the key
  itself. A base64 form with `+` or `/` differs percent-encoded, and a `/` differs in
  JSON whose encoder writes it as `\/`.
- The request goes to the host with `Accept-Encoding: identity`, and without `Range`,
  `If-Range`, `Upgrade` and any trailer: a trailer can contain a header the proxy sets,
  such as a model key's account header, beside the proxy's value. If the host compresses its answer anyway, or switches
  protocols, the agent gets a `502` from the gateway.
- An answer with a body has no `Content-Length` and comes chunked, since the
  placeholder and the value differ in length; an empty answer may have
  `Content-Length: 0`.

The proxy does not replace:

- a part of the value;
- a copy in the body in another case, or in another encoding, such as hex;
- a copy inside a compressed file, such as a zip archive;
- a value the credential had before a renewal;
- anything from another name or address of the same server that no credential is for,
  such as its IP address: the proxy replaces the value only in answers from a host a
  credential is for.

A tool's answers are the tool's.

## Model keys

A model key is the key of a model API. In `forager.yaml`, a model key has `format`,
`endpoint` and `auth` in place of `hosts`, `paths` and `placeholders`:

```yaml
# ~/.config/qory/forager.yaml
gateway:
  credentials:
    model:
      env: MODEL_API_KEY                    # or file, or adapter
      format: anthropic-messages            # the API the endpoint serves
      endpoint: https://api.model.example/anthropic
      auth: {scheme: header, header: x-api-key}
      key_prefixes: [sk-ant-]               # optional
```

- `format` is one of `anthropic-messages`, `openai-responses`, `openai-chat` and
  `gemini`.
- `endpoint` is the base URL of the model API: `https`, a host, an optional port and
  path, and no user name, query or fragment. The proxy sets the key on every path and
  on any port of the endpoint's host, and on no other host.
- `auth` is `{scheme: bearer}`, `{scheme: header, header: …}` or
  `{scheme: basic, username: …}`. Add `oauth: true` to a bearer for an OAuth token,
  such as a Claude subscription login's.
- `key_prefixes`, optional, are 1 to 4 prefixes, each 1 to 32 printable ASCII
  characters without a space. If the key starts with none of them, the run does not
  start, and the message does not contain the key. If a `file` key read again later
  starts with none of them, the gateway keeps setting the key it read when the run
  started.
- Under `egress.mode: enforce`, the run's allow list must cover the endpoint's host.

The session gives the key to the runtime's variable for its format and `auth`. For
Claude Code:

| `auth` | Claude Code's variable |
| --- | --- |
| `{scheme: header, header: x-api-key}` | `ANTHROPIC_API_KEY` |
| `{scheme: bearer}` | `ANTHROPIC_AUTH_TOKEN` |
| `{scheme: bearer, oauth: true}` | `CLAUDE_CODE_OAUTH_TOKEN` |

The session also sets `ANTHROPIC_BASE_URL` to the endpoint. Every other value of
`ANTHROPIC_BASE_URL`, from the server, `--env`, `wall.env`, the harness or the shell, is
left out. Claude Code's other key variables get no value in its process environment
either: with the start key in `ANTHROPIC_API_KEY`, a value of `ANTHROPIC_AUTH_TOKEN` or
`CLAUDE_CODE_OAUTH_TOKEN` from any of these sources or the runtime's preparation is left
out, and behind a wall the image's value is unset. One exception applies: when the run
has an authority, a variable that points at the CA bundle is set to the bundle's path,
even one of these. Without a wall these are the names the caller gives in
`OpenSpec.CAEnv`; `qory` is to set it from `wall.ca_env`. Behind a wall they are the names
in `CAEnv` of `wall.Docker`. A nil list means `wall.DefaultCAEnv`.

Claude Code also applies the `env` object of a settings file. The session copies the
`env` of the `--settings` file into the run's `settings.json` without
`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` and
`ANTHROPIC_BASE_URL`, and without the variables Claude Code's descriptor lists in
`denies` and, behind a wall, in its model `overrides`, as the session leaves those out
of Claude Code's process environment. It keeps the other members. It also leaves out the
file's top-level `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`,
`gcpAuthRefresh` and `modelOverrides`: Claude Code ranks `apiKeyHelper` above
`CLAUDE_CODE_OAUTH_TOKEN`, and the others set cloud credentials or a provider's model
ids. In a run whose image is named by its reference, a path in it is written as the
enclosure sees it. The session does not read Claude Code's other settings files, such as
`~/.claude/settings.json`, or the workspace's `.claude/settings.json`, which Claude Code
reads unless the launch passes `--setting-sources user`. A value set in one of them can
reach Claude Code.

If the runtime reads no key for the format or the `auth`, the run stops with
`run_configuration_invalid`.

A run may have several model keys, from `forager.yaml` and from the control plane. The
gateway holds every one and sets only the start key, the one the runtime starts with.
The proxy sets the start key only on a request to its endpoint's host that carries its
placeholder. Under `enforce`, a request to a host that only model keys other than the running
session's cover passes with no key set and needs no path rule, since a model provider
is an integration that a policy cannot deny. The proxy sets no value of such a key, and
replaces each model key's value in the answers from the key's host. With two or more model keys, the run configuration's `model_credential`
names the start key; without it, the run stops with `run_configuration_invalid`. With
one, that one is the start key. A session joined with no runtime,
`session.SessionSpec.Runtime` nil, has no start key: its program gets no model key's
variable, placeholder or endpoint.

A credential without `format` whose `placeholders` list a model key's variable, such as
`ANTHROPIC_API_KEY`, stops the run with `run_configuration_invalid`. Rewrite it as a
model key.

### Several keys of one provider

A key group lets a run go on when the model provider returns a limit refusal for a key.
Each API credential of the run configuration has `group`, the id of its provider, such
as `anthropic`, and the API credentials with one `group` value are one key group, in the
order of `credentials`. A run can have several groups, such as one of `anthropic` keys
and one of `openai` keys, and each group rotates, cools down and stops apart from the
others. The keys of one group need one `format`, `endpoint` and `auth`: two that differ
stop the run with `run_configuration_invalid`, such as `Give the keys of group
"anthropic" one format, endpoint and auth.` A key of `forager.yaml` has no `group` and
is never in a key group: a session on it gets that key alone.

A session starts on the key in its join request's `model_credential`, or on the start
key when the request has none. For a key of a group, the session gets the group's active
key. A group other than the start key's that no session used yet starts at the key in
the request, or, when that key is in cooldown or out, at the key a `429` switches to, as
below. When no key of that group is usable, the session starts at the key in the
request: its first model request gets the gateway's `429` with no `Retry-After`, and the
session stops at its next batch, as below.

1. Optionally set `pause_for_s` on a key of the group: the cooldown in seconds after a
   refusal with no reset, 1 to 604800. A key without it has a cooldown of 60 seconds
   for an API key, and of 3600 seconds for a subscription, a key whose `auth` has
   `oauth`. A `pause_for_s` of 0 stops the run with `run_configuration_invalid`.
2. Optionally set `schedule_resets_at`, the time a subscription's weekly limit resets,
   for a refusal with no reset. A key with it ignores `pause_for_s`.
3. Optionally set `use_up_to_percent`, 1 to 99, with `use_up_to_windows`, the limit
   windows it applies to, such as `["five_hour", "seven_day"]` for a subscription. Runs
   then stop using the key once a listed window's use reaches the percentage, until
   that window resets, and the rest of the window stays for the key's other uses.
   Set both or neither: a percentage outside 1 to 99, or one of the two alone, stops
   the run with `run_configuration_invalid`.

The keys of a group share one placeholder, that of the group's first key, and while a
session runs on the group, the proxy sets one of them, the group's active key, and no key
of another group. When the provider returns `429` for the active key, the proxy puts the key in
cooldown until the reset in the answer's headers, makes another key out of cooldown the
active key, and sends the request again with it. The proxy takes a key with no known
reset first, by the order, then the key whose limit resets soonest. A key with `cooldown_until` stays in cooldown until that time, until the
provider returns a `2xx` for it, or until the answer to a later model keys report has
an entry of the key that is not `rejected`. The session gets only the answer to that
second request. The proxy keeps a copy of each request
body up to 8 MiB for this; a larger body goes once.

Keys of the format `openai-responses` keep one key for each session, because Codex
sends its reasoning encrypted for one account. The proxy sends no such request again:
the provider's first `429` puts the key in cooldown and reaches Codex, and the run
pauses as below, also when another key is out of cooldown. The active key changes only
when a session joins: a key that goes into cooldown during a session for another
reason, such as its Use up to percentage, pauses the run the same way.

A key with `use_up_to_percent` is also in cooldown while a window in its
`use_up_to_windows` is at or above the percentage, until that window resets. The
gateway reads each window's use from the provider's responses to the run and from the
answers to its model keys reports, so a key that another run took to its percentage is
in cooldown too. The response that took the key to its percentage reaches the session
as the provider sent it, and the next request goes with the next key. A key can pass
its percentage by the requests already in flight on it when that response arrives.
When every key of the session's group is in cooldown, the run pauses as below, also
when no provider returned a `429`.

When no key of the session's group is left out of cooldown, the session gets the
`429`, and the proxy sends no more requests with the group's placeholder until the
session's join ends: each gets a `429` from the gateway that starts `The gateway sends
no more model requests in this session:`. The gateway's answer to the session's next
batch has `stop`, `model_key_limit`, so the session stops, and the run pauses at that
session. A key of another group never takes the place of the session's group. The next
join gets the group's active key again.

The gateway reports each key's limit windows to the control plane, at most once a
second, and takes the cooldowns other runs found from the answer. A cooldown from
another run counts for at most 7 days, and so does a reset. A run then stops
setting a key that another run found at its limit once the answer to its next report
arrives: until then, up to about a second after the other run's refusal and longer
while a report waits for a retry, the run can still send a request with that key and
get the refusal itself. The contract's
[§The server, The model keys](../contracts/forager/v1/README.md#the-server) lists the
report and its answers. The gateway writes one log line for each limit response, with the
status, the names of the limit headers and the error's type, and no value.

## From Qory Apiary

A run configuration may list `credentials`, with no value; the control plane stores the
values. An entry is one of two kinds:

- An API credential is a model key: `{name, format, endpoint, auth, paths,
  key_prefixes}`, as in [Model keys](#model-keys), with `paths` and an account header
  as in [Paths and an account header](#paths-and-an-account-header).
- A host credential is any other secret: `{name, apply, placeholders}`. Each of its 1
  to 16 `apply` items is one place and way the value is set: `{hosts, scheme, username,
  header, paths, push_ref}`.

```json
{"version": 1,
 "model_credential": "model",
 "credentials": [
   {"name": "model", "group": "anthropic", "format": "anthropic-messages",
    "endpoint": "https://api.model.example/anthropic",
    "auth": {"scheme": "header", "header": "x-api-key"},
    "key_prefixes": ["sk-ant-"]},
   {"name": "forge",
    "apply": [{"hosts": ["git.example"], "scheme": "basic",
               "username": "x-access-token", "paths": ["/example-org/app.git/*"]},
              {"hosts": ["api.git.example"], "scheme": "bearer",
               "paths": ["/repos/example-org/app/*"]}],
    "placeholders": ["GIT_TOKEN"]}]}
```

- A path in `paths` is matched whole, or up to a final `*` as a prefix. A segment
  written `{}` matches any one segment: `/repos/example-org/app/pulls/{}` matches
  `/repos/example-org/app/pulls/12`, and not `/repos/example-org/app/pulls/12/merge`.
  So an item can allow a repository's pull requests and leave out their merge. Two
  paths of one host overlap when one request can match both, and a `{}` overlaps
  every segment that is not empty.
- `push_ref` is the one branch a git push through the item may change, such as
  `refs/heads/qory/wi_01`. The proxy reads every push to a host of a credential before
  it sends a byte: each ref the push creates, updates or deletes must be `push_ref`.
  A push through an item with no `push_ref`, a push to another branch or a tag, a
  signed push, and a push with push options (`git push -o`) get a `403`, and the
  record has the request `denied` with the rule `wall:push-ref`. Through such an item a push to another branch fails with:

  ```text
  qory: push only refs/heads/qory/wi_01.
  The push of "refs/heads/main" to git.example/example-org/app.git/git-receive-pack was not sent: it creates, updates or deletes that ref.
  ```

  git itself prints only `The requested URL returned error: 403`. An adapter's output
  may have `push_ref` on an item in the same form. A credential defined with `env` or
  `file` has no `push_ref`, so no push goes through it.

- The run needs no wall: the gateway sets these credentials with or without one.
  On an unwalled local run the agent can read the gateway's access key, which opens the
  sealed values. The program that starts the run must refuse stored credentials there,
  as qory's `key_needs_wall` does.
- When the run starts, the gateway fetches the values, sealed to its access key, and
  opens them. The values stay outside the container. A model key's value that starts
  with none of its `key_prefixes` stops the run with `run_configuration_invalid`.
- The control plane may send a value with `expires_at`, when it stops working, and
  `apply`, where it is set. `apply` may narrow the entry's items, such as to fewer hosts
  or paths, with the same `push_ref`, and never widen them. A value that expired
  before the run started, or an item outside its entry, stops the run with
  `run_configuration_invalid`.
- The gateway fetches a value with `expires_at` again 5 minutes before it expires, and
  after a host answers `401` to a request with the value, at most every 30 seconds per
  credential. The renewed value takes the old value's place, and the gateway overwrites the
  old bytes with zeros. A value without `expires_at` is fetched once. A model key is
  renewed in a request that names it alone, so a key the control plane cannot seal
  blocks no other credential's renewal.
- If a renewal fails, or its `expires_at` is not after the machine's clock, the run
  keeps the old value and the gateway reports `run <run id>: If this repeats, check the
  control plane: credential "forge" was not renewed:` with the cause, then tries again
  30 seconds later. At `expires_at` with no renewal, the
  run's record gets one line, `Start another run once the control plane answers:
  credential "forge" expired at 2026-10-24T13:00:00Z`, and the proxy sets the value no
  more.
- On a host that one of these credentials is for, its value replaces the machine's
  credential, such as the model key in `forager.yaml` for the same endpoint host,
  whatever its name.
- `model_credential` names the start key: an API credential of the run configuration,
  or a model key of `forager.yaml`.
- A placeholder goes only into a variable for a credential. A host credential whose
  `placeholders` list a variable the runtime denies, a model override, the model
  endpoint's variable or a model key's variable stops the run
  (`run_configuration_invalid`). The same holds for the run's placeholders from this
  machine's credentials and tools. A tool's variable, such as `GITHUB_TOKEN`, is fine.
- The credentials and `model_credential` are fixed for the run: a renewal changes only
  a value. A reload that changes them fails, and the run keeps its policy. So does a reload that selects another
  model key of this machine's as the start key, with or without `model_credential`.
- Without `credentials`, the run gets the machine's credentials as before.

A run configuration may also list `stack_hosts`, the hosts qory may fetch the run's
harness definition from before the first session joins, beside `gateway.stack_hosts`
in `forager.yaml`:

```json
{"version": 1, "stack_hosts": ["git.example", "api.git.example"]}
```

- The run's stack proxy allows these hosts until the run's first join request. It sets
  only the run's harness credentials ([Harness credentials](#harness-credentials)).
- The node's policy decides each host. A host passes when the node's policy allows it
  and has no path rule for it: the stack proxy does not check the node's path rules. A
  host the node's policy does not allow is refused with "qory: allow git.example in the
  node's policy, or list it in gateway.stack_hosts."
- Each decision of the stack proxy is a `dev.qory.run.egress` in the run's record, with
  `channel: stack`.
- Behind a wall or a separate gateway they open no address of the gateway's machine
  and no private network address. Such an address is reached only for a host that
  `gateway.stack_hosts` and the node's policy both list by name.
- They are fixed for the run. A reload that lists other `stack_hosts` fails, and the run
  keeps its policy.

### Paths and an account header

A model key from the control plane may have `paths`, 1 to 32 paths of its endpoint's
host, in a host credential's grammar. The proxy then sets the key only on those paths:
a request to another path of the host gets `403` under `enforce`, unless the run
policy's `egress.paths` match it, and then goes with no key. Such a key may share its
host with a host credential whose paths overlap none of its paths. A path with a `.`
or `..` segment, an empty segment, a backslash, or an encoded slash, backslash, dot or
percent sign stops the run with `run_configuration_invalid`, and so does a segment that
is one of those before its first `;` or `%3B`, such as `/a/..;/b`. The same rule applies
to the paths of a host credential's `apply` items.

A key whose `auth` has `oauth` may also have `account_header` and `account_claim`,
both or neither. The proxy sets the header beside the token, to the string that
`account_claim`, a JSON pointer, points at in the token's JWT payload. A ChatGPT
subscription login is such a key:

```json
{"name": "subscription", "group": "openai", "format": "openai-responses",
 "endpoint": "https://chatgpt.example/backend-api/codex",
 "auth": {"scheme": "bearer", "oauth": true, "account_header": "chatgpt-account-id",
          "account_claim": "/https:~1~1api.openai.com~1auth/chatgpt_account_id"},
 "paths": ["/backend-api/codex/*"]}
```

- The proxy checks no signature, and decodes at most 8 KiB of payload.
- The header the session sends under that name, in any letter case and with `_` for
  `-`, never reaches the provider.
- A key whose value has no such string when the run opens leaves its key group, and
  the run's record gets one line that starts with the fix and contains neither the
  value nor the claim. With no key left in a key group of the run, the start key's
  group or another, the run stops with `run_configuration_invalid` at its start.
- An `account_header` that frames the request, is hop-by-hop, is one the proxy sets,
  or is `Authorization` stops the run with `run_configuration_invalid`.

### A key the provider returns 401 for

A model provider's `401` to a request on the model API's path, `/v1/messages` under
the endpoint for `anthropic-messages` and `/responses` for `openai-responses`, takes the
key out of use:

1. A key whose value has `expires_at` is renewed at once. A value puts it back; the
   control plane's `409` takes it out for the run, and so do a first value the run
   cannot set, for a key with no value yet, and `expires_at` with no renewal; any other
   failure, including a renewed value the run cannot set, keeps it out of use, and the
   gateway tries again after 30 seconds.
   A key without `expires_at` leaves the key group for the run at once.
2. For `anthropic-messages` the proxy sends the request again with the next usable key.
   For `openai-responses`, and when no key is usable, the session gets the `401`, and
   the run stops: `paused` with `model_key_switch` when another key is usable, `failed`
   with `model_key_unauthorized` when every key is out and a `401` took at least one
   out, and `paused` with `model_key_limit` otherwise.
3. The gateway reports the keys out after a `401` to the control plane with its model
   keys report.

A `401` on another path of the host, such as an account check, reaches the session as
the provider sent it, and the gateway renews a key with `expires_at` as for any
credential.

### Harness credentials

A host credential with `purpose: harness` is for qory's fetch of the run's harness
definition, before the first session joins. Without `purpose`, or with `purpose: work`,
a host credential is for the run's work, as described in [From Qory Apiary](#from-qory-apiary).
An API credential has no `purpose`.

```json
{"version": 1,
 "stack_hosts": ["git.example"],
 "credentials": [
   {"name": "harness-1", "purpose": "harness",
    "apply": [{"hosts": ["git.example"], "scheme": "basic",
               "username": "x-access-token", "paths": ["/example-org/harness.git/*"]}]},
   {"name": "work-1",
    "apply": [{"hosts": ["git.example"], "scheme": "basic",
               "username": "x-access-token", "paths": ["/example-org/app.git/*"]}],
    "placeholders": ["GIT_TOKEN"]}]}
```

- Only the run's stack proxy sets a harness credential, on its hosts and paths. The
  run's proxy, which the sessions, `HostProxy` and the setup step go through, never sets
  one, and the run answer lists no host or placeholder for it.
- The run gets a certificate authority. `(*session.Run).StackProxy` returns its bundle
  in `CABundle`, and its CA variables in `Env`. On a walled run whose bundle could not
  be written, such as on a machine with no CA bundle file, `CABundle` is empty and
  `Env` has no CA variable. On a harness credential's host the stack
  proxy reads each request: it sets the value on the credential's paths and passes other
  paths with no value.
- The gateway fetches and renews the value as any other stored credential's. At the
  run's first join request it overwrites the value with zeros and stops its renewals.
- The stack proxy must allow each host of a harness credential: a host of
  `gateway.stack_hosts`, or a host of the run configuration's `stack_hosts` that the
  node's policy allows with no path rule. Otherwise the run stops with
  `run_configuration_invalid`, such as "Add git.example to a stack_hosts list: the
  harness credential "harness-1" is for it". A harness credential with `placeholders`
  stops the run with "Remove placeholders from the harness credential "harness-1": no
  session gets it".
- Two harness credentials on one host, or two `apply` items of one, need paths, and
  their paths must not overlap. A work credential on the same host is fine: no proxy
  sets both.
- The open's `dev.qory.run.policy_applied` lists each harness credential with
  `purpose: harness`. A join's lists none.

A run configuration with `harness_hidden: true` is for a harness the run's workspace may
not see, such as one of another organisation. Its open's `dev.qory.run.policy_applied`
lists each harness credential by `name` and `purpose` alone, and the stack proxy's
`dev.qory.run.egress` records have no `path` and no `path_rule`. `harness_hidden` is
fixed when the run starts: a reload ignores it.

### Push credentials

A host credential with `purpose: push` is for qory's push of the work item's branch.
Qory Apiary lists only the repository's git paths, such as `/example-org/app.git/*`, in
a push credential's items: the forge's adapter opens the pull request. Forager does not
check which paths the items list; the push proxy sets the push value on every path an
item covers. Forager has no access level: Qory Apiary sends a push credential only for
a `write` run, beside a read work credential. A run with no push credential, such as a
`write-no-push` run, which gets a read work credential alone, has no push proxy:
`PushProxy` returns "Add a push credential to the run configuration: this run has no
push proxy."

```json
{"version": 1,
 "security_policy": {"version": 1, "egress": {"mode": "enforce", "allow": ["git.example"]}},
 "credentials": [
   {"name": "work-1",
    "apply": [{"hosts": ["git.example"], "scheme": "basic",
               "username": "x-access-token", "paths": ["/example-org/app.git/*"]}],
    "placeholders": ["GIT_TOKEN"]},
   {"name": "push-1", "purpose": "push",
    "apply": [{"hosts": ["git.example"], "scheme": "basic", "username": "x-access-token",
               "paths": ["/example-org/app.git/*"], "push_ref": "refs/heads/qory/wi_01"}]}]}
```

- Only the run's push proxy sets a push credential, on its items' hosts and paths, with
  the branch guard of each item's `push_ref`. The run's proxy, which the sessions, the
  setup step, After, the image step and `HostProxy` go through, never sets one, and the
  run answer lists no host or placeholder for it. A push through the run's proxy gets
  the branch guard's `403`, `wall:push-ref`, when no work credential there has a
  `push_ref`. The branch guard covers a git push to a host of a work credential; a write
  through the forge's API, such as a REST or GraphQL call, depends on the work
  credential's scope at the forge.
- qory reaches the push proxy through `(*session.Run).PushProxy`
  ([the push proxy](go.md#the-push-proxy)). The push proxy allows the push credentials'
  hosts alone. It sets the push value only on the paths of the push items, and returns
  a `403` for a path that no item covers.
- The push proxy checks paths, not methods. On a path an item covers, every method gets
  the push value: under the item `/example-org/app.git/*`, a `GET` of
  `/example-org/app.git/info/refs` and a `POST` of
  `/example-org/app.git/git-receive-pack` pass, and `GET
  /example-org/other.git/info/refs` gets a `403`. The branch guard limits each git push
  to the item's `push_ref`.
- The paths of the push items pin the repository. An item with no paths covers every
  path on its hosts.
- The push proxy stays open from the run's open until its close, through every join.
  On one machine the run answer's `push_proxy_secret` opens it. Behind a separate
  gateway `QORY-PUSH` and the run key open it. Neither enters a wall or a container.
- The run gets a certificate authority. The gateway fetches and renews the value as any
  other stored credential's.
- The policy in force must allow each host of a push credential, and no path rule of
  the node's may cover one, since the push proxy checks no path rule. At the start,
  the run stops with `run_configuration_invalid` otherwise. At a reload, the reload
  fails and the policy in force stays. The texts:
  - a host under no allow entry in `enforce` mode: "Add each push credential's host to
    the run's egress allow list.";
  - a host a deny entry covers: "Remove each push credential's host from the egress
    deny lists.";
  - a host a node's path rule covers: "Remove the node's path rules for each push
    credential's host: the push proxy checks none.".

  Each has a second line with the credential and the host.
- A push credential with `placeholders` stops the run with "Remove placeholders from
  push credentials: no session gets a push credential.", with the credential on a
  second line.
- Two `apply` items of push credentials on one host need paths, and their paths must
  not overlap. A work credential on the same host and paths is fine: no proxy sets both.
- Every `dev.qory.run.policy_applied`, the open's and each join's, lists each item of a
  push credential with `purpose: push`.

## Tools

A **tool** is a program of the machine's that serves hosts. It is for what a run reaches
that needs more than a credential in a header.

- The gateway starts a run's tools outside the container.
- The proxy passes each tool the requests to the hosts it serves.
- A policy selects tools by name, as it selects credentials.
- Tools need a wall.

## The gateway's process

The gateway holds each credential's secret and the access key in memory. Before it
starts anything, `gateway.Start` limits core dumps of the process and debugger access
to it:

- **Linux**: `prctl(PR_SET_DUMPABLE, 0)`, so that the kernel writes no core dump of
  the process, and a process of the same user without `CAP_SYS_PTRACE` can neither
  attach to it with `ptrace` nor read its memory or its environment under
  `/proc/<pid>/`; and `RLIMIT_CORE` 0, soft and hard.
- **macOS**: `ptrace(PT_DENY_ATTACH)`, so that no debugger attaches to the process with
  `ptrace`; and `RLIMIT_CORE` 0, soft and hard. Root, or a debugger that macOS allows
  to call `task_for_pid` on the process, can still read its memory through its task
  port.
- **Other systems**: nothing.

The settings stay for the life of the process, after `Close` too. In `qory run` the
session runs in that process, so the settings apply to it as well.

The caller's configuration, the TLS key and the environment are in memory before
`Start` runs. A Go program calls `gateway.HardenProcess` first in `main`: it makes the
same calls then, with the same errors, and in a test binary too. `Start` makes them
again, and the second call succeeds. `HardenProcess` locks no memory.

- A program the process starts keeps `RLIMIT_CORE` at 0. On Linux it is dumpable again
  after its `execve`.
- On macOS, a process that a debugger traces exits at `Start` with status 45
  (`ENOTSUP`). To debug the gateway, debug its tests: a test binary, the one `go test`
  builds, gets none of these settings. The tests of the settings run them in a child
  process.
- If a call fails, `Start` still makes the other calls, and the gateway does not
  start. The error has one line for each call that failed, in the order of the calls,
  and each line starts with its fix:
  - Linux: `allow prctl in this process's seccomp profile: PR_SET_DUMPABLE 0 failed: <reason>`
  - Linux: `allow prlimit64 in this process's seccomp profile: RLIMIT_CORE 0 failed: <reason>`
  - macOS: `allow ptrace in this process's sandbox: PT_DENY_ATTACH failed: <reason>`
  - macOS: `allow setrlimit in this process's sandbox: RLIMIT_CORE 0 failed: <reason>`

### Keep the memory out of swap

On Linux, `gateway.lock_memory: true` in `forager.yaml` keeps every page of the
gateway's process in RAM, so that the kernel writes no key to swap. A Go program sets
`gateway.Config.LockMemory`. The default is `false`, which locks nothing.

```yaml
gateway:
  lock_memory: true   # Linux only
```

1. Set the locked-memory limit of the gateway's process, `RLIMIT_MEMLOCK`, to
   unlimited:
   - in a systemd unit, `LimitMEMLOCK=infinity` under `[Service]`;
   - in a shell, `ulimit -l unlimited`, which needs a hard limit of unlimited;
   - in Docker, `docker run --ulimit memlock=-1`.
2. Start the gateway.

With `true`, `Start` calls `mlockall(MCL_CURRENT|MCL_FUTURE)`: the pages mapped now,
and each page mapped later.

- Linux counts the whole address space of the process against `RLIMIT_MEMLOCK`, not
  only the memory in use. A small Go program on Linux arm64 maps about 1.2 GB, so a
  lower limit fails at `Start`. A limit that the gateway reaches later ends it with
  `runtime: out of memory`. Set the limit to unlimited.
- A process with `CAP_IPC_LOCK` has no limit.
- Locking loads the mapped pages into RAM: the resident memory of the same small
  program grew from 2.5 MB to 42 MB when it locked its memory.
- A program the process starts locks nothing.
- If `mlockall` fails, the gateway does not start, and the error from `Start` starts
  with two lines:

  ```text
  raise RLIMIT_MEMLOCK to unlimited: LimitMEMLOCK=infinity in a systemd unit, or ulimit -l unlimited
  gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK at 8388608 bytes: cannot allocate memory; in Docker, pass --ulimit memlock=-1, or set gateway.lock_memory to false
  ```

  That first line is for a failure the limit causes: `cannot allocate memory`
  (`ENOMEM`) under a finite limit, or `operation not permitted` (`EPERM`) under a
  limit of 0. Any other failure, such as `EPERM` under an unlimited or a nonzero
  limit, comes from a seccomp filter that refuses the call. The error is then:

  ```text
  allow mlockall in the gateway's seccomp profile, or set gateway.lock_memory to false
  gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK unlimited: operation not permitted
  ```

  If reading `RLIMIT_MEMLOCK` fails too, the first line is
  `raise RLIMIT_MEMLOCK to unlimited, or allow mlockall and prlimit64 in the gateway's seccomp profile`.

- On macOS and other systems, `true` stops the gateway:
  `set gateway.lock_memory to false: Forager locks memory only on Linux, and this system is darwin`.
- When locking fails, `Start` still limits core dumps and debugger access. If one of
  those calls fails too, its line follows the lines of the locking failure.

## The details

The rules, the adapter's document and the tools: the contract's
[credentials section](../contracts/forager/v1/README.md#credentials) and
[tools section](../contracts/forager/v1/README.md#tools).
