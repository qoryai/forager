# How an issuer integrates with the Qory gateway

A gateway that serves other machines opens a run only for a **run credential**: a signed
statement, from an issuer the operator trusts, that names one run and its target. This
page is for whoever builds that issuer. It states what the gateway requires, from public
standards, and what it does with what it receives.

A separate gateway works only with a run credential issuer: it refuses to serve other
machines without `gateway.run_credentials` in the operator's `forager.yaml`.

## The run key and the run credential

- **The run key** identifies one run, and is unique per attempt. It is not a secret and
  proves nothing on its own. A retry gets a new run key, and so a new run.
- **The run credential** is a JWT ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html))
  signed as a JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html)) with an
  asymmetric key, following the best practices of
  [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html). The issuer gives each run its
  run credential, and may refresh it for the same run key.

The gateway verifies the run credential, not the run key.

## The claims

| Claim | Required | What the gateway does with it |
|---|---|---|
| `iss` | yes | equals the configured `issuer`, compared as a string |
| `aud` | yes | a string, or an array of strings, that contains the configured `audience` |
| `sub` | yes | the run key; it becomes the run's `run_key` label |
| `exp` | yes | the run credential is refused from `exp` plus the leeway on |
| `iat` | when `max_lifetime` is set | no later than now plus the leeway |
| `nbf` | no | when present, no later than now plus the leeway |
| claims that name the target | as the mapping names them | they make the `repository` label, and the `forge` label when it is not a constant |
| descriptive claims | as the mapping names them | they go into the run's `about.details`, never into a label |

`exp`, `iat` and `nbf` are NumericDates: seconds since the epoch, a JSON number, not
negative and no later than the year 9999. The leeway is 60 seconds unless the operator
sets another, and at most 5 minutes: the gateway refuses a configuration with a longer
one, which would keep an expired run credential alive.

The payload is one JSON object in UTF-8 that names each claim once: a payload that names
a claim twice is refused, so no two readers of it can see different claims.

Every claim the mapping names for a label is a string, and is required: a run credential
without one is refused, since a run's labels come from the run credential alone. A
descriptive claim is a string when present, and a run credential that carries one of
another type is refused; one it does not carry leaves that `about.details` key undecided,
and the client's own value stands. A label value is at most 256 bytes of UTF-8, and no
claim the mapping names, for a label or for `about.details`, holds a control character.
A claim that names the target never contains the `join` the operator sets between them,
so two different targets never make one repository.

A descriptive claim, such as `requester`, may be personal data: its value appears in the
run's `about.details`, and in the names of a refusal when a session sends that key with
another value.

The examples here use `namespace` and `project` as the claims that name the target and
`requester` as a descriptive claim. The names are the operator's choice; the gateway holds
no issuer's format.

A run credential at its simplest, decoded:

```json
{"alg": "ES256", "kid": "k2", "typ": "JWT"}
{
  "iss": "https://issuer.example",
  "aud": "qory-gateway",
  "sub": "rk-0001",
  "iat": 1700000000,
  "exp": 1700000600,
  "namespace": "example-namespace",
  "project": "project",
  "requester": "example-requester"
}
```

## The serialisation and the header

The run credential is the JWS compact serialisation
([RFC 7515 §7.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.1)), and the
gateway reads that one form alone:

- at most 16384 bytes;
- exactly three parts separated by dots: the header, the payload and the signature, the
  header and the payload not empty;
- each part base64url ([RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648.html#section-5))
  without padding: no `=`, no white space, no line break, no byte outside the base64url
  alphabet, and no bits set beyond a part's last byte.

The header is one JSON object in UTF-8 that names each member once. In it:

- `alg` is required (see the algorithms below);
- `kid` selects the key (see publishing and rotating keys);
- `typ` is optional, and when present is `JWT`, compared without regard to case
  ([RFC 7519 §5.1](https://www.rfc-editor.org/rfc/rfc7519.html#section-5.1)); any other
  value is refused;
- `crit` is refused: the gateway understands no extension.

The gateway never follows `jku`, `jwk`, `x5u` or `x5c`: it uses only the keys the operator
pinned.

## The algorithms

The issuer signs with one of three algorithms
([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html),
[RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html)):

- `RS256`: RSASSA-PKCS1-v1_5 with SHA-256, under an RSA key of at least 2048 bits; the
  signature is as long as the key's modulus;
- `ES256`: ECDSA with SHA-256 under a P-256 key, the signature `R` and `S`, 32 bytes each,
  64 bytes in all and not ASN.1, each of `R` and `S` in [1, n-1], n the order of P-256;
- `EdDSA`: Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)), a signature
  of 64 bytes. Ed448 is not accepted.

`none` is refused, and so is every HMAC algorithm: the gateway holds only public keys, so
no run credential is ever checked as HMAC under one. The header's `alg` must be among the
issuer's configured algorithms, and equal the algorithm of the key it selects. The
operator's configuration accepts no other algorithm, and no RSA key of fewer than 2048
bits.

## Publishing and rotating keys

The issuer publishes its public keys, each with a key id, `kid`. The operator pins them in
the gateway's configuration, each as a file holding one PEM block of type `PUBLIC KEY`.

- A run credential that carries a `kid` is verified under the pinned key of that `kid`;
  a `kid` that no pinned key has is refused, and so is a `kid` when the one key pinned
  has none.
- A run credential without a `kid` is accepted only while exactly one key is pinned.
- With more than one key pinned, every key has a `kid`, each its own.
- To rotate, the issuer publishes the next key under a new `kid`, the operator pins it
  beside the current one, the issuer signs with it, and the operator removes the old one
  once no run credential signed under it is still live.

## The gateway's own audience

The issuer mints a run credential for the gateway alone, with an audience of its own,
such as `qory-gateway`. `audience` is required in every issuer's configuration, and `aud`
must contain it. A run credential minted for another service never opens a run here, and
one minted for the gateway is of no use to another service that checks its own audience.

## The lifetime

A run credential is valid until `exp`. The operator can bound how long an issuer's run
credentials may live with `max_lifetime`: `exp` minus `iat` is then at most that, and a
run credential without `iat` is refused.

A run credential that expires mid-run is replaced by a fresh one for the same run key,
and the run goes on. Without one, the run ends at `exp`.

The leeway, 60 seconds by default and at most 5 minutes, applies to `exp`, `iat` and
`nbf` alike: a run credential is accepted until `exp` plus the leeway, and its `iat` and
`nbf` may be up to the leeway ahead of the gateway's clock.

A run credential is bound to its run as well: once its run is closed or has ended, the
gateway refuses it, not only at `exp`. The gateway keeps each ended run key, by issuer,
until its run credential's `exp` plus 5 minutes, the longest leeway, in a file of its
state directory (mode 0600, in a directory only its user writes), so a restart does not
reopen it. So the issuer gives a retry a new run key, and does not refresh the run
credential of a run key whose run has ended.

## The introspection endpoint

An issuer may offer an OAuth 2.0 token introspection endpoint
([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)), so the gateway can ask whether
a run credential is still active.

The request is the one of RFC 7662 §2.1:

```http
POST /introspect HTTP/1.1
Host: issuer.example
Content-Type: application/x-www-form-urlencoded
Accept: application/json
Authorization: Basic <base64 of client_id ":" client secret>

token=<the run credential>&token_type_hint=access_token
```

- The endpoint is an `https` URL, and the gateway reaches it over TLS 1.2 or later,
  verifying its certificate under the system's roots. It connects directly, through no
  proxy, and follows no redirect: a redirect is an answer other than `200`.
- The client authenticates with HTTP Basic
  ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html)): the configured `client_id`
  and the secret, each form-encoded as
  [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1) asks. The
  gateway reads the secret from `client_secret_file` once, when it starts: the file's
  bytes, less one line ending at their end, and not empty.
- The gateway waits at most 10 seconds for the whole answer.

The answer, RFC 7662 §2.2, means active only when all of these hold:

- the status is `200`;
- the body is at most 65536 bytes, one JSON object that names each member once;
- its member `active` is the JSON `true`, not the string `"true"` and not `1`.

`{"active": false}` ends the run (`run_ended_at_issuer`). Any other answer, or a failure
to ask, counts as not active too: the check fails closed. The gateway reads nothing else
of the answer.

The gateway asks before it opens a run, and again at most every `cache` while the run
has connections. It keeps each answer for `cache`, a failure included, by the SHA-256 of
the run credential, never by the run credential itself, so a refreshed run credential is
asked about anew. `cache` defaults to the run's heartbeat interval, at which Qory already
reports a run alive, so an ended run is noticed within one heartbeat.

Neither the run credential nor the client secret appears in the gateway's errors or
logs.

## The operator's configuration

The operator sets the issuer, the audience, the keys and the mapping of claims to labels
in `forager.yaml`. Its schema is
[`run-credentials.schema.json`](../contracts/forager/v1/run-credentials.schema.json).

```yaml
gateway:
  run_credentials:
    - issuer: https://issuer.example
      audience: qory-gateway                  # required; minted for the gateway alone
      algorithms: [RS256, ES256]
      keys:                                   # pinned; selected by kid
        - {kid: k1, alg: RS256, public_key_file: /etc/qory/issuer-k1.pem}
        - {kid: k2, alg: ES256, public_key_file: /etc/qory/issuer-k2.pem}
      leeway: 60s
      max_lifetime: 1h                        # optional; exp - iat at most this
      allow: {claim: namespace, values: ["example-namespace"]}
      labels:
        forge: {value: example-forge}
        repository: {claims: [namespace, project], join: "/"}
        run_key: {claim: sub}
      details:                                # into about.details, never labels
        requester: {claim: requester}
      introspection:                          # optional; RFC 7662
        url: https://issuer.example/introspect
        client_id: example-gateway
        client_secret_file: /etc/qory/issuer-introspection-secret
        cache: 30s                            # default: the run's heartbeat interval
```

- `allow` is the scope: the claim it names must hold one of the values it lists.
- `labels` makes the run's three labels: `forge`, a constant or a claim; `repository`, the
  claims that name the target joined with `join`, one claim, or a constant; and
  `run_key`, always `sub`. A run's labels come from the run credential alone; nothing else
  the client sends sets a label. The control plane picks the run's target by these
  labels, and a run credential whose labels match no target opens no run.
- `details` names the `about.details` keys the run credential decides, each from one
  claim. A key holds no `=`: a refusal names a key as `about.details.<key>=<value>`, and
  a key with `=` would make that name ambiguous.

With this run credential, the run's labels are `forge: example-forge`,
`repository: example-namespace/project` and `run_key: rk-0001`, and its `about.details`
holds `requester: example-requester`.

## How the gateway verifies a run credential

The gateway checks the signature against the pinned keys before it reads any claim:
before the signature verifies, it reads the header alone, and never the payload. In
order:

1. **Serialisation:** the one compact form above.
2. **Header and keys:** for each issuer, `alg` is among its algorithms and equals the
   selected key's; the key is selected by `kid`, or is the one key pinned; `typ` and
   `crit` as above.
3. **Signature,** under each key the header selected, over the exact bytes received: the
   header and the payload as they arrived, with the dot between them.
4. **Claims:** the issuer is the one whose key verified the signature and whose `issuer`
   equals `iss`; then `exp`, `iat`, `nbf`, `max_lifetime`, `aud` and `sub`, as above.
5. **Scope:** `allow`, from the signed claims, never from the request.
6. **Mapping:** the labels and `about.details`, from the signed claims.

## A client with no session

A client with no session sets the gateway as its proxy, with the run credential as its
proxy password: `Proxy-Authorization`
([RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) §11.7.2) with the Basic scheme
([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html)). The user name is ignored.

A proxy login over plain HTTP would carry the run credential in the clear, so the
gateway's listener for other machines speaks TLS only: the client reaches the gateway as
an HTTPS proxy, and the login travels inside TLS. A plain listener is allowed on loopback
alone. A connection without a valid run credential gets
`407 Proxy Authentication Required` with `Proxy-Authenticate: Basic realm="qory"`.

The first connection with a valid run credential whose run key has no run at the gateway
opens the run. Every later connection with a run credential for the same run key belongs
to that run, a refreshed one included.

## A session

A session reads the run credential from a file, a file descriptor, or the variable
`QORY_RUN_CREDENTIAL_SECRET`; a flag never carries it. It sends it on every request to the
gateway, and reads the file again before each, so an issuer that refreshes the file keeps
the run going. The session also sends the labels it takes from the checkout. When its
`forge` or `repository` differs from the run credential's, the gateway refuses the run
with `target_differs_from_credential`; when it sends any other key the mapping sets, a
label such as `run_key` or an `about.details` key such as `requester`, with another value,
the gateway refuses it with `differs_from_credential`. Each refusal names the member and
the run credential's value, `labels.<key>=<value>` or `about.details.<key>=<value>`.

qory takes `QORY_RUN_CREDENTIAL_SECRET` out of the agent's environment. A variable
an issuer itself sets for the run, `QORY_RUN_CREDENTIAL_SECRET` or any other, is the
operator's to deny through the node's variables policy.

## One opaque refusal

Every failure of a run credential gets the same answer, whatever check refused it:

- a client with no session gets `407`;
- a session gets one refusal code, `run_credential_refused`, with no names, and qory says
  "the gateway refused this run credential", with no reason beyond that.

## Where the run credential never goes

The run credential never appears in an event, a record or a log, on the session or the
gateway, and it is never sent to the control plane. Inside a wall the agent never sees
it: the relay adds the run's own proxy secret to every connection instead, which the
gateway issued for this run when it verified the run credential.

## Testing an issuer

The contract publishes known answers under
[`fixtures/known-answers/run-credentials/`](../contracts/forager/v1/fixtures/known-answers/run-credentials/):
fixture keys of each algorithm derived from a published seed, two configurations of the
fixture issuer, and run credentials signed under the keys, each with the outcome it gets
at a fixed time and, for a refused one, the step that refuses it: the serialisation, the
header, the signature, the claims, the scope or the mapping. These keys are public:
anyone can derive their private keys from the seed. Forager refuses them in a
configuration; never pin them.
