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
| `exp` | yes | the run credential is refused from `exp` on, give or take the leeway |
| `iat` | when `max_lifetime` is set | no later than now plus the leeway |
| `nbf` | no | when present, no later than now plus the leeway |
| claims that name the target | as the mapping names them | they make the `repository` label, and the `forge` label when it is not a constant |
| descriptive claims | as the mapping names them | they go into the run's `about.details`, never into a label |

`exp`, `iat` and `nbf` are NumericDates: seconds since the epoch, a JSON number. The
leeway is 60 seconds unless the operator sets another.

Every claim the mapping names is a string, and is required: a run credential without one
is refused, so a key the operator meant the run credential to decide is never left to the
client. A label value is at most 256 bytes of UTF-8. A claim that names the target never
contains the `join` the operator sets between them, so two different targets never make
one repository.

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

## The algorithms

The issuer signs with one of three algorithms
([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html),
[RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html)):

- `RS256`: RSASSA-PKCS1-v1_5 with SHA-256, under an RSA key of at least 2048 bits;
- `ES256`: ECDSA with SHA-256 under a P-256 key, the signature `R` and `S`, 32 bytes each,
  not ASN.1;
- `EdDSA`: under an Ed25519 key. Ed448 is not accepted.

`none` is refused, and so is every HMAC algorithm: the gateway holds only public keys, so
no run credential is ever checked as HMAC under one. The header's `alg` must be among the
issuer's configured algorithms, and equal the algorithm of the key it selects. A `crit`
header is refused. The gateway never follows `jku`, `jwk`, `x5u` or `x5c`: it uses only
the keys the operator pinned.

## Publishing and rotating keys

The issuer publishes its public keys, each with a key id, `kid`. The operator pins them in
the gateway's configuration, each as a file holding one PEM block of type `PUBLIC KEY`.

- A run credential that carries a `kid` is verified under the pinned key of that `kid`.
- A run credential without a `kid` is accepted only while exactly one key is pinned.
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

A run credential is bound to its run as well: once its run is closed or has ended, the
gateway refuses it, not only at `exp`. The gateway keeps each ended run key until its run
credential's `exp`, so a restart does not reopen it.

## The introspection endpoint

An issuer may offer an OAuth 2.0 token introspection endpoint
([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)), so the gateway can ask whether
a run credential is still active. The gateway:

- posts the run credential to the configured endpoint, authenticated with the configured
  client id and a secret it reads from a file;
- asks before it opens a run, and again at most every `cache` while the run has
  connections. `cache` defaults to the run's heartbeat interval, at which Qory already
  reports a run alive, so an ended run is noticed within one heartbeat;
- goes on with the run on `{"active": true}`, and ends it on `{"active": false}`;
- fails closed: any other answer, or a failure to ask, counts as not active.

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
  claim.

With this run credential, the run's labels are `forge: example-forge`,
`repository: example-namespace/project` and `run_key: rk-0001`, and its `about.details`
holds `requester: example-requester`.

## How the gateway verifies a run credential

The gateway checks the signature against the pinned keys before it uses any claim, in
this order:

1. **Header and keys:** `alg` is among the issuer's algorithms and equals the selected
   key's; the key is selected by `kid`, or is the one key pinned.
2. **Signature,** over the exact bytes received.
3. **Claims:** `exp`, `iat`, `nbf`, `max_lifetime`, `iss`, `aud` and `sub`, as above.
4. **Scope:** `allow`, from the signed claims, never from the request.

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

The session takes `QORY_RUN_CREDENTIAL_SECRET` out of the agent's environment. A variable
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
at a fixed time and, for a refused one, the step that refuses it. No gateway accepts the
fixture keys outside a test.
