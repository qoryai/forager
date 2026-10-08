# Contributing

Thank you for considering a contribution.

## Where contributions go

Everywhere. Three kinds are the most useful:

- **A runtime descriptor.** One YAML file under `contracts/runner/v1/runtimes/<name>/`
  that maps what a runtime emits, JSON lines on its standard output and hook calls, to the
  session events of the contract, with the fixtures that prove the mapping. A descriptor
  matches and copies; it never computes. A descriptor without fixtures is not accepted.
- **The contract.** The documents under `contracts/runner/v1/`, their schemas and their
  fixtures. A receiver follows the contract and lives in your own repository; nothing in
  this one has to change for it.
- **The runner** and the receiver: the packages `session` and `receiver` and what they
  share under `internal/`.

## Contributor Licence Agreement

Copyright in this project is held by a single owner: **8wonders GmbH, and its successors and
assigns**. To keep that true, every contribution is made under the Contributor Licence
Agreement in [CLA.md](CLA.md): a perpetual, worldwide, irrevocable licence to the
contribution, including the right to relicense it, and a patent grant on the same terms as
the Apache License, Version 2.0. You keep your copyright.

Opening a pull request against this repository is your acceptance of the agreement, for that
contribution and every later one. The pull request is the record of your acceptance. Read
[CLA.md](CLA.md) before your first pull request.

The agreement names the owner with successors-and-assigns wording, so that if the
project moves into a dedicated entity, existing grants travel with it and nobody signs again.

Why a CLA at all: the licensing decisions of the project are only executable with a sole
copyright holder. Declaring it before a community exists is what makes it a kept promise
rather than a takeback.

## Licence

By contributing, you agree that your contribution is licensed under the Apache License,
Version 2.0 (see [LICENSE](LICENSE)) in addition to the CLA grant above.

## Development

The toolchain is pinned in `mise.toml`; `mise install` provides it. Go 1.27.

```sh
go build ./...
go test ./...           # every fixture under contracts/runner/v1, and the unit tests
go test ./... -cover    # per-package statement coverage
gofmt -l .              # must print nothing
go vet ./...
go run github.com/mgechev/revive@v1.16.0 -config revive.toml ./...
```

A change to the contract starts with a fixture. A policy, a server document, a
configuration document or an event fixture is one document under
`contracts/runner/v1/fixtures/` that the schema accepts, or one under
`fixtures/invalid/` that it refuses; a signed request is one under `fixtures/signed/`
with the status a receiver answers. A descriptor fixture is one
directory under `runtimes/<name>/fixtures/` holding the recorded records and the events
they map to. The test suite validates every document against the schemas and runs every
descriptor fixture, so the schemas, the fixtures and the readers cannot drift apart.
Write the fixture, watch it fail, then change the code.

A test is hermetic: `t.TempDir` for the tree, `t.Setenv` for the environment, a loopback
listener for anything that speaks HTTP. No test reads the machine's configuration, runs a
runtime, or reaches the network. The session tests run the test binary itself as the
runtime and as the hook forwarder, so the whole boundary is exercised without Claude Code
installed; the proxy is tested against loopback origins and the server sink against the
receiver. Fixtures hold synthetic data only: no real host names of
anyone's infrastructure, no real secrets, no recorded session of anyone's work. Name a test
for the behaviour it pins, not for the function it calls.

One dependency direction is an invariant. `qory` imports this module and this module
imports nothing of `qory`: the runner knows nothing of stacks, modules, homes or reports.

Dependencies stay few: the standard library, a pseudo-terminal package, a terminal
package for raw mode, YAML, and JSON schema validation. No CloudEvents SDK: the
structured batch subset is small and the fixtures validate against the published schema.

## Doc comments

Every package and every exported name carries a doc comment, and CI fails without one. The
conventions, beyond what `revive` can check:

- The first sentence starts with the name and is a complete sentence: `Run starts ...`,
  `Policy is ...`. A package comment starts `Package x `.
- A package comment says what the package owns, the words it defines, how a caller uses it,
  and the invariants a caller must not break. It goes in `doc.go` when it runs past about
  eight lines.
- Exported struct fields carry a comment when the name alone does not settle what goes in
  them, in what format, or who sets them.
- Unexported types, and unexported functions longer than a few lines, are documented too.
  The comment says why the code exists or what is subtle in it, never what the next line
  does.
- Say what the code does, including what it refuses, what it overwrites, what it leaves
  behind, and which errors a caller matches with `errors.Is` or `errors.As`.
- Link identifiers as `[Policy]`, `[session.Run]`. Indent code blocks with a tab, write
  lists as two spaces and a dash, and wrap at 90 columns.

One vocabulary, no synonyms: **run** is one execution of one session under this runner,
with an id; **session** is the runtime at work inside a run; **runtime** is the program
that runs the session, such as Claude Code; **policy** is the document that narrows what a
run may do; **egress** is a connection the session opens to the outside through the
proxy; **event** is one CloudEvent the runner emits; **sink** is where events go, the file
or the server; **server** is what the runner is a client of, a control plane or a
receiver; **receiver** is a server that is not a control plane; **descriptor** is the document that
maps a runtime's output to session events; **record** is one unit of runtime output a
descriptor reads; **harness** is what the session runs on, composed elsewhere. A runtime is
never a provider, a tool, an agent or a vendor; the runner never names a hive, a bee or a
flower.

## Releases

A release is a tag on a branch named after it, `v0.1.0`, opened as one pull request. That
branch adds the release's section to `CHANGELOG.md`, `[X.Y.Z] - YYYY-MM-DD` with the day
the tag lands and a compare link at the foot of the file; a fix that goes to `main`
outside a release branch goes under `[Unreleased]` until the next one. Anything a person
upgrading has to do stands under Upgrading in the section. The module is a library: a tag
is what `qory` pins, and the control plane's CI pins the same tag for the fixtures.

Commit messages say what changed and why it was needed, in the imperative.
