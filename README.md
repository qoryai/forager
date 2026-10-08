# 🐝 Qory runner

The runner stands between your coding agent and the world.

It does four things:

1. **It records the whole session.** Every connection through the proxy is an event: the
   host, the decision, the rule. So is every chunk of output, and every prompt, tool call
   and turn the agent reports. The record is written to the checkout.
2. **It enforces a policy.** A policy lists what the agent may reach. `enforce` denies
   the rest. `observe` records everything and denies only what `deny` lists.
3. **It walls the agent in, and keeps your secrets out.** A wall starts the agent in a
   container whose one way out is the proxy. The credentials a run's policy selects stay
   with the runner. The proxy sets them on the way out.
4. **It reports to your server.** The events your server selects go there too, signed.
   The server can set each run's policy, and change it while the run goes.

A proxy sees connections. The runner owns the session: it starts the agent, watches what
it does, and stops it.

## Why

A coding agent acts on its own. It runs commands and calls hosts you don't see. It has
your secrets. Afterwards, you can't tell what it reached, or what it did there.

A proxy sees only the programs that honour it. A secret in the agent's environment goes
wherever the agent sends it. And connections are half the story: the prompts, the tool
calls and the exit are the rest. The runner covers all of it, in one record.

## Install

The runner ships inside [`qory`](https://github.com/qoryai/qory). You start it with
`qory run`, a subcommand of `qory`: it starts your agent inside the runner.

Install `qory`:

```sh
brew install qoryai/tap/qory
```

`qory` builds the agent's launch from the harness: what the agent reads, such as
instructions, skills and settings. The runner runs it.

To build the runner into a program of your own, see [Embed it in Go](#embed-it-in-go).

## Try it

With `qory` and Claude Code installed:

```sh
mkdir hello && cd hello
qory setup example              # a stack with two modules
qory harness compose            # build the harness into this folder
qory run -- -p "/hello"         # one headless turn; prints "the record is in <dir>"
cat <dir>/events.jsonl          # what it reached, what it printed, how it ended
```

## 1. Record the session

Each run gets a directory, `<id>/`, in the runs directory the caller passes. `qory` keeps
them under its state directory and prints the path:

- `events.jsonl`: one CloudEvent per line, in order.
- `output.log`: the session's bytes.

The runner writes its own events: the start, the policy, each connection, each chunk of
output, a heartbeat every 30 seconds, and the exit. The agent's hooks and output add the
session's events: prompts, tool calls, subagents, turns. A **descriptor** maps them. The
runner ships one for Claude Code.

More: [docs/events.md](docs/events.md).

## 2. Enforce a policy

A policy is a short document. It only narrows what the runner allows:

```yaml
version: 1
egress:
  mode: enforce               # or observe: record everything, deny only what deny lists
  allow: [api.anthropic.com, "*.github.com"]
  deny: [gist.github.com]     # denied in either mode
```

The policy comes from one of three places:

- **The machine**: the `egress` section of `~/.config/qory/runner.yaml`.
- **The run**: `qory run --policy <file>`, a file in the format above. It narrows the
  machine's policy, and never widens it.
- **Your server**: its run configuration, chosen by the run's labels, such as its
  repository. See [Report to a server](#4-report-to-a-server).

When your server sends a policy, the runner narrows it by the policy it is passed,
`Spec.Policy` in Go: the node only takes away. With no policy, the runner observes and
records everything.

A denied connection gets a `403`, and the record gets the event. The session goes on.
Behind a wall, a policy can also limit a host to paths, and select the credentials, the
tools and the image the run gets.

More: [docs/policy.md](docs/policy.md).

## 3. Wall the agent in, keep the secrets out

The proxy sees only programs that honour it. A **wall** makes the rest fail:

- The agent starts in a container, on a network with no route out.
- A relay leads to the proxy, and nowhere else.
- The runner, the policy and the access key secret stay outside. The record is written
  from outside.

Credentials stay outside too. The machine defines them, and a run's policy selects them
by name. Inside, the agent sees a placeholder. The proxy sets the real credential on the
requests to the hosts it is for.

A **tool**, a program of the machine's, runs outside as well. It is for what needs more
than a credential, such as a request signed with a key.

The wall ships with a Docker adapter. `e2e` checks it from inside the container, in
CI.

More: [docs/wall.md](docs/wall.md), [docs/credentials.md](docs/credentials.md). A machine
that runs agents for others: [docs/node.md](docs/node.md).

## 4. Report to a server

Every event goes to files. With a server, the events it selects go there too:

- Before the run starts, the runner fetches the server's configuration, signed. The run
  starts only when the server answers.
- It posts them in batches. Every request is signed with the machine's access key, an
  Ed25519 key, and every answer is verified under the server's key the machine pins.
- The server can return the run's policy and variables, chosen by the run's labels. It
  can change the policy while the run goes.

A server is your control plane, or a receiver of your own. The package `receiver` is a
worked example.

More: [docs/server.md](docs/server.md).

## Embed it in Go

The runner is a Go module, and `qory` is one program built on it. Build it into a
program of your own to run an agent inside the same boundary. It needs Go 1.27.1 or
above:

```sh
go get github.com/qoryai/runner
```

One call, `session.Run`, runs one session. You pass the program to start and its policy.
You get back the exit status and the directory of the record:

```go
rt, err := catalog.Lookup("claude", "")         // the runtime, by its name
if err != nil {
	return err
}
res, err := session.Run(ctx, session.Spec{
	Runtime:   rt,
	Command:   "claude",
	Args:      []string{"-p", "Reply pong."},
	Policy:    &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "enforce", Allow: hosts}},
	Forwarder: []string{exe, "forward"},          // the hook command; it calls session.Forward
})
if err != nil {                                   // the run did not start
	return err
}
os.Exit(res.ExitCode)                             // the runtime's status; res.Dir is the record
```

`qory` imports the runner, and the runner imports nothing of `qory`. What the runner
reads and writes is specified in [contracts/forager/v1](contracts/forager/v1/README.md).

More: [docs/go.md](docs/go.md).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). `go test ./...` validates every fixture against
the schemas.

## Licence

Apache License, Version 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Qory is a
trademark of 8wonders GmbH; see [TRADEMARKS.md](TRADEMARKS.md).
