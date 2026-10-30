# Qory Forager

Forager stands between your coding agent and the world.

It does four things:

1. **It records the whole session.** Every connection through the proxy is an event: the
   host, the decision, the rule. So is every chunk of output, and every prompt, tool call
   and turn the agent reports. The record is written to the checkout.
2. **It enforces a policy.** A policy lists what the agent may reach. `enforce` denies
   the rest. `observe` records everything and denies only what `deny` lists and
   `allow_first` does not.
3. **It walls the agent in, and keeps your secrets out.** A wall starts the agent in a
   container whose one way out is the proxy. The credentials a run's policy selects stay
   with the gateway, which sets them on the way out.
4. **It reports to your server.** The events your server selects go there too, signed.
   The server can set each run's policy, and change it while the run goes.

A proxy sees connections. Forager owns the session as well: it starts the agent, watches
what it does, and stops it.

## Why

A coding agent acts unsupervised. It runs commands and calls hosts you don't see. It has
your secrets. Afterwards, you can't tell what it reached, or what it did there.

A proxy sees only the programs that honour it. A secret in the agent's environment goes
wherever the agent sends it. And connections are half the story: the prompts, the tool
calls and the exit are the rest. Forager covers all of it, in one record.

## Install

Forager ships inside [`qory`](https://github.com/qoryai/qory). You start it with
`qory run`, a subcommand of `qory`: it starts your agent inside Forager.

Install `qory`:

```sh
brew install qoryai/tap/qory
```

`qory` builds the agent's launch from the harness: what the agent reads, such as
instructions, skills and settings. Forager runs it.

To build Forager into your program, see [Embed it in Go](#embed-it-in-go).

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

In a run with no wall, `qory-proxy-password` replaces the password of the agent's proxy
URL in the session's bytes and in the events made from the runtime's output and hook
records.

`***` replaces each secret the run knows: the values `qory` passes, such as those of
`--env` and `wall.env`, the server's variable values of 8 characters or more, and text in
the shape of an Anthropic, GitHub or AWS key or of an HTTP bearer token. It does so in
the session's bytes, the events, the copy of the output on your terminal, and the
errors that opening, joining and closing the run, its setup, its image's fetch and its
steps return. See [docs/go.md](docs/go.md) for the shapes.

Forager writes its events: the start, the policy, each connection, each chunk of output,
a heartbeat every 30 seconds, and the exit. The agent's hooks and output add the
runtime's events: prompts, tool calls, subagents, turns, as the runtime reports them
from inside, which an image a repository built can change. A **descriptor** maps them.
Forager ships one for Claude Code.

More: [docs/events.md](docs/events.md).

## 2. Enforce a policy

A policy is a short document. It only narrows what Forager allows:

```yaml
version: 1
egress:
  mode: enforce               # or observe: record everything, deny only what deny lists
  allow: [api.anthropic.com, "*.github.com"]
  deny: [gist.github.com]     # denied in either mode
```

The policy comes from one of three places:

- **The machine**: the `gateway.egress` section of `~/.config/qory/forager.yaml`.
- **The run**: `qory run --policy <file>`, a file in the format above. It narrows the
  machine's policy, and never widens it.
- **Your server**: its run configuration, chosen by the run's labels, such as its
  repository. See [Report to a server](#4-report-to-a-server).

When your server sends a policy, Forager narrows it by the policy it is passed,
`gateway.Config.Policy` in Go: the node only takes away. With no policy, the gateway observes and
records everything.

A denied connection gets a `403`, and the record gets the event. The session goes on.
A policy can also select the credentials the run gets, with or without a wall. Behind a
wall, it can also limit a host to paths, and select the tools and the image.

More: [docs/policy.md](docs/policy.md).

## 3. Wall the agent in, keep the secrets out

The proxy sees only programs that honour it. A **wall** makes the rest fail:

- The agent starts in a container, on a network with no route out.
- A relay leads to the proxy, and nowhere else.
- Setup runs in a separate container on the same network, so it reaches only the relay too.
- The session, the gateway, the policy and the access key secret stay outside. The
  record is written from outside.

Credentials stay outside too, with or without a wall. The machine defines them, and a
run's policy selects them by name. The agent sees a placeholder. The proxy sets the real
credential on the requests to the hosts it is for.

A **tool**, a program of the machine's, runs outside as well. It is for what needs more
than a credential, such as a request signed with a key.

The wall ships with a Docker adapter. `e2e` checks it from inside the container, in
CI.

More: [docs/wall.md](docs/wall.md), [docs/credentials.md](docs/credentials.md). A machine
that runs agents for others: [docs/node.md](docs/node.md).

## 4. Report to a server

Every event goes to files. With a server, the events it selects go there too:

- Before the run starts, Forager fetches the server's configuration and registers the
  run, both signed. The run starts only when the server accepts it.
- It posts them in batches. Every request is signed with the machine's access key, an
  Ed25519 key, and every answer is verified under the server's key the machine pins.
- The server can return the run's policy and variables, chosen by the run's labels. It
  can change the policy while the run goes.
- A name or a value that contains `qak_`, `qrk_`, `qecr_`, `qecn_`, `qecp_`, `qecg_`,
  `qeci_` or `qecd_`, the start of an access key secret, a run key, a run code or an
  enrolment code, is sent and printed as a phrase in its place, such as `(a name that
  contains a run key)`. [docs/server.md](docs/server.md) lists where.

A server is your control plane, or your receiver. The package `receiver` is a worked
example.

More: [docs/server.md](docs/server.md).

## Embed it in Go

Forager is a Go module, and `qory` is one program built on it. Build it into your
program to run an agent inside the same boundary. It needs Go 1.27.3 or above:

```sh
go get github.com/qoryai/forager
```

A gateway, `gateway.Start`, holds the policy, the credentials and the server.
`session.Open` opens a run at the gateway's local link. `Run.Join` runs one session in
the run: you pass the program to start, and you get back the exit status. `Run.Close`
ends the run with the outcome you give and returns the directory of the record:

```go
g, err := gateway.Start(ctx, gateway.Config{
	Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: hosts}},
	Dir:    stateDir,                              // the gateway's directory
})
if err != nil {
	return err
}
rt, err := catalog.Lookup("claude", "")         // the runtime, by its name
if err != nil {
	return err
}
run, err := session.Open(ctx, session.OpenSpec{
	Gateway: session.LocalGateway(g.LocalLink()), // the session speaks to the gateway alone
})
if err != nil {                                   // the run did not open
	return err
}
res, err := run.Join(ctx, session.SessionSpec{
	Runtime:   rt,
	Command:   "claude",
	Args:      []string{"-p", "Reply pong."},
	Forwarder: []string{exe, "forward"},          // the hook command; it calls session.Forward
})
out := session.Outcome{State: "failed", ExitCode: -1} // the session did not start
if err == nil {
	out = session.Outcome{State: res.State, ExitCode: res.ExitCode}
}
closed, cerr := run.Close(ctx, out)               // writes dev.qory.run.exited
g.Close(ctx)                                      // delivers the runs' last events, before the exit
if err != nil {
	return err
}
if cerr != nil {
	return cerr
}
fmt.Println("recorded in", closed.Dir)
os.Exit(res.ExitCode)                             // the runtime's status
```

`qory` imports Forager, and Forager imports nothing of `qory`. What Forager reads
and writes is specified in [contracts/forager/v1](contracts/forager/v1/README.md).

More: [docs/go.md](docs/go.md).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). `go test ./...` validates every fixture against
the schemas.

## Licence

Apache License, Version 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Qory is a
trademark of 8wonders GmbH; see [TRADEMARKS.md](TRADEMARKS.md).
