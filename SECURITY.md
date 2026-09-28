# Security

## Reporting a vulnerability

Write to **info@8wonders.de**. Do not open a public issue or pull request for it.

Say what you found, the version, and how to see it happen: the policy or `Spec` used,
the command, and what the session could do that it should not. A run's `events.jsonl`
helps; take any secret out of it first.

You get an answer within three working days. We tell you what we found, fix what is a
vulnerability in a new release, and publish an advisory that credits you unless you
would rather it did not.

## Supported versions

The latest release. Below 1.0 a fix is a new release and is not carried back to an
earlier one.

## What is a vulnerability here

The runner's promises are written down, so the test is whether one was broken. They are
in the contract: [what every wall guarantees](contracts/runner/v1/README.md#the-wall),
[credentials](contracts/runner/v1/README.md#credentials) and
[the server](contracts/runner/v1/README.md#the-server). For example:

- a session behind a wall reaches a host, or a path of a host, the run's policy denies;
- a session reads a credential the runner holds for it, the run's authority key, the
  relay's secret or the server's secret;
- a session changes the run's record, or what the runner reports;
- a run's policy, a descriptor or a credential adapter's answer makes the runner do
  something the binary does not already do, or widens what the machine's policy allows;
- a receiver accepts a request the runner did not sign, by following this contract.

## What is not

The contract states its [limits](contracts/runner/v1/README.md#limits), and what they
describe is how the runner works, not a flaw in it:

- without a wall, enforcement is cooperative: a program that ignores the proxy variables
  is not seen and not stopped;
- in mode `observe` nothing is denied;
- a host that answers with the headers it was sent shows a session the credential set on
  its request; a credential belongs only on hosts trusted not to;
- what a credential may do on the paths a run was given is the credential's own grant,
  not the runner's.

If you are not sure which side something falls on, write anyway.
