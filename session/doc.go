// Package session runs one coding agent session inside the runner's boundary.
//
// [Run] takes a [Spec], the program to start and how, and returns a [Result], the exit
// status and where the run's record is. Between the two it does what the contract,
// contracts/runner/v1/README.md, lists as the runner's duties, in that order:
//
//   - reads the policy once and pins it; an unreadable policy is a [*policy.Error] and
//     no run, no policy is observe everything
//   - starts a proxy in the policy's mode, on loopback or where the wall says, and
//     points the session at it
//   - with a [wall.Wall] in the spec, starts the runtime inside an enclosure whose only
//     route out leads to that proxy, and removes the enclosure at exit
//   - keeps every credential of the runner's out of the session: the session's
//     environment is the caller's plus the proxy and socket variables, nothing else
//   - behind a wall, starts the tools the policy selects outside the enclosure, hands
//     each the requests to the hosts it serves that the policy lets through, and stops
//     them when the run ends
//   - heartbeats from the accepted ping, or from the start without a server, and
//     reports the exit as the result
//   - with a server configured and the spec not local, signs every request with the
//     access key and verifies every answer under the pin before reading it; fetches
//     the server's configuration document with a signed GET, and the run
//     configuration it names, whose policy is then the run's; emits every event to the
//     file sink in the run directory and to the server's events endpoint too, after a
//     ping the server must accept; reloads the policy when an answer says another is
//     in force; and ends the run when the server closes it
//   - takes the harness's reports over a local socket and maps them, with the
//     runtime's structured output, to session events through the runtime's descriptor
//
// The package knows nothing of stacks, modules, homes or reports. The caller, the qory
// command, turns those into the spec.
package session
