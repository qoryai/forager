// Package session runs coding agent sessions inside Forager's boundary.
//
// [Open] takes an [OpenSpec], the gateway, the wall and the run's id, and opens the run
// at the gateway once. [Run.Join] takes a [SessionSpec], the program to start and how,
// joins one session to the run and returns a [Result], the session's exit status and
// where the run's record is. Sessions of one run join one after another. [Run.Close]
// takes the caller's [Outcome] and ends the run. The session speaks to one party alone, its
// gateway, over the gateway's link (contracts/forager/v1/README.md §The gateway's
// link): the gateway holds the proxy, the policy, the credentials, the tools and the
// access key, decides the run, numbers its events and is the node toward the server.
// Between the two the session:
//
//   - checks what it is given: its image table before the run request, each
//     session's variables before the join request, and each session's mounts after it
//   - discovers the gateway's link and opens the run with a run request: the run's id,
//     whether it has a wall, its labels, what it is about, and its images; each join
//     request has the names of the variables the session passes a value for
//   - applies what the gateway's run answer gives and decides none of it again: the
//     image, the placeholders, the names the gateway sets, the variables, the run's
//     certificate authority and the members of dev.qory.run.policy_applied the gateway
//     decides
//   - points the session at a forwarder of its own, on loopback or where the wall
//     says, which carries every connection to the gateway's proxy with the run's proxy
//     secret; the agent never holds the secret
//   - with a [wall.Wall] in the spec, starts the runtime inside an enclosure whose only
//     route out leads to that forwarder, and removes the enclosure at exit
//   - keeps every credential of the gateway's out of the session: the session's
//     environment is the caller's plus the proxy and socket variables, nothing else
//   - posts its events to the gateway in batches, heartbeats every interval the
//     discovery announces, records them in its own record, session.jsonl, fetches the
//     policy again when an answer's digest says another is in force, and ends the run
//     when the gateway closes it
//   - takes the harness's reports over a local socket and maps them, with the
//     runtime's structured output, to runtime events through the runtime's descriptor;
//     each runtime event, log chunk and resize of a session has the session's number
//     as session, and a line of the host work, which [Step.Log] writes, has none
//   - records the run's steps: the host steps the caller starts with [Run.StartStep],
//     and each join's join step and, behind a wall, its image and wall steps
//
// The package knows nothing of stacks, modules, homes or reports. The caller, the qory
// command, turns those into the spec.
package session
