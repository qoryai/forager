// Package session runs one coding agent session inside Forager's boundary.
//
// [Run] takes a [Spec], the program to start and how, and returns a [Result], the exit
// status and where the session's record is. The session speaks to one party alone, its
// gateway, over the gateway's link (contracts/forager/v1/README.md §The gateway's
// link): the gateway holds the proxy, the policy, the credentials, the tools and the
// access key, decides the run, numbers its events and is the node toward the server.
// Between the two the session:
//
//   - checks what it is given, its variables, its mounts and its image table, before
//     the gateway is contacted
//   - discovers the gateway's link and opens the run with a run request: the run's id,
//     whether it has a wall, its labels, what it is about, the names of the variables
//     it passes a value for, and its images
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
//     runtime's structured output, to session events through the runtime's descriptor
//
// The package knows nothing of stacks, modules, homes or reports. The caller, the qory
// command, turns those into the spec.
package session
