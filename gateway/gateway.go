// Package gateway decides each connection a run makes by the run's policy, records it,
// and sets credentials on it outside the agent: the proxy, the credentials it holds for
// a run, and the tools it hands requests to.
//
// [Start] starts a gateway that serves sessions on its local link, a Unix socket of the
// user's alone (contracts/forager/v1/README.md §The gateway's link): for each run a
// session opens, it fetches the run's policy by its labels, decides its connections
// through one proxy shared by every run, sets credentials and starts tools, numbers the
// run's events, the session's and its own, as one stream, writes the stream to the run's
// record and sends it to the server until the server answers 410, which ends no run.
// [Resend] sends one run's record again.
//
// Start, Resend and the types they take and give are the package's whole surface: a
// session drives a gateway over its link only, never by calling into this package.
package gateway
