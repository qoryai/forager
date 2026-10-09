// Package gateway decides each connection a run makes by the run's policy, records it,
// and sets credentials on it outside the agent: the proxy, the credentials it holds for
// a run, and the tools it hands requests to.
//
// [Start] starts a gateway that serves sessions on its local link, a Unix socket of the
// user's alone (contracts/forager/v1/README.md §The gateway's link): for each run a
// session opens, it fetches the run's policy by its labels, decides its connections
// through one proxy shared by every run, sets credentials and starts tools, numbers the
// run's events, the session's and its own, as one stream, writes the stream to the run's
// record and sends it to the server, and passes the server's close to the session.
// [Resend] sends one run's record again.
//
// The other names are the ones the session drives a gateway in its own process by
// today. Each is the gateway's own type or function under a name that says what it is
// for.
package gateway

import (
	"context"

	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/policy"
)

// Proxy is a listening proxy.
type Proxy = proxy.Proxy

// Decision is one connection the session asked for and what the proxy did with it.
type Decision = proxy.Decision

// CA is one run's certificate authority: what lets the proxy answer as a host it
// terminates TLS for. Its key is made for the run and lives in this process's memory
// only; only the certificate reaches an enclosure.
type CA = proxy.CA

// ProxyCredential is one use of a credential the proxy sets for the session: the hosts
// it goes to, how it is set, and the paths of those hosts the run may ask for.
type ProxyCredential = proxy.Credential

// ProxyTool is a tool as the proxy sees it: the hosts it serves and the Unix socket the
// proxy hands their requests to.
type ProxyTool = proxy.Tool

// Listen starts a proxy on addr, host:port, in the given mode with the given allow and
// deny lists, handing every decision to observe. An empty addr is the loopback address
// of package link; port 0 is a port of the system's choosing. Close stops it.
func Listen(addr string, mode policy.Mode, allow, deny []string, observe func(Decision)) (*Proxy, error) {
	return proxy.Listen(addr, mode, allow, deny, observe)
}

// NewCA makes an authority for the run named.
func NewCA(runID string) (*CA, error) { return proxy.NewCA(runID) }

// CredentialDefinition is one credential as the machine defines it.
type CredentialDefinition = credential.Definition

// HeldCredentials are a run's credentials, resolved.
type HeldCredentials = credential.Held

// ResolveCredentials reads the credentials a policy selects, asking every adapter once,
// and refuses what cannot hold: a name the machine does not define, an argument it does
// not provide for, a host two credentials claim or the run's allow list does not cover
// under enforce, a claim above the definition's own. report hears of a renewal that
// failed.
func ResolveCredentials(ctx context.Context, defs []CredentialDefinition, selected []policy.Selected, mode policy.Mode, allow []string, report func(string)) (*HeldCredentials, error) {
	return credential.Resolve(ctx, defs, selected, mode, allow, report)
}

// ToolDefinition is one tool as the machine defines it.
type ToolDefinition = tool.Definition

// ChosenTool is a tool a run's policy selects, with its argument: what is started.
type ChosenTool = tool.Chosen

// Tools are the tools started for one run.
type Tools = tool.Set

// ChooseTools resolves the tools a policy selects among the machine's definitions and
// refuses what cannot hold: a name the machine does not define, a tool selected twice,
// an argument the definition does not provide for, and a host two tools serve.
func ChooseTools(defs []ToolDefinition, selected []policy.Selected) ([]ChosenTool, error) {
	return tool.Choose(defs, selected)
}

// CheckTools refuses chosen tools a run cannot have beside what else it holds: a host a
// credential is for as well, claimed(host) naming that credential, and under enforce a
// host the run's allow list does not cover.
func CheckTools(chosen []ChosenTool, mode policy.Mode, allow []string, claimed func(host string) string) error {
	return tool.Check(chosen, mode, allow, claimed)
}

// ToolPlaceholders are the variables the chosen tools want set inside, each once.
func ToolPlaceholders(chosen []ChosenTool) []string { return tool.Placeholders(chosen) }

// StartTools starts every chosen tool with env as its environment, and waits until
// each listens. A tool that exits first, or does not listen in time, is no
// run. After that, what a tool writes to standard error goes to report line by line.
func StartTools(ctx context.Context, chosen []ChosenTool, runID string, env []string, report func(string)) (*Tools, error) {
	return tool.Start(ctx, chosen, runID, env, report)
}

// ToolSocketDirs is the pattern of the private directories the tools' sockets are in: a
// path that contains it contains every one of them.
func ToolSocketDirs() string { return tool.SocketDirs() }
