// Package link holds the names the session, the gateway and the wall agree on, so
// each part reads them from here and none imports another for them: the variables that
// point a program at the proxy, the preamble of the wall's relay, the proxy's loopback
// address, the variables that name the run's socket and a tool's socket, the headers
// the proxy sets on a request it hands to a tool, and the value of a placeholder
// variable.
package link

// Loopback is the address the proxy binds when it is given none: a port of the
// system's choosing on loopback.
const Loopback = "127.0.0.1:0"

// NoProxy is the value of NO_PROXY the session gets: loopback by every name, so a
// local server, a local model endpoint or any other program that listens on loopback
// is reached directly.
const NoProxy = "localhost,127.0.0.1,::1"

// ProxyEnv returns the variables that point a program at the proxy at u, in both cases,
// because curl reads http_proxy in lower case only and other programs document the
// upper case. A wall names the proxy by the address the enclosure reaches it on.
func ProxyEnv(u string) []string {
	return []string{
		"HTTP_PROXY=" + u, "http_proxy=" + u,
		"HTTPS_PROXY=" + u, "https_proxy=" + u,
		"NO_PROXY=" + NoProxy, "no_proxy=" + NoProxy,
	}
}

// RelayPreamble is what opens a connection to a proxy that requires the run's secret:
// this word, a space, the secret and a newline, before the first byte of HTTP. The
// wall's relay writes it on every connection it forwards, so the proxy serves the run's
// relay and nobody else who can reach its address: another container of the same
// engine, a process of the machine.
const RelayPreamble = "QORY-RELAY"

// EnvRunSocket is the variable that names the run's record socket in the session's
// environment.
const EnvRunSocket = "QORY_RUN_SOCKET"

// EnvToolListen names, in a tool's environment, the path of the Unix socket it listens
// on.
const EnvToolListen = "QORY_TOOL_LISTEN"

// The headers the proxy sets on a request it hands to a tool. A request the session
// sends with a header of the prefix Qory- has it taken off first, so a tool reads these
// as the proxy's word.
const (
	// RequestIDHeader carries the proxy's id of the request, the request_id of its
	// egress event.
	RequestIDHeader = "Qory-Request-Id"
	// PathRuleHeader carries the path rule that let the request through, [NoPathRule]
	// when the host has path rules and under observe none covers the path; it is absent
	// when the host has none.
	PathRuleHeader = "Qory-Path-Rule"
	// NoPathRule is the path rule a tool is handed for a request observed and let
	// through that no rule covers: never a path, which starts with a slash.
	NoPathRule = "none"
)

// Placeholder is the value a placeholder variable gets: it says what it is to whoever
// reads it, and is no credential anywhere.
const Placeholder = "qory-sets-the-credential-outside-the-enclosure"
