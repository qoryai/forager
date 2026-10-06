package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/runtimes/catalog"
	"github.com/qoryai/runner/session"
)

// Example runs one headless Claude Code turn inside the boundary, with a policy and a
// server the caller read from its own configuration, and exits with the runtime's
// status. The access key's secret and the pin come from the environment, as on a CI
// machine, and the instance id from the caller's own file. It compiles with the
// module's tests and is not run, since it starts a real program.
func Example() {
	exe, _ := os.Executable()
	key, err := accesskey.ParseSecret(os.Getenv("QORY_ACCESS_KEY_SECRET"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pin, err := accesskey.ParsePin([]byte(os.Getenv("QORY_APIARY_PUBLIC_KEY")))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	// The runtime by its name: a descriptor of the machine's, the contract's, or bare.
	rt, err := catalog.Lookup("claude", "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	res, err := session.Run(context.Background(), session.Spec{
		Runtime:      rt,
		Command:      "claude",
		Args:         []string{"--settings", "/path/to/settings.json", "-p", "Reply with the single word pong."},
		Policy:       &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "enforce", Allow: []string{"api.anthropic.com"}}},
		Server:       &session.Server{Version: 1, URL: "https://qory.example", AccessKeyID: os.Getenv("QORY_ACCESS_KEY_ID"), ApiaryPublicKey: pin},
		AccessKey:    key,
		InstanceID:   "i_gYKDhIWGh4iJiouMjY6PkA",
		InstanceName: "build-01",
		// The hook command; it calls session.Forward, see Example_forward.
		Forwarder: []string{exe, "forward"},
	})
	var refused *session.Refusal
	if errors.As(err, &refused) {
		fmt.Fprintln(os.Stderr, "the run was refused:", refused.Code)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "the run did not start:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "recorded in", res.Dir)
	os.Exit(res.ExitCode)
}

// Example_forward is the hook command the runner installs, `<exe> forward` for the
// spec above: it reads the hook's input from stdin and hands it to the run that
// installed it, and exits 0 whatever happened.
func Example_forward() {
	if err := session.Forward(context.Background(), os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
