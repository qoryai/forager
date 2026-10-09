package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes/catalog"
)

// Example runs one headless Claude Code turn inside the boundary: it starts the
// gateway on this machine, with a policy and a server the caller read from its own
// configuration, runs the session against the gateway's local link, and exits with the
// runtime's status. The access key's secret and the pin come from the environment, as on a CI
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
	ctx := context.Background()
	gw, err := gateway.Start(ctx, gateway.Config{
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.anthropic.com"}}},
		Server: &gateway.Server{Version: 1, URL: "https://qory.example", AccessKeyID: os.Getenv("QORY_ACCESS_KEY_ID"), ApiaryPublicKey: pin,
			AccessKey: key, InstanceID: "i_gYKDhIWGh4iJiouMjY6PkA", InstanceName: "build-01"},
		Dir: "/path/to/state",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "no gateway:", err)
		os.Exit(1)
	}
	res, err := session.Run(ctx, session.Spec{
		Runtime: rt,
		Command: "claude",
		Args:    []string{"--settings", "/path/to/settings.json", "-p", "Reply with the single word pong."},
		Gateway: session.LocalGateway(gw.LocalLink()),
		// The hook command; it calls session.Forward, see Example_forward.
		Forwarder: []string{exe, "forward"},
	})
	// The gateway's close delivers the run's last events to the server.
	gw.Close(ctx)
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

// Example_forward is the hook command the session installs, `<exe> forward` for the
// spec above: it reads the hook's input from stdin and hands it to the run that
// installed it, and exits 0 whatever happened.
func Example_forward() {
	if err := session.Forward(context.Background(), os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
