package wall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/runner/link"
)

// RelayTokenEnv is the variable of the relay's environment that holds the run's proxy
// token. With it set the relay opens every connection it forwards with the proxy's
// preamble, which is how the proxy knows the run's relay from anything else that
// reaches its address.
const RelayTokenEnv = "QORY_RELAY_TOKEN"

// RelayReady is the line the relay prints once every port listens. An adapter waits
// for it before it starts the agent.
const RelayReady = "relay: listening"

// Relay is the program that runs in the relay, the one peer an enclosure may reach: it
// listens on a port for each forward, written port=host:port, and copies every
// connection to that forward's target, fixed when it starts. It reads nothing, decides
// nothing and takes no instruction from whoever connects; the policy stays in the
// gateway. It prints [RelayReady] to ready once every port listens and returns
// when the context ends.
//
// The caller's binary runs it in a hidden mode, so the relay needs no image of its own:
// the adapter mounts that binary into a container and starts it there.
func Relay(ctx context.Context, forwards []string, ready io.Writer) error {
	if len(forwards) == 0 {
		return errors.New("relay: no forwards; want port=host:port")
	}
	preamble := ""
	if token := os.Getenv(RelayTokenEnv); token != "" {
		preamble = link.RelayPreamble + " " + token + "\n"
	}
	var lc net.ListenConfig
	var wg sync.WaitGroup
	var listeners []net.Listener
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
		wg.Wait()
	}()
	for _, f := range forwards {
		port, target, err := parseForward(f)
		if err != nil {
			return err
		}
		ln, err := lc.Listen(ctx, "tcp", ":"+strconv.Itoa(port))
		if err != nil {
			return fmt.Errorf("relay: %w", err)
		}
		listeners = append(listeners, ln)
		wg.Add(1)
		go func() {
			defer wg.Done()
			serve(ctx, ln, target, preamble)
		}()
	}
	fmt.Fprintln(ready, RelayReady)
	<-ctx.Done()
	return nil
}

// parseForward reads port=host:port.
func parseForward(f string) (int, string, error) {
	p, target, ok := strings.Cut(f, "=")
	port, err := strconv.Atoi(p)
	if !ok || err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("relay: forward %q is not port=host:port", f)
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return 0, "", fmt.Errorf("relay: forward %q is not port=host:port", f)
	}
	return port, target, nil
}

// dialWait is how long the target has to accept a connection.
const dialWait = 10 * time.Second

// serve accepts until the listener closes and copies each connection to the target,
// after the preamble when there is one.
func serve(ctx context.Context, ln net.Listener, target, preamble string) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		client, err := ln.Accept()
		if err != nil {
			// A closed listener is the end; anything else, too many open files say, is a
			// moment to wait out, because a relay that stops accepting is an agent cut
			// off for the rest of the run.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: dialWait}
			upstream, err := d.DialContext(ctx, "tcp", target)
			if err != nil {
				client.Close()
				return
			}
			stop := context.AfterFunc(ctx, func() { client.Close(); upstream.Close() })
			defer stop()
			if _, err := io.WriteString(upstream, preamble); err != nil {
				client.Close()
				upstream.Close()
				return
			}
			pipe(client, upstream)
		}()
	}
}

// pipe copies both ways, passes a half close on, and closes both ends when both
// directions are done.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	one := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	go one(a, b)
	go one(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
