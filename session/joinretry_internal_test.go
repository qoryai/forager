package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/qoryai/forager/server"
)

// TestJoinUnanswered pins which errors of a join request are a try with no answer: a
// connection refused or reset, an end of the connection, a timeout, and a binding
// that failed are; a refusal with a code, a 410, a status, an answer document the
// session refuses and an answer under a key the run key does not name are not.
func TestJoinUnanswered(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"connection refused", fmt.Errorf("the join request at the gateway: %w", refused), true},
		{"connection reset", fmt.Errorf("the join request: %w", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), true},
		{"end of the connection", fmt.Errorf("the join request: %w", io.EOF), true},
		{"timeout", fmt.Errorf("the join request: %w", context.DeadlineExceeded), true},
		{"binding failed", &server.GatewayKeyError{URL: "https://gateway.example", Unproven: true}, true},
		{"answer under another key", &server.GatewayKeyError{URL: "https://gateway.example"}, false},
		{"coded refusal", &Refusal{Code: "placeholder_conflict", Status: 403}, false},
		{"410", &Refusal{Code: "run_closed", Status: 410}, false},
		{"503", &server.StatusError{What: "the join request", Status: 503}, false},
		{"document", &server.DocumentError{What: "the join answer", Err: errors.New("no session")}, false},
	} {
		if got := joinUnanswered(c.err); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
