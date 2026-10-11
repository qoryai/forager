package gateway

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// Paths of the link on the one address, each under [link.RemotePathPrefix], as the
// discovery there lists them.
const (
	remoteRunPath    = "/qory-link/run-configuration"
	remoteEventsPath = "/qory-link/events"
)

// The codes of the attach's refusals the gateway decides itself, before it asks: a run
// key that does not verify, or names another run than the request; one of another
// gateway; one of a workspace the gateway does not serve; one past its attach window
// that never attached here; and a run the gateway already holds.
const (
	codeRunKeyInvalid      = "run_key_invalid"
	codeWrongGateway       = "wrong_gateway"
	codeWorkspaceNotServed = "workspace_not_served"
	codeRunKeyExpired      = "run_key_expired"
	codeRunAttached        = "run_attached"
)

// runKeyKey is the key of a request's [presented] run key in its context.
type runKeyKey struct{}

// presented is the run key a request on the one address carried: as it came, and what
// it verified to.
type presented struct {
	raw string
	key runkey.Key
}

// runKeyOf is the run key a request on the one address carried, verified.
func runKeyOf(ctx context.Context) (presented, bool) {
	p, ok := ctx.Value(runKeyKey{}).(presented)
	return p, ok
}

// config is the server's configuration document as the gateway holds it now, and its
// digest: discovery's, replaced when an answer says another is in force.
func (g *Gateway) config() (*server.Configuration, string) {
	g.confMu.Lock()
	defer g.confMu.Unlock()
	return g.conf, g.confDigest
}

// setConfig replaces the configuration document the gateway holds, the workspaces it
// serves among it, by one read again since an answer carried another digest.
func (g *Gateway) setConfig(conf *server.Configuration, digest string) {
	g.confMu.Lock()
	defer g.confMu.Unlock()
	g.conf, g.confDigest = conf, digest
}

// now is the clock the one address judges an attach window by.
func (g *Gateway) now() time.Time {
	if g.cfg.now != nil {
		return g.cfg.now()
	}
	return time.Now()
}

// runKeyInvalid is the gateway's refusal of a request whose bearer value is no run key
// that verifies under the server's pin, or that names another run than the request.
func runKeyInvalid() *accesskey.Refusal {
	return &accesskey.Refusal{Code: codeRunKeyInvalid, Status: http.StatusBadRequest, Text: gatewayText(codeRunKeyInvalid), From: accesskey.FromGateway}
}

// attachRefused is the gateway's own refusal of the attach of runID with the code and
// status, decided before it asks the server: its text is the line the server's
// refusal of the attach would give, attach <run.url>/<run_id>: <code> (status <status>).
func (g *Gateway) attachRefused(code string, status int, runID string) *accesskey.Refusal {
	conf, _ := g.config()
	return &accesskey.Refusal{Code: code, Status: status, Detail: "attach " + conf.Run.URL + "/" + runID, From: accesskey.FromGateway}
}

// admitRunKey decides the bearer value of a request on the one address, in order: no
// value, or one that is no run key that verifies under the server's pin, is
// run_key_invalid, 400; then, in the server's order of the attach, a run key past its
// attach_by of a run the gateway holds nothing of, never attached here, is
// run_key_expired, 409; one that names another gateway than the one discovery lists of
// the access key is wrong_gateway, 409; one of a workspace discovery does not list is
// workspace_not_served, 409. ok says the request carried one bearer value in its
// syntax.
func (g *Gateway) admitRunKey(value string, ok bool) (runkey.Key, *accesskey.Refusal) {
	if !ok {
		return runkey.Key{}, runKeyInvalid()
	}
	k, err := runkey.Verify(value, g.cfg.Server.ApiaryPublicKey)
	if err != nil {
		return runkey.Key{}, runKeyInvalid()
	}
	conf, _ := g.config()
	switch {
	case g.now().After(k.AttachBy) && !g.knows(k.RunID):
		return k, g.attachRefused(codeRunKeyExpired, http.StatusConflict, k.RunID)
	case k.Gateway != conf.NodeID:
		return k, g.attachRefused(codeWrongGateway, http.StatusConflict, k.RunID)
	case !slices.Contains(conf.Workspaces, k.Workspace):
		return k, g.attachRefused(codeWorkspaceNotServed, http.StatusConflict, k.RunID)
	}
	return k, nil
}

// knows reports whether the gateway holds anything of the run: a run open or opening,
// one it let go of and still keeps, or its record.
func (g *Gateway) knows(runID string) bool {
	g.mu.Lock()
	held := g.runs[runID] != nil || g.used[runID]
	g.mu.Unlock()
	if held {
		return true
	}
	if _, ok := g.spentOf(runID); ok {
		return true
	}
	return g.recorded(runID)
}

// recorded reports whether the run has a record here: its events.jsonl.
func (g *Gateway) recorded(runID string) bool {
	_, err := os.Stat(filepath.Join(g.stream.Dir(runID), sink.EventsFile))
	return !errors.Is(err, os.ErrNotExist)
}

// heldRun is the run of a request on the one address whose run key names runID, the
// run the gateway holds; nil when there is none to go on with, its answer written: the
// 410 of a run the gateway ended and let go of, and otherwise a 410 run_closed, a run
// that ended here before, the gateway's own stop among it, or that never opened here.
func (g *Gateway) heldRun(w http.ResponseWriter, runID string) *linkRun {
	g.mu.Lock()
	lr := g.runs[runID]
	g.mu.Unlock()
	if lr != nil && lr.remote {
		return lr
	}
	if sp, ok := g.spentOf(runID); ok {
		gone(w, sp.end)
		return nil
	}
	gone(w, runEnd{code: accesskey.CodeRunClosed, from: accesskey.FromGateway})
	return nil
}

// relayRun hands a bound connection that opened with the relay's preamble and a run
// key to the proxy of that run, live at the gateway, as the shared proxy does a local
// connection with a run's proxy secret. A run key [Gateway.admitRunKey] refuses, or one
// of no live run here, closes the connection unanswered. It reports whether c was
// handed on.
func (g *Gateway) relayRun(c net.Conn, r *bufio.Reader, value string) bool {
	k, ref := g.admitRunKey(value, b64token.MatchString(value))
	if ref != nil {
		return false
	}
	g.mu.Lock()
	lr := g.runs[k.RunID]
	g.mu.Unlock()
	if lr == nil || !lr.remote || lr.px == nil {
		return false
	}
	if _, ended := lr.gone(); ended {
		return false
	}
	c.SetDeadline(time.Time{})
	lr.px.ServeConn(&linkConn{Conn: c, r: r})
	return true
}

// attach attaches a run of the one address at the server under the gateway's access
// key, its body built once, so every try sends the same bytes ([Gateway.tries]), and
// returns the run's run configuration with its digest, and the record's first line,
// dev.qory.run.registered: the run key's workspace, node and instance, what the attach
// announced, and the labels and about the attach's answer gives back of the starter's
// registration. A run configuration Forager refuses is a [*server.DocumentError] with
// the first line, an attach the server accepted; any other failure has none.
func (g *Gateway) attach(ctx context.Context, conf *server.Configuration, runID string, how opening) (*server.RunConfiguration, string, map[string]any, error) {
	body, err := server.Attach{RunKey: how.runKey, IntervalSeconds: g.interval, Events: conf.Events.Types, ForagerVersion: g.cfg.Version}.Body()
	if err != nil {
		return nil, "", nil, err
	}
	var ans *server.AttachAnswer
	var digest string
	err = g.tries(ctx, how.deadline, func() (err error) {
		ans, digest, err = g.client.Attach(ctx, conf.Run.URL, runID, body)
		return err
	})
	var refused *server.DocumentError
	if err != nil && !errors.As(err, &refused) {
		return nil, "", nil, err
	}
	k := how.key
	registered := map[string]any{"workspace": k.Workspace, "node_id": k.NodeID, "instance_id": k.InstanceID, "forager_version": g.cfg.Version,
		"events": slices.Clone(conf.Events.Types), "contract_version": server.Revision, "interval_seconds": g.interval}
	var rc *server.RunConfiguration
	if ans != nil {
		rc = ans.RunConfiguration
		if len(ans.Labels) > 0 {
			registered["labels"] = ans.Labels
		}
		if ans.About != nil {
			registered["about"] = ans.About
		}
	}
	return rc, digest, registered, err
}
