package gateway

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/server"
)

// joinRequestSchema is link-join-request.schema.json, compiled once.
var joinRequestSchema = sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile("link-join-request.schema.json") })

// joinsPath is the last part of a join's path: <runs path>/<run_id>/sessions.
const joinsPath = "/sessions"

// join is one join request of a run that the gateway answered 200 or 403, numbered in
// the order the requests arrived.
type join struct {
	// session is the join's number in the run, from 1.
	session int
	// accepted says the gateway answered the join 200; a join answered 403 has no
	// dev.qory.session.started, only its dev.qory.session.exited.
	accepted bool
	// passes are the names of the variables the session passes a value for.
	passes []string
	// model is the model key the session starts with, the join answer's; empty when
	// the run holds none.
	model string
	// started and exited say the run's stream numbered the session's
	// dev.qory.session.started and dev.qory.session.exited; startedAt is the time of
	// the former.
	started, exited bool
	startedAt       time.Time
}

// open reports whether the join is open: answered 200, and its
// dev.qory.session.exited not numbered.
func (j *join) open() bool { return j.accepted && !j.exited }

// passing reports whether an open join of the run passes a value for the variable:
// the run's [run.Config.Passes], which a reload checks against the placeholders of the
// policy it puts in force.
func (lr *linkRun) passing(name string) bool {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	for _, j := range lr.joins {
		if j.open() && slices.Contains(j.passes, name) {
			return true
		}
	}
	return false
}

// openJoin is the run's open join, nil for none. Called with lr.mu held.
func (lr *linkRun) openJoin() *join {
	for _, j := range lr.joins {
		if j.open() {
			return j
		}
	}
	return nil
}

// joinRun is the run id of a join's path under runs, and whether the path is a join's:
// <runs>/<run_id>/sessions.
func joinRun(path, runs string) (string, bool) {
	rest, ok := strings.CutPrefix(path, runs+"/")
	if !ok {
		return "", false
	}
	id, ok := strings.CutSuffix(rest, joinsPath)
	return id, ok && id != "" && !strings.Contains(id, "/")
}

// isJoin reports whether path is a join's under runs.
func isJoin(path, runs string) bool {
	_, ok := joinRun(path, runs)
	return ok
}

// readJoinRequest reads a join request: one JSON object in UTF-8 with each member name
// once, which link-join-request.schema.json accepts.
func readJoinRequest(body []byte) (*server.LinkJoinRequest, bool) {
	var req server.LinkJoinRequest
	if !validate(joinRequestSchema, body) || jsonv2.Unmarshal(body, &req) != nil {
		return nil, false
	}
	return &req, true
}

// joinSession answers a join request of the run runID: 200 with the session's number,
// in the order the run's joins arrive; 403 placeholder_conflict, numbered too, for
// passes that contain a placeholder of a credential or a tool the gateway holds for
// the run, which leaves the run open; 410 for a run that ended at the gateway; and 400
// invalid_request for a body the schema refuses, for a model_credential of no model
// key of the run, for a join while another join of the run is open, and on the local
// link for a run id of no run here. On the one
// address the run id is the run key's, any other 400 run_key_invalid, and a run the
// gateway does not hold is a 410 ([Gateway.heldRun]).
func (g *Gateway) joinSession(s *side, w http.ResponseWriter, r *http.Request, runID string) {
	var lr *linkRun
	if s.remote {
		if p, _ := runKeyOf(r.Context()); runID != p.key.RunID {
			ref := runKeyInvalid()
			refuse(w, ref.Status, ref.Code, nil, ref.From, ref.Error())
			return
		}
		if lr = g.heldRun(w, runID); lr == nil {
			return
		}
	} else if lr = g.localRun(runID); lr == nil {
		invalid(w)
		return
	}
	if !mediaType(r, server.LinkContentType) {
		invalid(w)
		return
	}
	body, ok := readBody(r, server.MaxDocument)
	if !ok {
		invalid(w)
		return
	}
	req, ok := readJoinRequest(body)
	if !ok {
		invalid(w)
		return
	}
	// A reload waits for the join, and so does a batch: no batch is checked against the
	// joins while one is added, so a run.exited the link accepted finds no join it did
	// not check.
	lr.joining.Lock()
	defer lr.joining.Unlock()
	lr.batch.Lock()
	defer lr.batch.Unlock()
	if end, ended := lr.gone(); ended {
		gone(w, end)
		return
	}
	lr.touch()
	model, ok := lr.modelKey(req.ModelCredential)
	if !ok {
		invalid(w)
		return
	}
	conflict := lr.r.Conflict(run.Passing(req.Passes))
	lr.mu.Lock()
	if lr.ended {
		// The run ended since the check above: [linkRun.end] sets ended under lr.mu.
		end := lr.how
		lr.mu.Unlock()
		gone(w, end)
		return
	}
	if lr.openJoin() != nil {
		lr.mu.Unlock()
		refuse(w, http.StatusBadRequest, server.CodeInvalidRequest, nil, accesskey.FromGateway, joinWhileOpen)
		return
	}
	j := &join{session: len(lr.joins) + 1, accepted: conflict == nil, passes: slices.Clone(req.Passes), model: model}
	lr.joins = append(lr.joins, j)
	digest := lr.reloadDigest
	lr.mu.Unlock()
	if conflict != nil {
		refuseOpen(w, conflict)
		return
	}
	if model != "" {
		// From the join's 200 until its session.exited the proxy sets the session's
		// model key in place of the start key.
		lr.px.SetModelKey(model)
	}
	g.answerHeaders(s, w, r, digest)
	w.Header().Set("Content-Type", server.LinkContentType)
	w.WriteHeader(http.StatusOK)
	b, _ := json.Marshal(server.LinkJoinAnswer{Version: 1, Session: j.session, ModelCredential: model})
	w.Write(b)
}

// joinWhileOpen is the text of the 400 invalid_request of a join while another join of
// the run is open, from its 200 until the gateway numbers its dev.qory.session.exited.
const joinWhileOpen = "a join while another join of the run is open"

// modelKey is the model key a join's session starts with: name, when it is one of the
// model keys the gateway holds for the run, else the run's start key when name is
// empty; empty when the run holds no model key. It reports false for a name of no
// model key of the run's.
func (lr *linkRun) modelKey(name string) (string, bool) {
	held := lr.r.Held()
	if held == nil {
		return "", name == ""
	}
	if name == "" {
		return held.Start, true
	}
	for _, c := range held.Credentials() {
		if c.Format != "" && c.Name == name {
			return name, true
		}
	}
	return "", false
}
