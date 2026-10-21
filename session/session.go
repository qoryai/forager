package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/variables"
)

// Refusal is a run that did not start, and why: its refusal code, the status of the
// answer when the code came from one, and who refused, From. A refusal the gateway
// passes on from the server, From apiary, keeps the server's code and status, such as
// instance_limit when the server admits no further instance; the gateway's own, From
// gateway, are run_id_used and the codes Forager decides, run_configuration_invalid,
// placeholder_conflict, tool_unknown and image_unknown among them. The session's own
// refusals have no From: variable_reserved, mount_contains_forager_files,
// mount_mode_conflict and mount_shared_with_run among them, with the names they concern
// and never a value. errors.As finds one in what [Open] or [Run.Join] returns.
type Refusal = accesskey.Refusal

// The environment variables the session gets from Forager. EnvHarnessHome is set
// when the spec has a HarnessHome.
const (
	EnvRunID       = "QORY_RUN_ID"
	EnvSocket      = link.EnvRunSocket
	EnvHarnessHome = "QORY_HARNESS_HOME"
)

// MaxLabels is how many labels a run may carry.
const MaxLabels = server.MaxLabels

// errTimeout is the cause of the runtime's context ending at the spec's Timeout.
var errTimeout = errors.New("the run's time limit")

// errRunClosed is the cause of the run's context ending when the gateway closes the
// run: a 410 on the link, or the gateway's 400 to a batch.
var errRunClosed = errors.New("the run was closed")

var runIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CheckRunID refuses a caller's run id that is not a UUID in the canonical lower-case
// form. [Open] checks it; a command checks it first to call it a mistake of its user's.
func CheckRunID(id string) error {
	if !runIDShape.MatchString(id) {
		return fmt.Errorf("the run id %s is not a UUID in the canonical lower-case form", accesskey.ShownName(id, true))
	}
	return nil
}

// CheckLabels refuses labels the contract's schema would: too many, a key outside its
// grammar, a value too long. [Open] checks them; a command may first.
func CheckLabels(labels map[string]string) error { return server.CheckLabels(labels) }

// About is what a run is about, as the caller passed it: see [OpenSpec.About].
type About = server.About

// Subject is one thing a run works on, identified by its Type and Ref.
type Subject = server.Subject

// AboutError is why CheckAbout refuses an About: the Field, such as
// about.subjects[0].ref, and the Reason.
type AboutError = server.AboutError

// CheckAbout refuses an About the contract's rules refuse: a member over its bound in
// bytes, a string that is not UTF-8 or has a control character, a subject type outside
// its form, a URL that is not an absolute http or https one or that has a user name or
// password, two subjects with the same type and ref, and details that are not a JSON
// object of at most 8192 bytes as the event contains them and 4 levels. It returns the
// first failure as an [*AboutError]. [Open] checks it before it contacts the gateway; a
// command may first.
func CheckAbout(a *About) error { return server.CheckAbout(a) }

// closeWait is how long the sinks get to flush: at the end of a join, before the next
// join's request, and at the close. Tests set it shorter, so a fake gateway that does
// not accept a batch costs them less.
var closeWait = 15 * time.Second

// ended is how a run was closed from outside, set once.
type ended struct {
	mu  sync.Mutex
	end server.RunEnd
}

func (e *ended) set(end server.RunEnd) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.end.Code == "" {
		e.end = end
	}
}

func (e *ended) get() server.RunEnd {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.end
}

// recorded is the state and the reason the session records in its own
// dev.qory.run.exited of a run the gateway closed: the state and the reason the end
// carries, but its code as the reason after a refused batch, batch_refused; and, for
// an end that carries no state, failed with its code as the reason.
func recorded(e server.RunEnd) (state, reason string) {
	switch {
	case e.State == "":
		return "failed", e.Code
	case e.Code == event.ReasonBatchRefused:
		return e.State, e.Code
	}
	return e.State, e.Reason
}

// endedBeforeStart is what a refusal of a run the gateway closed before its runtime
// started says.
const endedBeforeStart = "the run did not start: it has ended already"

// refused ends a run the gateway did not open, with fail when it records why and quit
// when it records nothing. A 410 is the run closed before it started. wall_required is the error the session gave for it before there was a
// gateway, word for word, and is recorded nowhere. Any other refusal with a code is
// returned as the gateway gave it, From and all, and its dev.qory.run.refused is in the
// session's record alone: the refusal opened no run at the gateway. A 5xx is a failure
// without a code at the gateway: its message, the error's text as the user is told it,
// when it carries one, recorded nowhere. Nothing is posted on the link.
func refused(err error, fail, quit func(error) error, own func(string, any), end func(server.RunEnd)) error {
	if e, ok := server.Ended(err); ok {
		end(e)
		return fail(err)
	}
	var r *Refusal
	if errors.As(err, &r) {
		if r.Code == refusal.WallRequired {
			return quit(&refusal.NeedsWall{Names: r.Names})
		}
		// The refusal is told as one of the gateway's, never by the link's own URL.
		r.Detail = "the gateway"
		data := map[string]any{"code": r.Code}
		if len(r.Names) > 0 {
			data["names"] = eventNames(r.Names)
		}
		if r.From == accesskey.FromApiary && r.Status != 0 {
			data["status"] = r.Status
		}
		own(event.RunRefused, data)
		return quit(r)
	}
	var status *server.StatusError
	if errors.As(err, &status) && status.Status >= 500 {
		if status.Message != "" {
			return quit(errors.New(accesskey.ShownValue(status.Message, false)))
		}
		return quit(fmt.Errorf("the gateway answered the run request with status %d", status.Status))
	}
	return quit(err)
}

// linkImages are the machine's images as the run request contains them.
func linkImages(spec OpenSpec) *server.LinkImages {
	if spec.Image == "" && len(spec.Images) == 0 {
		return nil
	}
	out := &server.LinkImages{Default: spec.Image, Allow: spec.ImagesAllow}
	for _, d := range spec.Images {
		out.Definitions = append(out.Definitions, server.LinkImage{Name: d.Name, Ref: d.Ref, Runtime: d.Runtime, Docker: d.Docker})
	}
	return out
}

// appliedMembers are the members of dev.qory.run.policy_applied the gateway decides,
// as its answer carries them; none when it carries none.
func appliedMembers(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return nil, errors.New("the gateway's answer: applied is not a JSON object")
	}
	return out, nil
}

// insideAll are words, each written as inside writes it.
func insideAll(words []string, inside func(string) string) []string {
	if words == nil {
		return nil
	}
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = inside(w)
	}
	return out
}

// insideValues are NAME=value entries, each value written as inside writes it.
func insideValues(env []string, inside func(string) string) []string {
	if env == nil {
		return nil
	}
	out := make([]string, len(env))
	for i, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if out[i] = kv; ok {
			out[i] = name + "=" + inside(value)
		}
	}
	return out
}

// withoutNames are the NAME=value entries of env whose name is none of names.
func withoutNames(env, names []string) []string {
	if len(names) == 0 {
		return env
	}
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(names, name)
	})
}

// placeholders are the variables a program wants set before it starts, with a value
// that is no credential: [link.Placeholder], and the start key's variable its
// placeholder, [link.KeyPlaceholder].
func placeholders(names []string, key keyed) []string {
	variable, _, _ := strings.Cut(key.Variable, "=")
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = n + "=" + link.Placeholder
		if n == variable {
			out[i] = key.Variable
		}
	}
	return out
}

// environment is the session's environment: base with Forager's variables set,
// replacing any of the same names, and without the access key's variables or the run
// key's, [EnvRunKey], whichever of them brought one.
func environment(base []string, sets ...[]string) []string {
	var extra []string
	for _, s := range sets {
		extra = append(extra, s...)
	}
	names := map[string]bool{}
	for _, kv := range extra {
		name, _, _ := strings.Cut(kv, "=")
		names[name] = true
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if !names[name] {
			out = append(out, kv)
		}
	}
	return accesskey.WithoutVariables(append(out, extra...))
}

// heartbeat emits run.heartbeat every interval, its elapsed seconds counted from
// start, until the returned function is called; calling it again does nothing.
func heartbeat(ctx context.Context, interval time.Duration, start time.Time, write func(string, any)) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				write(event.RunHeartbeat, map[string]any{"elapsed_seconds": int(time.Since(start).Seconds()), "interval_seconds": int(math.Ceil(interval.Seconds()))})
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return sync.OnceFunc(func() { close(done); <-stopped })
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// ErrNotStarted wraps a failure to start the program, so a caller tells it from the
// runtime's own failure.
var ErrNotStarted = errors.New("the runtime did not start")

// loopback reports whether addr is host:port with an IP address on loopback as its
// host.
func loopback(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// shownVariables are the run's variables as its dev.qory.run.policy_applied sends them:
// each entry as it is, with its name as accesskey.ShownName shows it, bare, in the
// order of the names before. Two names that give one phrase are two entries with that
// phrase.
func shownVariables(applied []variables.Entry) []variables.Entry {
	out := make([]variables.Entry, len(applied))
	for i, e := range applied {
		out[i] = e
		out[i].Name = accesskey.ShownName(e.Name, false)
	}
	return out
}

// eventNames are a refusal's names as its dev.qory.run.refused sends them: as
// accesskey.ShownNames lists them, so a phrase two names give is sent once, as the
// schema holds the names unique.
func eventNames(names []string) []string { return accesskey.ShownNames(names) }

// shownValues are values as an event sends them: each as accesskey.ShownValue shows it,
// in order. A nil list is an empty one, as the event's arrays are never null.
func shownValues(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = accesskey.ShownValue(v, false)
	}
	return out
}
