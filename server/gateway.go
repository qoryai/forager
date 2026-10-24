package server

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/runkey"
)

// GatewayRegistration is the body of a run's registration when the registering node's
// or node pool's choice resolves to a gateway, the second shape of
// run-registration.schema.json: what a starter, or a keyed machine's qory behind a
// gateway, sends. It holds the run's id, its labels and what it is about, for
// information alone, the attach window it asks for and the time; what the run tells the
// server of itself, Forager's version, the contract revision, the heartbeat interval and
// the event types, moves to the attach ([Attach]). The server resolves the gateway from
// the access key's record, never from the body, and answers with the run key
// ([RegistrationAnswer]).
type GatewayRegistration struct {
	// Version is the document's version; 0 is written as 1.
	Version int `json:"version"`
	// RunID is the run's id: a UUID in the canonical lower-case form.
	RunID string `json:"run_id"`
	// Labels are the run's labels. None is left out.
	Labels map[string]string `json:"labels,omitempty"`
	// About is what the run is about, information alone; nil is left out.
	About *About `json:"about,omitempty"`
	// AttachSeconds is the attach window the run asks for, in seconds; 0 is left out,
	// and the server's default applies. The server clamps a longer one to its ceiling,
	// and the run key's attach_by states the window granted.
	AttachSeconds int `json:"attach_seconds,omitempty"`
	// Time is when the body was built, RFC 3339 in UTC with whole seconds. Empty, Body
	// sets it from the clock, so a caller never formats a time.
	Time string `json:"time"`
}

// Body is the registration's bytes, built once: every try sends them as they are, so
// a server that accepted them under any active key of the same node answers the same
// again. A Time left empty is the clock's now, as [RegistrationTime] writes it, and a
// Version left 0 is 1. A run id outside its form, labels [CheckLabels] refuses, an
// About [CheckAbout] refuses and an AttachSeconds below 0 are its error, and no body is
// built.
func (r GatewayRegistration) Body() ([]byte, error) {
	if r.Version == 0 {
		r.Version = 1
	}
	if r.Time == "" {
		r.Time = RegistrationTime(time.Now())
	}
	if !runIDShape.MatchString(r.RunID) {
		return nil, errors.New("the registration: the run id is not a UUID in the canonical lower-case form")
	}
	if err := CheckLabels(r.Labels); err != nil {
		return nil, err
	}
	if err := CheckAbout(r.About); err != nil {
		return nil, err
	}
	if r.AttachSeconds < 0 {
		return nil, errors.New("the registration: attach_seconds is below 1")
	}
	if len(r.Labels) == 0 {
		r.Labels = nil
	}
	// The body goes to Qory Apiary: labels and about as run.started sends them.
	r.Labels, r.About = ShownLabels(r.Labels), ShownAbout(r.About)
	if r.About.Empty() {
		r.About = nil
	}
	return json.Marshal(r)
}

// RegistrationAnswer is the server's signed 200 to a registration through a gateway,
// run-registration-answer.schema.json: the run's id and its run key, which the starter
// passes to the run as QORY_RUN_KEY. It carries no run configuration: the starter never
// receives the run's policy.
type RegistrationAnswer struct {
	Version int    `json:"version"`
	RunID   string `json:"run_id"`
	RunKey  string `json:"run_key"`
}

// shownRegistrationAnswer is a RegistrationAnswer without its methods, which fmt prints
// the way it prints any struct.
type shownRegistrationAnswer RegistrationAnswer

func (a RegistrationAnswer) shown() shownRegistrationAnswer {
	s := shownRegistrationAnswer(a)
	if s.RunKey != "" {
		s.RunKey = redactedSecret
	}
	return s
}

// Format prints a as fmt prints a struct, under every verb and flag, with its RunKey
// redacted.
func (a RegistrationAnswer) Format(f fmt.State, verb rune) {
	out := fmt.Sprintf(fmt.FormatString(f, verb), a.shown())
	if verb == 'v' && f.Flag('#') {
		out = strings.Replace(out, "server.shownRegistrationAnswer", "server.RegistrationAnswer", 1)
	}
	io.WriteString(f, out)
}

// String is a as %v prints it, its RunKey redacted.
func (a RegistrationAnswer) String() string { return fmt.Sprintf("%v", a) }

// GoString is a as %#v prints it, its RunKey redacted.
func (a RegistrationAnswer) GoString() string { return fmt.Sprintf("%#v", a) }

// LogValue is a as log/slog logs it: its version and run id, never the run key.
func (a RegistrationAnswer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("version", a.Version),
		slog.String("run_id", a.RunID),
		slog.String("run_key", a.shown().RunKey),
	)
}

// MarshalJSON is a as encoding/json writes a struct, with its RunKey redacted, for a
// log or a dump that writes it so. Reading one back is as encoding/json reads a struct.
func (a RegistrationAnswer) MarshalJSON() ([]byte, error) { return json.Marshal(a.shown()) }

// RegisterThroughGateway posts a run's registration through a gateway, body, the bytes
// of a [GatewayRegistration], to the run endpoint runURL, and returns the server's
// answer. The answer is a signed 200 with a run-registration-answer.schema.json
// document whose run id is the body's and whose run key reads, unverified, as one of
// that run ([runkey.Parse]), and with neither an X-Qory-Run-Configuration nor an ETag
// header: anything else of a signed 200 is a [*DocumentError]. A 401
// is unauthorized, an answer that does not verify answer_unsigned, and a signed refusal
// its code, each an [*accesskey.Refusal]: among them node_is_direct, the server's
// answer when the access key's node or node pool reports directly, no_default_gateway,
// gateway_not_serving, gateway_without_key, gateway_key for a gateway's own key,
// instance_limit and run_id_used. A signed 410, with any code or none, is
// [ErrNotAccepted]. The error names the URL and the status, and never contains the run
// key. A caller that tries again sends the same body.
func (c *Client) RegisterThroughGateway(ctx context.Context, runURL string, body []byte) (*RegistrationAnswer, error) {
	what := "register " + accesskey.ShownValue(runURL, false)
	var sent struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(body, &sent); err != nil || sent.RunID == "" {
		return nil, fmt.Errorf("%s: the body names no run id", what)
	}
	a, err := c.send(ctx, http.MethodPost, runURL, body, MaxRefusal, func(h http.Header) {
		h.Set("Content-Type", RegistrationContentType)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, accesskey.ShownError(err))
	}
	if err := a.notOK(what); err != nil {
		return nil, err
	}
	if len(a.header.Values(HeaderRunConfiguration)) > 0 || len(a.header.Values("ETag")) > 0 {
		return nil, &DocumentError{"registration answer", runURL, errors.New("the answer carries X-Qory-Run-Configuration or ETag; a registration through a gateway carries no run configuration")}
	}
	var ans RegistrationAnswer
	if err := readAnswer("run-registration-answer.schema.json", a.body, &ans); err != nil {
		return nil, &DocumentError{"registration answer", runURL, err}
	}
	if ans.RunID != sent.RunID {
		return nil, &DocumentError{"registration answer", runURL, errors.New("the answer's run_id is not the registration's")}
	}
	k, err := runkey.Parse(ans.RunKey)
	if err != nil {
		return nil, &DocumentError{"registration answer", runURL, fmt.Errorf("run_key: %w", err)}
	}
	if k.RunID != ans.RunID {
		return nil, &DocumentError{"registration answer", runURL, errors.New("the run key is not the run's")}
	}
	return &ans, nil
}

// notOK is the error of an answer other than a signed 200, as a registration reads
// it: a signed 410 is [ErrNotAccepted], with any code or none; a refusal is its
// [*accesskey.Refusal]; a signed answer with no code is [ErrNotAccepted] as well. Nil
// for a signed 200.
func (a *answer) notOK(what string) error {
	if a.signed && a.status == http.StatusGone {
		return fmt.Errorf("%s: status %d: %w", what, a.status, ErrNotAccepted)
	}
	if a.status == http.StatusOK && a.signed {
		return nil
	}
	err := a.refusal(what)
	var e *AnswerError
	if errors.As(err, &e) {
		return fmt.Errorf("%w: %w", err, ErrNotAccepted)
	}
	return err
}

// Attach is the body of a run's attach, run-attach.schema.json: the run key, and what
// the run tells the server of itself, the heartbeat interval it uses, the event types
// the server receives, Forager's version and the contract revision, with the time. The
// gateway the run key names sends it, signed by its own access key.
type Attach struct {
	// Version is the document's version; 0 is written as 1.
	Version int `json:"version"`
	// RunKey is the run's run key.
	RunKey string `json:"run_key"`
	// IntervalSeconds is the heartbeat interval the run uses, from 1 to [MaxInterval]:
	// the run's liveness counts from it.
	IntervalSeconds int `json:"interval_seconds"`
	// Events are the event types the server receives, as its configuration lists them;
	// nil is written as none.
	Events []string `json:"events"`
	// ForagerVersion is the Forager module version.
	ForagerVersion string `json:"forager_version"`
	// ContractVersion is the contract revision Forager implements; 0 is written as
	// [Revision].
	ContractVersion int `json:"contract_version"`
	// Time is when the body was built, RFC 3339 in UTC with whole seconds. Empty, Body
	// sets it from the clock.
	Time string `json:"time"`
}

// Body is the attach's bytes, built once: every try sends them as they are. A Time
// left empty is the clock's now, a Version left 0 is 1, and a ContractVersion left 0
// is [Revision]. A run key that does not read as one ([runkey.Parse]), an interval
// outside 1 to [MaxInterval] and an empty Forager version are its error, and no body is
// built; the error never contains the run key.
func (a Attach) Body() ([]byte, error) {
	if a.Version == 0 {
		a.Version = 1
	}
	if a.ContractVersion == 0 {
		a.ContractVersion = Revision
	}
	if a.Time == "" {
		a.Time = RegistrationTime(time.Now())
	}
	if a.Events == nil {
		a.Events = []string{}
	}
	if _, err := runkey.Parse(a.RunKey); err != nil {
		return nil, fmt.Errorf("the attach: the run key: %w", err)
	}
	if a.IntervalSeconds < 1 || a.IntervalSeconds > MaxInterval {
		return nil, fmt.Errorf("the attach: interval_seconds is %d; from 1 to %d belong", a.IntervalSeconds, MaxInterval)
	}
	if a.ForagerVersion == "" {
		return nil, errors.New("the attach: forager_version is empty")
	}
	// wireAttach is an Attach without its methods, which encoding/json writes with its
	// run key.
	type wireAttach Attach
	return json.Marshal(wireAttach(a))
}

// shownAttach is an Attach without its methods, which fmt prints the way it prints any
// struct.
type shownAttach Attach

func (a Attach) shown() shownAttach {
	s := shownAttach(a)
	if s.RunKey != "" {
		s.RunKey = redactedSecret
	}
	return s
}

// Format prints a as fmt prints a struct, under every verb and flag, with its RunKey
// redacted.
func (a Attach) Format(f fmt.State, verb rune) {
	out := fmt.Sprintf(fmt.FormatString(f, verb), a.shown())
	if verb == 'v' && f.Flag('#') {
		out = strings.Replace(out, "server.shownAttach", "server.Attach", 1)
	}
	io.WriteString(f, out)
}

// String is a as %v prints it, its RunKey redacted.
func (a Attach) String() string { return fmt.Sprintf("%v", a) }

// GoString is a as %#v prints it, its RunKey redacted.
func (a Attach) GoString() string { return fmt.Sprintf("%#v", a) }

// LogValue is a as log/slog logs it: what the run tells the server of itself and the
// time, never the run key.
func (a Attach) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("version", a.Version),
		slog.String("run_key", a.shown().RunKey),
		slog.Int("interval_seconds", a.IntervalSeconds),
		slog.Any("events", a.Events),
		slog.String("forager_version", a.ForagerVersion),
		slog.Int("contract_version", a.ContractVersion),
		slog.String("time", a.Time),
	)
}

// MarshalJSON is a as encoding/json writes a struct, with its RunKey redacted, for a
// log or a dump that writes it so; [Attach.Body] is the attach's bytes. Reading one
// back is as encoding/json reads a struct.
func (a Attach) MarshalJSON() ([]byte, error) { return json.Marshal(a.shown()) }

// AttachAnswer is the server's signed 200 to an attach, run-attach-answer.schema.json:
// the run's run configuration, as a direct registration's answer carries it, and the
// labels and what the run is about, as the starter's registration gave them, each
// absent when the registration had none.
type AttachAnswer struct {
	RunConfiguration *RunConfiguration
	Labels           map[string]string
	About            *About
}

// Attach posts a run's attach, body, the bytes of an [Attach], to
// <runURL>/<runID>/attach, signed by the gateway's own access key, and returns the
// server's answer with its digest of the run configuration. The answer is a signed
// 200, a run-attach-answer.schema.json document with the X-Qory-Run-Configuration
// header and one ETag, that digest in quotes: a run configuration Forager refuses,
// labels or an about the contract refuses, a digest header missing or misshapen, or an
// ETag that is not the digest in quotes, is a [*DocumentError]. A 401 is
// unauthorized, an answer that does not verify answer_unsigned, and a signed refusal
// its code, each an [*accesskey.Refusal]: not_a_gateway, run_key_invalid,
// run_key_expired, wrong_gateway, workspace_not_served and run_attached among them. A
// signed 410, with any code or none, is [ErrNotAccepted]: the run has ended. The error
// names the URL, attach <runURL>/<runID>, and the status, and never contains the run
// key.
func (c *Client) Attach(ctx context.Context, runURL, runID string, body []byte) (*AttachAnswer, string, error) {
	if !runIDShape.MatchString(runID) {
		return nil, "", errors.New("the attach: the run id is not a UUID in the canonical lower-case form")
	}
	what := "attach " + accesskey.ShownValue(runURL+"/"+runID, false)
	u := runURL + "/" + runID + "/attach"
	a, err := c.send(ctx, http.MethodPost, u, body, MaxDocument, func(h http.Header) {
		h.Set("Content-Type", RegistrationContentType)
	})
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", what, accesskey.ShownError(err))
	}
	if err := a.notOK(what); err != nil {
		return nil, "", err
	}
	rc, digest, err := runConfigurationOf(a, u)
	if err != nil {
		return nil, "", err
	}
	if etag := a.header.Values("ETag"); len(etag) != 1 || etag[0] != strconv.Quote(digest) {
		return nil, "", &DocumentError{"attach answer", u, errors.New("the ETag header is not the X-Qory-Run-Configuration digest in quotes")}
	}
	var more struct {
		Labels map[string]string `json:"labels"`
		About  *About            `json:"about"`
	}
	if err := readAnswer("run-attach-answer.schema.json", a.body, &more); err != nil {
		return nil, "", &DocumentError{"attach answer", u, err}
	}
	if err := CheckLabels(more.Labels); err != nil {
		return nil, "", &DocumentError{"attach answer", u, err}
	}
	if err := CheckAbout(more.About); err != nil {
		return nil, "", &DocumentError{"attach answer", u, err}
	}
	if len(more.Labels) == 0 {
		more.Labels = nil
	}
	if more.About.Empty() {
		more.About = nil
	}
	return &AttachAnswer{RunConfiguration: rc, Labels: more.Labels, About: more.About}, digest, nil
}

// readAnswer reads a small signed document of the server: through encoding/json/v2
// first, which refuses a member name that appears twice and invalid UTF-8, then against
// the schema, then into out, a member out does not hold ignored. An error names where
// in the document it is and which rule refused it, never a value: a registration's
// answer carries the run key.
func readAnswer(schemaName string, body []byte, out any) error {
	var v any
	if err := jsonv2.Unmarshal(body, &v); err != nil {
		var syn *jsontext.SyntacticError
		if errors.As(err, &syn) && syn.JSONPointer != "" {
			return fmt.Errorf("it is not one JSON value in UTF-8 with each member name once, at %s", accesskey.ShownValue(string(syn.JSONPointer), false))
		}
		return errors.New("it is not one JSON value in UTF-8 with each member name once")
	}
	doc, err := contracts.Decode("answer.json", body)
	if err != nil {
		return errors.New("it is not JSON")
	}
	schema, err := contracts.Compile(schemaName)
	if err != nil {
		return err
	}
	if err := schema.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(err, &ve) {
			return fmt.Errorf("%s refuses it", schemaName)
		}
		return fmt.Errorf("%s refuses %s", schemaName, strings.Join(leaves(ve), ", "))
	}
	// encoding/json reads About's details as the raw JSON they are.
	if err := json.Unmarshal(body, out); err != nil {
		return errors.New("it does not decode")
	}
	return nil
}
