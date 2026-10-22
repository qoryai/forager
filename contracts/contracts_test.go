package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// compile compiles every schema a test needs once.
func compile(t *testing.T, names ...string) map[string]*jsonschema.Schema {
	t.Helper()
	c, err := contracts.Compiler()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*jsonschema.Schema{}
	for _, n := range names {
		s, err := c.Compile(contracts.Base + "/" + n)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		out[n] = s
	}
	return out
}

// files lists the files under a directory of the contract, sorted, or fails the test
// when there are none: an empty fixture directory is a missing fixture.
func files(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := fs.ReadDir(contracts.FS, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, path.Join(dir, e.Name()))
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no fixture", dir)
	}
	return out
}

// TestEverySchemaCompiles pins that each schema of the contract is a valid schema under
// the draft it declares and that every $ref between them resolves from the embedded
// directory alone.
func TestEverySchemaCompiles(t *testing.T) {
	c, err := contracts.Compiler()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	err = fs.WalkDir(contracts.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".schema.json") {
			return err
		}
		n++
		if _, err := c.Compile(contracts.Base + "/" + p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 22 {
		t.Errorf("found %d schemas; want the envelope, the batch, the record, the policy, "+
			"the server, the configuration, the run configuration, the descriptor and one "+
			"per event type", n)
	}
}

// TestDocumentFixturesValidate pins that every policy, server, configuration, run
// registration, run configuration, attach answer, outcome, batch answer, API format and
// descriptor fixture passes its schema.
func TestDocumentFixturesValidate(t *testing.T) {
	s := compile(t, "policy.schema.json", "server.schema.json", "configuration.schema.json",
		"run-registration.schema.json", "run-configuration.schema.json",
		"run-attach-answer.schema.json", "run-outcome.schema.json", "batch-answer.schema.json",
		"api-format.schema.json", "descriptor.schema.json")
	dirs := map[string]string{
		"fixtures/api-format":        "api-format.schema.json",
		"fixtures/descriptor":        "descriptor.schema.json",
		"fixtures/run-attach-answer": "run-attach-answer.schema.json",
		"fixtures/run-outcome":       "run-outcome.schema.json",
		"fixtures/batch-answer":      "batch-answer.schema.json",
		"fixtures/policy":            "policy.schema.json",
		"fixtures/server":            "server.schema.json",
		"fixtures/configuration":     "configuration.schema.json",
		"fixtures/run-registration":  "run-registration.schema.json",
		"fixtures/run-configuration": "run-configuration.schema.json",
	}
	for dir, schema := range dirs {
		for _, f := range files(t, dir) {
			doc, err := contracts.Document(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := s[schema].Validate(doc); err != nil {
				t.Errorf("%s: %v", f, err)
			}
		}
	}
}

// TestAPIFormatsAreTheFixedList pins api-format.schema.json, which another contract
// refers to by its $id, one $ref per item: a string schema at that $id, without $defs,
// whose enum is the four formats in this order.
func TestAPIFormatsAreTheFixedList(t *testing.T) {
	s := compile(t, "api-format.schema.json")["api-format.schema.json"]
	b, err := fs.ReadFile(contracts.FS, "api-format.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["$id"] != contracts.Base+"/api-format.schema.json" || doc["type"] != "string" {
		t.Errorf("$id %v, type %v; want %s/api-format.schema.json and string", doc["$id"], doc["type"], contracts.Base)
	}
	if _, ok := doc["$defs"]; ok {
		t.Error("api-format.schema.json has $defs; a reference to it is to the whole file")
	}
	want := []any{"anthropic-messages", "openai-responses", "openai-chat", "gemini"}
	if !reflect.DeepEqual(doc["enum"], want) {
		t.Errorf("enum %v; want %v", doc["enum"], want)
	}
	for _, v := range want {
		if err := s.Validate(v); err != nil {
			t.Errorf("%v: %v", v, err)
		}
	}
	for _, v := range []any{"", "anthropic", "Anthropic-Messages", "openai-completions", json.Number("1"), nil} {
		if s.Validate(v) == nil {
			t.Errorf("%v passed; want a failure", v)
		}
	}
}

// The schemas of the gateway's link.
const (
	linkDiscovery  = "link-discovery.schema.json"
	linkRunRequest = "link-run-request.schema.json"
	linkRunAnswer  = "link-run-answer.schema.json"
	linkReload     = "link-reload-answer.schema.json"
	linkBatch      = "link-batch.schema.json"
	linkRefusal    = "link-refusal.schema.json"
	linkJoinReq    = "link-join-request.schema.json"
	linkJoinAnswer = "link-join-answer.schema.json"
)

// namedSchema returns the longest schema name, without .schema.json, that the file's
// base name starts with followed by a dash or by .json, or "" when none does.
func namedSchema(s map[string]*jsonschema.Schema, f string) string {
	kind := ""
	base := path.Base(f)
	for name := range s {
		prefix := strings.TrimSuffix(name, ".schema.json")
		if (strings.HasPrefix(base, prefix+"-") || strings.HasPrefix(base, prefix+".")) &&
			len(prefix) > len(kind) {
			kind = prefix
		}
	}
	return kind
}

// TestLinkFixturesValidate pins that every document under fixtures/link passes the schema
// of the gateway's link its name starts with: the discovery of the local link and of a
// separate gateway, each with its proxy address, a run request without a wall, one with a
// wall and its images, and one with a narrowing as well, a run
// answer with a wall, its placeholders, reserved names, credential hosts, image, applied
// and certificate authority, one with a wall and an image but no certificate
// authority, one without a wall, one without a wall whose gateway holds a credential,
// with its certificate authority, and one without a policy, a reload answer with and
// without a policy and one whose applied has ceiling_paths, a batch of a session's events without sequence, a batch of
// a run.refused with a code the session decides, a batch of a session.exited and a run.exited
// with timeout, two with interrupted, one of a refused join, two of a failure at the join
// after its session.started, with no reason and with the wall's refusal's code, and one
// of a run closed with no session, a batch of a setup step after a run.started with
// machine and setup, a batch of a build step and the run's run.built, a join request
// with and without model_credential, a join answer with and
// without model_credential, and refusals from the gateway, two internal ones among them, one whose message spans
// lines, two 410s with the state and the reason of the run's end, and from apiary.
func TestLinkFixturesValidate(t *testing.T) {
	s := compile(t, linkDiscovery, linkRunRequest, linkRunAnswer, linkReload, linkBatch, linkRefusal,
		linkJoinReq, linkJoinAnswer)
	seen := map[string]bool{}
	for _, f := range files(t, "fixtures/link") {
		kind := namedSchema(s, f)
		schema, ok := s[kind+".schema.json"]
		if !ok {
			t.Errorf("%s: no schema named by the prefix", f)
			continue
		}
		seen[kind] = true
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for name := range s {
		if kind := strings.TrimSuffix(name, ".schema.json"); !seen[kind] {
			t.Errorf("fixtures/link holds no %s", kind)
		}
	}
}

// TestLinkBatchRefusedCodesAreTheSessions pins the codes a link batch's
// dev.qory.run.refused may carry to the codes the session decides itself: every code of
// link-batch.schema.json's enum is one refusal.Decides reports, and every code of
// run.refused.schema.json that refusal.Decides reports is in it.
func TestLinkBatchRefusedCodesAreTheSessions(t *testing.T) {
	read := func(name string) map[string]any {
		b, err := fs.ReadFile(contracts.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	// at follows the keys from v, and returns nil where one is missing.
	at := func(v any, keys ...string) any {
		for _, k := range keys {
			m, _ := v.(map[string]any)
			v = m[k]
		}
		return v
	}
	var link []any
	parts, _ := at(read(linkBatch), "$defs", "event", "allOf").([]any)
	for _, part := range parts {
		if at(part, "if", "properties", "type", "const") == "dev.qory.run.refused" {
			link, _ = at(part, "then", "properties", "data", "properties", "code", "enum").([]any)
		}
	}
	if len(link) == 0 {
		t.Fatal("link-batch.schema.json holds no code enum for dev.qory.run.refused")
	}
	allowed := map[string]bool{}
	for _, c := range link {
		allowed[c.(string)] = true
		if !refusal.Decides(c.(string)) {
			t.Errorf("a link batch's run.refused allows %s, which the session does not decide", c)
		}
	}
	all, _ := at(read("events/run.refused.schema.json"), "then", "properties", "code", "enum").([]any)
	if len(all) == 0 {
		t.Fatal("run.refused.schema.json holds no code enum")
	}
	for _, c := range all {
		if refusal.Decides(c.(string)) && !allowed[c.(string)] {
			t.Errorf("a link batch's run.refused does not allow %s, which the session decides", c)
		}
	}
}

// beyondLinkSchema marks a refused fixture under fixtures/invalid whose rule only the
// gateway checks, which its schema accepts: a session's dev.qory.run.exited with a
// reason of the starter's, which the close never writes.
const beyondLinkSchema = "-beyond-schema-"

// TestInvalidFixturesAreRefused pins that each document under fixtures/invalid fails the
// schema its name starts with: a policy that widens or whose allow_first holds a *.
// pattern or 65 entries, a server without its access key id
// or its pin or with a secret, a configuration without events, without its run
// endpoint, without workspaces or with two, or whose run endpoint has a query, a fragment
// or a trailing slash, a batch that holds a
// run.registered, a run registration with a member it does not define, with an interval over
// 300 seconds or with a time that is not UTC in whole seconds, a run configuration
// whose image has a tag or is the machine's name for one, whose API credential has
// hosts or placeholders, no endpoint, an endpoint that is not https or has a user, a
// query or a fragment, a format outside the list, oauth beside a header or set to
// false, or key prefixes that are none, five, with a space or of 33 characters, or
// whose model_credential is no credential's name, a run.registered whose
// interval is over 300 seconds or without its workspace, an event with an unpadded sequence, a run.started without opened_by,
// with an unknown one, opened by a session, with a runtime member, with a machine in
// upper case or with a setup other than outside and inside, a session.started
// without its command, numbered 0, with preparation, whose setup_commands is empty, or
// whose harness is empty, has a member it does not define or a commit of 39 characters, a session.exited without its session, failed
// with exit status 0 and no reason, cancelled with stopped and an exit status, cancelled
// with gateway_lost, or of a refused join with an exit status other than -1, a run.log
// whose step is 0, a run.step_started with an unknown kind, without its name or numbered
// 0, a run.built whose image has a tag, whose size is 0, whose commit is in upper case
// or of 39 characters, or whose environment_ref is empty or missing, a
// run.step_exited without its state, with a state other than the three, with an
// exit code below -1 or without its duration, a run.exited with no_session and succeeded,
// a run.exited without state, with a state other than the three, with a reason that is
// not a code, with gateway_lost and a state other than failed, with quiet and no
// quiet_seconds or with quiet_seconds and another reason, a run.refused with a code outside the list and no
// status, a descriptor with an expression, a descriptor whose model section has a
// format outside the list, a place of two kinds or of none, an empty list of values,
// no formats, a member it does not define, an endpoint that is no variable,
// overrides that are empty, list a name twice or list something other than a
// variable's name, or keys that are empty, read from HOME, of a format outside the
// list, without a variable or with oauth beside a header, a descriptor that declares a
// secret read from LD_PRELOAD, a link run request
// without wall, whose run id is not lower-case or whose narrowing holds a member it does
// not define, that has passes, a member only a join request has, or whose image has no
// reference, a link run
// answer without applied, with a proxy secret too short, whose image has no reference
// or whose credential_hosts entry has a member it does not define, no hosts, no
// placeholders, a format without an endpoint or an endpoint without a format, a link reload answer with the proxy secret or the certificate
// authority or whose applied holds variables, a link batch whose event carries a sequence, that holds a
// run.registered or a run.egress, a run.started opened by a gateway or a session, a run.exited with one of Forager's reasons
// other than timeout, interrupted and no_session, its old names among them, or with timeout and a state other than cancelled
// or an exit code other than 124, a session.exited cancelled with no reason, succeeded with exit status 1, with stopped,
// succeeded with no exit status or cancelled with a refusal's code, or a run.refused with a gateway's code,
// its old codes among them, run_closed, another code of the
// server's or a name of the form <member>=<value>, a link discovery that lists a node or
// workspaces or has no heartbeat interval or proxy, a link join request without passes,
// with a member it does not define or a name of the form <name>=<value> in passes, a
// link join answer without its session or numbered 0, and a link refusal without from, with a control
// character other than tab and newline in its message, C0, DEL or C1, or with a state
// other than the three, and an API format outside the list, in upper case or as an
// object. A fixture whose name holds -beyond-schema- breaks a
// rule only the gateway checks, and passes its schema. The longest schema name the file name starts with is
// the schema, so run-configuration-variable-value-not-string is held to the run
// configuration and not to a schema named run.
func TestInvalidFixturesAreRefused(t *testing.T) {
	s := compile(t, "policy.schema.json", "server.schema.json", "configuration.schema.json",
		"run-registration.schema.json", "run-configuration.schema.json", "event.schema.json", "batch.schema.json",
		"api-format.schema.json", "descriptor.schema.json", "record.schema.json", "enrolment.schema.json",
		linkDiscovery, linkRunRequest, linkRunAnswer, linkReload, linkBatch, linkRefusal, linkJoinReq, linkJoinAnswer,
		"run-key.schema.json", "run-registration-answer.schema.json",
		"run-attach.schema.json", "run-attach-answer.schema.json", "run-outcome.schema.json",
		"run-outcome-answer.schema.json", "batch-answer.schema.json",
		"secrets-request.schema.json", "secrets-answer.schema.json", "sealed-plaintext.schema.json")
	for _, f := range files(t, "fixtures/invalid") {
		kind := namedSchema(s, f)
		schema, ok := s[kind+".schema.json"]
		if !ok {
			t.Errorf("%s: no schema named by the prefix", f)
			continue
		}
		var doc any
		var err error
		if strings.HasSuffix(f, ".jsonl") {
			var lines []any
			lines, err = contracts.Lines(f)
			if err == nil && len(lines) == 1 {
				doc = lines[0]
			}
		} else {
			doc, err = contracts.Document(f)
		}
		if err != nil {
			t.Fatal(err)
		}
		err = schema.Validate(doc)
		switch beyond := strings.Contains(path.Base(f), beyondLinkSchema); {
		case beyond && err != nil:
			t.Errorf("%s fails %s, but is marked as a rule only the gateway checks: %v", f, kind, err)
		case !beyond && err == nil:
			t.Errorf("%s passed %s; want a failure", f, kind)
		}
	}
}

// TestRecordedRunValidates pins the recorded run directory: every line of events.jsonl
// is an event of the contract, the sequence starts at one and is contiguous, every event
// names the same run in source and subject, the run starts with run.registered, the
// gateway's record of the server's accepted registration, or with run.started, and
// ends with run.exited, and output.log is the concatenation of the run.log chunks. What
// the schema does not require is pinned here: every run.exited Forager writes contains
// exit_code, beside state, which the schema requires; and the sessions are numbered from
// 1 in order, each session.started followed by the session.exited of its number before
// the next session.started and before run.exited; and a run.log, a run.resized or a
// runtime event with a session member lies inside that session, so a run.log of the
// host work, outside every session, has none; and the steps are numbered from 1 in the
// order they start, after run.started, each run.step_exited following the
// run.step_started of its number, once, and a run.log with a step member lies between
// that step's run.step_started and run.step_exited; a join step lies outside every
// session and no session starts during one, an image or a wall step lies inside a
// session, and a run.log with both session and step is one of an image, a wall or a
// setup step; and every step ends before run.exited, unless the gateway ended the run, whose
// run.exited has a reason the close never writes.
func TestRecordedRunValidates(t *testing.T) {
	s := compile(t, "event.schema.json")
	runs, err := fs.ReadDir(contracts.FS, "fixtures/run")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, run := range runs {
		if !run.IsDir() {
			continue
		}
		n++
		dir := path.Join("fixtures/run", run.Name())
		events, err := contracts.Lines(path.Join(dir, "events.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if len(events) == 0 {
			t.Fatalf("%s: no events", dir)
		}
		var log []byte
		open, last := 0, 0
		started, steps, stepped, kinds := false, 0, map[int]string{}, map[int]string{}
		// openJoin reports whether a join step is open.
		openJoin := func() bool {
			for n, k := range kinds {
				if k == "join" && stepped[n] == "started" {
					return true
				}
			}
			return false
		}
		for i, e := range events {
			if err := s["event.schema.json"].Validate(e); err != nil {
				t.Errorf("%s: line %d: %v", dir, i+1, err)
				continue
			}
			m := e.(map[string]any)
			if want := fmt.Sprintf("%010d", i+1); m["sequence"] != want {
				t.Errorf("%s: line %d: sequence %v, want %s", dir, i+1, m["sequence"], want)
			}
			if m["subject"] != run.Name() || m["source"] != "urn:qory:run:"+run.Name() {
				t.Errorf("%s: line %d: subject %v and source %v do not name the directory",
					dir, i+1, m["subject"], m["source"])
			}
			if m["type"] == "dev.qory.run.exited" {
				d, _ := m["data"].(map[string]any)
				_, state := d["state"]
				_, code := d["exit_code"]
				if !state || !code {
					t.Errorf("%s: line %d: a run exits with state %v and exit_code %v",
						dir, i+1, d["state"], d["exit_code"])
				}
			}
			if n, ok := sessionNumber(m); ok {
				switch m["type"] {
				case "dev.qory.session.started":
					if openJoin() {
						t.Errorf("%s: line %d: session %d starts during a join step", dir, i+1, n)
					}
					if open != 0 || n != last+1 {
						t.Errorf("%s: line %d: session %d starts after session %d, with session %d open", dir, i+1, n, last, open)
					}
					open, last = n, n
				case "dev.qory.session.exited":
					if n != open {
						t.Errorf("%s: line %d: session %d exits, with session %d open", dir, i+1, n, open)
					}
					open = 0
				}
			}
			if typ, _ := m["type"].(string); typ == "dev.qory.run.log" || typ == "dev.qory.run.resized" || strings.HasPrefix(typ, "dev.qory.runtime.") {
				if n, ok := m["data"].(map[string]any)["session"].(json.Number); ok && n.String() != strconv.Itoa(open) {
					t.Errorf("%s: line %d: %s of session %s, with session %d open", dir, i+1, typ, n, open)
				}
			}
			if m["type"] == "dev.qory.run.started" {
				started = true
			}
			if n, ok := stepNumber(m); ok {
				switch m["type"] {
				case "dev.qory.run.step_started":
					if !started {
						t.Errorf("%s: line %d: step %d starts before run.started", dir, i+1, n)
					}
					if n != steps+1 {
						t.Errorf("%s: line %d: step %d starts after step %d", dir, i+1, n, steps)
					}
					steps, stepped[n] = n, "started"
					kinds[n], _ = m["data"].(map[string]any)["kind"].(string)
					switch inside := open != 0; kinds[n] {
					case "join":
						if inside {
							t.Errorf("%s: line %d: join step %d starts inside session %d", dir, i+1, n, open)
						}
					case "image", "wall":
						if !inside {
							t.Errorf("%s: line %d: %s step %d starts outside every session", dir, i+1, kinds[n], n)
						}
					}
				case "dev.qory.run.step_exited":
					if stepped[n] != "started" {
						t.Errorf("%s: line %d: step %d exits, and its state is %q, not started", dir, i+1, n, stepped[n])
					}
					stepped[n] = "exited"
				case "dev.qory.run.log":
					if stepped[n] != "started" {
						t.Errorf("%s: line %d: a run.log of step %d, whose state is %q, not started", dir, i+1, n, stepped[n])
					}
					if _, ok := m["data"].(map[string]any)["session"]; ok && kinds[n] != "image" && kinds[n] != "wall" && kinds[n] != "setup" {
						t.Errorf("%s: line %d: a run.log of a session in %s step %d", dir, i+1, kinds[n], n)
					}
				}
			}
			if m["type"] == "dev.qory.run.exited" && open != 0 {
				t.Errorf("%s: line %d: the run exits with session %d open", dir, i+1, open)
			}
			if m["type"] == "dev.qory.run.exited" {
				reason, _ := m["data"].(map[string]any)["reason"].(string)
				byClose := reason == "" || reason == "timeout" || reason == "interrupted" || reason == "no_session"
				for n, st := range stepped {
					if st == "started" && byClose {
						t.Errorf("%s: line %d: the run exits with step %d open", dir, i+1, n)
					}
				}
			}
			if m["type"] == "dev.qory.run.log" {
				chunk, err := base64Decode(m["data"].(map[string]any)["bytes"].(string))
				if err != nil {
					t.Fatal(err)
				}
				log = append(log, chunk...)
			}
		}
		first := events[0].(map[string]any)["type"]
		if first != "dev.qory.run.registered" && first != "dev.qory.run.started" {
			t.Errorf("%s: first event is %v; want run.registered or run.started", dir, first)
		}
		if last := events[len(events)-1].(map[string]any)["type"]; last != "dev.qory.run.exited" {
			t.Errorf("%s: last event is %v; want run.exited", dir, last)
		}
		out, err := fs.ReadFile(contracts.FS, path.Join(dir, "output.log"))
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != string(log) {
			t.Errorf("%s: output.log is not the concatenation of the run.log chunks", dir)
		}
	}
	if n == 0 {
		t.Fatal("fixtures/run holds no run")
	}
}

// sessionNumber returns the session of a session.started or a session.exited.
func sessionNumber(m map[string]any) (int, bool) {
	if m["type"] != "dev.qory.session.started" && m["type"] != "dev.qory.session.exited" {
		return 0, false
	}
	n, _ := m["data"].(map[string]any)["session"].(json.Number)
	v, err := n.Int64()
	return int(v), err == nil
}

// stepNumber returns the step of a run.step_started, a run.step_exited or a run.log
// with a step member.
func stepNumber(m map[string]any) (int, bool) {
	if m["type"] != "dev.qory.run.step_started" && m["type"] != "dev.qory.run.step_exited" && m["type"] != "dev.qory.run.log" {
		return 0, false
	}
	n, ok := m["data"].(map[string]any)["step"].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	return int(v), err == nil
}

// TestSessionExitedReasonsAreTheSessions pins the reasons of a dev.qory.session.exited in a
// link batch to timeout, interrupted and the codes a link batch's dev.qory.run.refused may
// carry, the codes the session decides itself: a refused join has its refusal's code as
// reason. The event's reason is the open code of dev.qory.run.exited, since the gateway
// writes a session's dev.qory.session.exited with the reason of the run's end.
func TestSessionExitedReasonsAreTheSessions(t *testing.T) {
	doc, err := contracts.Document("link-batch.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rule := range doc.(map[string]any)["$defs"].(map[string]any)["event"].(map[string]any)["allOf"].([]any) {
		r, _ := rule.(map[string]any)
		typ, _ := dig(r, "if", "properties", "type", "const").(string)
		if typ != "dev.qory.session.exited" {
			continue
		}
		enum, _ := dig(r, "then", "properties", "data", "properties", "reason", "enum").([]any)
		for _, c := range enum {
			got = append(got, c.(string))
		}
	}
	for _, code := range got {
		if code != "timeout" && code != "interrupted" && !refusal.Decides(code) {
			t.Errorf("a link batch's session.exited allows the reason %s, which the session does not decide", code)
		}
	}
	for _, code := range []string{"timeout", "interrupted", "placeholder_conflict", "mount_mode_conflict", "engine_unreachable"} {
		if !slices.Contains(got, code) {
			t.Errorf("a link batch's session.exited does not allow the reason %s", code)
		}
	}
	pattern := func(name string) any {
		d, err := contracts.Document(name)
		if err != nil {
			t.Fatal(err)
		}
		return dig(d.(map[string]any), "properties", "reason", "pattern")
	}
	if s, r := pattern("events/session.exited.schema.json"), pattern("events/run.exited.schema.json"); s == nil || s != r {
		t.Errorf("session.exited's reason pattern is %v; want run.exited's, %v", s, r)
	}
}

// dig returns the value at the path of member names under m, or nil.
func dig(m map[string]any, names ...string) any {
	var v any = m
	for _, n := range names {
		o, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = o[n]
	}
	return v
}

// beyondSchema marks the refused fixtures of about whose rule only Forager checks: a
// byte limit, the 8192 bytes of details as the event contains them, two subjects with
// the same type and ref, a url's syntax and host, a url's user name or password, and a
// member name twice in details.
// The schema accepts each of them.
const beyondSchema = "about-refused-beyond-schema-"

// aboutFixtures lists the fixtures of about under fixtures/run, the accepted ones and
// the refused ones, about-refused-<reason>.json.
func aboutFixtures(t *testing.T) (accepted, refused []string) {
	t.Helper()
	for _, f := range files(t, "fixtures/run") {
		switch name := path.Base(f); {
		case strings.HasPrefix(name, "about-refused-"):
			refused = append(refused, f)
		case strings.HasPrefix(name, "about-"):
			accepted = append(accepted, f)
		}
	}
	if len(accepted) == 0 || len(refused) == 0 {
		t.Fatal("fixtures/run holds no accepted or no refused about")
	}
	return accepted, refused
}

// TestAboutFixturesValidate pins the about of dev.qory.run.started to its fixtures:
// every accepted one passes the schema's about, and every refused one fails it, apart
// from those marked beyond the schema, which pass it.
func TestAboutFixturesValidate(t *testing.T) {
	c, err := contracts.Compiler()
	if err != nil {
		t.Fatal(err)
	}
	const at = "/events/run.started.schema.json#/properties/about"
	about, err := c.Compile(contracts.Base + at)
	if err != nil {
		t.Fatal(err)
	}
	accepted, refused := aboutFixtures(t)
	for _, f := range accepted {
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := about.Validate(doc); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for _, f := range refused {
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		err = about.Validate(doc)
		switch beyond := strings.HasPrefix(path.Base(f), beyondSchema); {
		case beyond && err != nil:
			t.Errorf("%s is marked beyond the schema, and the schema refuses it: %v", f, err)
		case !beyond && err == nil:
			t.Errorf("%s passed the schema; want a failure", f)
		}
	}
}

// TestAboutFixturesAgreeWithCheckAbout holds Forager's check to the same fixtures as
// the schema: every accepted one decodes into an About that CheckAbout passes, and every
// refused one is refused, those marked beyond the schema included. A member About has no
// field for has nothing to decode into, so the decoding refuses it, and only it: an
// unknown member, in about or in a subject. Every other refused one decodes and
// CheckAbout refuses it.
func TestAboutFixturesAgreeWithCheckAbout(t *testing.T) {
	accepted, refused := aboutFixtures(t)
	decode := func(f string) (*server.About, error) {
		b, err := fs.ReadFile(contracts.FS, f)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var a server.About
		return &a, dec.Decode(&a)
	}
	for _, f := range accepted {
		a, err := decode(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if err := server.CheckAbout(a); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for _, f := range refused {
		a, err := decode(f)
		unknown := strings.Contains(path.Base(f), "unknown-member")
		switch {
		case unknown && err == nil:
			t.Errorf("%s decoded; want its unknown member refused", f)
		case unknown:
		case err != nil:
			t.Errorf("%s: %v", f, err)
		case server.CheckAbout(a) == nil:
			t.Errorf("%s passed CheckAbout; want a failure", f)
		}
	}
}

// TestBatchFixturesValidate pins that every batch fixture is a non-empty array of
// events.
func TestBatchFixturesValidate(t *testing.T) {
	s := compile(t, "batch.schema.json")
	for _, f := range files(t, "fixtures/batch") {
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := s["batch.schema.json"].Validate(doc); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// TestSignedFixtures pins the shape of every request under fixtures/signed, what any
// receiver is replayed: a method the contract signs, a target from the root, the
// headers every request contains and the ones its method adds, a revision from 1 to
// the contract's own, a body on a POST that is a batch, with X-Qory-Delivery, or a run
// registration, application/json without X-Qory-Delivery, and none on a GET, a status
// a receiver answers, the code of a coded refusal, and a note. A header a list holds is
// one sent once per value. On every request whose signature a receiver verifies, the
// signature is the Ed25519 one under the fixture access key secret over the request
// string, its lines the domain, the access key id and the instance id as the headers
// contain them, the method, the target, then the timestamp on a GET or the raw body on
// a POST, so the published signatures cannot drift from the fixtures they sign. Under
// -update-signed it signs the POSTs again instead (signBatches), after a change to a
// body; the command is updateSignedCommand.
func TestSignedFixtures(t *testing.T) {
	if *updateSigned {
		signBatches(t)
		return
	}
	s := compile(t, "batch.schema.json", "run-registration.schema.json")
	var keys struct {
		AccessKey struct {
			PublicKey  string `json:"public_key"`
			InstanceID string `json:"instance_id"`
		} `json:"access_key"`
	}
	b, err := fs.ReadFile(contracts.FS, "fixtures/known-answers/keys.json")
	if err != nil || json.Unmarshal(b, &keys) != nil {
		t.Fatalf("keys.json: %v", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(keys.AccessKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files(t, "fixtures/signed") {
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := doc.(map[string]any)
		method, _ := m["method"].(string)
		target, _ := m["target"].(string)
		headers, _ := m["headers"].(map[string]any)
		expect, _ := m["expect"].(json.Number)
		code, _ := m["expect_code"].(string)
		note, _ := m["note"].(string)
		if method != "GET" && method != "POST" {
			t.Errorf("%s: method %q; want GET or POST", f, method)
		}
		if !strings.HasPrefix(target, "/") {
			t.Errorf("%s: target %q; want a path from the root", f, target)
		}
		if note == "" {
			t.Errorf("%s: no note", f)
		}
		status := expect.String()
		seen[status+" "+code] = true
		switch status + " " + code {
		case "200 ", "202 ", "401 unauthorized", "400 bad_request", "400 invalid_request", "409 instance_limit", "409 run_id_used":
		default:
			t.Errorf("%s: expect %s %s; want 200, 202, 401 unauthorized, 400 bad_request, 400 invalid_request, "+
				"409 instance_limit or 409 run_id_used", f, status, code)
		}
		twice := false
		value := func(name string, required bool) string {
			switch v := headers[name].(type) {
			case string:
				return v
			case []any:
				twice = true
				if len(v) == 2 && v[0] == v[1] {
					s, _ := v[0].(string)
					return s
				}
			}
			if required {
				t.Errorf("%s: no %s header", f, name)
			}
			return ""
		}
		value("User-Agent", true)
		accessKeyID := value("X-Qory-Access-Key-Id", true)
		instanceID := value("X-Qory-Instance-Id", false)
		v := value("X-Qory-Contract-Version", true)
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > contracts.Revision || strconv.Itoa(n) != v {
			t.Errorf("%s: X-Qory-Contract-Version %q; want a revision from 1 to %d", f, v, contracts.Revision)
		}
		signature := value("X-Qory-Signature-Ed25519", true)
		for name := range headers {
			if strings.HasPrefix(name, "X-Qory-Signature-") && name != "X-Qory-Signature-Ed25519" || name == "X-Qory-Access-Key" {
				t.Errorf("%s: header %s, which the contract does not define", f, name)
			}
		}
		var last string
		switch method {
		case "POST":
			body, ok := m["body"].(string)
			if !ok {
				t.Errorf("%s: a POST carries a body", f)
				continue
			}
			if _, ok := headers["X-Qory-Timestamp"]; ok {
				t.Errorf("%s: a POST carries no timestamp", f)
			}
			// A POST is a batch to the events endpoint or a run's registration to the run
			// endpoint, told apart by its type. A registration carries no delivery id,
			// and its body passes the registration's schema, but where the body is what
			// the fixture's receiver refuses as the contract does: interval_seconds over
			// 300, a 400 invalid_request.
			schema := "batch.schema.json"
			switch ct := value("Content-Type", true); ct {
			case "application/cloudevents-batch+json":
				value("X-Qory-Delivery", true)
			case "application/json":
				schema = "run-registration.schema.json"
				if _, ok := headers["X-Qory-Delivery"]; ok {
					t.Errorf("%s: a registration carries no X-Qory-Delivery", f)
				}
			default:
				t.Errorf("%s: Content-Type %q", f, ct)
			}
			doc, err := contracts.Decode(f, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if err := s[schema].Validate(doc); (err != nil) != (status+" "+code == "400 invalid_request") {
				t.Errorf("%s: body against %s: %v, expecting %s %s", f, schema, err, status, code)
			}
			last = body
		case "GET":
			if m["body"] != nil {
				t.Errorf("%s: a GET carries no body", f)
			}
			last = value("X-Qory-Timestamp", true)
		}
		request := requestString(accessKeyID, instanceID, method, target, last)
		sig, err := base64.RawURLEncoding.Strict().DecodeString(signature)
		valid := err == nil && ed25519.Verify(pub, []byte(request), sig)
		// A request a receiver verifies is signed under the fixture key: every one but a
		// header sent twice, refused before verification, and the 401s, one of which
		// is a correct signature over a stale timestamp.
		switch {
		case twice:
			if status != "400" {
				t.Errorf("%s: a header sent twice is answered %s; want 400", f, status)
			}
		case status == "401":
		case !valid:
			t.Errorf("%s: the signature does not verify under the fixture access key over\n%s\n"+
				"after a change to a POST's body, sign the POSTs again: %s", f, request, updateSignedCommand)
		}
		if status[0] == '2' && (accessKeyID != "ak_f1xt0re000000000" || instanceID != keys.AccessKey.InstanceID) {
			t.Errorf("%s: accepted as %s, %s; want the fixture access key and instance", f, accessKeyID, instanceID)
		}
	}
	for _, want := range []string{"200 ", "202 ", "401 unauthorized", "400 bad_request", "400 invalid_request", "409 instance_limit", "409 run_id_used"} {
		if !seen[want] {
			t.Errorf("no signed fixture expects %s", want)
		}
	}
}

// requestString is the request string a request's signature covers: the domain, the access
// key id and the instance id as the headers contain them, the method, the target, then the
// timestamp of a GET or the raw body of a POST, one per line.
func requestString(accessKeyID, instanceID, method, target, last string) string {
	return strings.Join([]string{"qory-request-ed25519-v1", accessKeyID, instanceID, method, target, last}, "\n")
}

var updateSigned = flag.Bool("update-signed", false,
	"sign the POSTs under fixtures/signed again, over their bodies as they are, and write them")

// updateSignedCommand signs the POSTs under fixtures/signed again and checks them.
const updateSignedCommand = "go test ./contracts -run TestSignedFixtures -update-signed && " +
	"go test ./contracts -run TestSignedFixtures"

// signedWith names the batches under fixtures/signed that carry another's signature, the
// one that one's body is signed with: batch-tampered is batch-valid with one byte of the
// body changed after signing.
var signedWith = map[string]string{"batch-tampered.json": "batch-valid.json"}

// signatureHeader is the signature's member in a signed fixture, as the files write it.
var signatureHeader = regexp.MustCompile(`("X-Qory-Signature-Ed25519": )"[^"]*"`)

// signBatches writes the signature of every POST under fixtures/signed again, a batch or
// a registration: under the
// fixture access key secret over its own request string, its access key id and instance id
// as its headers contain them and its body as it is, or the signature of the batch that
// signedWith names. A GET is left as it is: its signature covers a timestamp and no body,
// and one of them is wrong on purpose. The files are read from and written to the source
// directory, so the embedded copy this test binary holds is the old one; the command run
// again without -update-signed checks the new ones.
func signBatches(t *testing.T) {
	priv := loadKeys(t).accessKey(t)
	dir := path.Join("forager", contracts.Version)
	source := func(f string) ([]byte, map[string]any) {
		b, err := os.ReadFile(path.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := contracts.Decode(f, b)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := doc.(map[string]any)
		return b, m
	}
	signature := map[string]string{}
	for _, f := range files(t, "fixtures/signed") {
		_, m := source(f)
		if m["method"] != "POST" || signedWith[path.Base(f)] != "" {
			continue
		}
		headers, _ := m["headers"].(map[string]any)
		accessKeyID, _ := headers["X-Qory-Access-Key-Id"].(string)
		instanceID, _ := headers["X-Qory-Instance-Id"].(string)
		target, _ := m["target"].(string)
		body, _ := m["body"].(string)
		sig := ed25519.Sign(priv, []byte(requestString(accessKeyID, instanceID, "POST", target, body)))
		signature[path.Base(f)] = base64.RawURLEncoding.EncodeToString(sig)
	}
	for _, f := range files(t, "fixtures/signed") {
		sig, ok := signature[path.Base(f)]
		if from := signedWith[path.Base(f)]; from != "" {
			sig, ok = signature[from]
			if !ok {
				t.Fatalf("%s carries the signature of %s, which is no signed batch", f, from)
			}
		}
		if !ok {
			continue
		}
		b, _ := source(f)
		if n := len(signatureHeader.FindAll(b, -1)); n != 1 {
			t.Fatalf("%s: %d X-Qory-Signature-Ed25519 members; want one", f, n)
		}
		out := signatureHeader.ReplaceAll(b, []byte(`${1}"`+sig+`"`))
		if string(out) == string(b) {
			continue
		}
		if err := os.WriteFile(path.Join(dir, f), out, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: signed again", f)
	}
}

// TestDescriptorsHaveFixturesThatValidate pins the rule that a descriptor without
// fixtures is not accepted: every runtime under runtimes/ has a descriptor that passes
// the schema, at least one fixture directory, and in each a records.jsonl of records and
// an expected/events.jsonl whose every line is a runtime type of the descriptor with
// data that passes that type's schema. It also pins that every hook event a rule matches
// on is one the descriptor installs.
func TestDescriptorsHaveFixturesThatValidate(t *testing.T) {
	c, err := contracts.Compiler()
	if err != nil {
		t.Fatal(err)
	}
	one := func(name string) *jsonschema.Schema {
		s, err := c.Compile(contracts.Base + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	descriptor := one("descriptor.schema.json")
	record := one("record.schema.json")
	runtimes, err := fs.ReadDir(contracts.FS, "runtimes")
	if err != nil {
		t.Fatal(err)
	}
	if len(runtimes) == 0 {
		t.Fatal("no runtime descriptor")
	}
	for _, rt := range runtimes {
		dir := path.Join("runtimes", rt.Name())
		doc, err := contracts.Document(path.Join(dir, "descriptor.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := descriptor.Validate(doc); err != nil {
			t.Errorf("%s: %v", dir, err)
			continue
		}
		d := doc.(map[string]any)
		if d["runtime"] != rt.Name() {
			t.Errorf("%s: descriptor names runtime %v; want the directory name", dir, d["runtime"])
		}
		installed := map[string]bool{}
		if hooks, ok := d["sources"].(map[string]any)["hooks"].(map[string]any); ok {
			for _, e := range hooks["events"].([]any) {
				installed[e.(string)] = true
			}
		}
		produces := map[string]bool{}
		for _, r := range d["rules"].([]any) {
			rule := r.(map[string]any)
			produces[rule["type"].(string)] = true
			if rule["source"] == "hooks" {
				name, ok := rule["match"].(map[string]any)["hook_event_name"].(string)
				if ok && !installed[name] {
					t.Errorf("%s: a rule matches hook %s, which sources.hooks.events does not install",
						dir, name)
				}
			}
		}
		cases, err := fs.ReadDir(contracts.FS, path.Join(dir, "fixtures"))
		if err != nil || len(cases) == 0 {
			t.Errorf("%s: no fixtures; a descriptor without fixtures is not accepted", dir)
			continue
		}
		for _, cs := range cases {
			cdir := path.Join(dir, "fixtures", cs.Name())
			records, err := contracts.Lines(path.Join(cdir, "records.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if len(records) == 0 {
				t.Errorf("%s: no records", cdir)
			}
			for i, r := range records {
				if err := record.Validate(r); err != nil {
					t.Errorf("%s: records.jsonl:%d: %v", cdir, i+1, err)
				}
			}
			expected, err := contracts.Lines(path.Join(cdir, "expected", "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			for i, e := range expected {
				m, ok := e.(map[string]any)
				typ, _ := m["type"].(string)
				if !ok || typ == "" || m["data"] == nil {
					t.Errorf("%s: expected/events.jsonl:%d: want an object with type and data", cdir, i+1)
					continue
				}
				if !produces[typ] {
					t.Errorf("%s: expected/events.jsonl:%d: no rule produces %s", cdir, i+1, typ)
				}
				name := strings.TrimPrefix(typ, "dev.qory.") + ".schema.json"
				schema, err := c.Compile(contracts.Base + "/events/" + name)
				if err != nil {
					t.Errorf("%s: expected/events.jsonl:%d: %v", cdir, i+1, err)
					continue
				}
				if err := schema.Validate(m["data"]); err != nil {
					t.Errorf("%s: expected/events.jsonl:%d: %v", cdir, i+1, err)
				}
			}
		}
	}
}

// TestEveryTypeHasASchemaAndTheReadmeNamesIt pins that the envelope's type list, the
// data schemas under events/ and the contract README agree on the set of types.
func TestEveryTypeHasASchemaAndTheReadmeNamesIt(t *testing.T) {
	doc, err := contracts.Document("event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, part := range doc.(map[string]any)["allOf"].([]any) {
		if props, ok := part.(map[string]any)["properties"].(map[string]any); ok {
			if typ, ok := props["type"].(map[string]any); ok {
				for _, v := range typ["enum"].([]any) {
					types = append(types, v.(string))
				}
			}
		}
	}
	readme, err := fs.ReadFile(contracts.FS, "README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range types {
		name := strings.TrimPrefix(typ, "dev.qory.")
		if _, err := fs.Stat(contracts.FS, "events/"+name+".schema.json"); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
		if !strings.Contains(string(readme), "`"+typ+"`") {
			t.Errorf("README does not name %s", typ)
		}
	}
	schemas, _ := fs.ReadDir(contracts.FS, "events")
	if len(schemas) != len(types) {
		t.Errorf("%d data schemas under events/ for %d types", len(schemas), len(types))
	}
}
