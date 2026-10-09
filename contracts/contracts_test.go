package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/contracts"
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

// TestDocumentFixturesValidate pins that every policy, server, configuration and run
// configuration fixture passes its schema.
func TestDocumentFixturesValidate(t *testing.T) {
	s := compile(t, "policy.schema.json", "server.schema.json", "configuration.schema.json",
		"run-configuration.schema.json")
	dirs := map[string]string{
		"fixtures/policy":            "policy.schema.json",
		"fixtures/server":            "server.schema.json",
		"fixtures/configuration":     "configuration.schema.json",
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

// The schemas of the gateway's link.
const (
	linkDiscovery  = "link-discovery.schema.json"
	linkRunRequest = "link-run-request.schema.json"
	linkRunAnswer  = "link-run-answer.schema.json"
	linkBatch      = "link-batch.schema.json"
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

// TestLinkFixturesValidate pins that every document under fixtures/link passes the
// schema of the gateway's link its name starts with: the discovery of the local link and
// of a separate gateway, a run request without a wall and one with a wall and a
// narrowing, a run answer with a wall, without one and without a policy, and a batch of
// events without sequence.
func TestLinkFixturesValidate(t *testing.T) {
	s := compile(t, linkDiscovery, linkRunRequest, linkRunAnswer, linkBatch)
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

// TestInvalidFixturesAreRefused pins that each document under fixtures/invalid fails
// the schema its name starts with: a policy that widens, a server without its access
// key id or its pin or with a secret, a configuration without events, a ping whose
// interval is over 300 seconds, an event with an unpadded sequence, a descriptor with
// an expression, a link run request without wall, whose run id is not lower-case or
// whose narrowing holds a member it does not define, a link run answer without its proxy
// secret, a link batch whose event carries a sequence or that holds a ping, a link
// discovery that lists a node or has no heartbeat interval. The longest schema name the
// file name starts with is the schema, so run-configuration-variable-value-not-string is
// held to the run configuration and not to a schema named run.
func TestInvalidFixturesAreRefused(t *testing.T) {
	s := compile(t, "policy.schema.json", "server.schema.json", "configuration.schema.json",
		"run-configuration.schema.json", "event.schema.json", "batch.schema.json",
		"descriptor.schema.json", "record.schema.json", "enrolment.schema.json",
		linkDiscovery, linkRunRequest, linkRunAnswer, linkBatch)
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
		if err := schema.Validate(doc); err == nil {
			t.Errorf("%s passed %s; want a failure", f, kind)
		}
	}
}

// TestRecordedRunValidates pins the recorded run directory: every line of events.jsonl
// is an event of the contract, the sequence starts at one and is contiguous, every event
// names the same run in source and subject, the run starts with ping or run.started and
// ends with run.exited, and output.log is the concatenation of the run.log chunks.
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
			if m["type"] == "dev.qory.run.log" {
				chunk, err := base64Decode(m["data"].(map[string]any)["bytes"].(string))
				if err != nil {
					t.Fatal(err)
				}
				log = append(log, chunk...)
			}
		}
		first := events[0].(map[string]any)["type"]
		if first != "dev.qory.ping" && first != "dev.qory.run.started" {
			t.Errorf("%s: first event is %v; want ping or run.started", dir, first)
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
// the contract's own, a body on a POST that is a batch and none on a GET, a status a
// receiver answers, the code of a coded refusal, and a note. A header a list holds is
// one sent once per value. On every request whose signature a receiver verifies, the
// signature is the Ed25519 one under the fixture access key secret over the request
// string, its lines the domain, the access key id and the instance id as the headers
// contain them, the method, the target, then the timestamp on a GET or the raw body on
// a POST, so the published signatures cannot drift from the fixtures they sign.
func TestSignedFixtures(t *testing.T) {
	s := compile(t, "batch.schema.json")
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
		case "200 ", "202 ", "401 unauthorized", "400 bad_request":
		default:
			t.Errorf("%s: expect %s %s; want 200, 202, 401 unauthorized or 400 bad_request", f, status, code)
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
		lines := []string{"qory-request-ed25519-v1", accessKeyID, instanceID, method, target}
		switch method {
		case "POST":
			body, ok := m["body"].(string)
			if !ok {
				t.Errorf("%s: a POST carries a body", f)
				continue
			}
			value("X-Qory-Delivery", true)
			if ct := value("Content-Type", true); ct != "application/cloudevents-batch+json" {
				t.Errorf("%s: Content-Type %q", f, ct)
			}
			if _, ok := headers["X-Qory-Timestamp"]; ok {
				t.Errorf("%s: a POST carries no timestamp", f)
			}
			batch, err := contracts.Decode(f, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if err := s["batch.schema.json"].Validate(batch); err != nil {
				t.Errorf("%s: body: %v", f, err)
			}
			lines = append(lines, body)
		case "GET":
			if m["body"] != nil {
				t.Errorf("%s: a GET carries no body", f)
			}
			lines = append(lines, value("X-Qory-Timestamp", true))
		}
		sig, err := base64.RawURLEncoding.Strict().DecodeString(signature)
		valid := err == nil && ed25519.Verify(pub, []byte(strings.Join(lines, "\n")), sig)
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
			t.Errorf("%s: the signature does not verify under the fixture access key over\n%s", f, strings.Join(lines, "\n"))
		}
		if status[0] == '2' && (accessKeyID != "ak_f1xt0re000000000" || instanceID != keys.AccessKey.InstanceID) {
			t.Errorf("%s: accepted as %s, %s; want the fixture access key and instance", f, accessKeyID, instanceID)
		}
	}
	for _, want := range []string{"200 ", "202 ", "401 unauthorized", "400 bad_request"} {
		if !seen[want] {
			t.Errorf("no signed fixture expects %s", want)
		}
	}
}

// TestDescriptorsHaveFixturesThatValidate pins the rule that a descriptor without
// fixtures is not accepted: every runtime under runtimes/ has a descriptor that passes
// the schema, at least one fixture directory, and in each a records.jsonl of records and
// an expected/events.jsonl whose every line is a session type of the descriptor with
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
