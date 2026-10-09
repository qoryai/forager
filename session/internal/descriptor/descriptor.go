// Package descriptor reads a runtime descriptor and maps the runtime's records to
// session events.
//
// A [Descriptor] is the document of contracts/forager/v1/descriptor.schema.json: how
// the session attaches to one runtime and the rules that turn its records into session
// events. [Load] takes the embedded default for a runtime and an optional override
// directory; [Parse] validates a document against the schema before decoding it, so the
// schema is the reader. A [Record] is one unit of runtime output with the source it
// came from, the shape a hook forwarder writes to the local socket and a fixture's
// records.jsonl holds.
//
// [Descriptor.Map] is the whole of the mapping engine: the first rule of the record's
// source whose match holds produces one event, type and data, by copying values out of
// the record. It matches and copies; it never computes, and there is nothing to
// configure that would make it.
//
// A descriptor's [Secrets] defines the secrets the runtime reads and the variables it
// keeps for itself. [Runtimes] renders them, for every descriptor the contract ships,
// as runtimes.json, the file a server vendors.
package descriptor

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/qoryai/forager/contracts"
)

// Descriptor is one runtime's descriptor.
type Descriptor struct {
	Version        int       `yaml:"version" json:"version"`
	Runtime        string    `yaml:"runtime" json:"runtime"`
	Title          string    `yaml:"title" json:"title,omitempty"`
	RuntimeVersion string    `yaml:"runtime_version" json:"runtime_version"`
	Sources        Sources   `yaml:"sources" json:"sources"`
	Stop           *Stop     `yaml:"stop" json:"stop,omitempty"`
	Headless       *Headless `yaml:"headless" json:"headless,omitempty"`
	Secrets        *Secrets  `yaml:"secrets" json:"secrets,omitempty"`
	Rules          []Rule    `yaml:"rules" json:"rules"`
}

// Secrets is what the runtime needs of a run's secrets and the variables it keeps for
// itself. Nil when the descriptor declares none.
type Secrets struct {
	// Declares is the secrets the runtime reads, each from one variable.
	Declares []Declaration `yaml:"declares" json:"declares,omitempty"`
	// OneOf is the groups of declarations of which the runtime needs at most one each.
	OneOf []Group `yaml:"one_of" json:"one_of,omitempty"`
	// Reserves is the variables the runtime reads a credential from beside the declared
	// ones.
	Reserves []string `yaml:"reserves" json:"reserves,omitempty"`
	// Denies is the variables the session leaves out of the server's set for the runtime.
	Denies []string `yaml:"denies" json:"denies,omitempty"`
	// CredentialFiles is the files in which the runtime keeps a credential of its own,
	// ~ being the home of the user Forager runs as.
	CredentialFiles []string `yaml:"credential_files" json:"credential_files,omitempty"`
}

// Declaration is one secret the runtime reads: the variable it reads it from, and the
// hosts, paths and scheme the proxy sets its value by.
type Declaration struct {
	ID    string   `yaml:"id" json:"id"`
	Title string   `yaml:"title" json:"title"`
	Name  string   `yaml:"name" json:"name"`
	Hosts []string `yaml:"hosts" json:"hosts"`
	// Paths bound the requests the value is set on; empty means every path.
	Paths []string `yaml:"paths" json:"paths,omitempty"`
	Auth  Auth     `yaml:"auth" json:"auth"`
}

// Auth is how a value is set on a request: Scheme is bearer, header or basic, Header
// the header of header, Username the fixed user of basic.
type Auth struct {
	Scheme   string `yaml:"scheme" json:"scheme"`
	Header   string `yaml:"header" json:"header,omitempty"`
	Username string `yaml:"username" json:"username,omitempty"`
}

// Group is a set of declarations of which the runtime needs at most one, and exactly
// one when Required.
type Group struct {
	ID       string   `yaml:"id" json:"id"`
	Required bool     `yaml:"required" json:"required,omitempty"`
	Of       []string `yaml:"of" json:"of"`
}

// Headless is the arguments that mean the runtime runs without an interface: started
// with one of them, the session runs on pipes whatever the caller asked. Nil when the
// runtime names none, and the caller alone decides.
type Headless struct {
	Args []string `yaml:"args" json:"args"`
}

// Stop is how the runtime is asked to leave: a signal of Forager's list and the time
// until SIGKILL, as a duration. Either may be empty, Forager's default.
type Stop struct {
	Signal string `yaml:"signal" json:"signal,omitempty"`
	Grace  string `yaml:"grace" json:"grace,omitempty"`
}

// Sources is how the session attaches to the runtime.
type Sources struct {
	// Output is the runtime's standard output as JSON lines, when the session runs on
	// pipes; nil when the runtime has none.
	Output *Output `yaml:"output" json:"output,omitempty"`
	// Hooks is the runtime's hook interface; nil when the runtime has none.
	Hooks *Hooks `yaml:"hooks" json:"hooks,omitempty"`
}

// Output describes the standard output source.
type Output struct {
	Format string `yaml:"format" json:"format"`
}

// Hooks describes the hook source: how the forwarder is installed and for which of the
// runtime's events.
type Hooks struct {
	Install string   `yaml:"install" json:"install"`
	Events  []string `yaml:"events" json:"events"`
}

// Rule maps records of one source to one event type.
type Rule struct {
	Source string `yaml:"source" json:"source"`
	// Match holds paths into the record and the values they must equal, or
	// map[string]any{"present": true} for a path that must exist.
	Match map[string]any `yaml:"match" json:"match"`
	Type  string         `yaml:"type" json:"type"`
	// Data holds the event's fields and the record paths their values are copied from.
	Data map[string]string `yaml:"data" json:"data"`
}

// Record is one unit of runtime output as a descriptor reads it.
type Record struct {
	// Source is "output" or "hooks".
	Source string `json:"source"`
	// Record is the JSON object the runtime produced, decoded with encoding/json.
	Record map[string]any `json:"record"`
}

// The two sources.
const (
	SourceOutput = "output"
	SourceHooks  = "hooks"
)

// Parse validates a descriptor document against the schema and decodes it. name is
// used in messages and chooses YAML or JSON by its extension.
func Parse(name string, b []byte) (*Descriptor, error) {
	doc, err := contracts.Decode(name, b)
	if err != nil {
		return nil, err
	}
	schema, err := contracts.Compile("descriptor.schema.json")
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var d Descriptor
	switch filepath.Ext(name) {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(b, &d)
	default:
		err = json.Unmarshal(b, &d)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := d.Secrets.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &d, nil
}

// check holds the secrets to what the schema cannot express: declaration ids and group
// ids are each distinct, and every id a group lists is a declared one, in one group at
// most.
func (s *Secrets) check() error {
	if s == nil {
		return nil
	}
	declared := map[string]bool{}
	for _, d := range s.Declares {
		if declared[d.ID] {
			return fmt.Errorf("secrets: %s is declared twice", d.ID)
		}
		declared[d.ID] = true
	}
	groups := map[string]bool{}
	grouped := map[string]string{}
	for _, g := range s.OneOf {
		if groups[g.ID] {
			return fmt.Errorf("secrets: one_of %s is defined twice", g.ID)
		}
		groups[g.ID] = true
		for _, id := range g.Of {
			if !declared[id] {
				return fmt.Errorf("secrets: one_of %s lists %s, which no declaration has as its id", g.ID, id)
			}
			if other, ok := grouped[id]; ok {
				return fmt.Errorf("secrets: %s is in one_of %s and in %s", id, other, g.ID)
			}
			grouped[id] = g.ID
		}
	}
	return nil
}

// Map applies the rules to one record: the first rule of the record's source whose
// match holds produces the event's type and data, and ok is true. A record no rule
// matches produces nothing.
func (d *Descriptor) Map(r Record) (typ string, data map[string]any, ok bool) {
	for i := range d.Rules {
		rule := &d.Rules[i]
		if rule.Source != r.Source || !matches(rule.Match, r.Record) {
			continue
		}
		data = map[string]any{}
		for field, path := range rule.Data {
			if v, ok := lookup(r.Record, path); ok {
				data[field] = v
			}
		}
		return rule.Type, data, true
	}
	return "", nil, false
}

// matches reports whether every entry of match holds against the record.
func matches(match map[string]any, record map[string]any) bool {
	for path, want := range match {
		got, ok := lookup(record, path)
		if !ok {
			return false
		}
		if m, isMap := want.(map[string]any); isMap {
			if present, _ := m["present"].(bool); present {
				continue
			}
			return false
		}
		if !equal(want, got) {
			return false
		}
	}
	return true
}

// lookup follows a dotted path through nested objects.
func lookup(record map[string]any, path string) (any, bool) {
	var cur any = record
	for _, key := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// equal compares a match value, as YAML or JSON decoded it, with a record value, as
// encoding/json decoded it: strings and booleans directly, numbers by value.
func equal(want, got any) bool {
	if wn, ok := number(want); ok {
		gn, ok := number(got)
		return ok && wn == gn
	}
	switch w := want.(type) {
	case string:
		g, ok := got.(string)
		return ok && g == w
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	}
	return false
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
