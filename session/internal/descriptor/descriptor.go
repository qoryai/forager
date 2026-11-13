// Package descriptor reads a runtime descriptor and maps the runtime's records to
// runtime events.
//
// A [Descriptor] is the document of contracts/forager/v1/descriptor.schema.json: how
// the session attaches to one runtime and the rules that turn its records into runtime
// events. [Load] takes the embedded default for a runtime and an optional override
// directory; [Parse] validates a document against the schema before decoding it, so the
// schema is the reader. A [Record] is one unit of runtime output with the source it
// came from, the shape a hook forwarder writes to the local socket and a fixture's
// records.jsonl holds.
//
// [Descriptor.Map] is the whole of the mapping engine: the first rule of the record's
// source whose match holds produces one event, type and data, by copying values out of
// the record. A rule with each produces one event per element of an array in the record
// that a rule with that each matches, each by the first such rule it matches. It matches
// and copies; it never computes, and there is nothing to configure that would make it.
// [Descriptor.Link] reads the descriptor's parent member: which tool call started a
// subagent, for the session to set the subagent's parent.
//
// A descriptor's [Secrets] defines the secrets the runtime reads and the variables it
// keeps for itself, and its [Model] the API formats the runtime sends, where a composer
// writes a run's model id, effort value and model endpoint, and the variables it reads
// a model key from. Its Fixed is the variables the session sets for the runtime in
// every launch, over every other source, its [Config] how the session passes
// settings to a runtime that reads them as TOML, and its EgressHosts the hosts the
// runtime needs to reach. [Runtimes] renders the secrets, the model section, the fixed
// variables, the egress hosts and the resume's prefix and path, for every descriptor
// the contract ships, as runtimes.json, the file a server vendors.
package descriptor

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/internal/variables"
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
	Model          *Model    `yaml:"model" json:"model,omitempty"`
	Tools          *Tools    `yaml:"tools" json:"tools,omitempty"`
	// Fixed is the variables the session sets for the runtime in every launch, by name,
	// walled or not: no other source's value of one applies. Nil when the descriptor
	// sets none.
	Fixed map[string]string `yaml:"fixed" json:"fixed,omitempty"`
	// Config is how the session passes settings to a runtime that reads them as TOML,
	// and the settings it passes in every launch. Nil when the descriptor has none, and
	// a setting goes in the JSON settings file the launch passes.
	Config *Config `yaml:"config" json:"config,omitempty"`
	// EgressHosts is the hosts the runtime needs to reach, which [Runtimes] lists for a
	// server to allow for a run. No code of this module applies them to a run's policy.
	// Nil when the descriptor has none.
	EgressHosts []string `yaml:"egress_hosts" json:"egress_hosts,omitempty"`
	// Resume is where the runtime writes the transcript of its session, and how the
	// session starts the runtime again from it. Nil when the runtime has no resume.
	Resume *Resume `yaml:"resume" json:"resume,omitempty"`
	Parent *Parent `yaml:"parent" json:"parent,omitempty"`
	Rules  []Rule  `yaml:"rules" json:"rules"`
}

// Config is how the session passes settings to a runtime that reads them as TOML: Flag,
// the argument that takes one key=value pair, such as --config, and Fixed, the
// settings it passes in every launch.
type Config struct {
	Flag string `yaml:"flag" json:"flag"`
	// Fixed maps a dotted key to a TOML value: a string, a bool or an int64. Nil when
	// the descriptor sets none.
	Fixed map[string]any `yaml:"fixed" json:"fixed,omitempty"`
	// Keys is the keys of Fixed in the descriptor's order, which [Parse] reads from the
	// document; runtimes.json lists them in that order.
	Keys []string `yaml:"-" json:"-"`
}

// Resume is where the runtime writes the transcript of its session, and the arguments
// that start the runtime again from it. Each path starts with ~/, the runtime's home,
// with /, an absolute path, or with ${HomeVar}/, the value of HomeVar in the launch's
// environment.
type Resume struct {
	// HomeVar is the variable of the launch's environment that contains the runtime's
	// home, such as CODEX_HOME; empty when Prefix and Path start with ~/ or /.
	HomeVar string `yaml:"home_var" json:"home_var,omitempty"`
	// PathFrom is the member of a hook's input that contains the transcript's path,
	// such as transcript_path; empty when the session takes the path from Path alone.
	PathFrom string `yaml:"path_from" json:"path_from,omitempty"`
	// Path is the transcript's path while no hook input contains PathFrom: a template
	// with {session_id} and {cwd_slug}, in which a * matches any characters other than
	// / inside one path name. It starts with Prefix.
	Path string `yaml:"path" json:"path"`
	// Prefix is the directory the transcript must lie under, ending in /, with no *.
	Prefix string `yaml:"prefix" json:"prefix"`
	// Args are the arguments the session adds when it resumes, with {session_id} in
	// place of the runtime's session id.
	Args []string `yaml:"args" json:"args"`
	// After is the argument Args follow, such as exec; empty when Args go at the end.
	After string `yaml:"after" json:"after,omitempty"`
	// Place is PlaceBeforeLast for Args that go before the launch's last argument after
	// After, or before the first -- after After; empty for right after After.
	Place string `yaml:"place" json:"place,omitempty"`
}

// PlaceBeforeLast is the resume.place whose arguments go before the launch's last
// argument after resume.after, the prompt, or before the first -- after resume.after.
const PlaceBeforeLast = "before_last"

// Tools is what the session copies from a tool's input onto the runtime's tool events.
// Nil when the descriptor has no tools member.
type Tools struct {
	// Summary maps a tool's name, as the runtime reports it in tool, to the dotted path
	// of the input member the session copies as the event's summary.
	Summary map[string]string `yaml:"summary" json:"summary"`
}

// Summary is the member of input at the path tools.summary gives for tool, when it is
// a string, and true; "" and false when the descriptor lists no such tool or input has
// no string there. The value is copied, not cut: the session cuts it.
func (d *Descriptor) Summary(tool string, input map[string]any) (string, bool) {
	if d.Tools == nil {
		return "", false
	}
	path, ok := d.Tools.Summary[tool]
	if !ok {
		return "", false
	}
	v, _ := lookup(input, path)
	s, ok := v.(string)
	return s, ok
}

// Parent is where the runtime reports which tool call started a subagent: a record of
// Source that matches Match contains the subagent's id at the path AgentID and the id
// of the tool call that started it at the path ToolUseID. Nil when the descriptor has
// no parent member.
type Parent struct {
	Source    string         `yaml:"source" json:"source"`
	Match     map[string]any `yaml:"match" json:"match"`
	AgentID   string         `yaml:"agent_id" json:"agent_id"`
	ToolUseID string         `yaml:"tool_use_id" json:"tool_use_id"`
}

// Model is the API formats the runtime sends its requests in, and where a composer
// writes a run's model id, effort value and model endpoint for it. Nil when the
// descriptor has no model section.
type Model struct {
	// Formats is the API formats, each one of api-format.schema.json.
	Formats []string `yaml:"formats" json:"formats"`
	// Model is where the run's model id goes.
	Model Place `yaml:"model" json:"model"`
	// Effort is where an effort value goes; nil when the runtime has no place for one.
	Effort *Effort `yaml:"effort" json:"effort,omitempty"`
	// Endpoint is where the base URL of the run's model API goes.
	Endpoint Endpoint `yaml:"endpoint" json:"endpoint"`
	// Keys is the variables the runtime reads a model key from, one per API format and
	// auth; nil when the section lists none.
	Keys []Key `yaml:"keys" json:"keys,omitempty"`
	// Overrides is the variables that would override the model id or effort value a
	// composer writes, which a walled run leaves out and unsets inside; nil when the
	// section lists none.
	Overrides []string `yaml:"overrides" json:"overrides,omitempty"`
}

// Key is one variable the runtime reads a model key from: the API format the key is
// for, how the runtime sends it, and the variable.
type Key struct {
	Format   string `yaml:"format" json:"format"`
	Auth     Auth   `yaml:"auth" json:"auth"`
	Variable string `yaml:"variable" json:"variable"`
}

// Place is where a value goes, exactly one of its fields set: Flag, an argument the
// runtime is started with, which takes the value; Setting, a dotted key in the JSON
// settings file the launch passes, or with [Config] a key=value pair of its Flag;
// Variable, an environment variable.
type Place struct {
	Flag     string `yaml:"flag" json:"flag,omitempty"`
	Setting  string `yaml:"setting" json:"setting,omitempty"`
	Variable string `yaml:"variable" json:"variable,omitempty"`
}

// ValuedPlace is a place and the values the runtime accepts there.
type ValuedPlace struct {
	Place  `yaml:",inline"`
	Values []string `yaml:"values" json:"values"`
}

// AgentPlace is where a value goes in an agent's file: Frontmatter, a key of the file's
// frontmatter, and the values the runtime accepts there.
type AgentPlace struct {
	Frontmatter string   `yaml:"frontmatter" json:"frontmatter"`
	Values      []string `yaml:"values" json:"values"`
}

// Effort is where an effort value goes: Run, the run's; Agent, an agent's, nil when the
// runtime has no place for an agent's effort.
type Effort struct {
	Run   ValuedPlace `yaml:"run" json:"run"`
	Agent *AgentPlace `yaml:"agent" json:"agent,omitempty"`
}

// Endpoint is where the base URL of the runtime's model API goes, exactly one of its
// fields set: Variable, the variable the runtime reads it from, or Setting, a dotted
// key of the runtime's settings, written as a [Place]'s setting.
type Endpoint struct {
	Variable string `yaml:"variable" json:"variable,omitempty"`
	Setting  string `yaml:"setting" json:"setting,omitempty"`
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
// the header of header, Username the fixed user of basic, and OAuth marks a bearer as
// an OAuth token. A descriptor's auth has no account_header or account_claim: only an
// API credential of a run configuration has them.
type Auth struct {
	Scheme   string `yaml:"scheme" json:"scheme"`
	Header   string `yaml:"header" json:"header,omitempty"`
	Username string `yaml:"username" json:"username,omitempty"`
	OAuth    bool   `yaml:"oauth" json:"oauth,omitempty"`
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
	// Each is a dotted path to an array in the record, or empty. With it, the rule
	// applies to the elements of the array, and a path of Match or Data that starts
	// with "each." reads the element.
	Each string `yaml:"each" json:"each,omitempty"`
	// Match holds paths into the record and the values they must equal, or
	// map[string]any{"present": true} for a path that must exist.
	Match map[string]any `yaml:"match" json:"match"`
	Type  string         `yaml:"type" json:"type"`
	// Data holds the event's fields and the record paths their values are copied from.
	Data map[string]string `yaml:"data" json:"data"`
	// Set maps event fields to values of the descriptor's, a string, a number or a
	// bool, for a field the record has no member for, such as source: startup.
	Set map[string]any `yaml:"set" json:"set,omitempty"`
	// FromStarted lists the event's fields the session copies from the session's last
	// dev.qory.runtime.started of the main agent, for a record that does not contain
	// them, such as session_id. Only a rule of the output source has it.
	FromStarted []string `yaml:"from_started" json:"from_started,omitempty"`
}

// Event is one event a rule produces: its type, its data, and FromStarted, the rule's
// fields the session copies from its dev.qory.runtime.started.
type Event struct {
	Type        string
	Data        map[string]any
	FromStarted []string
}

// Record is one unit of runtime output as a descriptor reads it.
type Record struct {
	// Source is "output" or "hooks"; "setup" for a setup command's record, or "measure"
	// for the enclosure's peak memory and CPU time, which the session reads and no
	// descriptor's rule maps.
	Source string `json:"source"`
	// Record is the JSON object the runtime produced, decoded with encoding/json.
	Record map[string]any `json:"record"`
	// Line is the number of the line of the runtime's standard output a record of the
	// output source was read from, from 1, counting every line; 0 for a record of
	// another source, and for one a fixture or a caller made. No rule reads it: the
	// session writes it as the events' line.
	Line int `json:"-"`
}

// The sources of a record. A descriptor's rules map records of SourceOutput and
// SourceHooks; the session reads the records of SourceSetup and SourceMeasure.
const (
	SourceOutput  = "output"
	SourceHooks   = "hooks"
	SourceSetup   = "setup"
	SourceMeasure = "measure"
)

// Parse validates a descriptor document against the schema and decodes it. name is
// used in messages and chooses YAML or JSON by its extension.
func Parse(name string, b []byte) (*Descriptor, error) {
	// shown is name as a message prints it.
	shown := accesskey.ShownValue(name, false)
	doc, err := contracts.Decode(name, b)
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	schema, err := contracts.Compile("descriptor.schema.json")
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("%s: %w", shown, accesskey.ShownError(err))
	}
	var d Descriptor
	switch filepath.Ext(name) {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(b, &d)
	default:
		err = json.Unmarshal(b, &d)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", shown, accesskey.ShownError(err))
	}
	if err := d.Secrets.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", shown, err)
	}
	if err := d.Model.check(d.Secrets); err != nil {
		return nil, fmt.Errorf("%s: %w", shown, err)
	}
	if err := d.checkFixed(); err != nil {
		return nil, fmt.Errorf("%s: %w", shown, err)
	}
	if err := d.Resume.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", shown, err)
	}
	if err := d.checkConfig(); err != nil {
		return nil, fmt.Errorf("%s: %w", shown, err)
	}
	if d.Config != nil {
		if d.Config.Keys, err = fixedKeys(b); err != nil {
			return nil, fmt.Errorf("%s: %w", shown, accesskey.ShownError(err))
		}
	}
	if err := d.checkRules(); err != nil {
		return nil, fmt.Errorf("%s: %w", shown, err)
	}
	return &d, nil
}

// fixedKeys is the keys of config.fixed in the document's order. A JSON document is
// YAML too, so one reader serves both.
func fixedKeys(b []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	node := &doc
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	for _, key := range []string{"config", "fixed"} {
		node = member(node, key)
		if node == nil {
			return nil, nil
		}
	}
	var keys []string
	for i := 0; i+1 < len(node.Content); i += 2 {
		keys = append(keys, node.Content[i].Value)
	}
	return keys, nil
}

// member is the value of key in the mapping node, nil when node is no mapping or has
// no such key.
func member(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// checkRules checks what the schema cannot express of the rules: a field of an event
// comes from one of data, set and from_started.
func (d *Descriptor) checkRules() error {
	for i, rule := range d.Rules {
		seen := map[string]string{}
		for _, m := range []struct {
			member string
			fields []string
		}{
			{"data", slices.Sorted(maps.Keys(rule.Data))},
			{"set", slices.Sorted(maps.Keys(rule.Set))},
			{"from_started", rule.FromStarted},
		} {
			for _, f := range m.fields {
				if other, ok := seen[f]; ok {
					return fmt.Errorf("rules[%d]: set the field %s in one of data, set and from_started, not in %s and %s",
						i, accesskey.ShownName(f, false), other, m.member)
				}
				seen[f] = m.member
			}
		}
	}
	return nil
}

// checkConfig checks what the schema cannot express of the settings, and makes each
// fixed value of config a string, a bool or an int64, whether the document was YAML or
// JSON. The settings of the model section, the model id's, the run's effort's and the
// endpoint's, are distinct, and none is a dotted prefix of another; with config, no
// fixed key is a setting of the model section, and no fixed key and no other fixed key
// or model setting is a dotted prefix of the other. A TOML key, or a key of the JSON
// settings file, has a value or a table of keys, not both.
func (d *Descriptor) checkConfig() error {
	var settings []string
	if m := d.Model; m != nil {
		settings = append(settings, m.Model.Setting, m.Endpoint.Setting)
		if m.Effort != nil {
			settings = append(settings, m.Effort.Run.Setting)
		}
		settings = slices.DeleteFunc(settings, func(s string) bool { return s == "" })
	}
	for i, a := range settings {
		for _, b := range settings[i+1:] {
			if a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".") {
				return fmt.Errorf("model: place the values of %s and %s in two settings, neither inside the other: a key has a value or a table of keys, not both",
					accesskey.ShownName(a, false), accesskey.ShownName(b, false))
			}
		}
	}
	if d.Config == nil {
		return nil
	}
	keys := slices.Sorted(maps.Keys(d.Config.Fixed))
	for _, k := range keys {
		switch v := d.Config.Fixed[k].(type) {
		case int:
			d.Config.Fixed[k] = int64(v)
		case float64:
			d.Config.Fixed[k] = int64(v)
		}
		shown := accesskey.ShownName(k, false)
		if slices.Contains(settings, k) {
			return fmt.Errorf("config.fixed: remove %s: it is a setting of the model section", shown)
		}
		for _, o := range settings {
			if strings.HasPrefix(o, k+".") || strings.HasPrefix(k, o+".") {
				return fmt.Errorf("config.fixed: remove %s: a TOML key has a value or a table of keys, not both, and %s is a setting of the model section",
					shown, accesskey.ShownName(o, false))
			}
		}
		for _, o := range keys {
			if strings.HasPrefix(o, k+".") {
				return fmt.Errorf("config.fixed: remove %s or %s: a TOML key has a value or a table of keys, not both, and %s lies inside %s",
					shown, accesskey.ShownName(o, false), accesskey.ShownName(o, false), shown)
			}
		}
	}
	return nil
}

// check checks what the schema cannot express of resume: path starts with prefix,
// neither has a .. segment, and the only variable either has is home_var's, as
// ${<home_var>}/ at its start, which each has when home_var is set. It also checks
// place, which the schema checks too: before_last or empty, and with after. A nil
// Resume passes.
func (r *Resume) check() error {
	if r == nil {
		return nil
	}
	for _, p := range []string{r.Prefix, r.Path} {
		if slices.Contains(strings.Split(p, "/"), "..") {
			return fmt.Errorf("resume: remove the .. segment from %s: the transcript lies under resume.prefix", accesskey.ShownValue(p, true))
		}
		rest := p
		if r.HomeVar != "" {
			lead := "${" + r.HomeVar + "}/"
			var ok bool
			if rest, ok = strings.CutPrefix(p, lead); !ok {
				return fmt.Errorf("resume: start %s with %s: home_var is %s, and the transcript lies below its value",
					accesskey.ShownValue(p, true), accesskey.ShownValue(lead, true), accesskey.ShownName(r.HomeVar, false))
			}
		}
		if strings.Contains(rest, "$") {
			return fmt.Errorf("resume: remove the $ from %s: resume.prefix and resume.path take no variable other than home_var, as ${<home_var>}/ at their start",
				accesskey.ShownValue(p, true))
		}
	}
	if !strings.HasPrefix(r.Path, r.Prefix) {
		return fmt.Errorf("resume: start path %s with prefix %s: the transcript lies under prefix", accesskey.ShownValue(r.Path, true), accesskey.ShownValue(r.Prefix, true))
	}
	switch {
	case r.Place != "" && r.Place != PlaceBeforeLast:
		return fmt.Errorf("resume: set place to %s or leave it out: %s is no place", PlaceBeforeLast, accesskey.ShownValue(r.Place, true))
	case r.Place != "" && r.After == "":
		return fmt.Errorf("resume: set after with place %s: the arguments go before the last argument after it", r.Place)
	}
	return nil
}

// checkFixed checks what the schema cannot express of the fixed variables: no name of
// fixed matches the built-in deny list, denied-variables.json, whose names Forager, the
// wall and the gateway set or leave out; and none is a variable that secrets declares,
// reserves or denies, or that model reads a key or its endpoint from or lists in
// overrides. Names are compared regardless of case.
func (d *Descriptor) checkFixed() error {
	if len(d.Fixed) == 0 {
		return nil
	}
	deny, err := variables.List(nil)
	if err != nil {
		return err
	}
	var listed []struct{ name, where string }
	add := func(where string, names ...string) {
		for _, n := range names {
			listed = append(listed, struct{ name, where string }{n, where})
		}
	}
	if s := d.Secrets; s != nil {
		for _, dc := range s.Declares {
			add("secrets.declares", dc.Name)
		}
		add("secrets.reserves", s.Reserves...)
		add("secrets.denies", s.Denies...)
	}
	if m := d.Model; m != nil {
		for _, k := range m.Keys {
			add("model.keys", k.Variable)
		}
		if m.Endpoint.Variable != "" {
			add("model.endpoint", m.Endpoint.Variable)
		}
		add("model.overrides", m.Overrides...)
	}
	for _, name := range slices.Sorted(maps.Keys(d.Fixed)) {
		shown := accesskey.ShownName(name, false)
		if deny.Matches(name) {
			return fmt.Errorf("fixed: remove %s: denied-variables.json lists it, and a descriptor sets no such variable", shown)
		}
		if i := slices.IndexFunc(listed, func(l struct{ name, where string }) bool { return strings.EqualFold(l.name, name) }); i >= 0 {
			return fmt.Errorf("fixed: remove %s from fixed or from %s: a variable that fixed sets is in no other list of the descriptor", shown, listed[i].where)
		}
	}
	return nil
}

// keyless are the variables a key may not be read from, compared without case: each
// changes what runs.
var keyless = []string{"HOME", "LD_PRELOAD", "NODE_OPTIONS", "BASH_ENV"}

// check holds the model keys to what the schema cannot express: a key's variable, and
// a declaration's, is none of keyless in any case; a key's format is one of Formats;
// each pair of format and auth appears once; a key's variable is not in the secrets'
// denies, Overrides or the endpoint's variable; and a key's variable that a
// declaration also has has the declaration's auth.
func (m *Model) check(s *Secrets) error {
	var secrets Secrets
	if s != nil {
		secrets = *s
	}
	for _, d := range secrets.Declares {
		if i := slices.IndexFunc(keyless, func(k string) bool { return strings.EqualFold(k, d.Name) }); i >= 0 {
			return fmt.Errorf("secrets.declares: read the secret %s from another variable than %s: a secret may not be read from HOME, LD_PRELOAD, NODE_OPTIONS or BASH_ENV",
				accesskey.ShownName(d.ID, false), accesskey.ShownName(d.Name, false))
		}
	}
	if m == nil {
		return nil
	}
	for i, k := range m.Keys {
		v := accesskey.ShownName(k.Variable, false)
		switch {
		case slices.ContainsFunc(keyless, func(n string) bool { return strings.EqualFold(n, k.Variable) }):
			return fmt.Errorf("model.keys: read the key from another variable than %s: a key may not be read from HOME, LD_PRELOAD, NODE_OPTIONS or BASH_ENV", v)
		case !slices.Contains(m.Formats, k.Format):
			return fmt.Errorf("model.keys: add %s to model.formats, or remove its keys: model.formats lists only %s",
				accesskey.ShownName(k.Format, false), strings.Join(m.Formats, ", "))
		case slices.ContainsFunc(m.Keys[:i], func(o Key) bool { return o.Format == k.Format && sameAuth(o.Auth, k.Auth) }):
			return fmt.Errorf("model.keys: list %s with %s once: two keys have it", accesskey.ShownName(k.Format, false), authWords(k.Auth))
		case slices.Contains(secrets.Denies, k.Variable) || slices.Contains(m.Overrides, k.Variable) || (m.Endpoint.Variable != "" && k.Variable == m.Endpoint.Variable):
			return fmt.Errorf("model.keys: read the key from a variable outside denies, overrides and the endpoint: %s is %s", v, place(m, k.Variable))
		}
		if j := slices.IndexFunc(secrets.Declares, func(d Declaration) bool { return d.Name == k.Variable }); j >= 0 && !sameAuth(secrets.Declares[j].Auth, k.Auth) {
			return fmt.Errorf("model.keys: give %s the auth of its secrets.declares entry: the two differ", v)
		}
	}
	return nil
}

// place is where the descriptor lists name among denies, overrides and the endpoint's
// variable, as check's message writes it.
func place(m *Model, name string) string {
	switch {
	case name == m.Endpoint.Variable:
		return "the endpoint"
	case slices.Contains(m.Overrides, name):
		return "in overrides"
	}
	return "in denies"
}

// sameAuth reports whether two auths are the same: the same scheme, the same header
// name with case ignored, the same username, and the same oauth.
func sameAuth(a, b Auth) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Header, b.Header) && a.Username == b.Username && a.OAuth == b.OAuth
}

// authWords is how check's message writes an auth: the header with its name, the
// bearer scheme, with oauth when it is set, or the basic scheme.
func authWords(a Auth) string {
	switch {
	case a.Scheme == "header":
		return "the header " + accesskey.ShownValue(a.Header, false)
	case a.OAuth:
		return "the bearer scheme and oauth"
	}
	return "the " + a.Scheme + " scheme"
}

// check holds the secrets to what the schema cannot express: declaration ids and group
// ids are each distinct, every id a group lists is a declared one, in one group at
// most.
func (s *Secrets) check() error {
	if s == nil {
		return nil
	}
	declared := map[string]bool{}
	for _, d := range s.Declares {
		if declared[d.ID] {
			return fmt.Errorf("secrets: %s is declared twice", accesskey.ShownName(d.ID, false))
		}
		declared[d.ID] = true
	}
	groups := map[string]bool{}
	grouped := map[string]string{}
	for _, g := range s.OneOf {
		if groups[g.ID] {
			return fmt.Errorf("secrets: one_of %s is defined twice", accesskey.ShownName(g.ID, false))
		}
		groups[g.ID] = true
		for _, id := range g.Of {
			if !declared[id] {
				return fmt.Errorf("secrets: one_of %s lists %s, which no declaration has as its id",
					accesskey.ShownName(g.ID, false), accesskey.ShownName(id, false))
			}
			if other, ok := grouped[id]; ok {
				return fmt.Errorf("secrets: %s is in one_of %s and in %s", accesskey.ShownName(id, false),
					accesskey.ShownName(other, false), accesskey.ShownName(g.ID, false))
			}
			grouped[id] = g.ID
		}
	}
	return nil
}

// Map applies the rules to one record: the first rule of the record's source that
// matches produces the events, and a record no rule matches produces nothing. A rule
// without each matches when the record matches every entry of its match, and produces
// one event. A rule with each matches when one element of its array matches it; then
// each element, in the array's order, produces the event of the first rule from this
// one on with the same source and each that the element matches, so one record's
// elements may produce events of different rules, and an element no such rule matches
// produces none. A rule whose path is no array matches no record.
func (d *Descriptor) Map(r Record) []Event {
	for i := range d.Rules {
		rule := &d.Rules[i]
		if rule.Source != r.Source {
			continue
		}
		if rule.Each == "" {
			if matches(rule.Match, r.Record, nil) {
				return []Event{rule.event(r.Record, nil)}
			}
			continue
		}
		list, _ := lookup(r.Record, rule.Each)
		elements, _ := list.([]any)
		if !slices.ContainsFunc(elements, func(e any) bool { return matches(rule.Match, r.Record, &e) }) {
			continue
		}
		var events []Event
		for k := range elements {
			element := &elements[k]
			for j := i; j < len(d.Rules); j++ {
				other := &d.Rules[j]
				if other.Source == r.Source && other.Each == rule.Each && matches(other.Match, r.Record, element) {
					events = append(events, other.event(r.Record, element))
					break
				}
			}
		}
		return events
	}
	return nil
}

// Link applies the parent member to one record: when the record is of the member's
// source and matches, it returns the subagent's id and the id of the tool call that
// started it, both strings that are not empty, and true.
func (d *Descriptor) Link(r Record) (agentID, toolUseID string, ok bool) {
	p := d.Parent
	if p == nil || p.Source != r.Source || !matches(p.Match, r.Record, nil) {
		return "", "", false
	}
	a, _ := lookup(r.Record, p.AgentID)
	c, _ := lookup(r.Record, p.ToolUseID)
	agentID, _ = a.(string)
	toolUseID, _ = c.(string)
	if agentID == "" || toolUseID == "" {
		return "", "", false
	}
	return agentID, toolUseID, true
}

// eachPrefix is how a path of a rule with each starts when it reads the element.
const eachPrefix = "each."

// event is the rule's event for the record, or for the element when it is not nil:
// the fields of Data whose path exists, with their values, and the fields of Set.
func (rule *Rule) event(record map[string]any, element *any) Event {
	data := copied(rule.Data, record, element)
	for field, v := range rule.Set {
		data[field] = v
	}
	return Event{Type: rule.Type, Data: data, FromStarted: slices.Clone(rule.FromStarted)}
}

// copied is the data of a rule's event: each field whose path exists, with its value.
func copied(data map[string]string, record map[string]any, element *any) map[string]any {
	out := map[string]any{}
	for field, path := range data {
		if v, ok := read(record, element, path); ok {
			out[field] = v
		}
	}
	return out
}

// matches reports whether the record matches every entry of match, or the element for a
// path that starts with each. when element is not nil.
func matches(match map[string]any, record map[string]any, element *any) bool {
	for path, want := range match {
		got, ok := read(record, element, path)
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

// read follows path through the element when element is not nil and path starts with
// each., and through the record otherwise.
func read(record map[string]any, element *any, path string) (any, bool) {
	if rest, ok := strings.CutPrefix(path, eachPrefix); ok && element != nil {
		m, ok := (*element).(map[string]any)
		if !ok {
			return nil, false
		}
		return lookup(m, rest)
	}
	return lookup(record, path)
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
