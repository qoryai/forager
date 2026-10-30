package contracts

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// Base is the $id every schema of the contract carries, followed by the schema's path
// under forager/v1. It names the contract; nothing is fetched from it.
const Base = "https://qory.dev/contracts/forager/v1"

// Version is the contract version the embedded directory holds.
const Version = "v1"

// Revision is the revision of the contract version this module implements: the
// integer Forager sends as X-Qory-Contract-Version and as contract_version in a
// run's registration. A revision adds; a breaking change is a new Version. The revision is raised
// only once a release of Forager is in use.
const Revision = 1

// runtimes.json lists the secrets and the model sections of the descriptors under
// forager/v1/runtimes, for a server to vendor; it is written from them and never by
// hand.
//go:generate go run ../session/internal/descriptor/runtimesjson forager/v1/runtimes.json

//go:embed all:forager
var embedded embed.FS

// FS is the contract directory, rooted at forager/v1: the README, the schemas, the
// runtime descriptors and the fixtures.
var FS = must(fs.Sub(embedded, "forager/v1"))

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// Compiler returns a schema compiler that resolves every schema of the contract from
// [FS] under its $id, with format and content assertions on, so "date-time", "uri" and
// "base64" are checked and not only annotated. The CloudEvents schema the envelope
// refers to is draft 7 and the contract's own are draft 2020-12; the compiler reads
// each under the draft it declares.
func Compiler() (*jsonschema.Compiler, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	c.AssertContent()
	err := fs.WalkDir(FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".schema.json") {
			return err
		}
		doc, err := Document(p)
		if err != nil {
			return err
		}
		return c.AddResource(Base+"/"+p, doc)
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Compile compiles one schema of the contract by its path under forager/v1, such as
// "policy.schema.json" or "events/run.log.schema.json".
func Compile(name string) (*jsonschema.Schema, error) {
	c, err := Compiler()
	if err != nil {
		return nil, err
	}
	return c.Compile(Base + "/" + name)
}

// Document reads one YAML or JSON file of the contract, by its path under forager/v1,
// into the JSON types a schema validates: maps with string keys, slices, json.Number
// for numbers. A YAML document goes through JSON on the way, so a YAML integer is a
// number and a YAML key is a string.
func Document(name string) (any, error) {
	b, err := fs.ReadFile(FS, name)
	if err != nil {
		return nil, err
	}
	return Decode(name, b)
}

// Decode turns the bytes of a YAML or JSON document into JSON types, choosing the
// reader by the file name's extension: .yaml and .yml are YAML, anything else is JSON.
func Decode(name string, b []byte) (any, error) {
	switch path.Ext(name) {
	case ".yaml", ".yml":
		var v any
		if err := yaml.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		j, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		b = j
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return v, nil
}

// Lines reads a JSON lines file of the contract, by its path under forager/v1, one JSON
// value per line in JSON types. A blank line is skipped; a line that is not JSON is an
// error naming the line number.
func Lines(name string) ([]any, error) {
	b, err := fs.ReadFile(FS, name)
	if err != nil {
		return nil, err
	}
	var out []any
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(nil, 16<<20)
	for n := 1; s.Scan(); n++ {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		out = append(out, v)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// Denied is the built-in deny list, denied-variables.json: the names and the patterns,
// in which * matches any run of characters, of the variables whose value a run leaves
// out of every source the deny list covers, matched regardless of case; and the names
// of the variables a credential is read from, which the deny list covers as names and
// which a credential's placeholder may take: the forge tokens', such as GH_TOKEN, and
// the model keys', such as ANTHROPIC_API_KEY.
type Denied struct {
	Version     int      `json:"version"`
	Names       []string `json:"names"`
	Patterns    []string `json:"patterns"`
	ForgeTokens []string `json:"forge_tokens"`
	ModelKeys   []string `json:"model_keys"`
}

// Credentials is the forge tokens' names and then the model keys', a new slice.
func (d Denied) Credentials() []string { return slices.Concat(d.ForgeTokens, d.ModelKeys) }

// DeniedVariables reads the built-in deny list from the embedded denied-variables.json,
// a new copy on each call.
func DeniedVariables() (Denied, error) {
	var d Denied
	b, err := fs.ReadFile(FS, "denied-variables.json")
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("denied-variables.json: %w", err)
	}
	return d, nil
}

// denied is the embedded deny list, read once; a test reads the same file, so it
// reads without an error.
var denied = sync.OnceValue(func() Denied {
	d, err := DeniedVariables()
	if err != nil {
		panic(err)
	}
	return d
})

// ForgeTokenNames is the forge_tokens of denied-variables.json, the variables a code
// forge's token is read from, such as GH_TOKEN and GITLAB_TOKEN: a new slice on each
// call.
func ForgeTokenNames() []string { return slices.Clone(denied().ForgeTokens) }

// ModelKeyNames is the model_keys of denied-variables.json, the variables a runtime
// descriptor reads a model key from, such as ANTHROPIC_API_KEY: a new slice on each
// call.
func ModelKeyNames() []string { return slices.Clone(denied().ModelKeys) }
