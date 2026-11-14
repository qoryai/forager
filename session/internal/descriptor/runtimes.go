package descriptor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"sort"

	"github.com/qoryai/forager/accesskey"
)

// RuntimesFile is the path, in the contract directory, of the file that lists the
// secrets, the model section, the fixed variables, the egress hosts and the transcript
// paths of every runtime the contract ships a descriptor for, the file a server vendors.
const RuntimesFile = "runtimes.json"

// runtimesFile is the document of [RuntimesFile].
type runtimesFile struct {
	Version  int            `json:"version"`
	Runtimes []runtimeEntry `json:"runtimes"`
}

// runtimeEntry is one runtime of [RuntimesFile]. Every list is present, empty when the
// descriptor has none, so a reader finds the same members for every runtime, and so is
// fixed, an empty object when the descriptor has none. Model, Config and Resume are the
// members that are absent when the descriptor has none.
type runtimeEntry struct {
	Name            string             `json:"name"`
	Title           string             `json:"title"`
	Reserves        []string           `json:"reserves"`
	Denies          []string           `json:"denies"`
	CredentialFiles []string           `json:"credential_files"`
	Declares        []declarationEntry `json:"declares"`
	OneOf           []groupEntry       `json:"one_of"`
	Model           *modelEntry        `json:"model,omitempty"`
	Config          *configEntry       `json:"config,omitempty"`
	Fixed           map[string]string  `json:"fixed"`
	EgressHosts     []string           `json:"egress_hosts"`
	Resume          *resumeEntry       `json:"resume,omitempty"`
}

// resumeEntry is where a runtime of [RuntimesFile] writes the transcript of its
// session: the descriptor's resume.prefix and resume.path, for a server to check a
// transcript's path against.
type resumeEntry struct {
	Prefix string `json:"prefix"`
	Path   string `json:"path"`
}

// configEntry is a descriptor's config in [RuntimesFile]: its flag, and the keys of
// its fixed settings in the descriptor's order, without their values.
type configEntry struct {
	Flag  string   `json:"flag"`
	Fixed []string `json:"fixed"`
}

// modelEntry is the model section of a runtime in [RuntimesFile], in the descriptor's
// shape: formats, model and endpoint always, effort, keys and overrides when the
// descriptor has them, and in effort agent when it has that. A place has only the member that is
// set.
type modelEntry struct {
	Formats   []string `json:"formats"`
	Model     Place    `json:"model"`
	Effort    *Effort  `json:"effort,omitempty"`
	Endpoint  Endpoint `json:"endpoint"`
	Keys      []Key    `json:"keys,omitempty"`
	Overrides []string `json:"overrides,omitempty"`
}

// declarationEntry is one declaration of a runtime in [RuntimesFile]; paths is absent
// when the declaration bounds none.
type declarationEntry struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
	Auth  Auth     `json:"auth"`
	Paths []string `json:"paths,omitempty"`
}

// groupEntry is one one_of group of a runtime in [RuntimesFile], with required always
// present.
type groupEntry struct {
	ID       string   `json:"id"`
	Required bool     `json:"required"`
	Of       []string `json:"of"`
}

// Runtimes renders [RuntimesFile] from the descriptors of a contract directory, such as
// contracts.FS: every runtimes/<name>/descriptor.yaml, sorted by name, with its name,
// its title, its secrets, the lists in the descriptor's order, its model section
// when it has one, its config's flag and fixed keys when it has a config, its fixed
// variables, by name, its egress hosts, and its resume's
// prefix and path when it has a resume. The output is
// indented JSON ending in a newline, the same bytes for the same descriptors. A
// descriptor without a title, or whose runtime is not its directory's name, is an
// error.
func Runtimes(fsys fs.FS) ([]byte, error) {
	dirs, err := fs.ReadDir(fsys, "runtimes")
	if err != nil {
		return nil, err
	}
	doc := runtimesFile{Version: 1, Runtimes: []runtimeEntry{}}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		p := path.Join("runtimes", dir.Name(), "descriptor.yaml")
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		d, err := Parse(p, b)
		if err != nil {
			return nil, err
		}
		if d.Runtime != dir.Name() {
			return nil, fmt.Errorf("%s describes %q; want the directory's name", accesskey.ShownValue(p, false), d.Runtime)
		}
		if d.Title == "" {
			return nil, fmt.Errorf("%s has no title; %s lists one for every runtime", accesskey.ShownValue(p, false), RuntimesFile)
		}
		doc.Runtimes = append(doc.Runtimes, entry(d))
	}
	sort.Slice(doc.Runtimes, func(i, j int) bool { return doc.Runtimes[i].Name < doc.Runtimes[j].Name })
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// entry is a descriptor as one runtime of [RuntimesFile].
func entry(d *Descriptor) runtimeEntry {
	s := d.Secrets
	if s == nil {
		s = &Secrets{}
	}
	e := runtimeEntry{
		Name:            d.Runtime,
		Title:           d.Title,
		Reserves:        list(s.Reserves),
		Denies:          list(s.Denies),
		CredentialFiles: list(s.CredentialFiles),
		Declares:        []declarationEntry{},
		OneOf:           []groupEntry{},
		Fixed:           map[string]string{},
		EgressHosts:     list(d.EgressHosts),
	}
	maps.Copy(e.Fixed, d.Fixed)
	for _, dc := range s.Declares {
		e.Declares = append(e.Declares, declarationEntry{
			ID: dc.ID, Title: dc.Title, Name: dc.Name, Hosts: list(dc.Hosts), Auth: dc.Auth, Paths: dc.Paths,
		})
	}
	for _, g := range s.OneOf {
		e.OneOf = append(e.OneOf, groupEntry{ID: g.ID, Required: g.Required, Of: list(g.Of)})
	}
	if m := d.Model; m != nil {
		e.Model = &modelEntry{Formats: m.Formats, Model: m.Model, Effort: m.Effort, Endpoint: m.Endpoint, Keys: m.Keys, Overrides: m.Overrides}
	}
	if c := d.Config; c != nil {
		e.Config = &configEntry{Flag: c.Flag, Fixed: list(c.Keys)}
	}
	if r := d.Resume; r != nil {
		e.Resume = &resumeEntry{Prefix: r.Prefix, Path: r.Path}
	}
	return e
}

// list is v, or an empty list when v is nil, so it encodes as [] and not null.
func list(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
