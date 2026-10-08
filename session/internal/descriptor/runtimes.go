package descriptor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
)

// RuntimesFile is the path, in the contract directory, of the file that lists the
// secrets of every runtime the contract ships a descriptor for, the file a server
// vendors.
const RuntimesFile = "runtimes.json"

// runtimesFile is the document of [RuntimesFile].
type runtimesFile struct {
	Version  int            `json:"version"`
	Runtimes []runtimeEntry `json:"runtimes"`
}

// runtimeEntry is one runtime of [RuntimesFile]. Every list is present, empty when the
// descriptor has none, so a reader finds the same members for every runtime.
type runtimeEntry struct {
	Name            string             `json:"name"`
	Title           string             `json:"title"`
	Reserves        []string           `json:"reserves"`
	Denies          []string           `json:"denies"`
	CredentialFiles []string           `json:"credential_files"`
	Declares        []declarationEntry `json:"declares"`
	OneOf           []groupEntry       `json:"one_of"`
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
// its title and its secrets, the lists in the descriptor's order. The output is
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
			return nil, fmt.Errorf("%s describes %q; want the directory's name", p, d.Runtime)
		}
		if d.Title == "" {
			return nil, fmt.Errorf("%s has no title; %s lists one for every runtime", p, RuntimesFile)
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
	}
	for _, dc := range s.Declares {
		e.Declares = append(e.Declares, declarationEntry{
			ID: dc.ID, Title: dc.Title, Name: dc.Name, Hosts: list(dc.Hosts), Auth: dc.Auth, Paths: dc.Paths,
		})
	}
	for _, g := range s.OneOf {
		e.OneOf = append(e.OneOf, groupEntry{ID: g.ID, Required: g.Required, Of: list(g.Of)})
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
