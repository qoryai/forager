package contracts_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
)

// openSchemas are the schemas whose objects accept a member they do not define, each
// with the must_understand that lists the members a reader must understand.
var openSchemas = []string{"auth.schema.json", "credential.schema.json", "events/run.exited.schema.json"}

// understoodObjects are the objects of the open schemas that have a must_understand:
// the schema and the JSON Pointer of the object's node in it, "" for the root.
var understoodObjects = []struct{ schema, node string }{
	{"auth.schema.json", ""},
	{"credential.schema.json", ""},
	{"credential.schema.json", "/properties/apply/items"},
	{"events/run.exited.schema.json", ""},
}

// definedPointers lists the JSON Pointers that the schema node defines below the
// pointer at: each member of properties but must_understand, and below a member whose
// value is a list, its item at the index 0 and below it.
func definedPointers(node map[string]any, at string) []string {
	var out []string
	props, _ := node["properties"].(map[string]any)
	for name, sub := range props {
		if name == "must_understand" {
			continue
		}
		p := at + "/" + name
		out = append(out, p)
		m, _ := sub.(map[string]any)
		out = append(out, definedPointers(m, p)...)
		if items, ok := m["items"].(map[string]any); ok {
			out = append(out, p+"/0")
			out = append(out, definedPointers(items, p+"/0")...)
		}
	}
	slices.Sort(out)
	return out
}

// closed reports whether a node of the schema, at any depth, has additionalProperties
// false.
func closed(node any) bool {
	switch v := node.(type) {
	case map[string]any:
		if v["additionalProperties"] == false {
			return true
		}
		for _, sub := range v {
			if closed(sub) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, closed)
	}
	return false
}

// TestMustUnderstandListsTheDefinedMembers pins that no object of an open schema has
// additionalProperties false, and the must_understand of each to the members the
// schema defines: a pointer to each of them, and to an item
// of a list at the index 0 or 12, passes; a pointer to a member it does not define,
// below a member that has none, to must_understand itself, at an index with a leading
// zero, of another case, without its first /, with a line feed or with a ~ that is not
// ~0 or ~1 fails; and so does a pointer twice. The list has at most 32 pointers, each
// of at most 256 characters. The root of each open schema has a must_understand, and so
// does an apply item of credential.schema.json, with pointers counted from the item.
func TestMustUnderstandListsTheDefinedMembers(t *testing.T) {
	for _, name := range openSchemas {
		doc, err := contracts.Document(name)
		if err != nil {
			t.Fatal(err)
		}
		if closed(doc) {
			t.Errorf("%s has an object with additionalProperties false; want each open", name)
		}
	}
	for _, o := range understoodObjects {
		name := o.schema + o.node
		doc, err := contracts.Document(o.schema)
		if err != nil {
			t.Fatal(err)
		}
		root := doc.(map[string]any)
		for _, seg := range strings.Split(o.node, "/")[1:] {
			root = root[seg].(map[string]any)
		}
		schema, err := contracts.Compile(o.schema + "#" + o.node + "/properties/must_understand")
		if err != nil {
			t.Fatal(err)
		}
		list := func(pointers ...string) error {
			v := make([]any, len(pointers))
			for i, p := range pointers {
				v[i] = p
			}
			return schema.Validate(v)
		}
		defined := definedPointers(root, "")
		if len(defined) == 0 {
			t.Fatalf("%s defines no member", name)
		}
		for _, p := range defined {
			if err := list(p); err != nil {
				t.Errorf("%s: the schema does not accept %s in must_understand, a member it defines: %v", name, p, err)
			}
			if strings.Contains(p, "/0") {
				if err := list(strings.ReplaceAll(p, "/0", "/12")); err != nil {
					t.Errorf("%s: the schema does not accept %s at the index 12 in must_understand: %v", name, p, err)
				}
				if err := list(strings.ReplaceAll(p, "/0", "/00")); err == nil {
					t.Errorf("%s: the schema accepts %s at the index 00 in must_understand", name, p)
				}
			}
			for _, bad := range []string{p + "/zz", p + "/", strings.ToUpper(p), p[1:], p + "\n", p + "~2"} {
				if slices.Contains(defined, bad) {
					continue
				}
				if err := list(bad); err == nil {
					t.Errorf("%s: the schema accepts %q in must_understand", name, bad)
				}
			}
		}
		for _, bad := range []string{"/zz", "/must_understand", "/", "", "zz"} {
			if err := list(bad); err == nil {
				t.Errorf("%s: the schema accepts %q in must_understand", name, bad)
			}
		}
		if err := list(defined[0], defined[0]); err == nil {
			t.Errorf("%s: the schema accepts %s twice in must_understand", name, defined[0])
		}
		// A list item's pointer is long and many at its index alone, so the length and
		// count limits fail with no other rule.
		if i := slices.IndexFunc(defined, func(p string) bool { return strings.HasSuffix(p, "/0") }); i >= 0 {
			list0 := strings.TrimSuffix(defined[i], "0")
			long := func(n int) string { return list0 + strings.Repeat("1", n-len(list0)) }
			if err := list(long(256)); err != nil {
				t.Errorf("%s: the schema does not accept a pointer of 256 characters: %v", name, err)
			}
			if err := list(long(257)); err == nil {
				t.Errorf("%s: the schema accepts a pointer of 257 characters", name)
			}
			many := make([]string, 33)
			for n := range many {
				many[n] = fmt.Sprintf("%s%d", list0, n)
			}
			if err := list(many[:32]...); err != nil {
				t.Errorf("%s: the schema does not accept 32 pointers: %v", name, err)
			}
			if err := list(many...); err == nil {
				t.Errorf("%s: the schema accepts 33 pointers", name)
			}
		}
		mu, _ := root["properties"].(map[string]any)["must_understand"].(map[string]any)
		if mu["maxItems"] != json.Number("32") {
			t.Errorf("%s: must_understand has maxItems %v; want 32", name, mu["maxItems"])
		}
	}
}
