package gateway

import (
	"reflect"
	"testing"
)

// filled is a value of v's type with every field set: a string to "x", a bool to
// true, a list of strings to two. A field of another kind fails the test, so a definition that gains
// one gains its copy and its case here together.
func filled(t *testing.T, v any) reflect.Value {
	t.Helper()
	out := reflect.New(reflect.TypeOf(v)).Elem()
	for i := range out.NumField() {
		f := out.Field(i)
		switch {
		case f.Kind() == reflect.String:
			f.SetString("x")
		case f.Kind() == reflect.Bool:
			f.SetBool(true)
		case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String:
			f.Set(reflect.ValueOf([]string{"a", "b"}))
		default:
			t.Fatalf("%s.%s is a %s, which the test does not fill", out.Type().Name(), out.Type().Field(i).Name, f.Type())
		}
	}
	return out
}

// sharesNothing fails the test when a list of got is the same as its list in from, or
// when got is not equal to from.
func sharesNothing(t *testing.T, from, got reflect.Value) {
	t.Helper()
	if !reflect.DeepEqual(from.Interface(), got.Interface()) {
		t.Errorf("the copy %+v, want %+v", got, from)
	}
	for i := range from.NumField() {
		if f := from.Field(i); f.Kind() == reflect.Slice && f.UnsafePointer() == got.Field(i).UnsafePointer() {
			t.Errorf("the copy of %s shares its %s", from.Type().Name(), from.Type().Field(i).Name)
		}
	}
}

// TestCopiesOfCredentialsAndToolsShareNothing pins that the copies Start takes of the
// credentials and tools equal them and share no list with them: the list of
// definitions and every list of each definition are new. A nil list stays nil and an
// empty one empty.
func TestCopiesOfCredentialsAndToolsShareNothing(t *testing.T) {
	c := filled(t, Credential{})
	creds := []Credential{c.Interface().(Credential)}
	gotCreds := copyCredentials(creds)
	if len(gotCreds) != 1 || &gotCreds[0] == &creds[0] {
		t.Fatalf("the copy of the credentials shares their list: %v", gotCreds)
	}
	sharesNothing(t, reflect.ValueOf(creds[0]), reflect.ValueOf(gotCreds[0]))
	tl := filled(t, Tool{})
	tools := []Tool{tl.Interface().(Tool)}
	gotTools := copyTools(tools)
	if len(gotTools) != 1 || &gotTools[0] == &tools[0] {
		t.Fatalf("the copy of the tools shares their list: %v", gotTools)
	}
	sharesNothing(t, reflect.ValueOf(tools[0]), reflect.ValueOf(gotTools[0]))

	if copyCredentials(nil) != nil || copyTools(nil) != nil {
		t.Error("the copy of no list is a list")
	}
	empty := copyCredentials([]Credential{{Name: "api", Paths: []string{}}})
	if empty[0].Paths == nil || empty[0].Hosts != nil {
		t.Errorf("the copy of empty Paths and nil Hosts: %#v, %#v", empty[0].Paths, empty[0].Hosts)
	}
}
