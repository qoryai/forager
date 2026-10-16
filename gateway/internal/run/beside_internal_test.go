package run

import (
	"errors"
	"reflect"
	"testing"

	"github.com/qoryai/forager/policy"
)

// TestDecideChecksTheSidesTheRunHolds pins that the sides of path rules a ceiling puts
// beside the node's policy are checked as the run holds them: the check is given the
// run's copy, and a change to the ceiling's maps while the check runs, a path replaced
// with one the schema refuses and a host added, reaches neither the sides the check was
// given nor the sides the run holds. A ceiling whose sides the check refuses is no run.
func TestDecideChecksTheSidesTheRunHolds(t *testing.T) {
	const host = "api.example"
	paths := map[string][]string{host: {"/v1/*"}}
	ceiling := &Policy{Version: 1, Egress: PolicyEgress{Mode: "enforce", Allow: []string{"*.example"}, Paths: paths}}
	node := (&Policy{Version: 1, Egress: PolicyEgress{Mode: "enforce", Allow: []string{host}}}).Under(ceiling)
	check := checkSides
	t.Cleanup(func() { checkSides = check })
	var given []map[string][]string
	checkSides = func(sides []map[string][]string) error {
		err := check(sides)
		given = sides
		paths[host][0] = "v2"
		paths["b.example"] = []string{"/x/*"}
		return err
	}
	r, err := Decide(Config{RunID: "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f", Node: node, Wall: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string][]string{{host: {"/v1/*"}}}
	if !reflect.DeepEqual(r.beside, want) {
		t.Errorf("the run holds the sides %v, want %v", r.beside, want)
	}
	if !reflect.DeepEqual(given, want) {
		t.Errorf("the check was given the sides %v, want %v", given, want)
	}
	if len(given) != 1 || len(r.beside) != 1 || reflect.ValueOf(given[0]).UnsafePointer() != reflect.ValueOf(r.beside[0]).UnsafePointer() {
		t.Error("the check was given other sides than the run holds")
	}
	checkSides = check
	bad := (&Policy{Version: 1, Egress: PolicyEgress{Mode: "enforce", Allow: []string{host}}}).Under(
		&Policy{Version: 1, Egress: PolicyEgress{Mode: "enforce", Allow: []string{"*.example"}, Paths: map[string][]string{host: {"v2"}}}})
	var perr *policy.Error
	if _, err := Decide(Config{RunID: "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f", Node: bad, Wall: true}); !errors.As(err, &perr) {
		t.Errorf("a ceiling whose sides the check refuses: %v, want the schema's refusal", err)
	}
}
