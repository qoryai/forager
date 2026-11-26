package session

import "testing"

// TestWithNewListsEachBindOnce pins withNew: a bind already listed, the same in every
// member, is not listed again, and a bind that differs in one member is.
func TestWithNewListsEachBindOnce(t *testing.T) {
	work := bindSource{Path: "/work", Resolved: "/work", Lookups: []string{"/"}, Writable: true}
	readOnly := work
	readOnly.Writable = false
	helper := bindSource{Path: "/opt/qory", Resolved: "/opt/qory", Kind: "helper"}
	got := withNew([]bindSource{work, helper}, []bindSource{work, readOnly, helper})
	if len(got) != 3 || !sameBind(got[2], readOnly) {
		t.Errorf("withNew listed %+v", got)
	}
}
