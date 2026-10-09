package refusal

import (
	"slices"
	"testing"

	"github.com/qoryai/forager/accesskey"
)

// TestDeciders pins who decides each code: Forager decides its own and none of a
// gateway's, and a gateway decides its own and none of Forager's.
func TestDeciders(t *testing.T) {
	forager := []string{
		RunConfigurationInvalid, ToolUnknown, ImageUnknown, VariableReserved,
		PlaceholderConflict, MountContainsForagerFiles, MountModeConflict, MountSharedWithRun,
		MountThroughLink, EngineUnreachable,
	}
	gateway := []string{RunCredentialRefused, TargetDiffersFromCredential, DiffersFromCredential, RunIDUsed}
	for _, code := range forager {
		if !Decides(code) || GatewayDecides(code) {
			t.Errorf("%s: Decides %v, GatewayDecides %v; want true, false", code, Decides(code), GatewayDecides(code))
		}
	}
	for _, code := range gateway {
		if Decides(code) || !GatewayDecides(code) {
			t.Errorf("%s: Decides %v, GatewayDecides %v; want false, true", code, Decides(code), GatewayDecides(code))
		}
	}
	if Decides("run_closed") || GatewayDecides("run_closed") {
		t.Error("run_closed is the server's; want neither to decide it")
	}
}

// TestByGateway pins that New leaves From empty, a session's refusal, and ByGateway
// sets it to gateway, with the same code, names, detail and text.
func TestByGateway(t *testing.T) {
	s := New(RunIDUsed, []string{"b", "a", "b"}, "run %s", "r1")
	g := ByGateway(RunIDUsed, []string{"b", "a", "b"}, "run %s", "r1")
	if s.From != "" || g.From != accesskey.FromGateway {
		t.Errorf("From: New %q, ByGateway %q", s.From, g.From)
	}
	if g.Code != s.Code || g.Detail != s.Detail || !slices.Equal(g.Names, []string{"a", "b"}) || g.Error() != s.Error() {
		t.Errorf("ByGateway %+v, New %+v", g, s)
	}
}
