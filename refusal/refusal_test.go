package refusal

import "testing"

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
