package refusal

import (
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
)

// TestDeciders pins who decides each code: Forager decides its own and none of a
// gateway's, and a gateway decides its own and none of Forager's.
func TestDeciders(t *testing.T) {
	forager := []string{
		RunConfigurationInvalid, ToolUnknown, ImageUnknown, ImageNotAllowed, ImageUserRoot,
		VariableReserved, PlaceholderConflict, ModelKeyMissing, MountContainsForagerFiles, MountModeConflict, MountSharedWithRun,
		MountThroughLink, EngineUnreachable,
	}
	gateway := []string{RunIDUsed}
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
		t.Error("run_closed is the gateway's 410 to a run already ended, no refusal of a run; want neither to decide it")
	}
	for _, code := range []string{"run_credential_refused", "target_differs_from_credential", "differs_from_credential"} {
		if Decides(code) || GatewayDecides(code) {
			t.Errorf("%s is a reserved old code no one decides any more", code)
		}
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

// TestNeedsWallSaysWhatARunAlwaysSaid pins the text of a run without a wall whose policy
// selects what needs one, rebuilt from the link's names word for word: the credentials'
// before the image's; with server_credentials among them, the text for a run
// configuration's credentials.
func TestNeedsWallSaysWhatARunAlwaysSaid(t *testing.T) {
	const selects = "the policy selects credentials or tools or has path rules, which need a wall: without one a program that ignores the proxy is bound by none of them"
	const server = "run it with a wall: the run configuration from Qory Apiary has credentials, and the gateway sets their values only for a run behind a wall"
	for names, want := range map[string]string{
		"credentials":            selects,
		"tools":                  selects,
		"paths":                  selects,
		"credentials,image=base": selects,
		"image=base":             `the policy selects the image "base", which needs a wall: without one the runtime is this machine's process`,
		"server_credentials":     server,
		"server_credentials,credentials,image=base": server,
	} {
		if got := (&NeedsWall{Names: strings.Split(names, ",")}).Error(); got != want {
			t.Errorf("%s: %s", names, got)
		}
	}
}
