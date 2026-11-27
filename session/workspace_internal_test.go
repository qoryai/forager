package session

import "testing"

// TestAWorkingFolderReachedThroughTheRoot pins atWorkspace for a plan whose workspace is
// reached through the bind of /, which cannot be shown at /workspace: a step's plan gets
// a text that starts with the fix, and a join's plan keeps its text.
func TestAWorkingFolderReachedThroughTheRoot(t *testing.T) {
	for _, c := range []struct {
		step bool
		want string
	}{
		{true, "Choose a working folder below /: a step shows its working folder at /workspace.\n" +
			`The working folder /srv/work is reached through the bind of "/"`},
		{false, `the workspace is reached through "/", which cannot be shown at /workspace`},
	} {
		p := mountPlan{root: "/", workspace: "/srv/work", stepBinds: c.step}
		if _, _, err := p.atWorkspace(); err == nil || err.Error() != c.want {
			t.Errorf("step %v: %v\nwant %q", c.step, err, c.want)
		}
	}
}
