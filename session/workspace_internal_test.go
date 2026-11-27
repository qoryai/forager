package session

import "testing"

// TestAWorkingFolderReachedThroughTheRoot pins atWorkspace for a plan whose workspace
// lies inside a mount of /, which cannot be shown at /workspace: a step's plan gets a
// text that starts with the fix, and a join's plan keeps its text.
func TestAWorkingFolderReachedThroughTheRoot(t *testing.T) {
	for _, c := range []struct {
		step bool
		want string
	}{
		{true, "Remove the mount of / from Mounts: a step shows its working folder at /workspace.\n" +
			"The working folder /srv/work lies inside the mount of /, which cannot be shown at /workspace"},
		{false, `the workspace is reached through "/", which cannot be shown at /workspace`},
	} {
		p := mountPlan{root: "/", workspace: "/srv/work", stepBinds: c.step}
		if _, _, err := p.atWorkspace(); err == nil || err.Error() != c.want {
			t.Errorf("step %v: %v\nwant %q", c.step, err, c.want)
		}
	}
}
