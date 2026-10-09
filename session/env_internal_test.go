package session

import (
	"slices"
	"strings"
	"testing"
)

// TestNoProgramReceivesTheAccessKeysVariables pins that QORY_ACCESS_KEY_SECRET,
// QORY_ACCESS_KEY_ID and QORY_APIARY_PUBLIC_KEY do not reach the agent, whose
// environment is the run's, Forager's own by default, and neither does
// QORY_RUN_CREDENTIAL_SECRET, whatever brought it, while the other variables do.
// A tool's environment is the gateway's.
func TestNoProgramReceivesTheAccessKeysVariables(t *testing.T) {
	t.Setenv("QORY_ACCESS_KEY_SECRET", "qak_not-a-real-one")
	t.Setenv("QORY_ACCESS_KEY_ID", "ak_f1xt0re000000000")
	t.Setenv("QORY_APIARY_PUBLIC_KEY", "[]")
	t.Setenv("QORY_RUN_CREDENTIAL_SECRET", "not-a-run-credential")
	t.Setenv("OTHER_SETTING", "kept")
	unwalled := withDefaults(Spec{Dir: t.TempDir()})
	for name, env := range map[string][]string{
		"the agent, by default":       environment(unwalled.Env, []string{EnvRunID + "=r"}),
		"the agent, passed them":      environment([]string{"QORY_ACCESS_KEY_SECRET=qak_x", "QORY_ACCESS_KEY_ID=x", "QORY_APIARY_PUBLIC_KEY=x", "QORY_RUN_CREDENTIAL_SECRET=x", "OTHER_SETTING=kept"}),
		"the agent, a run's variable": environment([]string{"OTHER_SETTING=kept"}, []string{"QORY_RUN_CREDENTIAL_SECRET=x"}),
	} {
		for _, kv := range env {
			if strings.HasPrefix(kv, "QORY_ACCESS_KEY_") || strings.HasPrefix(kv, "QORY_APIARY_") || strings.HasPrefix(kv, "QORY_RUN_CREDENTIAL_SECRET=") {
				t.Errorf("%s receives %s", name, kv)
			}
		}
		if !slices.Contains(env, "OTHER_SETTING=kept") {
			t.Errorf("%s lost the other variables", name)
		}
	}
}
