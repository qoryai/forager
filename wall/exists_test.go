package wall

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
)

// standIn writes a docker command to dir that answers info with the engine's id and ps
// with one container, and records the environment and the working directory of its ps
// in dir, as env and pwd.
func standIn(t *testing.T, dir string) string {
	t.Helper()
	script := filepath.Join(dir, "docker")
	body := "#!/bin/sh\ncase \"$1\" in\ninfo) echo engine-1 ;;\n" +
		"ps) env > '" + filepath.Join(dir, "env") + "'; pwd -P > '" +
		filepath.Join(dir, "pwd") + "'; echo c0ffee ;;\nesac\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

// TestRunContainersExistRunsTheRecordedCommand pins how a Docker with no field set, and
// the package's RunContainersExist with it, ask the engine an earlier run recorded:
// its command, in this process's working directory, with this process's environment
// without the access key's and the run key's variables and with the recorded selection
// in place of this process's.
func TestRunContainersExistRunsTheRecordedCommand(t *testing.T) {
	t.Setenv(accesskey.EnvSecret, "secret")
	t.Setenv(accesskey.EnvRunKey, "run-key")
	t.Setenv("DOCKER_HOST", "unix:///this/process.sock")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if wd, err = filepath.EvalSymlinks(wd); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		ask  func(ctx context.Context, e Engine, runID string) (bool, error)
	}{
		{"the method", (&Docker{}).RunContainersExist},
		{"a nil Docker", (*Docker)(nil).RunContainersExist},
		{"the function", RunContainersExist},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			e := Engine{Wall: "docker", Command: standIn(t, dir),
				Env: []string{"DOCKER_HOST=unix:///recorded.sock"}, Pinned: true, ID: "engine-1"}
			exists, err := c.ask(context.Background(), e, "0191f2a4-0000-7000-8000-00000000e815")
			if err != nil || !exists {
				t.Fatalf("exists %v, %v", exists, err)
			}
			pwd, err := os.ReadFile(filepath.Join(dir, "pwd"))
			if err != nil || strings.TrimSpace(string(pwd)) != wd {
				t.Errorf("the working directory %q, %v; want %q", pwd, err, wd)
			}
			b, err := os.ReadFile(filepath.Join(dir, "env"))
			if err != nil {
				t.Fatal(err)
			}
			// What the shell sets of itself is neither the caller's nor compared.
			shell := []string{"PWD", "SHLVL", "_", "OLDPWD"}
			ours := func(env []string) []string {
				var out []string
				for _, kv := range env {
					if name, _, _ := strings.Cut(kv, "="); !slices.Contains(shell, name) {
						out = append(out, kv)
					}
				}
				slices.Sort(out)
				return out
			}
			got := ours(strings.Split(strings.TrimSpace(string(b)), "\n"))
			want := ours(withSelection(accesskey.WithoutVariables(os.Environ()), e.Env))
			if !slices.Equal(got, want) {
				t.Errorf("the command's environment %q, want %q", got, want)
			}
			if !slices.Contains(got, "DOCKER_HOST=unix:///recorded.sock") ||
				slices.ContainsFunc(got, func(kv string) bool {
					return strings.HasPrefix(kv, accesskey.EnvSecret+"=") ||
						strings.HasPrefix(kv, accesskey.EnvRunKey+"=") ||
						kv == "DOCKER_HOST=unix:///this/process.sock"
				}) {
				t.Errorf("the command's environment %q", got)
			}
		})
	}
}
