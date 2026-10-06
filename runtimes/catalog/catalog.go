// Package catalog resolves a runtime's name to the way this runner runs it.
package catalog

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/runtimes"
	"github.com/qoryai/runner/runtimes/claude"
)

// Installers are the hook installers a descriptor may name, by the names it names them.
func Installers() map[string]runtimes.Installer {
	return map[string]runtimes.Installer{claude.SettingsInstaller: claude.Settings}
}

var name = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// Lookup is the runtime of a name. A descriptor in dir, <name>.yaml, comes first when
// dir is not empty: it is how a machine describes a runtime this runner ships nothing
// for, or replaces what it ships. Then the contract's own descriptor for the name. A
// name with neither is a bare runtime: the run is recorded, the session inside is not.
func Lookup(runtime, dir string) (runtimes.Runtime, error) {
	if !name.MatchString(runtime) {
		return nil, fmt.Errorf("runtime %q is not a name: a lower-case letter, then up to 63 lower-case letters, digits and dashes", runtime)
	}
	if dir != "" {
		p := filepath.Join(dir, runtime+".yaml")
		b, err := os.ReadFile(p)
		if err == nil {
			return described(p, runtime, b)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	p := "runtimes/" + runtime + "/descriptor.yaml"
	if b, err := fs.ReadFile(contracts.FS, p); err == nil {
		return described(p, runtime, b)
	}
	return runtimes.Bare(runtime), nil
}

func described(path, runtime string, b []byte) (runtimes.Runtime, error) {
	rt, err := runtimes.Described(path, b, Installers())
	if err != nil {
		return nil, err
	}
	if rt.Name() != runtime {
		return nil, fmt.Errorf("%s describes %q, not %q", path, rt.Name(), runtime)
	}
	return rt, nil
}
