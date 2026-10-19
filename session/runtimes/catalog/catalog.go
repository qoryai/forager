// Package catalog resolves a runtime's name to the way Forager runs it.
package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/internal/hostfile"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// Installers are the hook installers a descriptor may name, by the names it names them.
func Installers() map[string]runtimes.Installer {
	return map[string]runtimes.Installer{claude.SettingsInstaller: claude.Settings}
}

// maxDescriptor is the largest descriptor, in bytes, Lookup reads from dir: 1 MiB.
const maxDescriptor = 1 << 20

var name = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// Lookup is the runtime of a name. A descriptor in dir, <name>.yaml, comes first when
// dir is not empty: it is how a machine describes a runtime Forager ships nothing
// for, or replaces what it ships. Then the contract's own descriptor for the name. A
// name with neither is a bare runtime: the run is recorded, the session inside is not.
// A descriptor in dir is read only when its last part is no link, it is a regular file
// and it holds at most 1 MiB.
func Lookup(runtime, dir string) (runtimes.Runtime, error) {
	if !name.MatchString(runtime) {
		return nil, fmt.Errorf("runtime %s is not a name: a lower-case letter, then up to 63 lower-case letters, digits and dashes", accesskey.ShownName(runtime, true))
	}
	if dir != "" {
		p := filepath.Join(dir, runtime+".yaml")
		b, err := hostfile.Read(p, maxDescriptor, nil)
		if err == nil {
			return described(p, runtime, b)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("Make the runtime descriptor %s a readable regular file of at most 1 MiB, or remove it. It could not be read: %w", accesskey.ShownValue(p, false), accesskey.ShownError(err))
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
		return nil, fmt.Errorf("%s describes %q, not %q", accesskey.ShownValue(path, false), rt.Name(), runtime)
	}
	return rt, nil
}
