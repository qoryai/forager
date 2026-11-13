// Package codex is Codex as a runtime of Forager: the contract's descriptor for it, and
// the check of its launch arguments. Codex takes no hook: the session reads its
// standard output, passes the descriptor's config as --config pairs, and refuses a
// launch whose arguments change those settings through a flag of Codex's.
package codex

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/runtimes"
)

// Name is the runtime's name.
const Name = "codex"

// descriptorPath is the descriptor in the contract.
const descriptorPath = "runtimes/codex/descriptor.yaml"

// New is Codex by the contract's descriptor.
func New() (runtimes.Runtime, error) {
	b, err := fs.ReadFile(contracts.FS, descriptorPath)
	if err != nil {
		return nil, err
	}
	return runtimes.DescribedWithArgs(descriptorPath, b, nil, checkArgs)
}

// The flags of Codex 0.167.2 that change a setting the session passes, other than
// --config (codex-rs utils/cli/src/config_override.rs, utils/cli/src/shared_options.rs,
// cli/src/main.rs, tui/src/cli.rs). -c is the short form of --config. --oss and
// --local-provider select a local model provider in place of model_provider;
// --profile and -p layer $CODEX_HOME/<name>.config.toml over the settings; --search
// sets web_search; --enable and --disable set features.<name>.
const (
	flagShort         = "-c"
	flagOSS           = "--oss"
	flagLocalProvider = "--local-provider"
	flagProfile       = "--profile"
	flagProfileShort  = "-p"
	flagSearch        = "--search"
	flagEnable        = "--enable"
	flagDisable       = "--disable"
)

// checkArgs refuses, up to an argument --, the flags of Codex 0.167.2 that change one
// of keys, the settings the session passes:
//   - -c with a pair that sets one of keys, as -c k=v, -ck=v or -c=k=v;
//   - --enable or --disable of a feature whose features.<name> is one of keys, as
//     --enable x or --enable=x;
//   - --oss and --search;
//   - --local-provider, --profile and -p in every form: --profile x, --profile=x,
//     -p x, -px and -p=x.
//
// The error names the flag and never the argument's value.
func checkArgs(args, keys []string) error {
	for i := 0; i < len(args) && args[i] != "--"; i++ {
		a := args[i]
		// value is the argument after a, the flag's value, which the loop skips.
		value := func() string {
			i++
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		switch {
		case a == flagShort:
			if k, ok := runtimes.SessionKey(runtimes.PairKey(value()), keys); ok {
				return keyRefused(flagShort, k)
			}
		case strings.HasPrefix(a, flagShort):
			pair := strings.TrimPrefix(strings.TrimPrefix(a, flagShort), "=")
			if k, ok := runtimes.SessionKey(runtimes.PairKey(pair), keys); ok {
				return keyRefused(flagShort, k)
			}
		case a == flagEnable || a == flagDisable || strings.HasPrefix(a, flagEnable+"=") || strings.HasPrefix(a, flagDisable+"="):
			flag, feature, attached := strings.Cut(a, "=")
			if !attached {
				feature = value()
			}
			if k, ok := runtimes.SessionKey("features."+feature, keys); ok {
				return keyRefused(flag, k)
			}
		case a == flagOSS || a == flagSearch:
			return flagRefused(a)
		case a == flagLocalProvider || strings.HasPrefix(a, flagLocalProvider+"="):
			return flagRefused(flagLocalProvider)
		case a == flagProfile || strings.HasPrefix(a, flagProfile+"="):
			return flagRefused(flagProfile)
		case strings.HasPrefix(a, flagProfileShort):
			return flagRefused(flagProfileShort)
		}
	}
	return nil
}

// keyRefused is the refusal of flag for k, a setting the session passes.
func keyRefused(flag, k string) error {
	return fmt.Errorf("remove the %s that sets %s from the launch's arguments: the session sets %s for Codex",
		accesskey.ShownName(flag, false), accesskey.ShownName(k, false), accesskey.ShownName(k, false))
}

// flagRefused is the refusal of a flag that changes the model provider, web search or
// the settings as a whole.
func flagRefused(flag string) error {
	return fmt.Errorf("remove %s from the launch's arguments: it changes the model provider, web search or other settings the session sets for Codex",
		accesskey.ShownName(flag, false))
}
