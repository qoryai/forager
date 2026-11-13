// Package codex is Codex as a runtime of Forager: the contract's descriptor for it, and
// the check of its launch arguments. Codex takes no hook: the session reads its
// standard output and passes the descriptor's config as --config pairs. A launch whose
// arguments change those settings, or the other settings below, through a flag of
// Codex's is refused.
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
	flagConfig        = "--config"
	flagShort         = "-c"
	flagOSS           = "--oss"
	flagLocalProvider = "--local-provider"
	flagProfile       = "--profile"
	flagProfileShort  = "-p"
	flagSearch        = "--search"
	flagEnable        = "--enable"
	flagDisable       = "--disable"
)

// reserved are the settings of Codex 0.167.2 a launch's pair may not set beside the
// session's: every setting of the model providers, since a provider's other settings,
// such as supports_websockets or http_headers, change where and how Codex sends the
// requests; profile and profiles, which put a profile's settings over the session's;
// and the addresses of OpenAI and ChatGPT that no setting of the provider covers
// (codex-rs config/src/config_toml.rs). A pattern's * matches one or more characters
// other than a dot.
var reserved = []string{
	"model_providers",
	"profile",
	"profiles",
	"openai_base_url",
	"chatgpt_base_url",
	"experimental_realtime_*_base_url",
}

// connectors is the legacy name of the feature apps: Codex 0.167.2 reads
// features.connectors as features.apps, after apps, so connectors wins
// (codex-rs features/src/legacy.rs).
const (
	connectors = "features.connectors"
	apps       = "features.apps"
)

// checkArgs returns an error, up to an argument --, for each flag of Codex 0.167.2
// that changes one of keys, the settings the session passes, or a setting of
// [reserved]:
//   - --config or -c with a pair that sets one, as --config k=v, --config=k=v, -c k=v,
//     -ck=v or -c=k=v, where features.connectors counts as features.apps;
//   - --enable or --disable of a feature whose features.<name> is one of keys, as
//     --enable x or --enable=x, where connectors counts as apps;
//   - --oss and --search;
//   - --local-provider, --profile and -p in every form: --profile x, --profile=x,
//     -p x, -px and -p=x.
//
// The error contains the flag and never the argument's value.
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
		case a == flagConfig || a == flagShort:
			if err := checkPair(a, value(), keys); err != nil {
				return err
			}
		case strings.HasPrefix(a, flagConfig+"="):
			if err := checkPair(flagConfig, strings.TrimPrefix(a, flagConfig+"="), keys); err != nil {
				return err
			}
		case strings.HasPrefix(a, flagShort):
			if err := checkPair(flagShort, strings.TrimPrefix(strings.TrimPrefix(a, flagShort), "="), keys); err != nil {
				return err
			}
		case a == flagEnable || a == flagDisable || strings.HasPrefix(a, flagEnable+"=") || strings.HasPrefix(a, flagDisable+"="):
			flag, feature, attached := strings.Cut(a, "=")
			if !attached {
				feature = value()
			}
			if k, ok := runtimes.SessionKey(canonical("features."+feature), keys); ok {
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

// checkPair returns an error when pair, the value of flag, sets one of keys or a
// setting of [reserved].
func checkPair(flag, pair string, keys []string) error {
	key := canonical(runtimes.PairKey(pair))
	if k, ok := runtimes.SessionKey(key, keys); ok {
		return keyRefused(flag, k)
	}
	for _, r := range reserved {
		if covers(r, key) {
			return keyRefused(flag, r)
		}
	}
	return nil
}

// canonical is key without the spaces around it, with features.connectors, or a key
// under it, as the same key under features.apps.
func canonical(key string) string {
	key = strings.TrimSpace(key)
	if key == connectors || strings.HasPrefix(key, connectors+".") {
		return apps + strings.TrimPrefix(key, connectors)
	}
	return key
}

// covers reports whether a pair of key sets the setting r: key is r, a key under it or
// a key it is under, comparing a * of r with one dotless part of one or more
// characters of key.
func covers(r, key string) bool {
	rs, ks := strings.Split(r, "."), strings.Split(key, ".")
	for i := range min(len(rs), len(ks)) {
		if !part(rs[i], ks[i]) {
			return false
		}
	}
	return true
}

// part reports whether the part of a key equals the part p of a setting, where a * in
// p matches one or more characters.
func part(p, k string) bool {
	before, after, star := strings.Cut(p, "*")
	if !star {
		return p == k
	}
	return len(k) > len(before)+len(after) && strings.HasPrefix(k, before) && strings.HasSuffix(k, after)
}

// keyRefused is the error for flag with a pair that sets k.
func keyRefused(flag, k string) error {
	return fmt.Errorf("remove the %s that sets %s from the launch's arguments: the session sets it for Codex, or Codex reads it to choose where its requests go",
		accesskey.ShownName(flag, false), accesskey.ShownName(k, false))
}

// flagRefused is the error for a flag that changes the model provider, web search or
// the settings as a whole.
func flagRefused(flag string) error {
	return fmt.Errorf("remove %s from the launch's arguments: it changes the model provider, web search or other settings the session sets for Codex",
		accesskey.ShownName(flag, false))
}
