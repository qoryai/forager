package session

import (
	"slices"

	"github.com/qoryai/forager/session/runtimes"
)

// configArgs is args, a launch's arguments, with the settings of rt's config before
// them, for a runtime that reads its settings as TOML, such as Codex: config.flag and
// key=value for each of config.fixed and, in a run whose start key's endpoint is a
// setting of rt, the key's endpoint in that setting, sorted by key
// ([runtimes.ConfigArgs]). The pairs go right after the command, where a program reads
// them before any subcommand, so codex --config k=v exec --json applies them to the
// session; a pair of the same key later in args overrides one of them in Codex. args
// as they are for a runtime without config.
func configArgs(rt runtimes.Runtime, key keyed, args []string) ([]string, error) {
	c, ok := rt.(runtimes.Configs)
	if !ok {
		return args, nil
	}
	config, ok := c.Config()
	if !ok {
		return args, nil
	}
	var set map[string]any
	if key.Setting != "" {
		set = map[string]any{key.Setting: key.URL}
	}
	pairs, err := runtimes.ConfigArgs(config, set)
	if err != nil {
		return nil, err
	}
	return slices.Concat(pairs, args), nil
}
