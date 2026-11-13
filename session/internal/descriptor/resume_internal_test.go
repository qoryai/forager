package descriptor

import (
	"strings"
	"testing"
)

// TestTheResumeCheckRefusesAnyOtherVariable pins the Go check of resume apart from the
// schema: a $ outside the leading ${<home_var>}/ of resume.prefix or resume.path, with
// home_var or without it, and a prefix or path that does not start with it when
// home_var is set, each return an error that starts with the fix.
func TestTheResumeCheckRefusesAnyOtherVariable(t *testing.T) {
	for name, r := range map[string]Resume{
		"no home_var":            {Prefix: "${OTHER}/s/", Path: "${OTHER}/s/{session_id}.jsonl"},
		"a second variable":      {HomeVar: "AMP_HOME", Prefix: "${AMP_HOME}/s/", Path: "${AMP_HOME}/s/${OTHER}/{session_id}.jsonl"},
		"another variable":       {HomeVar: "AMP_HOME", Prefix: "${OTHER}/s/", Path: "${OTHER}/s/{session_id}.jsonl"},
		"a home path":            {HomeVar: "AMP_HOME", Prefix: "~/.amp/", Path: "~/.amp/{session_id}.jsonl"},
		"an absolute $ path":     {Prefix: "/var/$x/", Path: "/var/$x/{session_id}.jsonl"},
		"a $ after the home_var": {HomeVar: "AMP_HOME", Prefix: "${AMP_HOME}/$x/", Path: "${AMP_HOME}/$x/{session_id}.jsonl"},
	} {
		err := r.check()
		if err == nil || !(strings.HasPrefix(err.Error(), "resume: remove the $ from ") || strings.HasPrefix(err.Error(), "resume: start ")) {
			t.Errorf("%s: %v; want an error that starts with the fix", name, err)
		}
	}
	ok := Resume{HomeVar: "AMP_HOME", Prefix: "${AMP_HOME}/s/", Path: "${AMP_HOME}/s/*/{session_id}.jsonl"}
	if err := ok.check(); err != nil {
		t.Errorf("%+v: %v", ok, err)
	}
}

// TestTheResumeCheckRefusesAPlaceItCannotUse pins the Go check of resume.place apart
// from the schema: another place, and before_last without after, each return an error
// that starts with the fix.
func TestTheResumeCheckRefusesAPlaceItCannotUse(t *testing.T) {
	base := Resume{Prefix: "~/.amp/", Path: "~/.amp/{session_id}.jsonl", Args: []string{"resume", "{session_id}"}}
	for want, r := range map[string]Resume{
		`resume: set place to before_last or leave it out: "after_first" is no place`:                  {Prefix: base.Prefix, Path: base.Path, After: "exec", Place: "after_first"},
		"resume: set after with place before_last: the arguments go before the last argument after it": {Prefix: base.Prefix, Path: base.Path, Place: PlaceBeforeLast},
	} {
		if err := r.check(); err == nil || err.Error() != want {
			t.Errorf("%+v: %v; want %s", r, err, want)
		}
	}
	ok := base
	ok.After, ok.Place = "exec", PlaceBeforeLast
	if err := ok.check(); err != nil {
		t.Errorf("%+v: %v", ok, err)
	}
}
