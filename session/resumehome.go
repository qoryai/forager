package session

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// sessionResume is the resume of one session's runtime, with the descriptor's
// resume.home_var resolved: Prefix and Path start with ~/ or /. For a descriptor with
// home_var, ${<home_var>} is replaced by the variable's value in the launch's
// environment, an absolute path, so the rest of the session reads them as an absolute
// prefix and path.
type sessionResume struct {
	runtimes.Resume
	// prefix is the descriptor's resume.prefix as written, such as
	// ${CODEX_HOME}/sessions/, for a line.
	prefix string
	// tail is the descriptor's resume.prefix after ${<home_var>}/, such as sessions/;
	// empty for a descriptor without home_var.
	tail string
	// unset, when set, is why the runtime starts without a resume: home_var is unset,
	// empty or no absolute path with no . or .. name in the launch's environment.
	unset *wall.Unbound
}

// resumeOf is the resume of rt for a session whose launch's environment is env, the
// one the runtime gets; nil for a runtime without resume. A descriptor's home_var is
// read from env: the last value of the name counts, as in the environment the runtime
// gets. A value that is not set, is empty, is no absolute path in its shortest form
// ([path.Clean]), has a . or .. name, a space, a character that is not printable, a *,
// a $, a {, a }, a comma or a double quote, or is no UTF-8, leaves the resume with
// unset. The wall's bind of the transcript directory takes no comma or double quote.
func resumeOf(rt runtimes.Runtime, env []string) *sessionResume {
	resumes, ok := rt.(runtimes.Resumes)
	if !ok {
		return nil
	}
	rs, ok := resumes.Resume()
	if !ok {
		return nil
	}
	s := &sessionResume{Resume: rs, prefix: rs.Prefix}
	if rs.HomeVar == "" {
		return s
	}
	lead := "${" + rs.HomeVar + "}/"
	s.tail = strings.TrimPrefix(rs.Prefix, lead)
	value, set := lookupEnv(env, rs.HomeVar)
	if cause := homeFault(rs.HomeVar, value, set); cause != "" {
		s.unset = &wall.Unbound{
			Fix:   fmt.Sprintf("Set %s to an absolute path in UTF-8 in the launch's environment, with no . or .. name, no // or / at its end, and no space, non-printable character, *, $, {, }, comma or double quote", rs.HomeVar),
			Cause: fmt.Sprintf("%s, so resume.prefix %s has no value", cause, rs.Prefix),
		}
		return s
	}
	home := strings.TrimSuffix(value, "/") + "/"
	s.Prefix = home + s.tail
	s.Path = home + strings.TrimPrefix(rs.Path, lead)
	return s
}

// lookupEnv is the last value of name in env, and whether env has it.
func lookupEnv(env []string, name string) (string, bool) {
	for _, kv := range slices.Backward(env) {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// homeFault is what is wrong with value, the value of the home variable name, set
// false when the environment does not have it, as the start of a cause; empty when
// value is an absolute path the session reads the transcript below.
func homeFault(name, value string, set bool) string {
	switch {
	case !set:
		return name + " is not set"
	case value == "":
		return name + " is empty"
	case !strings.HasPrefix(value, "/") || path.Clean(value) != value || !utf8.ValidString(value) ||
		strings.ContainsAny(value, "*${},\"") || strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }):
		// The value is the launch's: at most its first 256 bytes, quoted, so no newline in
		// it starts another line.
		return fmt.Sprintf("%s is %q", name, value[:min(len(value), 256)])
	}
	return ""
}

// moved is p, the run configuration's resume.path, at the same names below this
// session's resolved resume.prefix, and true; for a descriptor with home_var, p is the
// transcript's path in the paused run, absolute, below that run's value of the
// variable, which may differ from this session's. The names below the prefix are as
// many as those of resume.path below it, since neither a * nor a replaced value
// matches a /. p must be absolute, with no empty, . or .. name, and have tail's names
// right above them. A descriptor without home_var leaves p as it is.
func (s *sessionResume) moved(p string) (string, bool) {
	if s.HomeVar == "" {
		return p, true
	}
	rel, ok := strings.CutPrefix(p, "/")
	if !ok || dotted(rel) {
		return "", false
	}
	n := strings.Count(strings.TrimPrefix(s.Path, s.Prefix), "/") + 1
	var tail []string
	if t := strings.TrimSuffix(s.tail, "/"); t != "" {
		tail = strings.Split(t, "/")
	}
	names := strings.Split(rel, "/")
	if len(names) < n+len(tail) || !slices.Equal(names[len(names)-n-len(tail):len(names)-n], tail) {
		return "", false
	}
	return s.Prefix + strings.Join(names[len(names)-n:], "/"), true
}
