package policy_test

import (
	"strings"
	"testing"

	"github.com/qoryai/forager/policy"
)

// TestASegmentOfBracesMatchesOneSegment pins {}: one segment that is not empty, in any
// place, the last included, and before a final * whose prefix follows it. Matching
// stays exact and case-sensitive.
func TestASegmentOfBracesMatchesOneSegment(t *testing.T) {
	for _, c := range []struct {
		pattern, path string
		want          bool
	}{
		{"/repos/o/r/pulls/{}", "/repos/o/r/pulls/12", true},
		{"/repos/o/r/pulls/{}", "/repos/o/r/pulls/12/merge", false},
		{"/repos/o/r/pulls/{}", "/repos/o/r/pulls/", false},
		{"/repos/o/r/pulls/{}", "/repos/o/r/pulls", false},
		{"/repos/{}/r/pulls", "/repos/o/r/pulls", true},
		{"/repos/{}/r/pulls", "/repos/o/x/r/pulls", false},
		{"/repos/{}/r/pulls", "/repos//r/pulls", false},
		{"/repos/{}/{}/pulls", "/repos/o/r/pulls", true},
		{"/repos/o/r/pulls/{}/files*", "/repos/o/r/pulls/12/files", true},
		{"/repos/o/r/pulls/{}/files*", "/repos/o/r/pulls/12/files/a/b", true},
		{"/repos/o/r/pulls/{}/files*", "/repos/o/r/pulls/12/merge", false},
		{"/repos/o/r/pulls/{}/f*", "/repos/o/r/pulls/12/files", true},
		{"/repos/o/r/pulls/{}*", "/repos/o/r/pulls/12/merge", true},
		{"/repos/o/r/pulls/{}*", "/repos/o/r/pulls/", false},
		{"/repos/o/r/pulls/{}", "/repos/O/r/pulls/12", false},
	} {
		_, got := policy.MatchPath([]string{c.pattern}, c.path)
		if got != c.want {
			t.Errorf("%s matches %s: %v; want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// TestAStrayBraceIsRefused pins the grammar: { and } only as a whole segment {}, and a
// pattern that holds one elsewhere matches nothing.
func TestAStrayBraceIsRefused(t *testing.T) {
	for _, p := range []string{"/a/{}", "/{}", "/a/{}/b*", "/a/{}*", "/a/*", "/a/b", "/"} {
		if !policy.ValidPath(p) {
			t.Errorf("%s refused; want it valid", p)
		}
	}
	for _, p := range []string{"/a/{", "/a/}", "/a/{x}", "/a/x{}", "/a/{}x", "/a/{{}}", "/a/{}/b{", "a/{}", "/a/*/b", "/a?b", "/a b"} {
		if policy.ValidPath(p) {
			t.Errorf("%s valid; want it refused", p)
		}
		if _, ok := policy.MatchPath([]string{p}, strings.ReplaceAll(p, "*", "")); ok && strings.ContainsAny(p, "{}") {
			t.Errorf("%s matched; want a refused pattern to match nothing", p)
		}
	}
	doc := `{"version": 1, "egress": {"mode": "enforce", "allow": ["git.example"], "paths": {"git.example": ["/repos/{x}/app"]}}}`
	if _, err := policy.Parse("policy.json", []byte(doc)); err == nil {
		t.Error("a policy with /repos/{x}/app parsed; want it refused")
	}
	doc = `{"version": 1, "egress": {"mode": "enforce", "allow": ["git.example"], "paths": {"git.example": ["/repos/{}/app", "/repos/o/{}/pulls/{}*"]}}}`
	if _, err := policy.Parse("policy.json", []byte(doc)); err != nil {
		t.Errorf("a policy with {} segments: %v; want it parsed", err)
	}
}

// TestCoversPathWithBraces pins which pattern covers another with {}: a case that
// cannot be shown is not covered.
func TestCoversPathWithBraces(t *testing.T) {
	for _, c := range []struct {
		entry, other string
		want         bool
	}{
		{"/a/{}", "/a/{}", true},
		{"/a/{}", "/a/x", true},
		{"/a/{}", "/a/", false},
		{"/a/{}", "/a/x/y", false},
		{"/a/{}", "/a/*", false},
		{"/a/{}", "/a/x*", false},
		{"/a/x", "/a/{}", false},
		{"/a/*", "/a/{}", true},
		{"/a/*", "/a/{}/b*", true},
		{"/a/x*", "/a/{}", false},
		{"/a/{}*", "/a/x/y", true},
		{"/a/{}*", "/a/{}/b", true},
		{"/a/{}*", "/a/*", false},
		{"/a/{}*", "/a/x*", true},
		{"/a/{}/b*", "/a/x/bc", true},
		{"/a/{}/b*", "/a/{}/b/c*", true},
		{"/a/{}/b*", "/a/{}/c", false},
		{"/a/{}/b", "/a/{}/b*", false},
	} {
		if got := policy.CoversPath(c.entry, c.other); got != c.want {
			t.Errorf("%s covers %s: %v; want %v", c.entry, c.other, got, c.want)
		}
	}
}

// TestOverlapPathsWithBraces pins which two patterns one path can match both of: {}
// against {}, against an exact segment and against a prefix; a case that cannot be
// told apart counts as an overlap.
func TestOverlapPathsWithBraces(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"/a/{}", "/a/{}", true},
		{"/a/{}", "/a/x", true},
		{"/a/{}", "/a/", false},
		{"/a/{}", "/a/x/y", false},
		{"/a/{}", "/b/{}", false},
		{"/a/{}/merge", "/a/{}/files", false},
		{"/a/{}/merge", "/a/x/{}", true},
		{"/a/{}", "/a/*", true},
		{"/a/{}", "/a/x*", true},
		{"/a/{}", "/b*", false},
		{"/a/{}/b*", "/a/x/bc", true},
		{"/a/{}/b*", "/a/x/c", false},
		{"/a/{}*", "/a/x", true},
		{"/a/{}*", "/a/", false},
		{"/a/{}*", "/b/*", false},
		{"/a/{}", "/a/{", true},
	} {
		if got := policy.OverlapPaths(c.a, c.b); got != c.want {
			t.Errorf("%s overlaps %s: %v; want %v", c.a, c.b, got, c.want)
		}
		if got := policy.OverlapPaths(c.b, c.a); got != c.want {
			t.Errorf("%s overlaps %s: %v; want %v", c.b, c.a, got, c.want)
		}
	}
}
