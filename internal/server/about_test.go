package server_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/qoryai/runner/internal/server"
)

// fullAbout is an About at its bounds: every member set, a kind of 64 bytes and titles
// of 256 bytes in two-byte characters, sixteen subjects, a URL of 2048 bytes, and
// details 4 levels deep with a key of 64 bytes.
func fullAbout() *server.About {
	a := &server.About{
		Kind:  strings.Repeat("k", 64),
		Title: strings.Repeat("é", 128),
		Details: json.RawMessage(`{"a": [1, {"b": {"` + strings.Repeat("c", 64) +
			`": "x"}}], "n": null}`),
	}
	for i := range 16 {
		a.Subjects = append(a.Subjects, server.Subject{Type: "example", Ref: fmt.Sprint(i)})
	}
	a.Subjects[0] = server.Subject{
		Type:  "pull request",
		Ref:   strings.Repeat("r", 256),
		URL:   "https://example.com/" + strings.Repeat("u", 2048-len("https://example.com/")),
		Title: strings.Repeat("é", 128),
	}
	a.Subjects[1].Type = "example.other_name-2"
	return a
}

// TestCheckAboutPassesWhatTheContractAccepts pins that nil, an About of empty members,
// a title alone and an About at every bound pass.
func TestCheckAboutPassesWhatTheContractAccepts(t *testing.T) {
	for name, a := range map[string]*server.About{
		"nil":                   nil,
		"empty":                 {},
		"empty details":         {Details: json.RawMessage(" {} ")},
		"a title alone":         {Title: "Fix the failing build"},
		"every member at bound": fullAbout(),
	} {
		if err := server.CheckAbout(a); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := server.CheckAbout(nil); err != nil {
		t.Errorf("nil gives %#v, not a nil error", err)
	}
}

// TestCheckAboutRefusesWithTheField pins each refusal's message, the field and the
// reason, word for word, at least once per reason.
func TestCheckAboutRefusesWithTheField(t *testing.T) {
	deep := `{"a": {"b": [{"c": {"d": 1}}]}}`
	type refusal struct {
		name   string
		change func(*server.About)
		want   string
	}
	var cases []refusal
	add := func(name, want string, change func(*server.About)) {
		cases = append(cases, refusal{name, change, want})
	}
	add("a kind of 65 bytes", "about.kind is longer than 64 bytes",
		func(a *server.About) { a.Kind += "k" })
	add("a kind not UTF-8", "about.kind is not UTF-8",
		func(a *server.About) { a.Kind = "k\xff" })
	add("a kind with a control character", "about.kind contains a control character",
		func(a *server.About) { a.Kind = "k\x1b" })
	add("a title of 257 bytes in 129 characters", "about.title is longer than 256 bytes",
		func(a *server.About) { a.Title += "t" })
	add("a title not UTF-8", "about.title is not UTF-8",
		func(a *server.About) { a.Title = "\xc3" })
	add("a title with DEL", "about.title contains a control character",
		func(a *server.About) { a.Title = "a\x7f" })
	add("a title with U+0085", "about.title contains a control character",
		func(a *server.About) { a.Title = "a\u0085" })
	add("a title with U+2028", "about.title contains a control character",
		func(a *server.About) { a.Title = "a b" })
	add("a title with U+2029", "about.title contains a control character",
		func(a *server.About) { a.Title = "a b" })
	add("17 subjects", "about.subjects has 17 entries; a run carries at most 16",
		func(a *server.About) {
			a.Subjects = append(a.Subjects, server.Subject{Type: "x", Ref: "17"})
		})
	add("a type of 65 bytes", "about.subjects[2].type is longer than 64 bytes",
		func(a *server.About) { a.Subjects[2].Type = strings.Repeat("e", 65) })
	typeWords := "is not words of a-z and 0-9, each joined to the next by one space, " +
		"underscore, dot or dash"
	for name, typ := range map[string]string{
		"an empty type": "", "a double space": "example  other", "a leading dash": "-example",
		"a trailing dot": "example.", "upper case": "Example", "a slash": "example/other",
	} {
		add(name, "about.subjects[3].type "+typeWords,
			func(a *server.About) { a.Subjects[3].Type = typ })
	}
	add("an empty ref", "about.subjects[4].ref is empty",
		func(a *server.About) { a.Subjects[4].Ref = "" })
	add("a ref of 257 bytes", "about.subjects[0].ref is longer than 256 bytes",
		func(a *server.About) { a.Subjects[0].Ref += "r" })
	add("a ref not UTF-8", "about.subjects[4].ref is not UTF-8",
		func(a *server.About) { a.Subjects[4].Ref = "\xff" })
	add("a ref with a line feed", "about.subjects[4].ref contains a control character",
		func(a *server.About) { a.Subjects[4].Ref = "a\nb" })
	add("a URL of 2049 bytes", "about.subjects[0].url is longer than 2048 bytes",
		func(a *server.About) { a.Subjects[0].URL += "u" })
	for name, u := range map[string]string{
		"ftp": "ftp://example.com/7", "relative": "/examples/7", "no host": "https:///7",
		"upper-case scheme": "HTTPS://example.com/7", "no scheme": "example.com/7",
		"a space in the host": "https://exa mple.com/",
	} {
		add("a URL, "+name, "about.subjects[5].url is not an absolute http or https URL",
			func(a *server.About) { a.Subjects[5].URL = u })
	}
	add("a subject title of 257 bytes", "about.subjects[0].title is longer than 256 bytes",
		func(a *server.About) { a.Subjects[0].Title += "t" })
	add("a subject title with a tab", "about.subjects[6].title contains a control character",
		func(a *server.About) { a.Subjects[6].Title = "a\tb" })
	add("a subject title not UTF-8", "about.subjects[6].title is not UTF-8",
		func(a *server.About) { a.Subjects[6].Title = "\xff" })
	add("the same type and ref twice",
		"about.subjects[9] has the same type and ref as about.subjects[7]",
		func(a *server.About) {
			a.Subjects[7] = server.Subject{Type: "example", Ref: "7", URL: "https://qory.example/7"}
			a.Subjects[9] = server.Subject{Type: "example", Ref: "7", Title: "Another"}
		})
	notObject := "about.details is not a JSON object"
	for name, d := range map[string]string{
		"an array": `["example"]`, "a string": `"example"`, "null": `null`, "not JSON": `{`,
		"two values": `{} {}`, "whitespace": `  `, "a member name twice": `{"a": 1, "a": 2}`,
		"invalid UTF-8": "{\"a\": \"\xff\"}",
	} {
		add("details, "+name, notObject,
			func(a *server.About) { a.Details = json.RawMessage(d) })
	}
	add("details of 8193 bytes compacted",
		"about.details is 8193 bytes compacted; at most 8192",
		func(a *server.About) {
			n := strings.Repeat("n", 8193-len(`{"n":""}`))
			a.Details = json.RawMessage(`{ "n" : "` + n + `" }`)
		})
	add("details 5 levels deep", "about.details nests deeper than 4 levels",
		func(a *server.About) { a.Details = json.RawMessage(deep) })
	add("a details key of 65 bytes",
		"about.details has a key that is empty or longer than 64 bytes",
		func(a *server.About) {
			a.Details = json.RawMessage(`{"` + strings.Repeat("k", 65) + `": 1}`)
		})
	add("an empty details key",
		"about.details has a key that is empty or longer than 64 bytes",
		func(a *server.About) { a.Details = json.RawMessage(`{"a": {"": 1}}`) })
	add("a details string with an escaped control character",
		"about.details has a key or a string that is not UTF-8 or contains a control character",
		func(a *server.About) { a.Details = json.RawMessage(`{"a": ["\u0007"]}`) })
	add("a details key with U+2028",
		"about.details has a key or a string that is not UTF-8 or contains a control character",
		func(a *server.About) { a.Details = json.RawMessage("{\"a \": 1}") })
	for _, c := range cases {
		a := fullAbout()
		c.change(a)
		err := server.CheckAbout(a)
		var ae *server.AboutError
		if !errors.As(err, &ae) {
			t.Errorf("%s: %v; want an *AboutError", c.name, err)
			continue
		}
		if err.Error() != c.want || ae.Field+" "+ae.Reason != c.want {
			t.Errorf("%s: %q; want %q", c.name, err, c.want)
		}
	}
}

// TestCheckAboutReportsTheFirstFailure pins the order of the checks: the kind before the
// title, the title before the subjects, a subject's own members before the rule on
// type and ref, the subjects before details; and within details the object before the
// size, the size before the depth, the depth before a key, a key before a string.
func TestCheckAboutReportsTheFirstFailure(t *testing.T) {
	big := strings.Repeat("n", 9000)
	for _, c := range []struct {
		about *server.About
		want  string
	}{
		{&server.About{Kind: strings.Repeat("k", 65) + "\x00", Title: "\x00"},
			"about.kind is longer than 64 bytes"},
		{&server.About{Title: "\x00", Subjects: []server.Subject{{}}},
			"about.title contains a control character"},
		{&server.About{Subjects: []server.Subject{
			{Type: "a", Ref: "1"}, {Type: "a", Ref: "1", URL: "ftp://x"}}},
			"about.subjects[1].url is not an absolute http or https URL"},
		{&server.About{Subjects: []server.Subject{{Type: "A"}}, Details: json.RawMessage(`[]`)},
			"about.subjects[0].type is not words of a-z and 0-9, each joined to the next " +
				"by one space, underscore, dot or dash"},
		{&server.About{Details: json.RawMessage(`{"a":{"b":{"c":{"d":{"": "` + big + `"}}}}}`)},
			"about.details is 9031 bytes compacted; at most 8192"},
		{&server.About{Details: json.RawMessage(`{"a":{"b":{"c":{"d":{"": "\u0000"}}}}}`)},
			"about.details nests deeper than 4 levels"},
		{&server.About{Details: json.RawMessage(`{"a":{"": "\u0000"}}`)},
			"about.details has a key that is empty or longer than 64 bytes"},
	} {
		if err := server.CheckAbout(c.about); err == nil || err.Error() != c.want {
			t.Errorf("%v; want %q", err, c.want)
		}
	}
}

// TestReportedAboutIsCompacted pins what run.started reports of an About: nothing for
// an empty one, details compacted, empty details left out, and a copy of the subjects.
func TestReportedAboutIsCompacted(t *testing.T) {
	for _, a := range []*server.About{nil, {}, {Details: json.RawMessage("\n{ }\n")}} {
		if got := server.ReportedAbout(a); got != nil || !a.Empty() {
			t.Errorf("%+v reported as %+v", a, got)
		}
	}
	a := &server.About{Title: "t", Subjects: []server.Subject{{Type: "example", Ref: "7"}},
		Details: json.RawMessage(`{ "a" : [ 1 , { "b" : "c" } ] }`)}
	got := server.ReportedAbout(a)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"title":"t","subjects":[{"type":"example","ref":"7"}],` +
		`"details":{"a":[1,{"b":"c"}]}}`
	if string(b) != want {
		t.Errorf("reported %s; want %s", b, want)
	}
	got.Subjects[0].Ref = "8"
	if a.Subjects[0].Ref != "7" {
		t.Error("the report shares the caller's subjects")
	}
	got = server.ReportedAbout(&server.About{Kind: "k", Details: json.RawMessage(" {} ")})
	if got == nil || got.Details != nil {
		t.Errorf("empty details reported as %+v", got)
	}
}
