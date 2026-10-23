package server

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/qoryai/forager/accesskey"
)

// About is what a run is about, as the caller passed it: dev.qory.run.started reports
// it as about, and no other event, request or policy contains it. Every member is
// optional.
type About struct {
	// Kind is the kind of run, the caller's word, at most 64 bytes.
	Kind string `json:"kind,omitempty"`
	// Title is the run's title, at most 256 bytes.
	Title string `json:"title,omitempty"`
	// Subjects are what the run works on, at most 16, no two with the same Type and Ref.
	Subjects []Subject `json:"subjects,omitempty"`
	// Details is a JSON object of the caller's, at most 8192 bytes as the event contains
	// it, compacted with <, > and & escaped, and nested at most 4 levels deep. It is
	// shown to every reader of the run, so it never holds a secret. An empty object is
	// the same as none.
	Details json.RawMessage `json:"details,omitempty"`
}

// Subject is one thing a run works on, identified by its Type and Ref.
type Subject struct {
	// Type is an open name the caller chooses: words of a-z and 0-9, each joined to the
	// next by one space, underscore, dot or dash, at most 64 bytes.
	Type string `json:"type"`
	// Ref is the subject's reference, 1 to 256 bytes.
	Ref string `json:"ref"`
	// URL is where the subject is shown, an absolute http or https URL of at most 2048
	// bytes with no control character and no user name or password; empty means none.
	URL string `json:"url,omitempty"`
	// Title is the subject's title, at most 256 bytes; empty means none.
	Title string `json:"title,omitempty"`
}

// AboutError is why [CheckAbout] refuses an About: the Field, such as about.title or
// about.subjects[0].ref, and the Reason.
type AboutError struct {
	Field, Reason string
}

func (e *AboutError) Error() string { return e.Field + " " + e.Reason }

// Empty reports whether a is nil or every member of it is empty, Details an empty
// object included. run.started leaves out an empty About.
func (a *About) Empty() bool {
	return a == nil || a.Kind == "" && a.Title == "" && len(a.Subjects) == 0 &&
		detailsAbsent(a.Details)
}

// The bounds of an About: lengths in bytes, the subjects in entries, the depth in levels.
const (
	maxAboutKind    = 64
	maxAboutTitle   = 256
	maxSubjects     = 16
	maxSubjectType  = 64
	maxSubjectRef   = 256
	maxSubjectURL   = 2048
	maxDetails      = 8192
	maxDetailsDepth = 4
	maxDetailsKey   = 64
)

// subjectTypeWords is the reason a subject type outside its form is refused for.
const subjectTypeWords = "is not words of a-z and 0-9, each joined to the next by one " +
	"space, underscore, dot or dash"

// subjectTypeShape is a subject type's form.
var subjectTypeShape = regexp.MustCompile(`^[a-z0-9]+([ _.-][a-z0-9]+)*$`)

// CheckAbout refuses an About the contract's rules refuse, the byte limits, the size of
// Details as the event contains them and the rule that no two subjects have the same
// type and ref among them, and returns the first failure as an [*AboutError]. A nil
// About passes.
func CheckAbout(a *About) error {
	if err := checkAbout(a); err != nil {
		return err
	}
	return nil
}

func checkAbout(a *About) *AboutError {
	if a == nil {
		return nil
	}
	if a.Kind != "" {
		if err := checkText("about.kind", a.Kind, maxAboutKind); err != nil {
			return err
		}
	}
	if a.Title != "" {
		if err := checkText("about.title", a.Title, maxAboutTitle); err != nil {
			return err
		}
	}
	if n := len(a.Subjects); n > maxSubjects {
		return &AboutError{"about.subjects",
			fmt.Sprintf("has %d entries; a run carries at most %d", n, maxSubjects)}
	}
	for j, s := range a.Subjects {
		at := fmt.Sprintf("about.subjects[%d]", j)
		switch {
		case len(s.Type) > maxSubjectType:
			return &AboutError{at + ".type", longer(maxSubjectType)}
		case !subjectTypeShape.MatchString(s.Type):
			return &AboutError{at + ".type", subjectTypeWords}
		}
		if s.Ref == "" {
			return &AboutError{at + ".ref", "is empty"}
		}
		if err := checkText(at+".ref", s.Ref, maxSubjectRef); err != nil {
			return err
		}
		if s.URL != "" {
			if len(s.URL) > maxSubjectURL {
				return &AboutError{at + ".url", longer(maxSubjectURL)}
			}
			if strings.ContainsFunc(s.URL, control) {
				return &AboutError{at + ".url", "contains a control character"}
			}
			u := webURL(s.URL)
			if u == nil {
				return &AboutError{at + ".url", "is not an absolute http or https URL"}
			}
			if u.User != nil {
				return &AboutError{at + ".url", "contains a user name or password"}
			}
		}
		if s.Title != "" {
			if err := checkText(at+".title", s.Title, maxAboutTitle); err != nil {
				return err
			}
		}
		for i, earlier := range a.Subjects[:j] {
			if earlier.Type == s.Type && earlier.Ref == s.Ref {
				return &AboutError{at,
					fmt.Sprintf("has the same type and ref as about.subjects[%d]", i)}
			}
		}
	}
	if !detailsAbsent(a.Details) {
		if reason := checkDetails(a.Details); reason != "" {
			return &AboutError{"about.details", reason}
		}
	}
	return nil
}

// checkText checks a string of an About: at most limit bytes, UTF-8, and no control
// character.
func checkText(field, s string, limit int) *AboutError {
	switch {
	case len(s) > limit:
		return &AboutError{field, longer(limit)}
	case !utf8.ValidString(s):
		return &AboutError{field, "is not UTF-8"}
	case strings.ContainsFunc(s, control):
		return &AboutError{field, "contains a control character"}
	}
	return nil
}

func longer(limit int) string { return fmt.Sprintf("is longer than %d bytes", limit) }

// control reports a control character as an About counts them: U+0000 to U+001F,
// U+007F to U+009F, and the line and paragraph separators U+2028 and U+2029.
func control(r rune) bool {
	return r <= 0x1f || r >= 0x7f && r <= 0x9f || r == 0x2028 || r == 0x2029
}

// webURL parses s as an absolute http or https URL with a host, or returns nil. The
// scheme is matched as written, in lower case, as the contract's schema matches it.
func webURL(s string) *url.URL {
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Scheme != "http" && u.Scheme != "https" ||
		u.Host == "" {
		return nil
	}
	return u
}

// detailsAbsent reports Details that are none: empty, or an empty object.
func detailsAbsent(d json.RawMessage) bool {
	if len(d) == 0 {
		return true
	}
	var compact bytes.Buffer
	return json.Compact(&compact, d) == nil && compact.String() == "{}"
}

// checkDetails returns why Details are refused, or nothing. They are read strictly,
// so a member name twice and invalid UTF-8 are no JSON object.
func checkDetails(d json.RawMessage) string {
	t := bytes.Trim(d, " \t\r\n")
	if !jsontext.Value(t).IsValid() || t[0] != '{' {
		return "is not a JSON object"
	}
	reported, err := eventDetails(t)
	if err != nil {
		return "is not a JSON object"
	}
	if n := len(reported); n > maxDetails {
		return fmt.Sprintf("is %d bytes compacted; at most %d", n, maxDetails)
	}
	depth, badKey, badString := 0, false, false
	dec := jsontext.NewDecoder(bytes.NewReader(t))
	for {
		kind, n := dec.StackIndex(dec.StackDepth())
		name := kind == '{' && n%2 == 0
		tok, err := dec.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "is not a JSON object"
		}
		switch tok.Kind() {
		case '{', '[':
			depth = max(depth, dec.StackDepth())
		case '"':
			s := tok.String()
			if name && (s == "" || len(s) > maxDetailsKey) {
				badKey = true
			}
			if !utf8.ValidString(s) || strings.ContainsFunc(s, control) {
				badString = true
			}
		}
	}
	switch {
	case depth > maxDetailsDepth:
		return fmt.Sprintf("nests deeper than %d levels", maxDetailsDepth)
	case badKey:
		return fmt.Sprintf("has a key that is empty or longer than %d bytes", maxDetailsKey)
	case badString:
		return "has a key or a string that is not UTF-8 or contains a control character"
	}
	return ""
}

// eventDetails are Details as an event contains them: compacted, with <, > and &
// written as \u003c, \u003e and \u0026, as encoding/json writes every event. Their size
// is the one the contract bounds, and encoding them again changes nothing.
func eventDetails(d json.RawMessage) ([]byte, error) {
	var compact, escaped bytes.Buffer
	if err := json.Compact(&compact, d); err != nil {
		return nil, err
	}
	json.HTMLEscape(&escaped, compact.Bytes())
	return escaped.Bytes(), nil
}

// ReportedAbout is a checked About as run.started reports it: a copy, with Details as
// the event contains them, the bytes CheckAbout measured, and left out when they are
// an empty object. An empty About is nil.
func ReportedAbout(a *About) *About {
	if a.Empty() {
		return nil
	}
	out := *a
	out.Subjects = append([]Subject(nil), a.Subjects...)
	out.Details = nil
	if !detailsAbsent(a.Details) {
		if d, err := eventDetails(a.Details); err == nil {
			out.Details = d
		}
	}
	return &out
}

// ShownAbout is a checked About as Forager sends it to Qory Apiary, in run.started and in
// a registration: a copy in which a value that contains qak_, qrk_, qecr_, qecn_, qecp_,
// qecg_ or qeci_ in any case does not appear. Kind, Title and each subject's Title are
// accesskey.ShownName's phrase in place of such a value. A subject whose Type or Ref
// contains one is left out, since neither form can be a phrase and a subject needs both,
// and so is a URL that contains one. In Details, a string is accesskey.ShownValue's phrase
// and a member name accesskey.ShownName's; of two members whose names become the same, the
// first is kept. Details that grow past their bound are left out, and Details without such
// a value are kept byte for byte. A nil About is nil.
func ShownAbout(a *About) *About {
	if a == nil {
		return nil
	}
	out := *a
	if !aboutContainsSecret(a) {
		return &out
	}
	out.Kind, out.Title = accesskey.ShownName(a.Kind, false), accesskey.ShownName(a.Title, false)
	out.Subjects = nil
	for _, s := range a.Subjects {
		if accesskey.ContainsSecret(s.Type) || accesskey.ContainsSecret(s.Ref) {
			continue
		}
		if accesskey.ContainsSecret(s.URL) {
			s.URL = ""
		}
		s.Title = accesskey.ShownName(s.Title, false)
		out.Subjects = append(out.Subjects, s)
	}
	if !detailsAbsent(a.Details) && jsonSecrets(a.Details) != "" {
		d, err := shownDetails(a.Details)
		if err != nil || checkDetails(d) != "" {
			d = nil
		}
		out.Details = d
	}
	return &out
}

// aboutContainsSecret reports whether a member of a, a decoded string or member name of
// its Details among them, contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_ or qeci_ in any
// case.
func aboutContainsSecret(a *About) bool {
	if accesskey.ContainsSecret(a.Kind) || accesskey.ContainsSecret(a.Title) {
		return true
	}
	for _, s := range a.Subjects {
		for _, v := range []string{s.Type, s.Ref, s.URL, s.Title} {
			if accesskey.ContainsSecret(v) {
				return true
			}
		}
	}
	return !detailsAbsent(a.Details) && jsonSecrets(a.Details) != ""
}

// jsonSecrets are the strings and member names of the JSON d, as they decode, that contain
// qak_, qrk_, qecr_, qecn_, qecp_, qecg_ or qeci_ in any case, joined by spaces, so an
// escape such as \u0061 hides neither; empty when there are none. Bytes that do not decode
// as JSON are checked as they are written.
func jsonSecrets(d []byte) string {
	dec := jsontext.NewDecoder(bytes.NewReader(d), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	var found []string
	for {
		tok, err := dec.ReadToken()
		if err == io.EOF {
			return strings.Join(found, " ")
		}
		if err != nil {
			if accesskey.ContainsSecret(string(d)) {
				return string(d)
			}
			return strings.Join(found, " ")
		}
		if tok.Kind() == '"' && accesskey.ContainsSecret(tok.String()) {
			found = append(found, tok.String())
		}
	}
}

// shownDetails are Details with each string as accesskey.ShownValue shows it and each
// member name as accesskey.ShownName shows it, the first of two members whose names
// become the same kept, in the order written.
func shownDetails(d json.RawMessage) (json.RawMessage, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(d))
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	var names []map[string]bool
	for {
		kind, n := dec.StackIndex(dec.StackDepth())
		name := kind == '{' && n%2 == 0
		tok, err := dec.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch tok.Kind() {
		case '{':
			names = append(names, map[string]bool{})
		case '}':
			names = names[:len(names)-1]
		case '"':
			if name {
				shown := accesskey.ShownName(tok.String(), false)
				if names[len(names)-1][shown] {
					if err := dec.SkipValue(); err != nil {
						return nil, err
					}
					continue
				}
				names[len(names)-1][shown] = true
				tok = jsontext.String(shown)
			} else {
				tok = jsontext.String(accesskey.ShownValue(tok.String(), false))
			}
		}
		if err := enc.WriteToken(tok); err != nil {
			return nil, err
		}
	}
	return eventDetails(bytes.TrimSpace(buf.Bytes()))
}
