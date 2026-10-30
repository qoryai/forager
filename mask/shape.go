package mask

import "bytes"

// Shape is the form of a kind of key that a masker from [New] replaces with Secret
// wherever it appears, the prefix included, whether or not the run knows the key's
// value: Prefix, then a token of at least Min characters of Alphabet. The find covers
// the whole token, up to Max characters: the characters after them are scanned again
// as text. A shape is looked for as it is, not percent-encoded or JSON-escaped.
type Shape struct {
	// Name says which key the shape is the form of.
	Name string
	// Prefix is the text every key of the shape starts with, compared exactly unless
	// AnyCase is set.
	Prefix string
	// AnyCase compares Prefix regardless of the case of its ASCII letters.
	AnyCase bool
	// Blank requires 1 to MaxBlank spaces or tabs between Prefix and the token; the
	// find covers them.
	Blank bool
	// Alphabet is the characters of the token, each an ASCII byte.
	Alphabet string
	// Min is how many characters of Alphabet the token has at least.
	Min int
	// Max is how many characters of the token a find covers at most: a writer keeps
	// back at most the prefix, the blanks and Max-1 characters of a token that a write
	// ends in.
	Max int
}

// MaxBlank is how many spaces or tabs a [Shape] with Blank allows after its prefix.
const MaxBlank = 16

// keyMax is the Max of a key's shape: the keys of [Shapes] but the bearer token have
// 20 to about 110 characters. A token whose prefix can occur inside it costs up to Max
// steps for each byte a writer keeps back, so the cap stays small.
const keyMax = 256

// The alphabets of [Shapes].
const (
	alnum      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperDigit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// keyChars is the alphabet of a key whose alphabet no public document states.
	keyChars = alnum + "_-"
	// tokenChars is the alphabet of a bearer token, the token68 of RFC 7235 without
	// its padding rule.
	tokenChars = alnum + "._~+/=-"
)

// Shapes is the shapes a masker from [New] replaces, a new slice on each call.
//
//   - Anthropic API keys and OAuth tokens: sk-ant- and 16 to 256 of A-Z, a-z, 0-9, _
//     and -. Anthropic publishes no alphabet or length, so this is the fallback.
//   - GitHub personal access, OAuth, user-to-server, app installation and refresh
//     tokens: ghp_, gho_, ghu_, ghs_ and ghr_, each with 36 to 256 of A-Z, a-z and 0-9;
//     36 is the 30 random and 6 checksum characters of GitHub's token format of 2021,
//     and a refresh token has 76 characters.
//   - GitHub fine-grained personal access tokens: github_pat_ and 16 to 256 of A-Z,
//     a-z, 0-9, _ and -. GitHub publishes no length for them, so this is the fallback.
//   - AWS access key ids, long-term and temporary: AKIA and ASIA, each with 16 to 256
//     of A-Z and 0-9; AWS's ids have 20 characters.
//   - HTTP bearer tokens: bearer in any case, 1 to 16 spaces or tabs, and 16 to 4096
//     of A-Z, a-z, 0-9 and . _ ~ + / = -. A JSON web token can have thousands of
//     characters, and a space cannot occur inside the token, so the cap is
//     MaxSecretSize.
func Shapes() []Shape {
	return []Shape{
		{Name: "Anthropic key", Prefix: "sk-ant-", Alphabet: keyChars, Min: 16, Max: keyMax},
		{Name: "GitHub personal access token", Prefix: "ghp_", Alphabet: alnum, Min: 36, Max: keyMax},
		{Name: "GitHub app installation token", Prefix: "ghs_", Alphabet: alnum, Min: 36, Max: keyMax},
		{Name: "GitHub OAuth token", Prefix: "gho_", Alphabet: alnum, Min: 36, Max: keyMax},
		{Name: "GitHub user-to-server token", Prefix: "ghu_", Alphabet: alnum, Min: 36, Max: keyMax},
		{Name: "GitHub refresh token", Prefix: "ghr_", Alphabet: alnum, Min: 36, Max: keyMax},
		{Name: "GitHub fine-grained personal access token", Prefix: "github_pat_", Alphabet: keyChars, Min: 16, Max: keyMax},
		{Name: "AWS access key id", Prefix: "AKIA", Alphabet: upperDigit, Min: 16, Max: keyMax},
		{Name: "AWS temporary access key id", Prefix: "ASIA", Alphabet: upperDigit, Min: 16, Max: keyMax},
		{Name: "HTTP bearer token", Prefix: "Bearer", AnyCase: true, Blank: true, Alphabet: tokenChars, Min: 16, Max: MaxSecretSize},
	}
}

// shape is a Shape as a masker looks for it. firsts is the first byte of the prefix in
// each case it may have.
type shape struct {
	prefix  []byte
	anyCase bool
	blank   bool
	firsts  string
	alpha   [256]bool
	min     int
	max     int
}

// compile is the shapes as a masker looks for them, and the longest find one of them
// can have: its prefix, its blanks and Max characters.
func compile(shapes []Shape) ([]shape, int) {
	out := make([]shape, len(shapes))
	longest := 0
	for i, s := range shapes {
		sh := shape{prefix: []byte(s.Prefix), anyCase: s.AnyCase, blank: s.Blank, min: s.Min, max: s.Max}
		if s.Prefix != "" {
			sh.firsts = string(bytes.ToLower(sh.prefix[:1])) + string(bytes.ToUpper(sh.prefix[:1]))
		}
		for j := 0; j < len(s.Alphabet); j++ {
			sh.alpha[s.Alphabet[j]] = true
		}
		n := len(s.Prefix) + s.Max
		if s.Blank {
			n += MaxBlank
		}
		out[i], longest = sh, max(longest, n)
	}
	return out, longest
}

// isPrefix reports whether b is the prefix, in a case the shape allows.
func (s *shape) isPrefix(b []byte) bool {
	if s.anyCase {
		return bytes.EqualFold(b, s.prefix)
	}
	return bytes.Equal(b, s.prefix)
}

// index is the first place in in where the prefix starts, -1 for none.
func (s *shape) index(in []byte) int {
	if !s.anyCase {
		return bytes.Index(in, s.prefix)
	}
	for i := 0; i < len(in); i++ {
		j := bytes.IndexAny(in[i:], s.firsts)
		if j < 0 {
			return -1
		}
		i += j
		if len(in)-i >= len(s.prefix) && s.isPrefix(in[i:i+len(s.prefix)]) {
			return i
		}
	}
	return -1
}

// at is the length of the shape's find at the start of in, 0 for none, and open reports
// whether bytes after the end of in could change that: in ends inside the prefix,
// inside the blanks, or inside a token of fewer than Max characters.
func (s *shape) at(in []byte) (n int, open bool) {
	p := len(s.prefix)
	if len(in) < p {
		if s.anyCase {
			return 0, bytes.EqualFold(in, s.prefix[:len(in)])
		}
		return 0, bytes.HasPrefix(s.prefix, in)
	}
	if !s.isPrefix(in[:p]) {
		return 0, false
	}
	if s.blank {
		g := 0
		for g < MaxBlank && p+g < len(in) && (in[p+g] == ' ' || in[p+g] == '\t') {
			g++
		}
		if p+g == len(in) {
			return 0, true
		}
		if g == 0 {
			return 0, false
		}
		p += g
	}
	t := 0
	for t < s.max && p+t < len(in) && s.alpha[in[p+t]] {
		t++
	}
	open = t < s.max && p+t == len(in)
	if t < s.min {
		return 0, open
	}
	return p + t, open
}

// next is the start and the length of the shape's first find at or after from that no
// byte after in can change, or that ends with in when final; start is -1 for none.
func (s *shape) next(in []byte, from int, final bool) (start, n int) {
	for from < len(in) {
		j := s.index(in[from:])
		if j < 0 {
			break
		}
		j += from
		if n, open := s.at(in[j:]); n > 0 && (final || !open) {
			return j, n
		}
		from = j + 1
	}
	return -1, 0
}
