package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
)

// MaxVariableValue is the most bytes of UTF-8 a run configuration's variable value
// holds. The schema's maxLength counts characters, so it is not the check.
const MaxVariableValue = 4096

// readRunConfiguration reads a run configuration document: through encoding/json/v2
// first, which refuses a member name that appears twice and invalid UTF-8, then its
// image ([CheckConfigurationImage]), then against the schema, then against the limits
// the schema cannot state: a variable's size, and a credential's name twice or its
// header one [ReservedHeader] reports. It sets [RunConfiguration.Computed] to the
// digest of body. Every refusal is a refusal with
// [refusal.RunConfigurationInvalid] whose message contains where in the document it is
// and which rule refused it, and never a value but the image's: a variable's value may
// be anything the server holds, and no decoder's message is wrapped, since those quote
// what they refuse.
func readRunConfiguration(body []byte) (*RunConfiguration, error) {
	invalid := func(format string, a ...any) error {
		return refusal.New(refusal.RunConfigurationInvalid, nil, "the document is refused: "+format, a...)
	}
	var v any
	if err := jsonv2.Unmarshal(body, &v); err != nil {
		var syn *jsontext.SyntacticError
		if errors.As(err, &syn) && syn.JSONPointer != "" {
			return nil, invalid("it is not one JSON value in UTF-8 with each member name once, at %s", syn.JSONPointer)
		}
		return nil, invalid("it is not one JSON value in UTF-8 with each member name once")
	}
	doc, err := contracts.Decode("run-configuration.json", body)
	if err != nil {
		return nil, invalid("it is not JSON")
	}
	if m, _ := doc.(map[string]any); m != nil {
		if image, ok := m["image"].(string); ok {
			if err := CheckConfigurationImage(image); err != nil {
				return nil, err
			}
		}
	}
	schema, err := contracts.Compile("run-configuration.schema.json")
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(err, &ve) {
			return nil, invalid("run-configuration.schema.json refuses it")
		}
		return nil, invalid("run-configuration.schema.json refuses %s", strings.Join(leaves(ve), ", "))
	}
	var rc RunConfiguration
	if err := jsonv2.Unmarshal(body, &rc); err != nil {
		return nil, invalid("it does not decode as a run configuration")
	}
	for name, v := range rc.Variables {
		if len(v.Value) > MaxVariableValue {
			return nil, refusal.New(refusal.RunConfigurationInvalid, []string{name}, "the document is refused: the variable %s holds more than %d bytes", name, MaxVariableValue)
		}
	}
	if err := CheckCredentials(rc.Credentials); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	rc.Computed = "sha256=" + hex.EncodeToString(sum[:])
	return &rc, nil
}

// CheckCredentials refuses what the schema cannot state of a run configuration's
// credentials, each [refusal.RunConfigurationInvalid] with the credential's name, a
// name that contains a secret left out ([refusal.Shown]): a name twice, a header
// [ReservedHeader] reports, and a placeholder [DeniedPlaceholder] reports. The reader
// of a document calls it, and so does whoever holds a document not read from bytes.
func CheckCredentials(creds []RunCredential) error {
	for i, c := range creds {
		name := accesskey.ShownName(c.Name, true)
		if slices.ContainsFunc(creds[:i], func(o RunCredential) bool { return o.Name == c.Name }) {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name), "the document is refused: list the credential %s once; the document lists it twice", name)
		}
		if c.Auth.Scheme == "header" && ReservedHeader(c.Auth.Header) {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"the document is refused: set the credential %s in another header than %s; that header frames the request, or the proxy sets it", name, accesskey.ShownName(c.Auth.Header, true))
		}
		for _, p := range c.Placeholders {
			if DeniedPlaceholder(p) {
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"the document is refused: give the credential %s another placeholder than %s; the built-in deny list, denied-variables.json, covers that variable", name, accesskey.ShownName(p, true))
			}
		}
	}
	return nil
}

// denied is the contract's built-in deny list, denied-variables.json: its names and
// its patterns, upper case.
var denied = sync.OnceValue(func() (list struct {
	Names    []string `json:"names"`
	Patterns []string `json:"patterns"`
}) {
	b, err := fs.ReadFile(contracts.FS, "denied-variables.json")
	if err != nil {
		panic("denied-variables.json: " + err.Error())
	}
	if err := jsonv2.Unmarshal(b, &list, jsonv2.RejectUnknownMembers(false)); err != nil {
		panic("denied-variables.json: " + err.Error())
	}
	return list
})

// DeniedPlaceholder reports whether a credential from the server may not have the
// variable name as a placeholder: an entry of the built-in deny list,
// denied-variables.json, covers it, case ignored, as the session's deny list does.
// Forager's names, QORY_, are among its patterns.
func DeniedPlaceholder(name string) bool {
	n := strings.ToUpper(name)
	list := denied()
	return slices.Contains(list.Names, n) || slices.ContainsFunc(list.Patterns, func(p string) bool { return glob(p, n) })
}

// glob reports whether pattern, in which * matches any run of characters, the empty
// run included, matches the whole of name.
func glob(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(name, part)
		if i < 0 {
			return false
		}
		name = name[i+len(part):]
	}
	return len(name) >= len(last) && strings.HasSuffix(name, last)
}

// ReservedHeader reports whether a credential from the server may not be set in the
// header name: a header that frames the request or is hop-by-hop, Host,
// Content-Length, Transfer-Encoding, Connection, TE, Trailer, Upgrade, Keep-Alive and
// Expect; any Proxy- header; Cookie; and the headers the proxy sets, X-Qory- and
// Qory-. Case is ignored, and an underscore counts as a dash, which some servers read
// as the same name.
func ReservedHeader(name string) bool {
	n := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	switch n {
	case "host", "content-length", "transfer-encoding", "connection", "te", "trailer", "upgrade", "keep-alive", "expect", "cookie":
		return true
	}
	return strings.HasPrefix(n, "proxy-") || strings.HasPrefix(n, "x-qory-") || strings.HasPrefix(n, "qory-")
}

// CheckConfigurationImage refuses a run configuration's image that is not a reference
// pinned by digest, NAME@sha256: and 64 lower-case hexadecimal digits, with
// run_configuration_invalid: a reference with a tag or without a digest, one in upper
// case, and the machine's name for an image, which a run configuration never names.
// The refusal names the image, as printable ASCII when it is, quoted otherwise.
func CheckConfigurationImage(image string) error {
	if policy.ImageReference(image) {
		return nil
	}
	shown := image
	if strings.ContainsFunc(image, func(r rune) bool { return r <= ' ' || r > '~' }) || image == "" {
		shown = strconv.Quote(image)
	}
	return refusal.New(refusal.RunConfigurationInvalid, nil, "the image %s is not a reference pinned by digest", shown)
}

// leaves are the places the schema refused, each as the JSON pointer of the value and
// the keyword that refused it, sorted, each once. A member name propertyNames refuses
// is reported by the name, which is no value: the validator's location of it is not
// one to rely on, as it shares its storage with the locations validated after it.
func leaves(ve *jsonschema.ValidationError) []string {
	if pn, ok := ve.ErrorKind.(*kind.PropertyNames); ok {
		return []string{"the member name " + pn.Property + " (propertyNames)"}
	}
	if len(ve.Causes) == 0 {
		where := "/" + strings.Join(escaped(ve.InstanceLocation), "/")
		keyword := ""
		if ve.ErrorKind != nil {
			keyword = strings.Join(ve.ErrorKind.KeywordPath(), "/")
		}
		if keyword == "" {
			return []string{where}
		}
		return []string{where + " (" + keyword + ")"}
	}
	var out []string
	for _, c := range ve.Causes {
		out = append(out, leaves(c)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// escaped are the parts of a JSON pointer as RFC 6901 writes them.
func escaped(parts []string) []string {
	out := make([]string, len(parts))
	for i, t := range parts {
		out[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~", "~0"), "/", "~1")
	}
	return out
}
