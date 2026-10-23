package server_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/server"
)

const (
	accessKeyName  = "(a name that contains an access key secret)"
	runKeyName     = "(a name that contains a run key)"
	accessKeyValue = "(a value that contains an access key secret)"
	runKeyValue    = "(a value that contains a run key)"
	runCodeName    = "(a name that contains a run code)"
)

// noSecretPrefix fails when text contains qak_, qrk_ or qecr_ in any case.
func noSecretPrefix(t *testing.T, what, text string) {
	t.Helper()
	if low := strings.ToLower(text); strings.Contains(low, "qak_") || strings.Contains(low, "qrk_") || strings.Contains(low, "qecr_") {
		t.Errorf("%s: %s contains a secret's prefix", what, text)
	}
}

// TestShownLabelsPhraseAKeyAndAValue pins the labels Forager sends to Qory Apiary: a key
// or a value that contains qak_ or qrk_ in any case is the name's phrase, of two keys
// that become one phrase the one that sorts first is kept, and the rest is as it is.
func TestShownLabelsPhraseAKeyAndAValue(t *testing.T) {
	got := server.ShownLabels(map[string]string{"QAK_b": "first", "qak_key": "second", "qrk_k": "qak_v", "repository": "acme/qrk_x", "issue": "7"})
	want := map[string]string{accessKeyName: "first", runKeyName: accessKeyName, "repository": runKeyName, "issue": "7"}
	if !maps.Equal(got, want) {
		t.Errorf("ShownLabels = %v, want %v", got, want)
	}
	if err := server.CheckLabels(got); err != nil {
		t.Errorf("CheckLabels refuses the phrased labels: %v", err)
	}
	if clean := map[string]string{"issue": "7"}; !maps.Equal(server.ShownLabels(clean), clean) || server.ShownLabels(nil) != nil {
		t.Errorf("clean labels change")
	}
	err := server.CheckLabels(map[string]string{"QAK_x": "v"})
	if want := "the label key " + accessKeyName + " is not 1 to 64 of a-z, 0-9, underscore, dot and dash"; err == nil || err.Error() != want {
		t.Errorf("a key in upper case: %v, want %s", err, want)
	}
}

// TestARunCodeInALabelIsTheRunCodesPhrase pins a run code, qecr_ in any case, in the
// labels Forager sends to Qory Apiary: a key or a value that contains one is the run
// code's phrase, CheckLabels accepts it, and the registration through a gateway contains
// no qecr_ and is a body the schema accepts.
func TestARunCodeInALabelIsTheRunCodesPhrase(t *testing.T) {
	labels := map[string]string{"qecr_k": "v", "repository": "acme/QECR_x"}
	got := server.ShownLabels(labels)
	if want := map[string]string{runCodeName: "v", "repository": runCodeName}; !maps.Equal(got, want) {
		t.Errorf("ShownLabels = %v, want %v", got, want)
	}
	if err := server.CheckLabels(got); err != nil {
		t.Errorf("CheckLabels refuses the phrased labels: %v", err)
	}
	b, err := server.GatewayRegistration{RunID: gatewayRunID, Labels: labels, Time: "2026-10-11T12:00:00Z"}.Body()
	if err != nil {
		t.Fatal(err)
	}
	noSecretPrefix(t, "the registration", string(b))
	schema, err := contracts.Compile("run-registration.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := contracts.Decode("r.json", b)
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the schema refuses %s: %v", b, err)
	}
}

// TestShownAboutLeavesOutWhatCannotHoldAPhrase pins what the run is about as Forager
// sends it to Qory Apiary: kind, title and a subject's title are the name's phrase; a
// subject whose type or ref contains a prefix is left out, and so is a url that
// contains one; in details a string is the value's phrase, a member name the name's,
// the first of two names that become one phrase kept; details that grow past 8192
// bytes are left out; a clean about is as it is.
func TestShownAboutLeavesOutWhatCannotHoldAPhrase(t *testing.T) {
	a := &server.About{Kind: "qak_k", Title: "QRK_t",
		Subjects: []server.Subject{
			{Type: "issue", Ref: "7", URL: "https://x.example/qak_y", Title: "qrk_t"},
			{Type: "qak_type", Ref: "1"},
			{Type: "issue", Ref: "qrk_ref"},
			{Type: "issue", Ref: "8", URL: "https://ok.example/8", Title: "ok"},
		},
		Details: json.RawMessage(`{"a":"qak_v","qak_k":1,"QAK_j":2,"n":{"x":["qrk_y",3]}}`),
	}
	got := server.ShownAbout(a)
	want := &server.About{Kind: accessKeyName, Title: runKeyName,
		Subjects: []server.Subject{{Type: "issue", Ref: "7", Title: runKeyName}, {Type: "issue", Ref: "8", URL: "https://ok.example/8", Title: "ok"}},
		Details:  json.RawMessage(`{"a":"` + accessKeyValue + `","` + accessKeyName + `":1,"n":{"x":["` + runKeyValue + `",3]}}`),
	}
	if g, w := fmt.Sprintf("%+v %s", *got, got.Details), fmt.Sprintf("%+v %s", *want, want.Details); g != w {
		t.Errorf("ShownAbout:\n got %s\nwant %s", g, w)
	}
	if err := server.CheckAbout(got); err != nil {
		t.Errorf("CheckAbout refuses the phrased about: %v", err)
	}
	clean := &server.About{Kind: "fix", Title: "A title", Subjects: []server.Subject{{Type: "issue", Ref: "7", URL: "https://ok.example/7", Title: "t"}}, Details: json.RawMessage(`{"a":"b"}`)}
	if g, w := fmt.Sprintf("%+v %s", *server.ShownAbout(clean), server.ShownAbout(clean).Details), fmt.Sprintf("%+v %s", *clean, clean.Details); g != w {
		t.Errorf("a clean about:\n got %s\nwant %s", g, w)
	}
	var many []string
	for i := range 300 {
		many = append(many, fmt.Sprintf(`"k%03d":"qak_"`, i))
	}
	big := &server.About{Title: "t", Details: json.RawMessage("{" + strings.Join(many, ",") + "}")}
	if err := server.CheckAbout(big); err != nil {
		t.Fatal(err)
	}
	if d := server.ShownAbout(big).Details; d != nil {
		t.Errorf("details past their bound are sent: %d bytes", len(d))
	}
	if server.ShownAbout(nil) != nil {
		t.Errorf("a nil about is not nil")
	}
}

// TestARegistrationBodySendsAPhraseForASecret pins both registration bodies: the labels
// and about as ShownLabels and ShownAbout give them, and the body the schema accepts.
func TestARegistrationBodySendsAPhraseForASecret(t *testing.T) {
	schema, err := contracts.Compile("run-registration.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"qak_k": "v", "repository": "acme/QRK_x"}
	about := &server.About{Title: "qak_t", Subjects: []server.Subject{{Type: "issue", Ref: "qrk_r"}}}
	for name, body := range map[string]func() ([]byte, error){
		"through a gateway": server.GatewayRegistration{RunID: gatewayRunID, Labels: labels, About: about, Time: "2026-10-11T12:00:00Z"}.Body,
		"direct":            server.Registration{Version: 1, RunID: gatewayRunID, Labels: labels, About: about, Time: "2026-10-11T12:00:00Z"}.Body,
	} {
		b, err := body()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		noSecretPrefix(t, name, string(b))
		var m struct {
			Labels map[string]string `json:"labels"`
			About  *server.About     `json:"about"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(m.Labels, map[string]string{accessKeyName: "v", "repository": runKeyName}) || m.About == nil || m.About.Title != accessKeyName || len(m.About.Subjects) != 0 {
			t.Errorf("%s: %s", name, b)
		}
		doc, _ := contracts.Decode("r.json", b)
		if name == "through a gateway" {
			if err := schema.Validate(doc); err != nil {
				t.Errorf("%s: the schema refuses %s: %v", name, b, err)
			}
		}
	}
	if labels["qak_k"] != "v" || about.Title != "qak_t" {
		t.Errorf("the caller's labels or about changed")
	}
}

// TestAServerErrorPrintsAPhraseForASecret pins the errors of a server document and of
// a document the server answered: a server document's name or error's text, and an
// answer's URL, that contains qak_ or qrk_ in any case prints the value's phrase, and
// the error still wraps its cause. An answer's error is phrased where it is made, so
// a fixed reason that names a prefix prints as it is.
func TestAServerErrorPrintsAPhraseForASecret(t *testing.T) {
	cause := errors.New("at /x: qrk_y")
	e := &server.Error{Name: "qak_server.json", Err: cause}
	if want := "server " + accessKeyValue + ": " + runKeyValue; e.Error() != want || !errors.Is(e, cause) {
		t.Errorf("Error = %q, want %q wrapping its cause", e, want)
	}
	reason := errors.New("run_key: it does not start with qrk_")
	d := &server.DocumentError{What: "registration answer", URL: "https://apiary.example/qak_x", Err: reason}
	if want := "registration answer " + accessKeyValue + ": run_key: it does not start with qrk_"; d.Error() != want || !errors.Is(d, reason) {
		t.Errorf("DocumentError = %q, want %q", d, want)
	}
	clean := &server.DocumentError{What: "run configuration", URL: "https://apiary.example/run", Err: errors.New("at /x: no")}
	if want := "run configuration https://apiary.example/run: at /x: no"; clean.Error() != want {
		t.Errorf("a clean DocumentError = %q, want %q", clean, want)
	}
	err := server.CheckConfigurationImage("registry.example/qak_x:1")
	if err == nil || !strings.Contains(err.Error(), "the image "+accessKeyName+" is not a reference pinned by digest") {
		t.Errorf("an image: %v", err)
	}
}

// TestALinkRunAnswerPrintsAPhraseForASecret pins a run answer as fmt and log/slog
// print it and encoding/json writes it: no name or value of it that contains qak_ or
// qrk_ in any case prints, credential_hosts included, and a credential's empty
// placeholders stay an empty list.
func TestALinkRunAnswerPrintsAPhraseForASecret(t *testing.T) {
	a := server.LinkRunAnswer{Version: 1, RunID: gatewayRunID, Labels: map[string]string{"qak_k": "qrk_v"},
		Variables: map[string]server.Variable{"QAK_N": {Value: "v"}, "N": {Value: "qrk_v"}}, Placeholders: []string{"QRK_P"}, Reserved: []string{"QAK_R"},
		Policy: json.RawMessage(`{"egress":{"paths":{"a.example":["/qak_x"]}}}`), Image: &server.LinkImage{Name: "qak_i", Ref: "registry.example/qrk_x:1"}, RelayImage: "qak_relay",
		CredentialHosts: []server.LinkCredentialHosts{{Name: "qak_c", Hosts: []string{"qrk_h.example"}, Placeholders: []string{"QAK_PH"}}, {Name: "clean", Hosts: []string{"a.example"}, Placeholders: []string{}}}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		noSecretPrefix(t, verb, fmt.Sprintf(verb, a))
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	noSecretPrefix(t, "json", string(b))
	if !strings.Contains(string(b), `{"name":"clean","hosts":["a.example"],"placeholders":[]}`) {
		t.Errorf("a clean credential prints %s", b)
	}
	if s := fmt.Sprintf("%v", server.LinkRunAnswer{Version: 1, RunID: gatewayRunID, Labels: map[string]string{"issue": "7"}}); !strings.Contains(s, "issue:7") {
		t.Errorf("a clean answer prints %s", s)
	}
}
