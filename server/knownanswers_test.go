package server_test

import (
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// TestTheSessionAcceptsTheLinkKnownAnswers pins the session's side of the binding and
// of a separate gateway's answer against through-gateway.json: under the run key's
// gateway key, the fixture gateway key of its payload, the bound line is accepted for
// the fixed exporter value and refused for another, and the link answer is accepted for
// its request and refused for another target or a changed digest.
func TestTheSessionAcceptsTheLinkKnownAnswers(t *testing.T) {
	var v struct {
		RunKey struct {
			RunKey string `json:"run_key"`
		} `json:"run_key"`
		Binding struct {
			EKM       string `json:"ekm"`
			BoundLine string `json:"bound_line"`
		} `json:"binding"`
		LinkAnswer struct {
			EKM         string   `json:"ekm"`
			Method      string   `json:"method"`
			RequestURI  string   `json:"request_uri"`
			RequestBody string   `json:"request_body"`
			Status      int      `json:"status"`
			Lines       []string `json:"lines"`
			Signature   string   `json:"signature"`
		} `json:"link_answer"`
	}
	b, err := fs.ReadFile(contracts.FS, "fixtures/known-answers/through-gateway.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	k, err := runkey.Parse(v.RunKey.RunKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := k.GatewayKeys
	ekm, _ := hex.DecodeString(v.Binding.EKM)
	if !server.BindingAccepted(keys, ekm, v.Binding.BoundLine) {
		t.Error("the session refuses the binding's bound line")
	}
	other := append([]byte{}, ekm...)
	other[0] ^= 1
	if server.BindingAccepted(keys, other, v.Binding.BoundLine) {
		t.Error("the session accepts the bound line for another exporter value")
	}
	la := v.LinkAnswer
	body, err := fs.ReadFile(contracts.FS, la.RequestBody)
	if err != nil {
		t.Fatal(err)
	}
	accepted := func(target string, d server.Digests) bool {
		req, err := http.NewRequest(la.Method, "https://gateway.example:8443"+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		return server.LinkAnswerAccepted(keys, ekm, req, body, la.Status, nil, d, []string{la.Signature})
	}
	d := server.Digests{Configuration: la.Lines[4], RunConfiguration: la.Lines[5]}
	if !accepted(la.RequestURI, d) {
		t.Error("the session refuses the link answer")
	}
	if accepted(la.RequestURI+"?x=1", d) || accepted(la.RequestURI, server.Digests{Configuration: la.Lines[4]}) {
		t.Error("the session accepts the link answer for another target or digest")
	}
}
