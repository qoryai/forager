package gateway_test

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// linkVectors is what the gateway's tests read of the contract's known answers: the
// fixture gateway key's secret, and the binding and the link answer of
// through-gateway.json.
type linkVectors struct {
	key     *accesskey.Key
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

// readLinkVectors reads them.
func readLinkVectors(t *testing.T) linkVectors {
	t.Helper()
	var v linkVectors
	var keys struct {
		GatewayKey struct {
			Secret string `json:"secret"`
		} `json:"gateway_key"`
	}
	for name, doc := range map[string]any{"fixtures/known-answers/through-gateway.json": &v, "fixtures/known-answers/keys.json": &keys} {
		b, err := fs.ReadFile(contracts.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, doc); err != nil {
			t.Fatal(err)
		}
	}
	k, err := accesskey.ParseSecret(keys.GatewayKey.Secret)
	if err != nil {
		t.Fatal(err)
	}
	v.key = k
	return v
}

// TestTheGatewaySignsTheBindingKnownAnswer pins the line the gateway answers QORY-BIND
// with: under the fixture gateway key, for the binding's fixed exporter value, it is
// through-gateway.json's bound line, byte for byte.
func TestTheGatewaySignsTheBindingKnownAnswer(t *testing.T) {
	v := readLinkVectors(t)
	ekm, err := hex.DecodeString(v.Binding.EKM)
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.BoundLine(v.key, ekm); got != v.Binding.BoundLine {
		t.Errorf("the gateway answers the binding with %q; want %q", got, v.Binding.BoundLine)
	}
}

// TestTheGatewaySignsTheLinkAnswerKnownAnswer pins the one address's signed answer: a
// handler that answers the link answer's request with its status and digests and no
// body, the request's body unread, is written with through-gateway.json's signature
// under the fixture gateway key, exactly once.
func TestTheGatewaySignsTheLinkAnswerKnownAnswer(t *testing.T) {
	v := readLinkVectors(t)
	la := v.LinkAnswer
	ekm, err := hex.DecodeString(la.EKM)
	if err != nil {
		t.Fatal(err)
	}
	body, err := fs.ReadFile(contracts.FS, la.RequestBody)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(la.Method, la.RequestURI, nil)
	rec := gateway.SignedAnswer(v.key, ekm, req, body, func(w http.ResponseWriter, r *http.Request) {
		io.CopyN(io.Discard, r.Body, 10)
		w.Header().Set(server.HeaderConfiguration, la.Lines[4])
		w.Header().Set(server.HeaderRunConfiguration, la.Lines[5])
		w.WriteHeader(la.Status)
	})
	if got := rec.Header().Values(server.HeaderSignature); len(got) != 1 || got[0] != la.Signature {
		t.Errorf("the gateway signs %q; want %s", got, la.Signature)
	}
	if rec.Code != la.Status || rec.Body.Len() != 0 {
		t.Errorf("status %d with %d bytes; want %d with none", rec.Code, rec.Body.Len(), la.Status)
	}
}
