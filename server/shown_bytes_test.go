package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// TestALinkRunAnswerWithASecretInADocumentMarshals pins a run answer's policy and
// applied as they print: a document with a string or member name that contains qak_
// or qrk_, escaped or not, is the value's phrase as a JSON string, so json.Marshal
// still writes the answer, and a clean document is printed as it is.
func TestALinkRunAnswerWithASecretInADocumentMarshals(t *testing.T) {
	for name, doc := range map[string]string{
		"plain":       `{"a":"qak_FAKE"}`,
		"escaped":     `{"a":"qak_FAKE"}`,
		"member name": `{"QRK_FAKE":1}`,
	} {
		a := server.LinkRunAnswer{Version: 1, RunID: gatewayRunID, Policy: json.RawMessage(doc), Applied: json.RawMessage(doc)}
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", name, err)
		}
		var back struct{ Policy, Applied string }
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("%s: %s: %v", name, b, err)
		}
		if back.Policy != back.Applied || (back.Policy != accessKeyValue && back.Policy != runKeyValue) {
			t.Errorf("%s: the answer marshals as %s", name, b)
		}
		noSecretPrefix(t, name, fmt.Sprintf("%v", a))
	}
	b, err := json.Marshal(server.LinkRunAnswer{Version: 1, RunID: gatewayRunID, Policy: json.RawMessage(`{"a":"b"}`)})
	if err != nil || !strings.Contains(string(b), `"policy":{"a":"b"}`) {
		t.Errorf("a clean answer marshals as %s, %v", b, err)
	}
}

// TestShownAboutKeepsCleanDetailsByteForByte pins Details without qak_ or qrk_ as
// written, an escaped slash and an escaped letter among them, beside a title that is
// phrased, and Details with one rewritten.
func TestShownAboutKeepsCleanDetailsByteForByte(t *testing.T) {
	clean := json.RawMessage(`{"u":"a\/b","e":"é"}`)
	for _, title := range []string{"t", "qak_FAKE"} {
		a := &server.About{Title: title, Details: clean}
		if got := server.ShownAbout(a); string(got.Details) != string(clean) {
			t.Errorf("title %q: details %s, want %s", title, got.Details, clean)
		}
	}
	got := server.ShownAbout(&server.About{Details: json.RawMessage(`{"u":"a\/b","k":"qak_FAKE"}`)})
	if string(got.Details) != `{"u":"a/b","k":"`+accessKeyValue+`"}` {
		t.Errorf("details with a secret are %s", got.Details)
	}
}

// TestADeliveryErrorPrintsAPhraseForASecret pins a transport error of a delivery, to
// the server and over the link, as a phrase when it quotes a URL or a socket path
// that contains qak_ or qrk_, the error it wraps still found by errors.Is and errors.As.
func TestADeliveryErrorPrintsAPhraseForASecret(t *testing.T) {
	ctx := context.Background()
	c := &server.Client{Config: &server.Config{Version: 1, URL: "http://127.0.0.1:1", AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(seeded(t, 65))}, Key: seeded(t, 1), InstanceID: instance, UserAgent: "qory-forager/test"}
	_, err := c.Deliver(ctx, "http://127.0.0.1:1/qak_FAKE/events", gatewayRunID, []byte(`[]`), "")
	if err == nil {
		t.Fatal("a delivery to a closed port succeeded")
	}
	noSecretPrefix(t, "the delivery's error", err.Error())
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("the delivery's error %v does not wrap ECONNREFUSED", err)
	}
	socket := filepath.Join(t.TempDir(), "qrk_FAKE", "link.sock")
	k, err := server.NewLocalLink(link.Local{Socket: socket}, "qory-forager/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.Deliver(ctx, server.LocalOrigin+"/v1/events", gatewayRunID, []byte(`[]`), "")
	if err == nil {
		t.Fatal("a delivery over a missing socket succeeded")
	}
	noSecretPrefix(t, "the link's error", err.Error())
	if oe := (*net.OpError)(nil); !errors.As(err, &oe) {
		t.Errorf("the link's error %v does not wrap a *net.OpError", err)
	}
}
