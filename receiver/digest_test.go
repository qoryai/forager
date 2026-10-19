package receiver_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
)

// TestTheReceiverComputesTheRunConfigurationsDigest pins the digest of a run
// configuration to the contract's form whatever the hook returns: a hook's empty digest
// and its digest of the bytes are served as sha256= and the lower-case hex SHA-256 of
// the document; any other digest is a signed 500 with no body, to the registration and
// to a reload alike, and no batch answer carries it.
func TestTheReceiverComputesTheRunConfigurationsDigest(t *testing.T) {
	ss := newStand(t)
	doc := []byte(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}}`)
	other := []byte(`{"version":1}`)
	for name, given := range map[string]string{"empty": "", "the bytes' digest": digestOf(doc)} {
		ss.h.RunConfiguration = func(receiver.Run) ([]byte, string, *receiver.Refusal) { return doc, given, nil }
		runID := event.NewRunID()
		req, rec := ss.register(directKey, ss.directBody(runID))
		if rec.Code != http.StatusOK || rec.Header().Get(server.HeaderRunConfiguration) != digestOf(doc) || !runAnswer(req, rec, doc) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Header().Get(server.HeaderRunConfiguration))
		}
	}
	runID := event.NewRunID()
	if _, rec := ss.register(directKey, ss.directBody(runID)); rec.Code != http.StatusOK {
		t.Fatalf("the registration: %d %s", rec.Code, rec.Body.String())
	}
	for name, given := range map[string]string{
		"upper case":         strings.ToUpper(digestOf(doc)),
		"another document's": digestOf(other),
		"opaque":             "sha256=" + strings.Repeat("a", 64),
		"another form":       "v1-" + strings.Repeat("a", 8),
	} {
		ss.h.RunConfiguration = func(receiver.Run) ([]byte, string, *receiver.Refusal) { return doc, given, nil }
		req, rec := ss.register(directKey, ss.directBody(event.NewRunID()))
		ss.expect(name+": the registration", req, rec, http.StatusInternalServerError, "")
		req, rec = serveReload(ss, directKey, runID)
		ss.expect(name+": a reload", req, rec, http.StatusInternalServerError, "")
		e := event.NewEmitter(runID, nil)
		if _, rec := ss.batch(directKey, e, event.RunHeartbeat); rec.Code != http.StatusAccepted || rec.Header().Get(server.HeaderRunConfiguration) != "" {
			t.Errorf("%s: a batch %d with the digest %q", name, rec.Code, rec.Header().Get(server.HeaderRunConfiguration))
		}
	}
}

// serveReload reloads the run's configuration as the access key id.
func serveReload(s *stand, id, runID string) (*http.Request, *httptest.ResponseRecorder) {
	req := s.signed(id, http.MethodGet, receiver.DefaultRunPath+"/"+runID, nil)
	return req, serve(s.h, req)
}
