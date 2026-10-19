package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// secrets is the secrets request of the run runID, for [run.Config.Secrets]: once the
// run's run configuration has credentials, a signed POST to discovery's secrets.url
// with the access key, and the open of its answer, [sealed.Open], with the pin read
// again with [accesskey.ParsePin], the digest Forager computed of the document's bytes
// and this machine's clock. Nil when discovery lists no secrets endpoint. A pin that
// lists a published fixture key, and an access key that is one, are refused before
// anything is sent: anyone can sign under the one and open what is sealed to the other.
// Each refusal of the open is one code, [sealedCode].
func (g *Gateway) secrets(runID string) func(context.Context, string, []string) (sealed.Values, error) {
	conf, _ := g.config()
	if conf == nil || conf.Secrets == nil {
		return nil
	}
	u := conf.Secrets.URL
	return func(ctx context.Context, digest string, names []string) (sealed.Values, error) {
		s := g.cfg.Server
		b, err := json.Marshal(s.ApiaryPublicKey)
		if err != nil {
			return sealed.Values{}, err
		}
		pin, err := accesskey.ParsePin(b)
		if err != nil {
			return sealed.Values{}, fmt.Errorf("secrets %s: %w", u, err)
		}
		if pin.Fixture() {
			return sealed.Values{}, refusal.New(refusal.RunConfigurationInvalid, nil,
				"secrets %s: pin Qory Apiary's signing key: the server document's apiary_public_key lists a published fixture key, under which anyone can sign", u)
		}
		if s.AccessKey.PublicKey().Fixture() {
			return sealed.Values{}, refusal.New(refusal.RunConfigurationInvalid, nil,
				"secrets %s: enrol another access key: this access key is a published fixture key, and anyone can open what is sealed to it", u)
		}
		body, err := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: digest, Credentials: names, Timestamp: time.Now().Unix()}.Body()
		if err != nil {
			return sealed.Values{}, err
		}
		answer, err := g.client.Secrets(ctx, u, body)
		if err != nil {
			return sealed.Values{}, err
		}
		// The local clock, never the answer's Date: exp is judged by this machine.
		values, err := sealed.Open(answer, sealed.AccessKey{ID: s.AccessKeyID, Key: s.AccessKey}, pin, runID, digest, names, time.Now())
		if err != nil {
			return sealed.Values{}, &accesskey.Refusal{Code: sealedCode(err), Detail: fmt.Sprintf("secrets %s: %s; the answer does not open: %v", u, sealedFix(err), err)}
		}
		return values, nil
	}
}

// sealedCode is the refusal code of an error of [sealed.Open]: answer_unsigned for an
// envelope whose signature does not verify under the pin, as for any answer that does
// not; run_configuration_invalid for every other refusal, an answer, an envelope or a
// plaintext that is not the one the run configuration asks for.
func sealedCode(err error) string {
	if errors.Is(err, sealed.ErrSignature) {
		return accesskey.CodeAnswerUnsigned
	}
	return refusal.RunConfigurationInvalid
}

// sealedFix is the step that fixes a refusal of [sealed.Open], first in its message:
// for a signature, the pin; for an exp outside the window, this machine's clock; for
// every other refusal, Qory Apiary, which sealed an answer that is not the request's.
func sealedFix(err error) string {
	switch {
	case errors.Is(err, sealed.ErrSignature):
		return "pin Qory Apiary's current signing key in apiary_public_key"
	case errors.Is(err, sealed.ErrExpired), errors.Is(err, sealed.ErrAhead):
		return "set this machine's clock to the right time"
	}
	return "report this answer to whoever runs Qory Apiary"
}
