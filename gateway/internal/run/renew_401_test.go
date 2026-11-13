package run_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/server"
)

// expiring answers model with model-<call>, expiring an hour after the start plus call
// hours, and forge as renewing does.
func expiring(name string, call int) (answer, error) {
	if name == "model" {
		return answer{value: fmt.Sprintf("model-%d", call), expires: start.Add(time.Hour + time.Duration(call)*time.Hour)}, nil
	}
	return renewing(name, call)
}

// keyRun is a run of renewDoc whose model key's value expires, with the key group of
// that key, and the proxy's Rejected of the key.
type keyRun struct {
	r      *run.Run
	g      *modelkey.Group
	c      *fakeClock
	s      *controlPlane
	log    *reports
	report *reports
}

func newKeyRun(t *testing.T, fail func(call int) error) *keyRun {
	t.Helper()
	k := &keyRun{c: &fakeClock{now: start}, s: &controlPlane{answer: expiring, fail: fail}, log: &reports{}, report: &reports{}}
	k.r = renewRun(t, renewDoc, k.s, k.c, k.report, k.log)
	k.g = modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}}, "model", k.c.Now)
	k.r.SetKeyGroup(k.g)
	return k
}

// reject is the proxy's 401 to a request with the model key: the group takes the key
// out of use, and its Rejected asks for its value again. It waits until the renewer
// waits again.
func (k *keyRun) reject(t *testing.T) {
	t.Helper()
	var rejected func()
	for _, u := range k.r.Uses() {
		if u.Name == "model" {
			rejected = u.Rejected
		}
	}
	if rejected == nil {
		t.Fatal("the model key whose value expires has no Rejected")
	}
	n := k.c.count()
	k.g.Reject("model", true)
	rejected()
	k.c.idle(t, n)
}

// unauth are the unauthorized names of each secrets request after the start's.
func (k *keyRun) unauth() [][]string {
	k.s.mu.Lock()
	defer k.s.mu.Unlock()
	return slices.Clone(k.s.unauth[1:])
}

// TestARenewalAfterA401BringsTheKeyBack pins a 200: the renewal after the provider's
// 401 lists the key as unauthorized, its value takes the old one's place, and the key
// is back in the group. A renewal before expires_at lists none.
func TestARenewalAfterA401BringsTheKeyBack(t *testing.T) {
	k := newKeyRun(t, nil)
	k.c.advance(credential.RetryWait)
	k.reject(t)
	if got := k.unauth(); len(got) != 1 || !slices.Equal(got[0], []string{"model"}) {
		t.Fatalf("the renewal's unauthorized %v; want [model]", got)
	}
	if value(k.r, "model") != "model-1" || k.g.Pending("model") || k.g.Unauthorized() != nil {
		t.Errorf("after the renewal: model %s, unauthorized %+v", value(k.r, "model"), k.g.Unauthorized())
	}
	k.c.step(t, 2*time.Hour-credential.RenewBefore-credential.RetryWait)
	if got := k.unauth(); len(got) < 2 || got[len(got)-1] != nil {
		t.Errorf("the renewal before expires_at has unauthorized %v; want none", got)
	}
}

// TestA409TakesTheKeyOut pins the server's signed 409 to a renewal after a 401, with a
// code or with none: the key leaves the group for the run, the run's record gets one
// line, and the key is asked for no more.
func TestA409TakesTheKeyOut(t *testing.T) {
	for name, refusal := range map[string]error{
		"with a code": &accesskey.Refusal{Code: "credential_revoked", Status: 409, Detail: "secrets https://apiary.example/v1/secrets", From: accesskey.FromApiary},
		"with none":   &server.AnswerError{What: "secrets https://apiary.example/v1/secrets", Status: 409},
	} {
		t.Run(name, func(t *testing.T) {
			k := newKeyRun(t, func(int) error { return refusal })
			k.c.advance(credential.RetryWait)
			k.reject(t)
			got := k.g.Unauthorized()
			if len(got) != 1 || !got[0].Out || !got[0].At.Equal(start.Add(credential.RetryWait)) {
				t.Fatalf("after the 409: %+v; want model out, at its 401", got)
			}
			deadline := time.Now().Add(10 * time.Second)
			for len(k.log.lines()) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if l := k.log.lines(); len(l) != 1 || !strings.HasPrefix(l[0], `Store in the control plane a value of the model key "model" that its provider accepts; the run sets the key no more: the provider returned 401 for it, and its renewal was refused: `) {
				t.Errorf("the record %q", l)
			}
			calls := len(k.s.called())
			// No renewal is due before forge's at 12:55.
			k.c.advance(10 * credential.RetryWait)
			time.Sleep(20 * time.Millisecond)
			for _, c := range k.s.called()[calls:] {
				if slices.Contains(c, "model") {
					t.Errorf("a request for model after the 409: %v", c)
				}
			}
		})
	}
}

// TestA503KeepsTheKeyCoolingAndTriesAgain pins a renewal after a 401 that fails with
// the server's 503, an unsigned 409 or no answer: the key stays out of use, a report
// line contains the cause, and the request goes again every RetryWait, 30 seconds,
// with the key unauthorized, until a value brings it back.
func TestA503KeepsTheKeyCoolingAndTriesAgain(t *testing.T) {
	for name, err := range map[string]error{
		"503":          &accesskey.Refusal{Code: "unavailable", Status: 503, From: accesskey.FromApiary},
		"unsigned 409": &accesskey.Refusal{Code: accesskey.CodeAnswerUnsigned, Status: 409},
		"no answer":    errors.New("secrets https://apiary.example/v1/secrets: context deadline exceeded"),
	} {
		t.Run(name, func(t *testing.T) {
			fails := 3
			k := newKeyRun(t, func(int) error {
				if fails == 0 {
					return nil
				}
				fails--
				return err
			})
			k.c.advance(credential.RetryWait)
			k.reject(t)
			if !k.g.Pending("model") || value(k.r, "model") != "model-0" {
				t.Fatalf("after the failure: pending %v, model %s", k.g.Pending("model"), value(k.r, "model"))
			}
			if !slices.ContainsFunc(k.report.lines(), func(l string) bool {
				return strings.HasPrefix(l, `run `+runID+`: If this repeats, check the control plane: credential "model" was not renewed: `)
			}) {
				t.Errorf("reports %q", k.report.lines())
			}
			k.c.advance(credential.RetryWait - time.Second)
			time.Sleep(20 * time.Millisecond)
			if got := len(k.unauth()); got != 1 {
				t.Fatalf("%d requests a second before RetryWait; want 1", got)
			}
			k.c.step(t, time.Second)
			k.c.step(t, credential.RetryWait)
			k.c.step(t, credential.RetryWait)
			got := k.unauth()
			if len(got) != 4 || slices.ContainsFunc(got, func(u []string) bool { return !slices.Equal(u, []string{"model"}) }) {
				t.Fatalf("the requests' unauthorized %v; want [model] 4 times, 30 s apart", got)
			}
			if k.g.Pending("model") || value(k.r, "model") != "model-4" {
				t.Errorf("after the value: pending %v, model %s", k.g.Pending("model"), value(k.r, "model"))
			}
		})
	}
}

// TestAKeyThatExpiresWaitingForItsRenewalGoesOut pins a key whose renewal after a 401
// fails until its value expires: it leaves the group for the run.
func TestAKeyThatExpiresWaitingForItsRenewalGoesOut(t *testing.T) {
	k := newKeyRun(t, func(int) error { return errors.New("secrets https://apiary.example/v1/secrets: 503") })
	k.c.advance(credential.RetryWait)
	k.reject(t)
	for k.c.Now().Before(start.Add(time.Hour - credential.RetryWait)) {
		k.c.step(t, credential.RetryWait)
	}
	if !k.g.Pending("model") {
		t.Fatal("the key went out before its expires_at")
	}
	// At expires_at, no renewal of forge or model is left to wait for.
	k.c.advance(credential.RetryWait)
	deadline := time.Now().Add(10 * time.Second)
	for k.g.Pending("model") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := k.g.Unauthorized(); len(got) != 1 || !got[0].Out {
		t.Errorf("after expires_at: %+v; want model out", got)
	}
}
