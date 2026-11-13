package run_test

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// expiring returns model-<call> for model, expiring an hour after the start plus call
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
// out of use, and its Rejected requests its value again. It waits until the renewer
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
			if l := k.log.lines(); len(l) != 1 || !strings.HasPrefix(l[0], `Store in the control plane a value of the model key "model" that its provider accepts; the run sets the key no more: the provider returned 401 for it, and its renewal brought no value the run can set: `) {
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

// twoKeysDoc is renewDoc with a second model key, model-2, in model's key group.
const twoKeysDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","git.example","api.git.example"]}},"model_credential":"model","credentials":[` +
	`{"name":"model","format":"anthropic-messages","pause_for_s":18000,"endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}},` +
	`{"name":"model-2","format":"anthropic-messages","pause_for_s":18000,"endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}},` +
	`{"name":"forge","apply":[{"hosts":["git.example","api.git.example"],"scheme":"basic","username":"x-access-token"}]}]}`

// TestEachKeyAfterA401IsRenewedAlone pins the requests of renewals due together: each
// model key whose renewal after a 401 is pending goes in a request that names it alone,
// with itself as unauthorized, and the other credentials in one request with none,
// since the server returns 409 to a whole request that has a name it cannot seal.
func TestEachKeyAfterA401IsRenewedAlone(t *testing.T) {
	c := &fakeClock{now: start}
	s := &controlPlane{answer: func(name string, call int) (answer, error) {
		if name == "model-2" {
			return answer{value: fmt.Sprintf("model-2-%d", call), expires: start.Add(time.Hour)}, nil
		}
		return expiring(name, call)
	}}
	r := renewRun(t, twoKeysDoc, s, c, &reports{}, &reports{})
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", c.Now)
	r.SetKeyGroup(g)
	var forge func()
	for _, u := range r.Uses() {
		if u.Name == "forge" {
			forge = u.Rejected
		}
	}
	c.advance(credential.RetryWait)
	g.Reject("model", true)
	g.Reject("model-2", true)
	n := c.count()
	forge()
	c.idle(t, n)
	calls := s.called()[1:]
	s.mu.Lock()
	unauth := slices.Clone(s.unauth[1:])
	s.mu.Unlock()
	want := [][]string{{"model"}, {"model-2"}, {"forge"}}
	if len(calls) != 3 {
		t.Fatalf("the renewals %v; want 3 requests", calls)
	}
	for i, w := range want {
		if !slices.Equal(calls[i][1:], w) {
			t.Errorf("request %d names %v; want %v", i+1, calls[i][1:], w)
		}
	}
	if !slices.Equal(unauth[0], []string{"model"}) || !slices.Equal(unauth[1], []string{"model-2"}) || unauth[2] != nil {
		t.Errorf("the requests' unauthorized %v; want [model], [model-2], none", unauth)
	}
	if g.Unauthorized() != nil {
		t.Errorf("after the renewals: %+v; want both keys back", g.Unauthorized())
	}
}

// TestARevokedKeyIsLeftOutOfTheReopen pins Config.Revoked, a reopened run whose record
// has model out after a 401: the secrets request leaves model out and keeps the order
// of the rest, model gets no value, and no renewal requests it.
func TestARevokedKeyIsLeftOutOfTheReopen(t *testing.T) {
	c := &fakeClock{now: start}
	s := &controlPlane{answer: expiring}
	f := document(t, twoKeysDoc, digest('1'))
	f.Document.Computed = digest('c')
	n := c.count()
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: f, Secrets: s.fetch, Clock: c, Report: (&reports{}).report, Revoked: []string{"model"}})
	c.idle(t, n)
	if got := s.called(); len(got) != 1 || !slices.Equal(got[0], []string{digest('c'), "model-2", "forge"}) {
		t.Fatalf("the reopen's request %v; want model-2 and forge", got)
	}
	if value(r, "model") != "(none)" {
		t.Errorf("model's value %s; want none", value(r, "model"))
	}
	c.step(t, time.Hour-credential.RenewBefore)
	for _, call := range s.called()[1:] {
		if slices.Contains(call, "model") {
			t.Errorf("a renewal requests model: %v", call)
		}
	}
	if len(s.called()) < 2 {
		t.Error("no renewal of forge")
	}
}

// TestAPendingKeyIsRenewedAloneAfterTheReopen pins Config.Pending, a reopened run whose
// record has model's renewal after a 401 pending: the secrets request leaves model out,
// model has no value and no renewal until the key group has it pending, then one
// request names model alone with model as unauthorized. A 200 puts model back in the
// group with its value; a signed 409 takes it out, with no value and no renewal.
func TestAPendingKeyIsRenewedAloneAfterTheReopen(t *testing.T) {
	for _, c := range []struct {
		name  string
		fail  error
		value string
	}{
		{"200", nil, "model-1"},
		{"409", &server.AnswerError{What: "secrets https://apiary.example/v1/secrets", Status: http.StatusConflict}, "(none)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			clock := &fakeClock{now: start}
			s := &controlPlane{answer: expiring, fail: func(call int) error {
				if call == 1 {
					return c.fail
				}
				return nil
			}}
			f := document(t, twoKeysDoc, digest('1'))
			f.Document.Computed = digest('c')
			n := clock.count()
			r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: f, Secrets: s.fetch, Clock: clock, Report: (&reports{}).report, Log: (&reports{}).report, Pending: []string{"model"}})
			clock.idle(t, n)
			if got := s.called(); len(got) != 1 || !slices.Equal(got[0], []string{digest('c'), "model-2", "forge"}) {
				t.Fatalf("the reopen's request %v; want model-2 and forge", got)
			}
			if value(r, "model") != "(none)" {
				t.Errorf("model's value before its renewal %s; want none", value(r, "model"))
			}
			g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", clock.Now)
			r.SetKeyGroup(g)
			g.Restore([]modelkey.Unauthorized{{Credential: "model", At: start}})
			n = clock.count()
			if !r.Renew("model") {
				t.Fatal("Renew of the pending key reports no renewal")
			}
			clock.idle(t, n)
			calls := s.called()
			s.mu.Lock()
			unauth := slices.Clone(s.unauth)
			s.mu.Unlock()
			if len(calls) != 2 || !slices.Equal(calls[1][1:], []string{"model"}) || !slices.Equal(unauth[1], []string{"model"}) {
				t.Fatalf("the requests %v, unauthorized %v; want model alone as unauthorized", calls, unauth)
			}
			if got := value(r, "model"); got != c.value {
				t.Errorf("model's value %s; want %s", got, c.value)
			}
			u := g.Unauthorized()
			switch {
			case c.fail == nil && u != nil:
				t.Errorf("after the 200: %+v; want model back", u)
			case c.fail != nil && (len(u) != 1 || !u[0].Out):
				t.Errorf("after the 409: %+v; want model out", u)
			case c.fail != nil && r.Renew("model"):
				t.Error("a renewal of model after the 409")
			}
		})
	}
}

// keysOnlyDoc is twoKeysDoc with no credential outside model's key group.
const keysOnlyDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}},"model_credential":"model","credentials":[` +
	`{"name":"model","format":"anthropic-messages","pause_for_s":18000,"endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}},` +
	`{"name":"model-2","format":"anthropic-messages","pause_for_s":18000,"endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}}]}`

// TestAReopenWithEveryKeyLeftOutSendsNoRequest pins a reopened run whose every
// credential is out or pending after a 401: the contract's secrets request names at
// least one credential, so the reopen sends none and the run opens with no value. The
// pending key's renewal, alone, then brings its value, and a renewal of another
// pending key puts that one in place beside it.
func TestAReopenWithEveryKeyLeftOutSendsNoRequest(t *testing.T) {
	clock := &fakeClock{now: start}
	s := &controlPlane{answer: func(name string, call int) (answer, error) {
		return answer{value: fmt.Sprintf("%s-%d", name, call), expires: start.Add(time.Hour)}, nil
	}}
	f := document(t, keysOnlyDoc, digest('1'))
	f.Document.Computed = digest('c')
	// The renewer sets no timer: no renewal is due before the key group has a key
	// pending.
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: f, Secrets: s.fetch, Clock: clock, Report: (&reports{}).report, Log: (&reports{}).report, Pending: []string{"model", "model-2"}})
	if got := s.called(); len(got) != 0 {
		t.Fatalf("the reopen sent %v; want no request", got)
	}
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", clock.Now)
	r.SetKeyGroup(g)
	g.Restore([]modelkey.Unauthorized{{Credential: "model", At: start}, {Credential: "model-2", At: start}})
	for _, name := range []string{"model", "model-2"} {
		n := clock.count()
		if !r.Renew(name) {
			t.Fatalf("Renew of %s reports no renewal", name)
		}
		clock.idle(t, n)
	}
	for i, call := range s.called() {
		if len(call) != 2 {
			t.Errorf("request %d names %v; want one key", i+1, call[1:])
		}
	}
	if got := len(s.called()); got != 2 {
		t.Errorf("%d requests; want one per key", got)
	}
	if value(r, "model") != "model-0" || value(r, "model-2") != "model-2-1" {
		t.Errorf("the values %s, %s; want model-0 and model-2-1", value(r, "model"), value(r, "model-2"))
	}
	if u := g.Unauthorized(); u != nil {
		t.Errorf("after the renewals: %+v; want both keys back", u)
	}
}

// TestAPendingKeysFirstApplyIsTaken pins the apply of a model key with no value at the
// reopen, whose credentials the proxy built with its entry's items: a first value with
// that apply puts the key back in the group, and the next renewal puts its value in
// place. A first value with another apply within the entry takes the key out, with
// no value and a line that starts with the fix; one outside the entry takes it out.
func TestAPendingKeysFirstApplyIsTaken(t *testing.T) {
	for _, c := range []struct {
		name  string
		apply sealed.Apply
		value string
		line  string
	}{
		{"same", sealed.Apply{Hosts: []string{"api.model.example"}, Scheme: "header", Header: "x-api-key"}, "model-2", ""},
		{"other paths", sealed.Apply{Hosts: []string{"api.model.example"}, Scheme: "header", Header: "x-api-key", Paths: []string{"/anthropic/*"}}, "(none)",
			`Store a value of the model key "model" whose apply matches its run configuration entry`},
		{"outside", sealed.Apply{Hosts: []string{"other.example"}, Scheme: "header", Header: "x-api-key"}, "(none)", `Store in the control plane a value of the model key "model"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			clock := &fakeClock{now: start}
			s := &controlPlane{answer: func(name string, call int) (answer, error) {
				if name == "model" {
					return answer{value: fmt.Sprintf("model-%d", call), expires: start.Add(time.Hour), apply: []sealed.Apply{c.apply}}, nil
				}
				return renewing(name, call)
			}}
			f := document(t, twoKeysDoc, digest('1'))
			f.Document.Computed = digest('c')
			log := &reports{}
			r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: f, Secrets: s.fetch, Clock: clock, Report: (&reports{}).report, Log: log.report, Pending: []string{"model"}})
			g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", clock.Now)
			r.SetKeyGroup(g)
			g.Restore([]modelkey.Unauthorized{{Credential: "model", At: start}})
			renew := func() {
				t.Helper()
				n := clock.count()
				if !r.Renew("model") {
					return
				}
				clock.idle(t, n)
			}
			renew()
			clock.advance(credential.RetryWait)
			g.Reject("model", true)
			renew()
			if got := value(r, "model"); got != c.value {
				t.Errorf("model's value %s; want %s", got, c.value)
			}
			u := g.Unauthorized()
			switch {
			case c.line == "" && u != nil:
				t.Errorf("the keys after a 401 %+v; want none", u)
			case c.line != "" && (len(u) != 1 || !u[0].Out):
				t.Errorf("the keys after a 401 %+v; want model out", u)
			case c.line != "" && !log.reported(c.line):
				t.Errorf("the record %q; want a line that starts %q", log.said, c.line)
			}
		})
	}
}

// TestEachModelKeyIsRenewedAlone pins a renewal round with no 401: the two model keys
// and forge expire together, and the round sends three requests, each model key alone
// and forge alone, none with an unauthorized. A signed 409 to model-2's request leaves
// forge and model renewed, and model-2 with its value and in the key group.
func TestEachModelKeyIsRenewedAlone(t *testing.T) {
	for _, c := range []struct {
		name string
		fail error
		want map[string]string
	}{
		{"200", nil, map[string]string{"model": "model-1", "model-2": "model-2-2", "forge": "forge-3"}},
		{"409", &server.AnswerError{What: "secrets https://apiary.example/v1/secrets", Status: http.StatusConflict}, map[string]string{"model": "model-1", "model-2": "model-2-0", "forge": "forge-3"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			clock := &fakeClock{now: start}
			s := &controlPlane{
				answer: func(name string, call int) (answer, error) {
					return answer{value: fmt.Sprintf("%s-%d", name, call), expires: start.Add(time.Hour + time.Duration(call)*time.Hour)}, nil
				},
				fail: func(call int) error {
					if call == 2 {
						return c.fail
					}
					return nil
				},
			}
			r := renewRun(t, twoKeysDoc, s, clock, &reports{}, &reports{})
			g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", clock.Now)
			r.SetKeyGroup(g)
			clock.step(t, time.Hour-credential.RenewBefore)
			calls := s.called()
			s.mu.Lock()
			unauth := slices.Clone(s.unauth)
			s.mu.Unlock()
			if len(calls) != 4 {
				t.Fatalf("the requests %v; want the start's and three", calls)
			}
			for i, w := range [][]string{{"model"}, {"model-2"}, {"forge"}} {
				if !slices.Equal(calls[i+1][1:], w) || unauth[i+1] != nil {
					t.Errorf("request %d has %v, unauthorized %v; want %v, none", i+1, calls[i+1][1:], unauth[i+1], w)
				}
			}
			for name, want := range c.want {
				if got := value(r, name); got != want {
					t.Errorf("%s's value %s; want %s", name, got, want)
				}
			}
			if u := g.Unauthorized(); u != nil {
				t.Errorf("the keys after a 401 %+v; want none", u)
			}
		})
	}
}
