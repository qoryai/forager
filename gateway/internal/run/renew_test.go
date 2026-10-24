package run_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/sealed"
)

// renewDoc is a run configuration with a model key and a host credential, forge, set
// as basic on git.example and api.git.example, under a policy that allows them.
const renewDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","git.example","api.git.example"]}},"credentials":[` +
	`{"name":"model","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}},` +
	`{"name":"forge","apply":[{"hosts":["git.example","api.git.example"],"scheme":"basic","username":"x-access-token"}]}]}`

// start is the fake clock's time when a test's run opens.
var start = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// fakeClock is a [run.Clock] that moves only when the test advances it. Each After
// call is counted, so a test can wait until the renewer waits again.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []fakeTimer
	calls  int
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.timers = append(c.timers, fakeTimer{c.now.Add(d), ch})
	return ch
}

// count is how many times After was called.
func (c *fakeClock) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// advance moves the clock by d and fires every timer due.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	var left []fakeTimer
	for _, t := range c.timers {
		if t.at.After(c.now) {
			left = append(left, t)
			continue
		}
		t.ch <- c.now
	}
	c.timers = left
}

// idle waits until After was called more than n times: the renewer waits again.
func (c *fakeClock) idle(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for c.count() <= n {
		if time.Now().After(deadline) {
			t.Fatalf("the renewer did not wait again after %d waits", n)
		}
		time.Sleep(time.Millisecond)
	}
}

// step advances the clock by d, which fires a timer, and waits until the renewer
// waits again.
func (c *fakeClock) step(t *testing.T, d time.Duration) {
	t.Helper()
	n := c.count()
	c.advance(d)
	c.idle(t, n)
}

// answer is what the fake server seals for one credential.
type answer struct {
	value   string
	expires time.Time
	apply   []sealed.Apply
}

// controlPlane is a Config.Secrets that answers each name with answer, and records each
// call's digest and names. answer gets the call's number, from 0, the start's.
type controlPlane struct {
	mu     sync.Mutex
	calls  [][]string
	answer func(name string, call int) (answer, error)
	// opened are the Values of each call, so a test can see the bytes it handed out.
	opened []sealed.Values
	// block, when set, makes every call after the start's wait until its context ends.
	block bool
}

func (s *controlPlane) fetch(ctx context.Context, digest string, names []string) (sealed.Values, error) {
	s.mu.Lock()
	call := len(s.calls)
	s.calls = append(s.calls, append([]string{digest}, names...))
	block := s.block && call > 0
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return sealed.Values{}, ctx.Err()
	}
	sl := sealed.Sealing{AccessKeyID: "ak_0123456789abcdef", RunID: runID, RunConfiguration: digest, Credentials: names, Exp: 1}
	for _, n := range names {
		a, err := s.answer(n, call)
		if err != nil {
			return sealed.Values{}, err
		}
		v := sealed.NewValue(n, []byte(a.value))
		v.ExpiresAt, v.Apply = a.expires, a.apply
		sl.Values = append(sl.Values, v)
	}
	pt, err := sl.Plaintext()
	if err != nil {
		return sealed.Values{}, err
	}
	v, err := sealed.Plaintext(pt, digest, names)
	if err == nil {
		s.mu.Lock()
		s.opened = append(s.opened, v)
		s.mu.Unlock()
	}
	return v, err
}

func (s *controlPlane) called() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// renewing answers forge with forge-<call>, expiring an hour after the call's start
// time plus call minutes, and model with a key that does not expire.
func renewing(name string, call int) (answer, error) {
	if name == "model" {
		return answer{value: "sk-model-fake"}, nil
	}
	return answer{value: fmt.Sprintf("forge-%d", call), expires: start.Add(time.Hour + time.Duration(call)*time.Hour)}, nil
}

// renewRun opens a run of doc with the server s, the clock c and the reports rep, and
// waits until its renewer waits.
func renewRun(t *testing.T, doc string, s *controlPlane, c *fakeClock, rep *reports, log *reports) *run.Run {
	t.Helper()
	f := document(t, doc, digest('1'))
	f.Document.Computed = digest('c')
	cfg := run.Config{RunID: runID, Wall: true, Server: true, Fetched: f, Secrets: s.fetch, Clock: c, Report: rep.report}
	if log != nil {
		cfg.Log = log.report
	}
	n := c.count()
	r := open(t, cfg)
	c.idle(t, n)
	return r
}

// value is the value the run's proxy sets for the credential name now, "(none)" when
// it sets none.
func value(r *run.Run, name string) string {
	for _, u := range r.Uses() {
		if u.Name == name && u.Value != nil {
			if v := u.Value(); len(v) > 0 {
				return string(v)
			}
		}
	}
	return "(none)"
}

// TestAValueIsRenewedBeforeItExpires pins the timing of a renewal: nothing is asked
// for until RenewBefore before expires_at, and then the due credential alone, under
// the digest Forager computed; the renewed value takes the old one's place, whose bytes
// are zeros, and the next renewal comes RenewBefore before the renewed expires_at. A
// model key without expires_at is never asked for again.
func TestAValueIsRenewedBeforeItExpires(t *testing.T) {
	c := &fakeClock{now: start}
	s := &controlPlane{answer: renewing}
	r := renewRun(t, renewDoc, s, c, &reports{}, nil)
	if got := s.called(); len(got) != 1 || !slices.Equal(got[0], []string{digest('c'), "model", "forge"}) {
		t.Fatalf("calls at the start %v", got)
	}
	old, _ := s.opened[0].Value("forge")
	c.advance(time.Hour - credential.RenewBefore - time.Second)
	if got := s.called(); len(got) != 1 || value(r, "forge") != "forge-0" {
		t.Fatalf("before RenewBefore: calls %v, forge %s", got, value(r, "forge"))
	}
	c.step(t, time.Second)
	if got := s.called(); len(got) != 2 || !slices.Equal(got[1], []string{digest('c'), "forge"}) {
		t.Fatalf("at RenewBefore: calls %v", got)
	}
	if value(r, "forge") != "forge-1" || value(r, "model") != "sk-model-fake" {
		t.Errorf("after the renewal: forge %s, model %s", value(r, "forge"), value(r, "model"))
	}
	if string(old) != strings.Repeat("\x00", len(old)) {
		t.Errorf("the old value's bytes are %q; want zeros", old)
	}
	// The renewed value expires at start + 2h: the next renewal is RenewBefore before.
	c.advance(time.Hour - time.Second)
	if got := s.called(); len(got) != 2 {
		t.Fatalf("before the second renewal: calls %v", got)
	}
	c.step(t, time.Second)
	if got := s.called(); len(got) != 3 || !slices.Equal(got[2], []string{digest('c'), "forge"}) || value(r, "forge") != "forge-2" {
		t.Errorf("the second renewal: calls %v, forge %s", got, value(r, "forge"))
	}
}

// TestCredentialsDueTogetherGoInOneRequest pins the batching: two credentials whose
// renewals come within RetryWait of each other are asked for in one request, in the
// document's order, and a third, due later, alone in a second request.
func TestCredentialsDueTogetherGoInOneRequest(t *testing.T) {
	doc := `{"version":1,"credentials":[` +
		`{"name":"a","apply":[{"hosts":["a.example"],"scheme":"bearer"}]},` +
		`{"name":"b","apply":[{"hosts":["b.example"],"scheme":"bearer"}]},` +
		`{"name":"c","apply":[{"hosts":["c.example"],"scheme":"bearer"}]}]}`
	expires := map[string]time.Duration{"a": time.Hour + 20*time.Second, "b": time.Hour, "c": time.Hour + time.Minute}
	c := &fakeClock{now: start}
	s := &controlPlane{answer: func(name string, call int) (answer, error) {
		return answer{value: fmt.Sprintf("%s-%d", name, call), expires: start.Add(expires[name] + time.Duration(call)*time.Hour)}, nil
	}}
	renewRun(t, doc, s, c, &reports{}, nil)
	c.step(t, time.Hour-credential.RenewBefore)
	if got := s.called(); len(got) != 2 || !slices.Equal(got[1], []string{digest('c'), "a", "b"}) {
		t.Fatalf("calls %v; want a and b together", got)
	}
	c.step(t, time.Minute)
	if got := s.called(); len(got) != 3 || !slices.Equal(got[2], []string{digest('c'), "c"}) {
		t.Errorf("calls %v; want c alone", got)
	}
}

// TestA401AsksAgainAtMostEveryRetryWait pins a host's 401: the proxy's Rejected of a
// value with expires_at asks for it again once RetryWait has passed since the last
// asking, and never sooner; a 401 to a model key without expires_at asks for nothing,
// since its use has no Rejected.
func TestA401AsksAgainAtMostEveryRetryWait(t *testing.T) {
	c := &fakeClock{now: start}
	s := &controlPlane{answer: renewing}
	r := renewRun(t, renewDoc, s, c, &reports{}, nil)
	rejected := func(name string) func() {
		for _, u := range r.Uses() {
			if u.Name == name {
				return u.Rejected
			}
		}
		return nil
	}
	if rejected("model") != nil {
		t.Error("a model key without expires_at has Rejected")
	}
	c.advance(10 * time.Second)
	n := c.count()
	rejected("forge")()
	c.idle(t, n)
	if got := s.called(); len(got) != 1 {
		t.Fatalf("a 401 10 s after the start asked at once: %v", got)
	}
	c.step(t, credential.RetryWait-10*time.Second)
	if got := s.called(); len(got) != 2 || !slices.Equal(got[1], []string{digest('c'), "forge"}) || value(r, "forge") != "forge-1" {
		t.Fatalf("RetryWait after the start: calls %v, forge %s", got, value(r, "forge"))
	}
	c.advance(time.Second)
	n = c.count()
	rejected("forge")()
	c.idle(t, n)
	if got := s.called(); len(got) != 2 {
		t.Fatalf("a second 401 1 s after a renewal asked at once: %v", got)
	}
	c.step(t, credential.RetryWait-time.Second)
	if got := s.called(); len(got) != 3 {
		t.Errorf("RetryWait after the renewal: calls %v", got)
	}
}

// TestAFailedRenewalKeepsTheValue pins a renewal that fails, or whose answer changes
// the start's apply or has no expires_at: the value stays, a report line contains the cause, the
// request goes again RetryWait later, and a value that a later renewal brings takes
// the old one's place.
func TestAFailedRenewalKeepsTheValue(t *testing.T) {
	for name, c := range map[string]struct {
		fail func(call int) (answer, error)
		want string
	}{
		"the request fails": {func(int) (answer, error) {
			return answer{}, errors.New("secrets https://apiary.example/v1/secrets: 503")
		},
			`If this repeats, check the control plane: credential "forge" was not renewed: secrets https://apiary.example/v1/secrets: 503`},
		"another apply": {func(call int) (answer, error) {
			return answer{value: "forge-moved", expires: start.Add(2 * time.Hour), apply: []sealed.Apply{{Hosts: []string{"git.example"}, Scheme: "basic", Username: "x-access-token"}}}, nil
		}, `If this repeats, check the control plane: credential "forge" was not renewed: its apply differs from the start`},
		"no expires_at": {func(int) (answer, error) { return answer{value: "forge-forever"}, nil },
			`If this repeats, check the control plane: credential "forge" was not renewed: the answer has no expires_at`},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{now: start}
			fails := true
			s := &controlPlane{answer: func(n string, call int) (answer, error) {
				if n == "forge" && call > 0 && fails {
					return c.fail(call)
				}
				return renewing(n, call)
			}}
			rep := &reports{}
			r := renewRun(t, renewDoc, s, clock, rep, nil)
			clock.step(t, time.Hour-credential.RenewBefore)
			if value(r, "forge") != "forge-0" || !rep.reported(c.want) {
				t.Fatalf("after the failed renewal: forge %s, reports %q", value(r, "forge"), rep.lines())
			}
			for _, l := range rep.lines() {
				if strings.Contains(l, "forge-moved") || strings.Contains(l, "forge-forever") {
					t.Errorf("a report contains a value: %s", l)
				}
			}
			fails = false
			clock.step(t, credential.RetryWait)
			if got := s.called(); len(got) != 3 || value(r, "forge") != "forge-2" {
				t.Errorf("RetryWait later: calls %v, forge %s", got, value(r, "forge"))
			}
		})
	}
}

// TestAValueThatExpiresIsSetNoMore pins expires_at with no renewal: one line in the
// run's record, the value set no more, and no request after.
func TestAValueThatExpiresIsSetNoMore(t *testing.T) {
	clock := &fakeClock{now: start}
	s := &controlPlane{answer: func(n string, call int) (answer, error) {
		if n == "forge" && call > 0 {
			return answer{}, errors.New("secrets https://apiary.example/v1/secrets: 503")
		}
		return renewing(n, call)
	}}
	log := &reports{}
	r := renewRun(t, renewDoc, s, clock, &reports{}, log)
	clock.step(t, time.Hour-credential.RenewBefore)
	for range int(credential.RenewBefore/credential.RetryWait) - 1 {
		clock.step(t, credential.RetryWait)
	}
	if value(r, "forge") != "forge-0" || len(log.lines()) != 0 {
		t.Fatalf("before expires_at: forge %s, record %q", value(r, "forge"), log.lines())
	}
	calls := len(s.called())
	clock.advance(credential.RetryWait)
	deadline := time.Now().Add(10 * time.Second)
	for len(log.lines()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	want := []string{`Start another run once the control plane answers: credential "forge" expired at 2026-10-24T13:00:00Z`}
	if !slices.Equal(log.lines(), want) || value(r, "forge") != "(none)" || value(r, "model") != "sk-model-fake" {
		t.Errorf("at expires_at: record %q, forge %s, model %s", log.lines(), value(r, "forge"), value(r, "model"))
	}
	clock.advance(time.Hour)
	time.Sleep(20 * time.Millisecond)
	if got := len(s.called()); got != calls {
		t.Errorf("%d requests after expires_at", got-calls)
	}
	if len(log.lines()) != 1 {
		t.Errorf("record %q; want one line", log.lines())
	}
}

// TestARenewalAfterAReloadUsesItsDigest pins the digest of a renewal: the one Forager
// computed of the run configuration in force, a reload's once it is committed. The
// reload resolves the credentials again and starts no second renewer: one request.
func TestARenewalAfterAReloadUsesItsDigest(t *testing.T) {
	clock := &fakeClock{now: start}
	s := &controlPlane{answer: renewing}
	r := renewRun(t, renewDoc, s, clock, &reports{}, nil)
	next := document(t, strings.Replace(renewDoc, `"api.git.example"]}}`, `"api.git.example","b.example"]}}`, 1), digest('2'))
	next.Document.Computed = digest('d')
	d, err := reload(t, r, next)
	if err != nil {
		t.Fatal(err)
	}
	r.Commit(d)
	clock.step(t, time.Hour-credential.RenewBefore)
	if got := s.called(); len(got) != 2 || !slices.Equal(got[1], []string{digest('d'), "forge"}) || value(r, "forge") != "forge-1" {
		t.Errorf("calls %v, forge %s; want one under the reload's digest", got, value(r, "forge"))
	}
}

// TestCloseStopsTheRenewer pins Close: a request in flight ends, no request goes after
// it, and the values are cleared.
func TestCloseStopsTheRenewer(t *testing.T) {
	clock := &fakeClock{now: start}
	s := &controlPlane{answer: renewing, block: true}
	rep := &reports{}
	f := document(t, renewDoc, digest('1'))
	f.Document.Computed = digest('c')
	n := clock.count()
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: f, Secrets: s.fetch, Clock: clock, Report: rep.report})
	if err != nil {
		t.Fatal(err)
	}
	clock.idle(t, n)
	clock.advance(time.Hour - credential.RenewBefore)
	deadline := time.Now().Add(10 * time.Second)
	for len(s.called()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	uses := r.Uses()
	r.Close()
	clock.advance(time.Hour)
	time.Sleep(20 * time.Millisecond)
	if got := s.called(); len(got) != 2 {
		t.Errorf("calls %v; want the start's and the one Close ended", got)
	}
	for _, u := range uses {
		if u.Value != nil && len(u.Value()) != 0 {
			t.Errorf("after Close %s has a value", u.Name)
		}
	}
	if len(rep.lines()) != 0 {
		t.Errorf("reports %q; a renewal Close ended is no failure", rep.lines())
	}
}

// TestTheStartsAnswerIsCheckedAgainstItsEntry pins the open of values with expires_at
// and apply: a value that expired before the run started and an apply outside its
// entry are run_configuration_invalid with the contract's texts; an apply that
// narrows the entry is where the proxy sets the value.
func TestTheStartsAnswerIsCheckedAgainstItsEntry(t *testing.T) {
	narrow := []sealed.Apply{{Hosts: []string{"git.example"}, Scheme: "basic", Username: "x-access-token", Paths: []string{"/example-org/app.git/*"}}}
	for name, c := range map[string]struct {
		forge answer
		want  string
	}{
		"expired": {answer{value: "forge-0", expires: start}, `Tell whoever runs the control plane: credential "forge" expired before the run started`},
		"another host": {answer{value: "forge-0", expires: start.Add(time.Hour), apply: []sealed.Apply{{Hosts: []string{"git2.example"}, Scheme: "basic", Username: "x-access-token"}}},
			`Tell whoever runs the control plane: credential "forge" applies to git2.example, outside its entry`},
		"another scheme": {answer{value: "forge-0", expires: start.Add(time.Hour), apply: []sealed.Apply{{Hosts: []string{"git.example"}, Scheme: "bearer"}}},
			`Tell whoever runs the control plane: credential "forge" applies to git.example, outside its entry`},
	} {
		t.Run(name, func(t *testing.T) {
			s := &controlPlane{answer: func(n string, call int) (answer, error) {
				if n == "forge" {
					return c.forge, nil
				}
				return renewing(n, call)
			}}
			f := document(t, renewDoc, digest('1'))
			f.Document.Computed = digest('c')
			_, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: f, Secrets: s.fetch, Clock: &fakeClock{now: start}})
			if code, names := refusalOf(err); code != "run_configuration_invalid" || !slices.Equal(names, []string{"forge"}) || err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Errorf("%v; want %q", err, c.want)
			}
		})
	}
	s := &controlPlane{answer: func(n string, call int) (answer, error) {
		if n == "forge" {
			return answer{value: fmt.Sprintf("forge-%d", call), expires: start.Add(time.Duration(call+1) * time.Hour), apply: narrow}, nil
		}
		return renewing(n, call)
	}}
	clock := &fakeClock{now: start}
	r := renewRun(t, renewDoc, s, clock, &reports{}, nil)
	for _, u := range r.Uses() {
		if u.Name == "forge" && (!slices.Equal(u.Hosts, []string{"git.example"}) || !slices.Equal(u.Paths, narrow[0].Paths) || u.Rejected == nil) {
			t.Errorf("forge is set on %v %v, Rejected %v", u.Hosts, u.Paths, u.Rejected != nil)
		}
	}
	// A renewal that answers the start's narrowed apply is taken.
	clock.step(t, time.Hour-credential.RenewBefore)
	if value(r, "forge") != "forge-1" {
		t.Errorf("forge %s after a renewal with the start's apply", value(r, "forge"))
	}
}

// lines are what was reported so far.
func (r *reports) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.said)
}
