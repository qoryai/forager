package runcredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/event"
)

// IntrospectionTimeout is how long the gateway waits for an introspection endpoint's
// whole answer to one try, from the connection to the last byte.
const IntrospectionTimeout = 2 * time.Second

// The tries of one introspection: up to three, the second [introspectionWaits][0]
// after the first ends and the third [introspectionWaits][1] after the second, and a
// try starts only within [introspectionWindow] of the first's start. A check therefore
// ends within about 3 seconds when the endpoint refuses connections at once, and within
// 5 when every try hangs, inside the 10 seconds a session's request and a client's
// proxy login wait.
var (
	introspectionWaits  = []time.Duration{time.Second, 2 * time.Second}
	introspectionWindow = 4 * time.Second
)

// MaxIntrospectionAnswer is the largest answer of an introspection endpoint the gateway
// reads, in bytes; a longer one is no valid answer.
const MaxIntrospectionAnswer = 64 << 10

// ErrIssuerUnreachable is an introspection whose every try failed to get an answer: a
// transport, TLS or timeout failure, a failed read of the answer, a 5xx or a 429.
var ErrIssuerUnreachable = errors.New("the introspection endpoint could not be reached")

// ErrAnswerInvalid is what every introspection the endpoint answered with no valid
// answer wraps: a status other than 200, 5xx and 429 aside, and a 200 that is too long,
// not one JSON object with each member name once, or without a boolean active. It is
// tried once.
var ErrAnswerInvalid = errors.New("the introspection endpoint gave no valid answer")

// The failures of one introspection request. Each is a constant text: none names the
// run credential, the client secret, or anything the endpoint answered but its status.
var (
	errIntrospectionUnreachable = errors.New("the introspection endpoint could not be asked")
	errIntrospectionTooLong     = invalidAnswer("the introspection endpoint answered more than MaxIntrospectionAnswer bytes")
	errIntrospectionNotJSON     = invalidAnswer("the introspection endpoint answered other than one JSON object with each member name once")
	errIntrospectionNoActive    = invalidAnswer("the introspection endpoint answered no boolean active")
)

// invalidAnswer is a failure of an answer the endpoint gave, which is [ErrAnswerInvalid].
type invalidAnswer string

func (e invalidAnswer) Error() string { return string(e) }

// Unwrap is [ErrAnswerInvalid].
func (invalidAnswer) Unwrap() error { return ErrAnswerInvalid }

// errIntrospectionStatus is the failure of an answer with a status other than 200 that
// is not tried again: it names the status.
func errIntrospectionStatus(status int) error {
	return invalidAnswer(fmt.Sprintf("the introspection endpoint answered status %d", status))
}

// Introspector asks an issuer's OAuth 2.0 token introspection endpoint (RFC 7662)
// whether a run credential is still active, and keeps each answer it gives for the
// cache. It is safe for concurrent use.
type Introspector struct {
	endpoint string
	// authorization is the value of the Authorization header, HTTP Basic with the
	// client id and secret.
	authorization string
	cache         time.Duration
	client        *http.Client
	// waits are the waits between tries, and window how long after the first try's
	// start a try may start; sleep waits, which a test replaces.
	waits  []time.Duration
	window time.Duration
	sleep  func(time.Duration)

	mu       sync.Mutex
	answers  map[[sha256.Size]byte]introspection
	inflight map[[sha256.Size]byte]*introspectionCall
}

// introspection is one answer, kept until until.
type introspection struct {
	answer Answer
	until  time.Time
}

// Answer is a valid answer of an introspection endpoint: whether the run credential is
// still active, and of one that is not, how the run's starter says its run ended, the
// answer's members qory_outcome and qory_reason (contracts/forager/v1 README.md §Run
// credentials, How a run's starter says how it ended).
type Answer struct {
	Active bool
	// Outcome is qory_outcome of an inactive answer: succeeded, failed or cancelled;
	// empty when the answer holds none, or one that is none of the three, which counts
	// as none.
	Outcome string
	// Reason is qory_reason of an inactive answer with an outcome, a code of the pattern
	// of dev.qory.run.exited's reason, as given; empty when the answer holds none, or one
	// that is no code or is one of Forager's reserved codes, which is dropped.
	Reason string
}

// StarterOutcome is how the run's starter said its run ended, by the rules of
// qory_outcome and qory_reason: an outcome other than succeeded, failed and cancelled is
// none, and drops the reason with it; a reason that does not match the pattern of
// dev.qory.run.exited's reason, or is one of Forager's reserved codes, is dropped, and
// the outcome kept.
func StarterOutcome(outcome, reason string) (string, string) {
	if !event.IsState(outcome) {
		return "", ""
	}
	if !event.StarterReason(reason) {
		reason = ""
	}
	return outcome, reason
}

// MaxIntrospectionAnswers is how many answers an [Introspector] keeps at once: past it,
// the answer that would lapse first goes, so the cache does not grow with the run
// credentials a gateway has seen.
const MaxIntrospectionAnswers = 4096

// maxAnswers is [MaxIntrospectionAnswers], which a test lowers.
var maxAnswers = MaxIntrospectionAnswers

// introspectionCall is a request in flight, which other callers for the same run
// credential wait for.
type introspectionCall struct {
	done   chan struct{}
	answer Answer
	err    error
}

// NewIntrospector makes the client of an issuer's introspection endpoint. It reads the
// client's secret from in.ClientSecretFile with read, once: the file's bytes, less one
// line ending at their end, and not empty. An answer holds for in.Cache, or for
// heartbeat, the run's heartbeat interval, when it sets none.
//
// The endpoint is https, and every request is made over TLS 1.2 or later under the
// system's roots, directly, through no proxy, and follows no redirect. The error names
// the file, never what it holds.
func NewIntrospector(in Introspection, read ReadFile, heartbeat time.Duration) (*Introspector, error) {
	return newIntrospector(in, read, heartbeat, nil, IntrospectionTimeout)
}

// newIntrospector is [NewIntrospector] under roots, the system's when nil, with a
// timeout of each try of its own, which the tests alone set.
func newIntrospector(in Introspection, read ReadFile, heartbeat time.Duration, roots *x509.CertPool, timeout time.Duration) (*Introspector, error) {
	if err := checkHTTPS(in.URL); err != nil {
		return nil, fmt.Errorf("introspection: %w", err)
	}
	if in.ClientID == "" || in.ClientSecretFile == "" {
		return nil, fmt.Errorf("introspection: no client id or no client secret file")
	}
	cache := in.CacheOr(heartbeat)
	if cache <= 0 {
		return nil, fmt.Errorf("introspection: the cache is not positive")
	}
	if read == nil {
		return nil, fmt.Errorf("introspection: the client secret %s: no way to read it", in.ClientSecretFile)
	}
	b, err := read(in.ClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("introspection: the client secret %s: %w", in.ClientSecretFile, err)
	}
	secret := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if secret == "" {
		return nil, fmt.Errorf("introspection: the client secret %s is empty", in.ClientSecretFile)
	}
	// RFC 6749 §2.3.1: the client id and the secret are each form-encoded, then joined
	// for HTTP Basic (RFC 7617).
	credentials := url.QueryEscape(in.ClientID) + ":" + url.QueryEscape(secret)
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: timeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Introspector{
		endpoint:      in.URL,
		authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials)),
		cache:         cache,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		waits:    introspectionWaits,
		window:   introspectionWindow,
		sleep:    time.Sleep,
		answers:  map[[sha256.Size]byte]introspection{},
		inflight: map[[sha256.Size]byte]*introspectionCall{},
	}, nil
}

// Cache is how long an answer holds before the endpoint is asked again.
func (c *Introspector) Cache() time.Duration { return c.cache }

// Active asks whether a run credential is still active, at now: [Introspector.Answer]'s
// Active.
func (c *Introspector) Active(ctx context.Context, credential string, now time.Time) (bool, error) {
	a, err := c.Answer(ctx, credential, now)
	return a.Active, err
}

// Answer asks whether a run credential is still active, at now, and of one that is not,
// how the run's starter says its run ended. It is active only when the endpoint
// answered status 200 with one JSON object, each member name once, at most
// [MaxIntrospectionAnswer] bytes, whose member active is the JSON true. An answer active
// false is not active with a nil error, and carries its qory_outcome and qory_reason by
// the rules of [StarterOutcome]: neither member makes the answer invalid, and a bad one
// is dropped. Any other answer, and a failure to ask, is not active with an error, so
// the check fails closed: [ErrIssuerUnreachable] once every try failed to get an
// answer, and an error that is [ErrAnswerInvalid] for an answer that is no valid one.
// The error is a constant text, which names neither the run credential nor the client
// secret.
//
// A try that gets no answer, a transport, TLS or timeout failure, a failed read of the
// answer, a 5xx or a 429, is tried again: up to three tries, each bounded by its own
// timeout, 1 second and then 2 seconds apart, and a try starts only within 4 seconds of
// the first. An answer, valid or not, is tried once.
//
// An answer the endpoint gave, active or not, is kept for [Introspector.Cache] by the
// SHA-256 of the run credential, at most [MaxIntrospectionAnswers] of them, and the
// endpoint is asked again only once it is older; a failure to ask, or an answer that is
// not one, is kept for no one, and the next caller asks again. Callers for the same run
// credential while its tries are in flight wait for their end. The tries are made for
// all of them, whatever becomes of the caller that started them: a caller whose ctx
// ends first is not active with ctx's error, alone, and the others still get the answer.
func (c *Introspector) Answer(ctx context.Context, credential string, now time.Time) (Answer, error) {
	key := sha256.Sum256([]byte(credential))
	c.mu.Lock()
	if a, ok := c.answers[key]; ok {
		if now.Before(a.until) {
			c.mu.Unlock()
			return a.answer, nil
		}
		delete(c.answers, key)
	}
	f, ok := c.inflight[key]
	if !ok {
		f = &introspectionCall{done: make(chan struct{})}
		c.inflight[key] = f
		go c.call(f, key, credential, now, true)
	}
	c.mu.Unlock()
	return wait(ctx, f)
}

// AnswerNow is [Introspector.Answer], asked of the endpoint now, not from the cache and
// sharing no call in flight: the gateway's one ask of a run's starter at its runtime's
// exit. Its answer is kept for the callers of Answer after it, as theirs are.
func (c *Introspector) AnswerNow(ctx context.Context, credential string, now time.Time) (Answer, error) {
	f := &introspectionCall{done: make(chan struct{})}
	go c.call(f, sha256.Sum256([]byte(credential)), credential, now, false)
	return wait(ctx, f)
}

// wait is the answer of the call f, or ctx's error once ctx ends first.
func wait(ctx context.Context, f *introspectionCall) (Answer, error) {
	select {
	case <-f.done:
		return f.answer, f.err
	case <-ctx.Done():
		return Answer{}, ctx.Err()
	}
}

// call makes the tries f stands for, each bounded by the client's own timeout and by no
// caller's context, and keeps the answer when it is one; inflight says f is among the
// calls in flight, which it leaves.
func (c *Introspector) call(f *introspectionCall, key [sha256.Size]byte, credential string, now time.Time, inflight bool) {
	f.answer, f.err = c.try(credential)
	c.mu.Lock()
	if inflight {
		delete(c.inflight, key)
	}
	if f.err == nil {
		c.keep(key, introspection{answer: f.answer, until: now.Add(c.cache)}, now)
	}
	c.mu.Unlock()
	close(f.done)
}

// keep keeps an answer: the answers past their time at now go first, and while the
// cache is full, the one that would lapse first. Called with c.mu held.
func (c *Introspector) keep(key [sha256.Size]byte, a introspection, now time.Time) {
	for k, kept := range c.answers {
		if !now.Before(kept.until) {
			delete(c.answers, k)
		}
	}
	for len(c.answers) >= maxAnswers {
		var first [sha256.Size]byte
		var at time.Time
		for k, kept := range c.answers {
			if at.IsZero() || kept.until.Before(at) {
				first, at = k, kept.until
			}
		}
		delete(c.answers, first)
	}
	c.answers[key] = a
}

// try asks the endpoint, again after a try that got no answer, until one does, the
// tries run out, or the next would start past the window: then [ErrIssuerUnreachable].
func (c *Introspector) try(credential string) (Answer, error) {
	first := time.Now()
	for n := 0; ; n++ {
		a, err := c.ask(context.Background(), credential)
		if !errors.Is(err, errIntrospectionUnreachable) {
			return a, err
		}
		if n >= len(c.waits) || time.Since(first)+c.waits[n] > c.window {
			return Answer{}, ErrIssuerUnreachable
		}
		c.sleep(c.waits[n])
	}
}

// ask makes one introspection request (RFC 7662 §2.1) and reads its answer (§2.2): of
// an inactive answer, its qory_outcome and qory_reason too, a member that is no string
// as one that is no outcome or no code. A try that got no answer, a 5xx and a 429 among
// it, is errIntrospectionUnreachable.
func (c *Introspector) ask(ctx context.Context, credential string) (Answer, error) {
	form := url.Values{"token": {credential}, "token_type_hint": {"access_token"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form))
	if err != nil {
		return Answer{}, errIntrospectionUnreachable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.authorization)
	res, err := c.client.Do(req)
	if err != nil {
		return Answer{}, errIntrospectionUnreachable
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxIntrospectionAnswer+1))
	if res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests {
		return Answer{}, errIntrospectionUnreachable
	}
	if res.StatusCode != http.StatusOK {
		return Answer{}, errIntrospectionStatus(res.StatusCode)
	}
	if err != nil {
		return Answer{}, errIntrospectionUnreachable
	}
	if len(body) > MaxIntrospectionAnswer {
		return Answer{}, errIntrospectionTooLong
	}
	var answer map[string]any
	if decodeObject(bytes.TrimLeft(body, " \t\r\n"), &answer) != nil {
		return Answer{}, errIntrospectionNotJSON
	}
	active, ok := answer["active"].(bool)
	if !ok {
		return Answer{}, errIntrospectionNoActive
	}
	if active {
		return Answer{Active: true}, nil
	}
	outcome, _ := answer["qory_outcome"].(string)
	reason, _ := answer["qory_reason"].(string)
	outcome, reason = StarterOutcome(outcome, reason)
	return Answer{Outcome: outcome, Reason: reason}, nil
}
