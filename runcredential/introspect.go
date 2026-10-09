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
)

// IntrospectionTimeout is how long the gateway waits for an introspection endpoint's
// whole answer, from the connection to the last byte.
const IntrospectionTimeout = 10 * time.Second

// MaxIntrospectionAnswer is the largest answer of an introspection endpoint the gateway
// reads, in bytes; a longer one counts as not active.
const MaxIntrospectionAnswer = 64 << 10

// The failures of an introspection request. Each is a constant text: none names the
// run credential, the client secret, or anything the endpoint answered.
var (
	errIntrospectionUnreachable = errors.New("the introspection endpoint could not be asked")
	errIntrospectionStatus      = errors.New("the introspection endpoint answered a status other than 200")
	errIntrospectionTooLong     = errors.New("the introspection endpoint answered more than MaxIntrospectionAnswer bytes")
	errIntrospectionNotJSON     = errors.New("the introspection endpoint answered other than one JSON object with each member name once")
	errIntrospectionNoActive    = errors.New("the introspection endpoint answered no boolean active")
)

// Introspector asks an issuer's OAuth 2.0 token introspection endpoint (RFC 7662)
// whether a run credential is still active, and keeps each answer for the cache. It is
// safe for concurrent use.
type Introspector struct {
	endpoint string
	// authorization is the value of the Authorization header, HTTP Basic with the
	// client id and secret.
	authorization string
	cache         time.Duration
	client        *http.Client

	mu       sync.Mutex
	answers  map[[sha256.Size]byte]introspection
	inflight map[[sha256.Size]byte]*introspectionCall
}

// introspection is one answer, kept until until.
type introspection struct {
	active bool
	err    error
	until  time.Time
}

// introspectionCall is a request in flight, which other callers for the same run
// credential wait for.
type introspectionCall struct {
	done   chan struct{}
	active bool
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
// timeout of its own, which the tests alone set.
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
		answers:  map[[sha256.Size]byte]introspection{},
		inflight: map[[sha256.Size]byte]*introspectionCall{},
	}, nil
}

// Cache is how long an answer holds before the endpoint is asked again.
func (c *Introspector) Cache() time.Duration { return c.cache }

// Active asks whether a run credential is still active, at now. It is true only when
// the endpoint answered status 200 with one JSON object, each member name once, at most
// [MaxIntrospectionAnswer] bytes, whose member active is the JSON true. An answer
// active false is false with a nil error; any other answer, and a failure to ask, is
// false with an error, so the check fails closed. The error is a constant text, which
// names neither the run credential nor the client secret.
//
// An answer is kept for [Introspector.Cache] by the SHA-256 of the run credential, and
// the endpoint is asked again only once it is older; callers for the same run
// credential while a request is in flight wait for its answer. A request whose ctx ends
// first is false, and is not kept.
func (c *Introspector) Active(ctx context.Context, credential string, now time.Time) (bool, error) {
	key := sha256.Sum256([]byte(credential))
	c.mu.Lock()
	if a, ok := c.answers[key]; ok && now.Before(a.until) {
		c.mu.Unlock()
		return a.active, a.err
	}
	if f, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.active, f.err
		case <-ctx.Done():
			return false, errIntrospectionUnreachable
		}
	}
	f := &introspectionCall{done: make(chan struct{})}
	c.inflight[key] = f
	for k, a := range c.answers {
		if !now.Before(a.until) {
			delete(c.answers, k)
		}
	}
	c.mu.Unlock()

	f.active, f.err = c.ask(ctx, credential)

	c.mu.Lock()
	delete(c.inflight, key)
	if ctx.Err() == nil {
		c.answers[key] = introspection{active: f.active, err: f.err, until: now.Add(c.cache)}
	}
	c.mu.Unlock()
	close(f.done)
	return f.active, f.err
}

// ask makes one introspection request (RFC 7662 §2.1) and reads its answer (§2.2).
func (c *Introspector) ask(ctx context.Context, credential string) (bool, error) {
	form := url.Values{"token": {credential}, "token_type_hint": {"access_token"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form))
	if err != nil {
		return false, errIntrospectionUnreachable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.authorization)
	res, err := c.client.Do(req)
	if err != nil {
		return false, errIntrospectionUnreachable
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxIntrospectionAnswer+1))
	if res.StatusCode != http.StatusOK {
		return false, errIntrospectionStatus
	}
	if err != nil {
		return false, errIntrospectionUnreachable
	}
	if len(body) > MaxIntrospectionAnswer {
		return false, errIntrospectionTooLong
	}
	var answer map[string]any
	if decodeObject(bytes.TrimLeft(body, " \t\r\n"), &answer) != nil {
		return false, errIntrospectionNotJSON
	}
	active, ok := answer["active"].(bool)
	if !ok {
		return false, errIntrospectionNoActive
	}
	return active, nil
}
