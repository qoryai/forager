package server

import (
	"errors"
	"net/http"
	"net/url"
)

// Via is the server document's via: the gateway a keyed machine or a starter reaches
// the server through, which relays its enrolment, discovery, registrations and
// outcomes to the server's origin and passes each answer back byte for byte. URL is the
// gateway's https origin. Every request to the server goes to URL's origin with its
// target, the path and the query, unchanged, discovery's absolute run.url included, so
// the request's signature and the answer's are the server's as without Via; the server
// document's own url stays the server's, and records and texts name it.
//
// The chain of the gateway's certificate is always checked, for URL's host name,
// against the system's roots, or, with CAFile, against the authorities of that PEM file
// alone, which replace them; with CertificateSHA256, the SHA-256 of the certificate's
// DER SubjectPublicKeyInfo in standard base64 with padding, 44 characters ending in
// "=", only a certificate with that public key is accepted besides. A relayed
// registration's answer carries the run key, so this trust is never relaxed. The
// connection is TLS 1.3 alone, made to the gateway itself: no proxy of the
// environment is used.
type Via struct {
	URL               string `json:"url"`
	CAFile            string `json:"ca_file,omitempty"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
}

// errViaURL refuses a via URL that is not an https origin.
var errViaURL = errors.New("via's url is not an https URL of a host and an optional port, with no user information, path, query or fragment")

// origin parses URL, which must be an https origin.
func (v Via) origin() (*url.URL, error) {
	u, err := url.Parse(v.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errViaURL
	}
	return u, nil
}

// Check refuses a via Forager cannot send through: a URL that is not an https origin, a
// CAFile it cannot read or that holds no PEM certificate, and a CertificateSHA256 not
// in its form. It sends nothing.
func (v Via) Check() error {
	_, err := v.Transport()
	return err
}

// Transport returns a transport to the gateway with Via's trust, as [Client] uses with
// Via set: Go's default transport, cloned, with no proxy of the environment, TLS 1.3
// alone, the chain checked for URL's host name against the system's roots or CAFile's
// authorities, and the pin when CertificateSHA256 is set. A caller that sends to the gateway itself, an enrolment
// through [accesskey.EnrolmentRequest.PostVia] say, uses it in its http.Client.
func (v Via) Transport() (*http.Transport, error) {
	return v.transport(nil)
}

// transport is base, cloned, or Go's default transport when base is nil, with Via's
// trust in place of its TLS, no proxy, the environment's or base's, so the request
// reaches the gateway itself, and no connection kept idle, since a [Client] makes one
// for each request. A base that is not an *http.Transport cannot carry the trust.
func (v Via) transport(base http.RoundTripper) (*http.Transport, error) {
	u, err := v.origin()
	if err != nil {
		return nil, err
	}
	cfg, err := RemoteTLS{CAFile: v.CAFile, CertificateSHA256: v.CertificateSHA256}.config(u.Hostname())
	if err != nil {
		return nil, err
	}
	var t *http.Transport
	switch b := base.(type) {
	case nil:
		t = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		t = b.Clone()
	default:
		return nil, errors.New("via needs the client's transport to be an *http.Transport, which carries its trust")
	}
	t.TLSClientConfig = cfg
	t.Proxy = nil
	t.DisableKeepAlives = true
	t.ForceAttemptHTTP2 = false
	return t, nil
}

// rebase returns u with Via's origin in place of its own and its target, the path and
// the query, unchanged.
func (v Via) rebase(u string) (string, error) {
	o, err := v.origin()
	if err != nil {
		return "", err
	}
	r, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	r.Scheme, r.Host, r.User = "https", o.Host, nil
	return r.String(), nil
}
