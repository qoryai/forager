package session

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"

	"github.com/qoryai/runner/internal/policy"
	"github.com/qoryai/runner/internal/server"
	"github.com/qoryai/runner/internal/sink"
)

// live is a run's server while the run goes: the configuration document as
// discovered, the run configuration in force, and the reload that keeps both current
// from the digests the server's answers carry. One reload runs at a time; answers
// that arrive during one are coalesced into the next pass.
type live struct {
	client *server.Client
	// labels are the run's, sent on every run configuration request.
	labels map[string]string
	report func(string)
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.Mutex
	conf       *server.Configuration
	confDigest string
	// runDigest is the server's digest of the run configuration in force, empty when
	// none was fetched.
	runDigest string
	posts     *sink.Server
	// apply puts a fetched policy in force, or says why it cannot; nil until the proxy
	// exists.
	apply func(*policy.Loaded) error
	// want is what the server's answers last said is in force.
	want server.Digests
	// tried is the answered run configuration digest that last led to a fetch the
	// server answered: it is not fetched for again until the answer changes, whether
	// the document was the one in force, was refused, or was put in force.
	tried          string
	running, dirty bool
}

// discover fetches the server's configuration document for a run.
func discover(ctx context.Context, cfg *server.Config, spec Spec) (*live, error) {
	client := &server.Client{Config: cfg, Key: spec.AccessKey, InstanceID: spec.InstanceID, InstanceName: spec.InstanceName, UserAgent: "qory-runner/" + spec.RunnerVersion}
	conf, digest, err := client.Discover(ctx)
	if err != nil {
		return nil, err
	}
	l := &live{client: client, labels: maps.Clone(spec.Labels), report: spec.Report, conf: conf, confDigest: digest}
	l.ctx, l.cancel = context.WithCancel(ctx)
	return l, nil
}

// fetch fetches the run configuration at runURL for the run's labels and reads its
// policy, which is then the run's, with the source fetched and the server's digest.
func (l *live) fetch(ctx context.Context, runURL string) (*policy.Loaded, error) {
	rc, digest, err := l.client.RunConfiguration(ctx, runURL, l.labels)
	if err != nil {
		return nil, err
	}
	pol, err := policy.Read("run-configuration", rc.SecurityPolicy)
	if err != nil {
		return nil, fmt.Errorf("run configuration %s: %w", runURL, err)
	}
	pol.Source, pol.URL, pol.RunConfiguration = "fetched", runURL, digest
	return pol, nil
}

// holds records the digest of the run configuration put in force.
func (l *live) holds(digest string) {
	l.mu.Lock()
	l.runDigest = digest
	l.mu.Unlock()
}

// start arms the reload with what puts a policy in force, once the proxy exists.
func (l *live) start(apply func(*policy.Loaded) error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.apply = apply
	l.kick()
}

// digests takes what an answer said is in force, on the sink's goroutine, and
// schedules a reload when it differs from what the run holds. A digest an answer did
// not carry means nothing.
func (l *live) digests(d server.Digests) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d.Configuration != "" {
		l.want.Configuration = d.Configuration
	}
	if d.RunConfiguration != "" {
		l.want.RunConfiguration = d.RunConfiguration
	}
	l.kick()
}

// kick starts the reload loop when something differs and none runs, or marks a
// running one to go again. Called with the lock held.
func (l *live) kick() {
	if l.apply == nil || l.ctx.Err() != nil || !l.stale() {
		return
	}
	if l.running {
		l.dirty = true
		return
	}
	l.running = true
	l.wg.Add(1)
	go l.loop()
}

// stale reports whether what the server said is in force differs from what the run
// holds. Called with the lock held.
func (l *live) stale() bool {
	if l.want.Configuration != "" && l.want.Configuration != l.confDigest {
		return true
	}
	return l.conf.Run != nil && l.want.RunConfiguration != "" && l.want.RunConfiguration != l.runDigest && l.want.RunConfiguration != l.tried
}

// failed reports a reload that failed, unless the run's end is why.
func (l *live) failed(err error) {
	if l.ctx.Err() == nil {
		l.report("the reload failed: " + err.Error())
	}
}

// loop runs passes until nothing is marked dirty or the run ends.
func (l *live) loop() {
	defer l.wg.Done()
	for {
		l.pass()
		l.mu.Lock()
		if !l.dirty || l.ctx.Err() != nil {
			l.running = false
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
	}
}

// pass reloads what differs: the configuration document first, whose sections are
// used from then on, then the run configuration, which is put in force. A fetch the
// server did not answer is reported and leaves what the run holds; the next answer
// asks again. A fetch it answered is not repeated until the answered digest changes:
// a document that is the one in force changes nothing and says nothing, and one that
// cannot be put in force is reported once and the policy in force stays.
func (l *live) pass() {
	l.mu.Lock()
	want, conf, confDigest, runDigest, tried, apply := l.want, l.conf, l.confDigest, l.runDigest, l.tried, l.apply
	l.dirty = false
	l.mu.Unlock()
	fetchRun := false
	if want.Configuration != "" && want.Configuration != confDigest {
		next, digest, err := l.client.Discover(l.ctx)
		if err != nil {
			l.failed(err)
			return
		}
		l.mu.Lock()
		l.conf, l.confDigest = next, digest
		l.mu.Unlock()
		l.posts.SetTarget(sink.Target{URL: next.Events.URL, Types: next.Events.Types})
		// A run section that appears names a run configuration the run does not hold
		// yet; one that disappears leaves the policy in force as it is.
		fetchRun = next.Run != nil && runDigest == ""
		conf = next
	}
	if conf.Run == nil || !(fetchRun || (want.RunConfiguration != "" && want.RunConfiguration != runDigest && want.RunConfiguration != tried)) {
		return
	}
	pol, err := l.fetch(l.ctx, conf.Run.URL)
	if err != nil {
		// Only a document the server answered and the runner refuses is not asked for
		// again; a fetch the server did not answer is.
		var document *server.DocumentError
		var refused *policy.Error
		if !errors.As(err, &document) && !errors.As(err, &refused) {
			l.failed(err)
			return
		}
	}
	l.mu.Lock()
	l.tried = want.RunConfiguration
	l.mu.Unlock()
	if err != nil {
		l.failed(err)
		return
	}
	if pol.RunConfiguration == runDigest {
		return
	}
	if err := apply(pol); err != nil {
		l.failed(fmt.Errorf("run configuration %s: %w; the policy in force stays", pol.URL, err))
		return
	}
	l.holds(pol.RunConfiguration)
}

// stop ends the reload: no pass starts after it, and one in flight is cancelled and
// waited for. It may be called more than once.
func (l *live) stop() {
	l.mu.Lock()
	l.cancel()
	l.mu.Unlock()
	l.wg.Wait()
}
