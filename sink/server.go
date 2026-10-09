package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/server"
)

// The batching rule: a batch is cut at BatchEvents events, at BatchBytes of encoded
// events, or BatchWait after its first event, whichever comes first.
const (
	BatchEvents = 100
	BatchBytes  = 1 << 20
	BatchWait   = time.Second
)

// LinkBatchWait is the wait of a batch the session posts to its gateway's link: short,
// since the gateway batches again toward the server, so an event is not delayed twice.
const LinkBatchWait = 100 * time.Millisecond

// The retry rule: a delivery the server did not accept is retried after Backoff,
// doubling to MaxBackoff, until the run ends.
const (
	Backoff    = time.Second
	MaxBackoff = time.Minute
)

// QueueSize is how many events the sink holds before it spools instead of blocking.
const QueueSize = 10000

// DeliveredFile is the file in the run directory that holds what the server accepted,
// a line per batch written as the answer comes: the delivery id, then the sequence of
// each event in it. A server's stop, a signed 410 with run_closed or without a code,
// is the one word stopped. With events.jsonl it says what a run cut short still owes
// its server.
const DeliveredFile = "delivered.log"

// stoppedWord is the line of [DeliveredFile] that records the server's stop.
const stoppedWord = "stopped"

// UndeliveredDir is the directory under the run directory that holds the batches the
// server did not accept, one file per delivery id.
const UndeliveredDir = "undelivered"

// Target is where events go and which: the events section of the configuration
// document as it stands now, since a reload may replace it.
type Target struct {
	URL string
	// Types are full type names, or "*" for every type. The ping is always wanted.
	Types []string
}

// Wants reports whether the target asks for events of the type.
func (t Target) Wants(typ string) bool {
	if typ == "dev.qory.ping" {
		return true
	}
	for _, e := range t.Types {
		if e == "*" || e == typ {
			return true
		}
	}
	return false
}

// Deliverer posts one batch and says what its receiver answered: a [server.Client],
// toward the server, signed, and a [server.Link], to the gateway, on its link.
type Deliverer interface {
	Deliver(ctx context.Context, eventsURL, deliveryID string, body []byte, runDigest string) (server.Delivery, error)
}

// Config is what [New] needs of a sink that posts a run's events.
type Config struct {
	// To posts each batch.
	To Deliverer
	// Target is where events go and which.
	Target Target
	// Spool is the run directory, which holds the record of accepted batches and,
	// under [UndeliveredDir], the batches not accepted. Empty keeps neither: the
	// batches not accepted are counted alone.
	Spool string
	// Report receives one line per thing worth telling the user, a stop or a spool;
	// nil means nobody. On the link, or without a Spool, the caller words the end of
	// the run and what was not accepted itself, from OnEnded and Undelivered, and
	// Report gets neither.
	Report func(string)
	// OnDigests, when not nil, gets the digests of every answer to read but a 410, on
	// the worker's goroutine, and must not block.
	OnDigests func(server.Digests)
	// OnEnded, when not nil, is called once, on the worker's goroutine, when the
	// receiver ends the run, with the end code and who ended it: the server's signed 410
	// run_closed, from empty; on the link the answer's End, one of [server.EndCodes],
	// and its From, gateway or apiary. It must not block.
	OnEnded func(code, from string)
	// Wait is how long a batch waits after its first event; zero means [BatchWait].
	Wait time.Duration
	// Link posts to the gateway's link: each event without its sequence, which the
	// gateway gives the run's stream.
	Link bool
}

// Server posts a run's events to the server's events endpoint, or to the gateway's
// link.
type Server struct {
	client    Deliverer
	target    atomic.Pointer[Target]
	runDigest atomic.Pointer[string]
	onDigests func(server.Digests)
	onEnded   func(code, from string)
	closeOnce sync.Once
	dir       string
	report    func(string)
	sleep     func(context.Context, time.Duration) bool
	wait      time.Duration
	link      bool

	queue   chan queued
	acks    *os.File
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	stopped bool
	// runClosed says the server closed the run, a signed 410 run_closed.
	runClosed bool
	closed    bool
	lost      int
}

// queued is one event in the queue: its line and its sequence, which the record of
// accepted batches names it by.
type queued struct {
	line []byte
	seq  string
}

// NewServer returns a sink posting through the client to the target, with
// [BatchWait]. spool is the run directory, under which undelivered batches are
// written; report receives one line per thing worth telling the user, a stop or a
// spool, and may be nil; onDigests, when not nil, gets the digests every signed answer
// contains, on the worker's goroutine, and must not block; onClosed, when not nil, is
// called once, on the worker's goroutine, when the server closes the run with a signed
// 410 run_closed, and must not block. The worker runs until Close.
func NewServer(client Deliverer, target Target, spool string, report func(string), onDigests func(server.Digests), onClosed func()) *Server {
	var onEnded func(string, string)
	if onClosed != nil {
		onEnded = func(string, string) { onClosed() }
	}
	if spool == "" {
		// Today's record of a run always has its directory: an empty one is the
		// working directory, as it always was.
		spool = "."
	}
	return New(Config{To: client, Target: target, Spool: spool, Report: report, OnDigests: onDigests, OnEnded: onEnded})
}

// New returns a sink posting as c says. The worker runs until Close.
func New(c Config) *Server {
	report := c.Report
	if report == nil {
		report = func(string) {}
	}
	wait := c.Wait
	if wait <= 0 {
		wait = BatchWait
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &Server{client: c.To, onDigests: c.OnDigests, onEnded: c.OnEnded, dir: c.Spool, report: report, queue: make(chan queued, QueueSize), ctx: ctx, cancel: cancel, done: make(chan struct{}), sleep: sleep, wait: wait, link: c.Link}
	w.target.Store(&c.Target)
	if c.Spool != "" {
		if acks, err := os.OpenFile(filepath.Join(c.Spool, DeliveredFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			w.acks = acks
		} else {
			report("the record of accepted batches: " + err.Error())
		}
	}
	go w.run()
	return w
}

// unnumbered is an event as a link batch carries it: without its sequence.
type unnumbered struct {
	SpecVersion string `json:"specversion"`
	ID          string `json:"id"`
	Source      string `json:"source"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
	Time        string `json:"time"`
	DataSchema  string `json:"dataschema"`
	Data        any    `json:"data"`
}

// line is the event as the sink posts it: the line events.jsonl holds toward the
// server, and without its sequence on the link.
func (w *Server) line(ev *event.Event) ([]byte, error) {
	if !w.link {
		return ev.JSON()
	}
	return json.Marshal(unnumbered{ev.SpecVersion, ev.ID, ev.Source, ev.Type, ev.Subject, ev.Time, ev.DataSchema, ev.Data})
}

// SetTarget replaces where events go and which, for the batches from now on: what a
// reloaded configuration document says.
func (w *Server) SetTarget(t Target) { w.target.Store(&t) }

// SetRunDigest sets the run configuration digest every delivery from now on carries;
// empty means none is sent.
func (w *Server) SetRunDigest(d string) { w.runDigest.Store(&d) }

// Write queues the event when the target wants its type. A full queue spools the
// event as a batch of one rather than blocking; a sink told to stop drops it.
func (w *Server) Write(ev *event.Event) error {
	if !w.target.Load().Wants(ev.Type) {
		return nil
	}
	line, err := w.line(ev)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped || w.closed {
		return nil
	}
	q := queued{line, ev.Sequence}
	select {
	case w.queue <- q:
	default:
		w.spool([]queued{q}, event.NewID())
	}
	return nil
}

// Resend queues a line events.jsonl already holds, waiting for room in the queue: what
// is sent again has no session to delay. On the link the line is one of the session's
// record, session.jsonl, and goes without its sequence, as the link carries it; a line
// that does not decode as an event is not queued. It reports false once the sink
// stopped or the context ended. It is not called together with Close.
func (w *Server) Resend(ctx context.Context, line []byte, seq string) bool {
	if w.link {
		var ev struct {
			SpecVersion string          `json:"specversion"`
			ID          string          `json:"id"`
			Source      string          `json:"source"`
			Type        string          `json:"type"`
			Subject     string          `json:"subject"`
			Time        string          `json:"time"`
			DataSchema  string          `json:"dataschema"`
			Data        json.RawMessage `json:"data"`
		}
		if json.Unmarshal(line, &ev) != nil || ev.Type == "" {
			return true
		}
		b, err := json.Marshal(unnumbered{ev.SpecVersion, ev.ID, ev.Source, ev.Type, ev.Subject, ev.Time, ev.DataSchema, ev.Data})
		if err != nil {
			return true
		}
		line = b
	}
	w.mu.Lock()
	over := w.stopped || w.closed
	w.mu.Unlock()
	if over {
		return false
	}
	select {
	case w.queue <- queued{line, seq}:
		return true
	case <-ctx.Done():
		return false
	}
}

// run is the worker: it forms batches from the queue and delivers each with retries.
func (w *Server) run() {
	defer close(w.done)
	for {
		batch, ok := w.next()
		if len(batch) > 0 {
			w.deliver(batch)
		}
		if !ok {
			return
		}
	}
}

// next collects one batch. It returns ok false once the queue is closed and drained.
func (w *Server) next() ([]queued, bool) {
	var batch []queued
	size := 0
	var timer <-chan time.Time
	for {
		select {
		case line, ok := <-w.queue:
			if !ok {
				return batch, false
			}
			batch = append(batch, line)
			size += len(line.line)
			if len(batch) >= BatchEvents || size >= BatchBytes {
				return batch, true
			}
			if timer == nil {
				timer = time.After(w.wait)
			}
		case <-timer:
			return batch, true
		}
	}
}

// deliver posts one batch until it is accepted, the server says stop, or the sink's
// context ends; then it spools what was not accepted. An answer whose signature does
// not verify under the pin is no answer, retried like a transport failure. The digests
// of every signed answer but a 410 go to the caller. A signed 410 stops the
// deliveries; with run_closed it also closes the run, which the caller hears of once.
// On the link every answer is read, and an answer with an End, a 410 or a 400
// invalid_request, closes the run with it.
// A batch queued before the stop is dropped, as one written after it is.
func (w *Server) deliver(batch []queued) {
	w.mu.Lock()
	stopped := w.stopped
	w.mu.Unlock()
	if stopped {
		return
	}
	body := encode(batch)
	id := event.NewID()
	backoff := Backoff
	for {
		ctx, cancel := context.WithTimeout(w.ctx, server.Timeout)
		digest := ""
		if d := w.runDigest.Load(); d != nil {
			digest = *d
		}
		d, err := w.client.Deliver(ctx, w.target.Load().URL, id, body, digest)
		cancel()
		// A stop ends the run's deliveries, so its digests are no reason to reload.
		if err == nil && d.Authentic() && !d.Stop() && w.onDigests != nil {
			w.onDigests(d.Digests)
		}
		switch {
		case err == nil && d.Accepted():
			w.ack(id, batch)
			return
		case err == nil && d.Stop():
			w.mu.Lock()
			w.stopped = true
			if d.Closed() {
				w.runClosed = true
			}
			w.mu.Unlock()
			w.ack(stoppedWord, nil)
			if d.Closed() {
				w.closeOnce.Do(func() {
					code := d.Code
					if d.Link {
						code = d.End
					} else {
						w.report("the server closed the run with a signed 410 run_closed; the run ends, and no further batch is sent")
					}
					if w.onEnded != nil {
						w.onEnded(code, d.From)
					}
				})
				return
			}
			w.report(fmt.Sprintf("the server answered %d; no further batch is sent for this run", d.Status))
			return
		}
		if w.ctx.Err() != nil || !w.sleep(w.ctx, backoff) {
			w.mu.Lock()
			w.spool(batch, id)
			w.mu.Unlock()
			return
		}
		if backoff *= 2; backoff > MaxBackoff {
			backoff = MaxBackoff
		}
	}
}

// Accepted records a delivery the sink did not make itself, the ping, which the session
// posts before there is a sink.
func (w *Server) Accepted(id, seq string) { w.ack(id, []queued{{seq: seq}}) }

// ack records an accepted batch, or the server's stop, as it happens: a session that
// dies after it has nothing to say twice.
func (w *Server) ack(id string, batch []queued) {
	if w.acks == nil {
		return
	}
	var b strings.Builder
	b.WriteString(id)
	for _, q := range batch {
		b.WriteString(" " + q.seq)
	}
	b.WriteString("\n")
	if _, err := w.acks.WriteString(b.String()); err != nil {
		w.report("the record of accepted batches: " + err.Error())
	}
}

// spool writes a batch the server did not accept under the undelivered directory,
// named by its delivery id, and counts its events; a sink without a run directory
// counts them alone. Called with the lock held.
func (w *Server) spool(batch []queued, id string) {
	w.lost += len(batch)
	if w.dir == "" {
		return
	}
	dir := filepath.Join(w.dir, UndeliveredDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		w.report("spool: " + err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), encode(batch), 0o644); err != nil {
		w.report("spool: " + err.Error())
	}
}

// encode renders a batch as the JSON array of its events.
func encode(batch []queued) []byte {
	raw := make([]json.RawMessage, len(batch))
	for i, b := range batch {
		raw[i] = b.line
	}
	body, _ := json.Marshal(raw)
	return body
}

// Close stops taking events and lets the worker deliver what is queued until the
// context ends; what is still undelivered then is spooled. It reports the count and
// returns nil: an undelivered copy is not a failed run.
func (w *Server) Close(ctx context.Context) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.queue)
	w.mu.Unlock()
	select {
	case <-w.done:
	case <-ctx.Done():
		w.cancel()
		<-w.done
	}
	w.cancel()
	if w.acks != nil {
		w.acks.Close()
	}
	if n := w.Undelivered(); n > 0 && !w.link && w.dir != "" {
		w.report(fmt.Sprintf("%d events were not accepted by the server; see %s", n, filepath.Join(w.dir, UndeliveredDir)))
	}
	return nil
}

// Undelivered is the number of events spooled so far.
func (w *Server) Undelivered() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lost
}

// Stopped reports whether the receiver asked for nothing more.
func (w *Server) Stopped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}

// RunClosed reports whether the server closed the run, a signed 410 run_closed, or on
// the link an answer ended it.
func (w *Server) RunClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.runClosed
}

// sleep waits d or until the context ends, reporting whether it waited the whole d.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Delivered reads the record of accepted batches in a run directory: the sequences the
// server accepted, and whether it said stop. No file means nothing was accepted.
func Delivered(dir string) (map[string]bool, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, DeliveredFile))
	if err != nil && !os.IsNotExist(err) {
		return nil, false, err
	}
	seqs, stopped := map[string]bool{}, false
	for _, line := range strings.Split(string(b), "\n") {
		// A line the session died in the middle of still names accepted events only: it is
		// written after the answer, and a sequence cut short matches none.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == stoppedWord {
			stopped = true
			continue
		}
		for _, seq := range fields[1:] {
			seqs[seq] = true
		}
	}
	return seqs, stopped, nil
}
