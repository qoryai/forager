package gateway

import (
	"context"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/sink"
)

// ResendConfig is what sending one run's record again is given.
type ResendConfig struct {
	// Server is where the events go: the server the run had, or another. Its
	// configuration document is fetched first, as for a run, and every answer is
	// verified under its pin. Nil completes the record and sends nothing.
	Server *Server
	// Dir is the run's record directory, the one the gateway wrote its events.jsonl in;
	// its name is the run id.
	Dir string
	// Version is Forager's version, in the deliveries' user agent; empty means "dev".
	Version string
	// Report receives one line per thing worth telling the user; nil means nothing is.
	Report func(string)
}

// Resend completes and delivers the record of one run whose gateway is gone, as
// today's resend does: a record still held, by an open run or by the run's session, is
// [ErrRunning] and left as it is; a record with run.started and no run.exited gets
// one, with the reason gateway_lost, Completed; then every event the server wants that
// no accepted batch contained is posted, in order and in the run's own batches, until
// the server accepts it or ctx ends. A line of the record that holds no whole event, a
// write the gateway did not finish, is skipped, and every event after it is sent. A
// record whose ping the server never accepted, of a run that never opened, is left as
// it is and sent nothing: NotOpened, Sent and Undelivered 0. So is a record with no
// ping and no delivered.log, of a run that had no server, sent to one. A server that said stop during the
// run is sent nothing. A refusal of the server's, at
// its discovery, is an [*accesskey.Refusal] with its From, Code and Names. A server
// that closes the run now, a signed 410 run_closed, is RunClosed, from apiary: the
// events stay in the directory.
func Resend(ctx context.Context, cfg ResendConfig) (Delivery, error) {
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.Report == nil {
		cfg.Report = func(string) {}
	}
	rc := stream.ResendConfig{Dir: cfg.Dir, Report: cfg.Report}
	if cfg.Server != nil {
		client, err := newClient(cfg.Server, cfg.Version)
		if err != nil {
			return Delivery{}, err
		}
		conf, _, err := client.Discover(ctx)
		if err != nil {
			return Delivery{}, err
		}
		rc.Wants = conf.Wants
		rc.Sink = func(dir string) stream.Sink {
			return sink.NewServer(client, sink.Target{URL: conf.Events.URL, Types: conf.Events.Types}, dir, cfg.Report, nil, nil)
		}
	}
	res, err := stream.Resend(ctx, rc)
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{Undelivered: res.Undelivered, Sent: res.Sent, Completed: res.Closed, NotOpened: res.NotOpened}
	if res.RunClosed {
		d.RunClosed, d.ClosedBy, d.Reason = true, accesskey.FromApiary, accesskey.CodeRunClosed
	}
	return d, nil
}

// ErrRunning says a run's record is still held: by an open run of a gateway's, or by
// the run's session.
var ErrRunning = stream.ErrRunning

// Three of the lines Resend passes to ResendConfig.Report: those of a record that is
// not sent since its run never opened at the server, and that of lines of a record
// that are not whole events. A caller that reports Delivery.NotOpened itself may leave
// out ResendNotOpened and ResendNoServer.
const (
	// ResendTorn is reported when lines of the record hold bytes that are no whole
	// event, a write the gateway did not finish, which are skipped: a format of their
	// count, %d, and the record's path, %s, its events.jsonl.
	ResendTorn = stream.ResendTorn
	// ResendNoServer is reported when the record holds no ping and there is no
	// delivered.log, of a run that had no server, and it is sent to one: the Delivery is
	// NotOpened and nothing is sent.
	ResendNoServer = stream.ResendNoServer
	// ResendNotOpened is reported when the record holds a ping and there is no
	// delivered.log, of a run whose ping the server never accepted: the Delivery is
	// NotOpened and nothing is sent.
	ResendNotOpened = stream.ResendNotOpened
)
