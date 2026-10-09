package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// ResendSpec is what sending a run's record again through its separate gateway is
// given.
type ResendSpec struct {
	// Gateway is the separate gateway the run spoke to, as the run's Spec gave it: the
	// resend reaches it as the run did, with the run credential Credential returns.
	Gateway RemoteGateway
	// Dir is the run directory on the session's machine, the one that holds the
	// session's record, session.jsonl; its name is the run id.
	Dir string
	// ForagerVersion is Forager's version, in the requests' user agent; empty means
	// "dev".
	ForagerVersion string
	// Report receives one line per thing worth telling the user; nil means nothing is.
	Report func(string)
}

// ResendResult is what sending again came to: what gateway.Delivery says of a
// gateway's resend, but Completed, since the session completes no record.
type ResendResult struct {
	// Sent is how many events the gateway accepted now, and Undelivered how many it
	// still has not; those are in session.jsonl, and under the run directory's
	// undelivered/ as after a run, except when the gateway ended the run.
	Sent        int
	Undelivered int
	// RunClosed says the run had ended at the gateway: nothing more was sent, and the
	// events stay in the run directory. ClosedBy says who ended it, "gateway", or
	// "apiary" when the server closed it, and Reason the code of the gateway's 410, as
	// [Result.ClosedReason] holds it; batch_refused when the gateway refused a batch.
	RunClosed bool
	ClosedBy  string
	Reason    string
	// NotOpened says the record holds no delivered.log: the run never opened at the
	// gateway, so nothing of it is sent, and the record is left as it is. A record
	// that owes nothing has a delivered.log, and NotOpened false.
	NotOpened bool
}

// Resend sends the gateway what a run's session did not deliver to it, from the run
// directory on the session's machine. That directory holds, behind a separate gateway,
// the session's record, session.jsonl, and what the gateway accepted of it,
// delivered.log: every event of the record the link takes that no accepted batch
// contained is posted again, in order and in batches cut as the session cuts them,
// until the gateway accepts it or ctx ends, and what it still has not accepted is under
// undelivered/ again, unless the gateway ended the run. The events the session records in its own record alone are not
// sent: a run.exited the gateway decides and a run.refused of a code the session does
// not decide. A record that owes nothing is sent nothing, and no request is made. A
// record with no delivered.log is of a run that never opened at the gateway, a run
// refused at its run request say: it is NotOpened, left as it is, and sent nothing,
// with no request.
//
// The record is never completed: a session that was lost leaves its run's end to the
// gateway, which writes it itself. A record still held by its session is [ErrRunning].
// Every batch carries the run's secret the directory keeps, run-secret, which is
// removed once nothing is owed: everything accepted, the run ended at the gateway, or
// nothing owed from the start; it is kept after a refusal or a failure to send. A
// directory that keeps none sends without it, and the gateway answers with the 401.
// A directory that holds the run's stream, events.jsonl, is a gateway's record, which
// gateway.Resend sends. A run the gateway has ended answers with its 410: RunClosed,
// and the events stay in the directory. A refusal of the run credential, the 401
// run_credential_refused, at the discovery or at a batch, and the 403 of a run
// credential that differs from the run's, are a [*Refusal] with their code and From
// gateway; what was not accepted is under undelivered/. After a gateway restarts, it
// holds no run of the run credential: its batches get the 401, and its own resend
// completes the run gateway_lost.
func Resend(ctx context.Context, spec ResendSpec) (ResendResult, error) {
	if spec.ForagerVersion == "" {
		spec.ForagerVersion = "dev"
	}
	if spec.Report == nil {
		spec.Report = func(string) {}
	}
	if spec.Gateway.Credential == nil {
		return ResendResult{}, errNoCredential
	}
	if err := CheckRunID(filepath.Base(spec.Dir)); err != nil {
		return ResendResult{}, err
	}
	if _, err := os.Lstat(filepath.Join(spec.Dir, sink.EventsFile)); err == nil {
		return ResendResult{}, &fs.PathError{Op: "open", Path: filepath.Join(spec.Dir, sink.EventsFile), Err: syscall.EEXIST}
	}
	file := filepath.Join(spec.Dir, sink.SessionFile)
	if _, err := os.Stat(file); err != nil {
		return ResendResult{}, err
	}
	unlock, err := lock(spec.Dir)
	if err != nil {
		return ResendResult{}, err
	}
	defer unlock()
	if _, err := os.Stat(filepath.Join(spec.Dir, sink.DeliveredFile)); errors.Is(err, fs.ErrNotExist) {
		// The link's sink never started: the run never opened at the gateway.
		return ResendResult{NotOpened: true}, nil
	} else if err != nil {
		return ResendResult{}, err
	}
	lines, err := sessionRecord(file)
	if err != nil {
		return ResendResult{}, err
	}
	accepted, _, err := sink.Delivered(spec.Dir)
	if err != nil {
		return ResendResult{}, err
	}
	var owed []recordedLine
	for _, l := range lines {
		if !accepted[l.Sequence] && l.posted() {
			owed = append(owed, l)
		}
	}
	if len(owed) == 0 {
		removeRunSecret(spec.Dir)
		return ResendResult{}, nil
	}
	k, err := spec.Gateway.link(spec.ForagerVersion, nil)
	if err != nil {
		return ResendResult{}, err
	}
	defer k.Close()
	k.UseRunSecret(readRunSecret(spec.Dir))
	disc, err := k.Discover(ctx)
	if err != nil {
		return ResendResult{}, err
	}
	target := sink.Target{URL: disc.Events.URL, Types: disc.Events.Types}
	owed = slices.DeleteFunc(owed, func(l recordedLine) bool { return !target.Wants(l.Type) })
	if len(owed) == 0 {
		removeRunSecret(spec.Dir)
		return ResendResult{}, nil
	}
	// What was spooled is in session.jsonl as well, and is spooled again if the
	// gateway still does not take it.
	if err := os.RemoveAll(filepath.Join(spec.Dir, sink.UndeliveredDir)); err != nil {
		return ResendResult{}, err
	}
	sendCtx, stop := context.WithCancel(ctx)
	defer stop()
	to := &refusing{to: k, stop: stop}
	var closedCode, closedFrom string
	posts := sink.New(sink.Config{
		To: to, Target: target, Spool: spec.Dir, Report: spec.Report,
		OnEnded: func(code, from string) { closedCode, closedFrom = code, from },
		Wait:    sink.LinkBatchWait, Link: true,
	})
	for _, l := range owed {
		if !posts.Resend(sendCtx, l.line, l.Sequence) {
			break
		}
	}
	// The worker is done once Close returns, so what it set is read after.
	posts.Close(sendCtx)
	if r := to.refused(); r != nil {
		return ResendResult{}, r
	}
	res := ResendResult{RunClosed: posts.RunClosed(), Undelivered: len(owed)}
	if res.RunClosed {
		res.ClosedBy, res.Reason = closedFrom, closedCode
	}
	if after, _, err := sink.Delivered(spec.Dir); err == nil {
		for _, l := range owed {
			if after[l.Sequence] {
				res.Sent++
			}
		}
		res.Undelivered = len(owed) - res.Sent
	}
	if res.RunClosed || res.Undelivered == 0 {
		// Nothing more is owed: the gateway took everything, or ended the run.
		removeRunSecret(spec.Dir)
	}
	return res, nil
}

// refusing is the link's deliveries during a resend, which stop at the gateway's
// refusal of the run credential: the 401 run_credential_refused, and the 403 of one
// that differs from the run's. Sending again cannot change either; a run sends again,
// as its credential may be refreshed meanwhile.
type refusing struct {
	to   sink.Deliverer
	stop context.CancelFunc

	mu  sync.Mutex
	ref *Refusal
}

// errRefusedBefore is a delivery not sent, after the gateway refused the run credential.
var errRefusedBefore = errors.New("the gateway refused the run credential")

// Deliver posts one batch through the link, and stops the resend at the gateway's
// refusal of the run credential; after it, nothing more is sent.
func (r *refusing) Deliver(ctx context.Context, eventsURL, deliveryID string, body []byte, runDigest string) (server.Delivery, error) {
	if r.refused() != nil {
		return server.Delivery{}, errRefusedBefore
	}
	d, err := r.to.Deliver(ctx, eventsURL, deliveryID, body, runDigest)
	if err == nil && credentialRefusal(d) {
		r.mu.Lock()
		if r.ref == nil {
			r.ref = d.Refusal
		}
		r.mu.Unlock()
		r.stop()
	}
	return d, err
}

// refused is the gateway's refusal of the run credential, nil for none.
func (r *refusing) refused() *Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ref
}

// credentialRefusal reports whether the gateway refused a batch for its run credential.
func credentialRefusal(d server.Delivery) bool {
	if d.Refusal == nil || d.Refusal.From != accesskey.FromGateway {
		return false
	}
	switch d.Status {
	case http.StatusUnauthorized:
		return d.Code == refusal.RunCredentialRefused
	case http.StatusForbidden:
		return d.Code == refusal.TargetDiffersFromCredential || d.Code == refusal.DiffersFromCredential
	}
	return false
}

// recordedLine is one line of session.jsonl and what Resend reads of it.
type recordedLine struct {
	Type     string `json:"type"`
	Sequence string `json:"sequence"`
	ID       string `json:"id"`
	Data     struct {
		Reason string          `json:"reason"`
		Code   string          `json:"code"`
		Status json.RawMessage `json:"status"`
	} `json:"data"`
	line []byte
}

// posted reports whether the line is one the session posts on the link: not a
// run.exited with a reason other than timeout, nor a run.refused of a code the session
// does not decide or with a status, which the session records in its own record alone.
func (l recordedLine) posted() bool {
	switch l.Type {
	case event.RunExited:
		return l.Data.Reason == "" || l.Data.Reason == event.ReasonTimeout
	case event.RunRefused:
		return refusal.Decides(l.Data.Code) && l.Data.Status == nil
	}
	return true
}

// sessionRecord reads session.jsonl, up to a last line the session died in the middle
// of, which is no event; the file is not changed.
func sessionRecord(file string) ([]recordedLine, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []recordedLine
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break
		}
		var l recordedLine
		if json.Unmarshal(line, &l) != nil || l.Type == "" || l.ID == "" {
			break
		}
		l.line = bytes.TrimSuffix(line, []byte("\n"))
		out = append(out, l)
	}
	return out, nil
}

// runSecretFile is the file of the run directory that keeps the run's secret behind a
// separate gateway, the run answer's run_secret followed by a newline, mode 0600: written
// when the run opens, so that [Resend] reaches the run, and removed once nothing is owed.
const runSecretFile = "run-secret"

// writeRunSecret writes the run's secret to the run directory, mode 0600, by a temporary
// file renamed into place. Its error never holds the secret.
func writeRunSecret(dir, secret string) error {
	f, err := os.CreateTemp(dir, "."+runSecretFile+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.WriteString(secret + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, runSecretFile))
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// readRunSecret is the run's secret the run directory keeps, empty when it keeps none.
// A file that holds more than a secret could is none.
func readRunSecret(dir string) string {
	f, err := os.Open(filepath.Join(dir, runSecretFile))
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRunSecretFile+1))
	if err != nil || len(b) > maxRunSecretFile {
		return ""
	}
	return strings.TrimSuffix(string(b), "\n")
}

// maxRunSecretFile is the most bytes a run-secret file holds: the longest secret the
// schema allows and its newline.
const maxRunSecretFile = 257

// owes reports whether the session's record in dir holds an event the link takes,
// target's, that no batch the gateway accepted contained, as [Resend] reads it: one it
// would send. A record it cannot read owes.
func owes(dir string, target sink.Target) bool {
	lines, err := sessionRecord(filepath.Join(dir, sink.SessionFile))
	if err != nil {
		return true
	}
	accepted, _, err := sink.Delivered(dir)
	if err != nil {
		return true
	}
	for _, l := range lines {
		if !accepted[l.Sequence] && l.posted() && target.Wants(l.Type) {
			return true
		}
	}
	return false
}

// removeRunSecret removes the run's secret from the run directory, once nothing is owed.
func removeRunSecret(dir string) { os.Remove(filepath.Join(dir, runSecretFile)) }
