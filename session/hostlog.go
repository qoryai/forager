package session

import (
	"errors"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/internal/chunk"
)

// HostLog writes b, lines of the run's host work such as a fetch or a compose, into the
// record as dev.qory.run.log with stream stderr and no session member: one chunk per
// line, and a line longer than 4096 bytes in chunks of 4096, as a session's chunks on
// pipes. The run's masker replaces the password of each forwarder of the run in b
// first, within this call alone: a password split across two calls stays as written,
// so pass whole lines. The chunks go to output.log in the run directory. A last line without a
// line break is a chunk too, and an empty b writes nothing. A run the gateway closed
// has the chunks in session.jsonl alone.
//
// An error means nothing is written: a session of the run is running, or the run is
// closed. Host lines go before the first join and between joins, never during one, so
// sessions/<n>/output.log contains the bytes of session n alone; the host work's
// [HostProxy] ends at a join as well.
func (r *Run) HostLog(b []byte) error {
	if !r.joining.TryLock() {
		return errors.New("write the host work's lines after Join returns: a session of the run is still running")
	}
	defer r.joining.Unlock()
	if r.closed {
		return errors.New("open a new run for the host work's lines: the run is closed")
	}
	r.writeLog("stderr", 0, b)
	return nil
}

// writeLog writes b as dev.qory.run.log chunks of stream, cut as on pipes, after the
// run's masker: with n as session, or with no session member when n is 0, for the
// run's host work. A run the gateway closed has the chunks in its record alone.
func (r *Run) writeLog(stream string, n int, b []byte) {
	emit := func(c []byte) {
		data := map[string]any{"stream": stream, "bytes": encode(c)}
		if n > 0 {
			data["session"] = n
		}
		if r.closing.Err() != nil {
			r.own(event.RunLog, data)
			return
		}
		r.write(event.RunLog, data)
	}
	masker := r.masker
	if masker.Empty() {
		masker = nil
	}
	chunks := chunk.New(emit)
	masked := mask.NewWriter(chunks, masker)
	masked.Write(b)
	masked.Flush()
	chunks.Flush()
}

// failureLine is the text of err as one stderr line of the session's output: what a
// failure with no refusal code after dev.qory.session.started, such as a pull or the
// wall's start, writes, since its dev.qory.session.exited has no reason.
func failureLine(err error) []byte {
	text := accesskey.ShownError(err).Error()
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return []byte(text)
}
