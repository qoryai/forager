package session

import (
	"fmt"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/internal/chunk"
)

// Step is one step of the run: one named unit of host work, such as a fetch or a
// compose, with a start, an end, an outcome and its lines. [Run.StartStep] starts a
// step of the caller's host work; [Run.FetchImage] writes the image step of an image by
// reference; [Run.Join] writes the join, image and wall steps of a session. The steps
// of a run are numbered from 1 in the order they start.
type Step struct {
	r      *Run
	n      int
	start  time.Time
	exited bool
}

// StartStep starts a step of the run's host work and writes its
// dev.qory.run.step_started, with the run's next step number as step, name as name and
// kind as kind: event.StepFetch, event.StepCompose or event.StepBuild. Join numbers its
// steps from the same counter. The run's masker replaces each forwarder's password in
// name, and a name that contains qak_, qrk_ or qecr_ in any case is a phrase in its place, as
// accesskey.ShownValue gives it. Write the step's lines with [Step.Log], and end it with
// [Step.Exit].
//
// An error means nothing is written: the kind is not fetch, compose or build, the name
// is empty, a session of the run is running, another host step is open, or the run is
// closed. Host steps go before the first join and between joins, never during one: Join
// returns an error and writes nothing while a host step is open.
//
// The name must contain no URL userinfo, token or other credential. The masker
// replaces only the forwarders' passwords, and accesskey.ShownValue replaces only a
// name that contains qak_, qrk_ or qecr_; any other secret in name is written as given.
func (r *Run) StartStep(kind, name string) (*Step, error) {
	if kind != event.StepFetch && kind != event.StepCompose && kind != event.StepBuild {
		return nil, fmt.Errorf("start a host step of kind fetch, compose or build, not %s: Join writes the join, image and wall steps", accesskey.ShownValue(kind, true))
	}
	if name == "" {
		return nil, fmt.Errorf("give the step a name, such as %q: a step's name is never empty", "fetch github.com/example-org/app")
	}
	if !r.joining.TryLock() {
		return nil, fmt.Errorf("start the host step after Join returns: a session of the run is still running")
	}
	defer r.joining.Unlock()
	if r.closed {
		return nil, fmt.Errorf("open a new run for the host step: the run is closed")
	}
	if r.hostStep != nil {
		return nil, fmt.Errorf("exit step %d before the next host step starts: one host step is open at a time", r.hostStep.n)
	}
	r.hostStep = r.startStep(kind, name)
	return r.hostStep, nil
}

// Log writes b, lines of the step, into the record as dev.qory.run.log with stream
// stderr, the step's number as step and no session member: one chunk per line, and a
// line longer than 4096 bytes in chunks of 4096, as a session's chunks on pipes. The
// run's masker replaces the password of each forwarder of the run in b first, within
// this call alone: a password split across two calls stays as written, so pass whole
// lines. The chunks go to output.log in the run directory. A last line without a line
// break is a chunk too, and an empty b writes nothing. A run the gateway closed has the
// chunks in session.jsonl alone.
//
// An error means nothing is written: the step exited, a session of the run is running,
// or the run is closed.
func (s *Step) Log(b []byte) error {
	r := s.r
	if !r.joining.TryLock() {
		return fmt.Errorf("write step %d's lines after Join returns: a session of the run is still running", s.n)
	}
	defer r.joining.Unlock()
	if s.exited {
		return fmt.Errorf("start a new step for these lines: step %d exited", s.n)
	}
	if r.closed {
		return fmt.Errorf("open a new run for the host work's lines: the run is closed")
	}
	r.writeLog("stderr", 0, s.n, b)
	return nil
}

// Exit ends the step and writes its dev.qory.run.step_exited, with state, one of
// event.StateSucceeded, event.StateFailed and event.StateCancelled, exitCode, the exit
// status of the step's process or -1 when it has none, and duration_ms, the time from
// [Run.StartStep] to Exit.
//
// An error means nothing is written: the state is not one of the three, exitCode is
// below -1, the step exited already, a session of the run is running, or the run is
// closed, whose [Run.Close] ended the step as cancelled.
func (s *Step) Exit(state string, exitCode int) error {
	r := s.r
	if !event.IsState(state) {
		return fmt.Errorf("exit the step with succeeded, failed or cancelled, not %s", accesskey.ShownValue(state, true))
	}
	if exitCode < -1 {
		return fmt.Errorf("exit the step with -1 when its process has no exit status, not %d", exitCode)
	}
	if !r.joining.TryLock() {
		return fmt.Errorf("exit step %d after Join returns: a session of the run is still running", s.n)
	}
	defer r.joining.Unlock()
	if s.exited {
		return fmt.Errorf("start a new step: step %d exited already", s.n)
	}
	if r.closed {
		return fmt.Errorf("open a new run for the host work: the run is closed")
	}
	s.end(state, exitCode)
	return nil
}

// startStep writes the dev.qory.run.step_started of the run's next step, with name
// as [Run.stepName] shows it, and returns the step.
func (r *Run) startStep(kind, name string) *Step {
	r.steps++
	s := &Step{r: r, n: r.steps, start: time.Now()}
	r.post(event.StepStarted, map[string]any{"step": s.n, "name": r.stepName(name), "kind": kind})
	return s
}

// end writes the step's dev.qory.run.step_exited, once. A host step that ends is no
// longer the run's open one.
func (s *Step) end(state string, exitCode int) {
	if s.exited {
		return
	}
	s.exited = true
	if s.r.hostStep == s {
		s.r.hostStep = nil
	}
	s.r.post(event.StepExited, map[string]any{"step": s.n, "state": state, "exit_code": exitCode, "duration_ms": time.Since(s.start).Milliseconds()})
}

// stepName is name as a step's dev.qory.run.step_started has it: the run's masker
// replaces each forwarder's password in it, then a name that contains qak_, qrk_ or qecr_ in
// any case is accesskey.ShownValue's phrase in its place.
func (r *Run) stepName(name string) string {
	return accesskey.ShownValue(r.masker.Replace(name), false)
}

// post writes an event to every sink, or, once the gateway closed the run, to the
// session's record alone: the gateway answers every later batch of the run with a 410
// and writes none of its events.
func (r *Run) post(typ string, data any) {
	if r.closing.Err() != nil {
		r.own(typ, data)
		return
	}
	r.write(typ, data)
}

// writeLog writes b as dev.qory.run.log chunks of stream, cut as on pipes, after the
// run's masker: with n as session, or with no session member when n is 0, for the
// run's host work, and with step as step, or with no step member when step is 0. A run
// the gateway closed has the chunks in its record alone.
func (r *Run) writeLog(stream string, n, step int, b []byte) {
	masker := r.masker
	if masker.Empty() {
		masker = nil
	}
	chunks := chunk.New(r.logEmit(stream, n, step))
	masked := mask.NewWriter(chunks, masker)
	masked.Write(b)
	masked.Flush()
	chunks.Flush()
}

// logEmit is what writes each chunk of stream as a dev.qory.run.log, with n as
// session, or with no session member when n is 0, and with step as step, or with no
// step member when step is 0.
func (r *Run) logEmit(stream string, n, step int) func([]byte) {
	return func(c []byte) {
		data := map[string]any{"stream": stream, "bytes": encode(c)}
		if n > 0 {
			data["session"] = n
		}
		if step > 0 {
			data["step"] = step
		}
		r.post(event.RunLog, data)
	}
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
