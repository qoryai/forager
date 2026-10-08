// Package sink is where events go: the file sink that is the record of truth, and the
// server sink that is a copy of it.
//
// A [Sink] takes the events of one run in sequence order and is closed once at the
// end. [File] writes events.jsonl and output.log in the run directory and never loses
// an event. [Server] batches, signs and posts to the server's events endpoint without
// ever delaying the session: writes go into a bounded queue, a worker delivers with
// retries, and what the server does not accept by the time the run ends is spooled as
// batch files and counted. [Writer] prints the same line events.jsonl gets to a stream the caller
// owns, standard output say. [Multi] fans one write out to several sinks.
package sink

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/qoryai/runner/event"
)

// Sink takes events and is closed once.
type Sink interface {
	// Write takes one event. It must not block on anything outside the machine.
	Write(*event.Event) error
	// Close flushes what is pending, within the context's deadline, and releases what
	// the sink holds.
	Close(ctx context.Context) error
}

// The record files of a run.
const (
	EventsFile = "events.jsonl"
	OutputFile = "output.log"
)

// File writes the two record files of a run.
type File struct {
	mu     sync.Mutex
	events *os.File
	output *os.File
}

// NewFile creates the run directory, if needed, and opens the record files in it for
// appending. A directory that already holds an events.jsonl is refused: a run id is
// never reused.
func NewFile(dir string) (*File, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	events, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	output, err := os.OpenFile(filepath.Join(dir, OutputFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		events.Close()
		return nil, err
	}
	return &File{events: events, output: output}, nil
}

// Write appends the event as one line to events.jsonl and, for a log event, its bytes
// to output.log.
func (f *File) Write(ev *event.Event) error {
	line, err := ev.JSON()
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.events.Write(append(line, '\n')); err != nil {
		return err
	}
	if ev.Type == event.RunLog {
		if data, ok := ev.Data.(map[string]any); ok {
			if enc, ok := data["bytes"].(string); ok {
				b, err := base64.StdEncoding.DecodeString(enc)
				if err != nil {
					return err
				}
				if _, err := f.output.Write(b); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Close syncs and closes both files.
func (f *File) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return errors.Join(f.events.Sync(), f.events.Close(), f.output.Sync(), f.output.Close())
}

// Writer writes every event as one JSON line, the line events.jsonl holds, to a stream
// it does not own: a run with no server is followed on standard output this way.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter returns a sink writing to w. Close leaves w open.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write writes the event as one line.
func (s *Writer) Write(ev *event.Event) error {
	line, err := ev.JSON()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(line, '\n'))
	return err
}

// Close does nothing: the stream is the caller's.
func (s *Writer) Close(context.Context) error { return nil }

// Multi writes to every sink in order and closes them all.
type Multi []Sink

// Write writes to each sink; the first error is returned after every sink was tried.
func (m Multi) Write(ev *event.Event) error {
	var first error
	for _, s := range m {
		if err := s.Write(ev); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Close closes each sink; every error is returned, joined.
func (m Multi) Close(ctx context.Context) error {
	var errs []error
	for _, s := range m {
		errs = append(errs, s.Close(ctx))
	}
	return errors.Join(errs...)
}
