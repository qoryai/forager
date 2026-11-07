package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// modeTerminal is the probe of an interactive run that counts a resize and a Ctrl-C.
const modeTerminal = "terminal"

// What the terminal probe prints when it waits for the resize, and for the Ctrl-C.
const (
	terminalReady   = "walltest-terminal: ready"
	terminalResized = "walltest-terminal: resized"
)

// The size the suite's terminal starts with, and the size it changes to.
const (
	terminalCols, terminalRows = 80, 24
	resizedCols, resizedRows   = 101, 33
)

// terminalWait is how long the terminal probe waits for the resize and for the Ctrl-C.
const terminalWait = 2 * time.Minute

// terminalReport is what the terminal probe found: its process group and the
// terminal's foreground group, its parent's process id, how many WINCH and INT reached
// it, each counted for half a second after the first, and the terminal's size after
// the resize.
type terminalReport struct {
	Group      int    `json:"group"`
	Foreground int    `json:"foreground"`
	Parent     int    `json:"parent"`
	Winch      int    `json:"winch"`
	Int        int    `json:"int"`
	Size       string `json:"size"`
	Err        string `json:"err"`
}

// terminalProbe is the runtime of the suite's interactive run on the suite's terminal:
// it waits for a resize, then for a Ctrl-C, prints its report, and exits 40 and the
// number of INT that reached it.
func terminalProbe() int {
	winch, ints := make(chan os.Signal, 8), make(chan os.Signal, 8)
	signal.Notify(winch, syscall.SIGWINCH)
	signal.Notify(ints, os.Interrupt)
	r := report{Terminal: term.IsTerminal(int(os.Stdout.Fd()))}
	t := &terminalReport{Group: syscall.Getpgrp(), Parent: os.Getppid()}
	r.TTY = t
	t.Foreground, _ = unix.IoctlGetInt(0, unix.TIOCGPGRP)
	r.Parent = probeParent()
	size := func() string {
		cols, rows, err := term.GetSize(0)
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("%dx%d", cols, rows)
	}
	// count is 1 and the signals of ch in the next half second.
	count := func(ch chan os.Signal) int {
		n := 1
		end := time.After(500 * time.Millisecond)
		for {
			select {
			case <-ch:
				n++
			case <-end:
				return n
			}
		}
	}
	fmt.Println(terminalReady, size())
	select {
	case <-winch:
		t.Winch = count(winch)
		t.Size = size()
		fmt.Println(terminalResized, t.Size)
		select {
		case <-ints:
			t.Int = count(ints)
		case <-time.After(terminalWait):
			t.Err = "no INT"
		}
	case <-time.After(terminalWait):
		t.Err = "no WINCH"
	}
	b, _ := json.Marshal(r)
	// The terminal echoes the Ctrl-C as ^C: the report starts on the next line.
	fmt.Println()
	fmt.Println(probePrefix + string(b))
	return 40 + t.Int
}

// watch is the run's standard output as it arrives, which the suite waits on.
type watch struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *watch) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// wait reports whether the output contains s within d.
func (w *watch) wait(s string, d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		w.mu.Lock()
		found := strings.Contains(w.b.String(), s)
		w.mu.Unlock()
		if found {
			return true
		}
	}
	return false
}

// terminal runs the terminal probe in an interactive run on a terminal of the suite's,
// a pseudo-terminal whose other end the suite drives: it resizes the terminal and
// sends the session SIGWINCH, as a terminal emulator does, then types a Ctrl-C.
// The runtime is in a separate process group, the terminal's foreground group inside the
// enclosure, so the Ctrl-C reaches the runtime once, and the helper's exec, its parent,
// not at all; the exit status is the runtime's.
func terminal(t *testing.T, o Options, h hosts, outside string) {
	t.Run("on a terminal a resize reaches the runtime and a Ctrl-C reaches it once", func(t *testing.T) {
		ptmx, tty, err := pty.Open()
		if err != nil {
			Skip(t, "this machine opens no pseudo-terminal: "+err.Error())
		}
		defer ptmx.Close()
		defer tty.Close()
		if err := pty.Setsize(ptmx, &pty.Winsize{Cols: terminalCols, Rows: terminalRows}); err != nil {
			t.Fatal(err)
		}
		w := &watch{}
		driven := make(chan string, 1)
		go func() {
			if !w.wait(terminalReady, 3*time.Minute) {
				driven <- "the probe never became ready"
				return
			}
			if err := pty.Setsize(ptmx, &pty.Winsize{Cols: resizedCols, Rows: resizedRows}); err != nil {
				driven <- err.Error()
				return
			}
			syscall.Kill(os.Getpid(), syscall.SIGWINCH)
			if !w.wait(terminalResized, terminalWait) {
				driven <- "the probe saw no resize"
				return
			}
			_, err := ptmx.Write([]byte{3})
			driven <- fmt.Sprint(err)
		}()
		r, err := runIn(t, o, variant{mode: modeTerminal, stdin: tty, stdout: w}, true, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if why := <-driven; why != "<nil>" {
			t.Fatalf("driving the terminal: %s", why)
		}
		p := r.probe.TTY
		if p == nil {
			t.Fatal("the terminal probe reported nothing of the terminal")
		}
		// One resize gives the runtime two WINCH through docker run --tty --init, with
		// docker-init as the runtime's parent too: the count of WINCH is docker's. A
		// Ctrl-C is one INT.
		if p.Err != "" || p.Winch < 1 || p.Int != 1 || p.Size != strconv.Itoa(resizedCols)+"x"+strconv.Itoa(resizedRows) {
			t.Errorf("the runtime got %d WINCH and %d INT and the size %s (%s); want a WINCH, one INT and %dx%d", p.Winch, p.Int, p.Size, p.Err, resizedCols, resizedRows)
		}
		if p.Group != p.Foreground || p.Group == p.Parent {
			t.Errorf("the runtime's process group is %d, the terminal's foreground group %d, its parent %d; want its group in the foreground, apart from its parent's", p.Group, p.Foreground, p.Parent)
		}
		if why := r.probe.Parent.problem(); why != "" {
			t.Error(why)
		}
		if r.res.ExitCode != 41 {
			t.Errorf("the exit status is %d; want the runtime's 41", r.res.ExitCode)
		}
		resized := false
		for _, e := range r.events {
			if d, _ := e["data"].(map[string]any); e["type"] == "dev.qory.run.resized" && d["cols"] == float64(resizedCols) && d["rows"] == float64(resizedRows) {
				resized = true
			}
		}
		if !resized {
			t.Errorf("no dev.qory.run.resized of %dx%d in the record", resizedCols, resizedRows)
		}
	})
}
