package tool

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/runner/link"
	"github.com/qoryai/runner/policy"
)

// envMode makes the test binary a tool: serve, fail, stall or leave.
const envMode = "QORY_TOOL_TEST_MODE"

func TestMain(m *testing.M) {
	switch os.Getenv(envMode) {
	case "":
		os.Exit(m.Run())
	case "serve":
		ln, err := net.Listen("unix", os.Getenv(link.EnvToolListen))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "listening for", os.Getenv(EnvRunID), "with", strings.Join(os.Args[1:], " "))
		http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Join(os.Args[1:], " "))
			if r.URL.Path == "/leave" {
				go func() { time.Sleep(50 * time.Millisecond); os.Exit(3) }()
			}
		}))
	case "fail":
		fmt.Fprintln(os.Stderr, "starting")
		fmt.Fprintln(os.Stderr, "no key for the store")
		os.Exit(2)
	case "stall":
		time.Sleep(time.Hour)
	}
}

func def(name, argument string, serves ...string) Definition {
	exe, _ := os.Executable()
	return Definition{Name: name, Command: []string{exe, "--prefix", "media/${argument}/"}, Argument: argument, Serves: serves}
}

// TestCheckRefusesWhatCannotBeATool pins the definition's own checks.
func TestCheckRefusesWhatCannotBeATool(t *testing.T) {
	for name, d := range map[string]Definition{
		"a name outside the grammar":      {Name: "Files", Command: []string{"x"}, Serves: []string{"a.internal"}},
		"no command":                      {Name: "files", Serves: []string{"a.internal"}},
		"the argument in the program":     {Name: "files", Command: []string{"/opt/${argument}"}, Serves: []string{"a.internal"}},
		"a pattern that does not compile": {Name: "files", Command: []string{"x"}, Argument: "(", Serves: []string{"a.internal"}},
		"no host":                         {Name: "files", Command: []string{"x"}},
		"a host with a port":              {Name: "files", Command: []string{"x"}, Serves: []string{"a.internal:443"}},
		"an upper-case host":              {Name: "files", Command: []string{"x"}, Serves: []string{"A.internal"}},
		"a placeholder not a variable":    {Name: "files", Command: []string{"x"}, Serves: []string{"a.internal"}, Placeholders: []string{"A-B"}},
	} {
		if err := d.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (Definition{Name: "files", Command: []string{"x", "${argument}"}, Argument: "[a-z]+", Serves: []string{"*.tools.internal"}, Placeholders: []string{"AWS_ACCESS_KEY_ID"}}).Check(); err != nil {
		t.Errorf("a definition that is one: %v", err)
	}
}

// TestChooseAndCheckRefuseWhatCannotHold pins what a run's selection is refused for:
// an unknown name, a name twice, an argument the definition does not provide for, a
// host two tools serve, a host a credential is for, and under enforce a host the allow
// list does not cover.
func TestChooseAndCheckRefuseWhatCannotHold(t *testing.T) {
	defs := []Definition{def("files", `[a-z]+/[a-z]+`, "files.tools.internal"), def("more", "", "*.tools.internal"), def("plain", "", "plain.internal")}
	for name, c := range map[string]struct {
		sel  []policy.Selected
		want string
	}{
		"unknown":        {[]policy.Selected{{Name: "nothing"}}, "does not define"},
		"twice":          {[]policy.Selected{{Name: "plain"}, {Name: "plain"}}, "twice"},
		"no argument":    {[]policy.Selected{{Name: "files"}}, "not one the machine provides for"},
		"a wide one":     {[]policy.Selected{{Name: "files", Argument: "acme/shop/../x"}}, "not one the machine provides for"},
		"one too many":   {[]policy.Selected{{Name: "plain", Argument: "x"}}, "takes no argument"},
		"a host for two": {[]policy.Selected{{Name: "files", Argument: "acme/shop"}, {Name: "more"}}, "both serve"},
	} {
		if _, err := Choose(defs, c.sel); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	chosen, err := Choose(defs, []policy.Selected{{Name: "files", Argument: "acme/shop"}, {Name: "plain"}})
	if err != nil {
		t.Fatal(err)
	}
	none := func(string) string { return "" }
	if err := Check(chosen, policy.Enforce, []string{"files.tools.internal"}, none); err == nil || !strings.Contains(err.Error(), "plain.internal") {
		t.Errorf("a host the allow list does not cover under enforce: %v", err)
	}
	if err := Check(chosen, policy.Observe, nil, none); err != nil {
		t.Errorf("under observe: %v", err)
	}
	if err := Check(chosen, policy.Enforce, []string{"*.internal", "files.tools.internal"}, none); err != nil {
		t.Errorf("covered hosts: %v", err)
	}
	claimed := func(h string) string {
		if h == "plain.internal" {
			return "token"
		}
		return ""
	}
	if err := Check(chosen, policy.Observe, nil, claimed); err == nil || !strings.Contains(err.Error(), "credential token") {
		t.Errorf("a host a credential is for: %v", err)
	}
}

// TestStartRunsATool pins a tool's life: started with its argument in its command line
// and the socket in its environment, reached there, its lines reported once it
// listens, its exit while the run goes on reported, and gone after Close.
func TestStartRunsATool(t *testing.T) {
	t.Setenv(envMode, "serve")
	chosen, err := Choose([]Definition{def("files", `[a-z]+/[a-z]+`, "files.tools.internal")}, []policy.Selected{{Name: "files", Argument: "acme/shop"}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	report := func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }
	set, err := Start(context.Background(), chosen, "the-run", os.Environ(), report)
	if err != nil {
		t.Fatal(err)
	}
	tl := set.Tools[0]
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", tl.Socket)
	}}}
	get := func(path string) string {
		resp, err := client.Get("http://files.tools.internal" + path)
		if err != nil {
			return err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := get("/"); got != "--prefix media/acme/shop/" {
		t.Errorf("the tool's command line: %q", got)
	}
	get("/leave")
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		said := strings.Join(lines, "\n")
		mu.Unlock()
		if strings.Contains(said, "exited while the run goes on") {
			if !strings.Contains(said, "tool files: listening for the-run") {
				t.Errorf("what the tool wrote was not reported: %q", said)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tool's exit was not reported: %q", said)
		}
		time.Sleep(20 * time.Millisecond)
	}
	set.Close()
	if _, err := os.Stat(tl.Socket); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after Close: %v", err)
	}
}

// TestStartRefusesAToolThatDoesNotListen pins that a tool that exits first, or does not
// listen in time, is no run, with the last line it wrote as the reason, and that a
// stalled one is stopped.
func TestStartRefusesAToolThatDoesNotListen(t *testing.T) {
	chosen, _ := Choose([]Definition{def("files", "", "files.tools.internal")}, []policy.Selected{{Name: "files"}})
	t.Setenv(envMode, "fail")
	_, err := Start(context.Background(), chosen, "the-run", os.Environ(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "exited before it listened") || !strings.Contains(err.Error(), "no key for the store") {
		t.Errorf("a tool that exits: %v", err)
	}
	// A tool that leaves a child holding its standard error is seen to exit all the same.
	chosen[0].Command = []string{"/bin/sh", "-c", "sleep 30 & echo no key for the store >&2; exit 4"}
	start := time.Now()
	_, err = Start(context.Background(), chosen, "the-run", os.Environ(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "exited before it listened") || !strings.Contains(err.Error(), "no key for the store") || time.Since(start) > 5*time.Second {
		t.Errorf("a tool whose child holds its standard error: %v after %s", err, time.Since(start))
	}
	chosen, _ = Choose([]Definition{def("files", "", "files.tools.internal")}, []policy.Selected{{Name: "files"}})
	t.Setenv(envMode, "stall")
	was := listenWait
	listenWait = 300 * time.Millisecond
	defer func() { listenWait = was }()
	start = time.Now()
	_, err = Start(context.Background(), chosen, "the-run", os.Environ(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "did not listen") {
		t.Errorf("a tool that stalls: %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("stopping a stalled tool took %s", time.Since(start))
	}
}
