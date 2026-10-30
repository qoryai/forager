package tool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// envMode makes the test binary a tool: serve, fail, stall or leave.
const envMode = "QORY_TOOL_TEST_MODE"

// envLine is a line the test binary as a tool writes to standard error: after its
// first line when it serves, and in place of its last when it fails.
const envLine = "QORY_TOOL_TEST_LINE"

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
		if l := os.Getenv(envLine); l != "" {
			fmt.Fprintln(os.Stderr, l)
		}
		http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Join(os.Args[1:], " "))
			if r.URL.Path == "/leave" {
				go func() { time.Sleep(50 * time.Millisecond); os.Exit(3) }()
			}
		}))
	case "fail":
		fmt.Fprintln(os.Stderr, "starting")
		if l := os.Getenv(envLine); l != "" {
			fmt.Fprintln(os.Stderr, l)
		} else {
			fmt.Fprintln(os.Stderr, "no key for the store")
		}
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
		"a name outside the grammar":                     {Name: "Files", Command: []string{"x"}, Serves: []string{"a.internal"}},
		"no command":                                     {Name: "files", Serves: []string{"a.internal"}},
		"the argument in the program":                    {Name: "files", Command: []string{"/opt/${argument}"}, Serves: []string{"a.internal"}},
		"a pattern that does not compile":                {Name: "files", Command: []string{"x"}, Argument: "(", Serves: []string{"a.internal"}},
		"a pattern that compiles alone and not anchored": {Name: "files", Command: []string{"x"}, Argument: `a\Q`, Serves: []string{"a.internal"}},
		"no host":                      {Name: "files", Command: []string{"x"}},
		"a host with a port":           {Name: "files", Command: []string{"x"}, Serves: []string{"a.internal:443"}},
		"an upper-case host":           {Name: "files", Command: []string{"x"}, Serves: []string{"A.internal"}},
		"a placeholder not a variable": {Name: "files", Command: []string{"x"}, Serves: []string{"a.internal"}, Placeholders: []string{"A-B"}},
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

// TestAHostAToolAndACredentialClaimPrintsAPhraseForASecret pins the refusal of a host
// a tool serves and a credential is for: a credential's name that contains qak_ or
// qrk_ in any case prints the name's phrase, and a clean name prints as it is.
func TestAHostAToolAndACredentialClaimPrintsAPhraseForASecret(t *testing.T) {
	chosen, err := Choose([]Definition{def("plain", "", "plain.internal")}, []policy.Selected{{Name: "plain"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, shown := range map[string]string{
		"qak_x": "(a name that contains an access key secret)", "a.qrk_b": "(a name that contains a run key)",
		"qrk_x.qak_y": "(a name that contains an access key secret)", "token": "token",
	} {
		claimed := func(string) string { return name }
		err := Check(chosen, policy.Observe, nil, claimed)
		if want := "the tool plain and the credential " + shown + " both claim plain.internal; a host has one"; err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", name, err, want)
		} else if lower := strings.ToLower(err.Error()); strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") || strings.Contains(lower, "qecr_") || strings.Contains(lower, "qecn_") || strings.Contains(lower, "qecp_") || strings.Contains(lower, "qecg_") || strings.Contains(lower, "qeci_") || strings.Contains(lower, "qecd_") {
			t.Errorf("%s: a secret's prefix in %v", name, err)
		}
	}
}

// The phrases a tool message prints in place of a name that contains qak_ or qrk_ in
// any case.
const (
	accessKeyPhrase = "(a name that contains an access key secret)"
	runKeyPhrase    = "(a name that contains a run key)"
)

// noSecretPrefix fails the test when text contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_,
// qeci_ or qecd_ in any case.
func noSecretPrefix(t *testing.T, what, text string) {
	t.Helper()
	if lower := strings.ToLower(text); strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") || strings.Contains(lower, "qecr_") || strings.Contains(lower, "qecn_") || strings.Contains(lower, "qecp_") || strings.Contains(lower, "qecg_") || strings.Contains(lower, "qeci_") || strings.Contains(lower, "qecd_") {
		t.Errorf("%s: a secret's prefix in %s", what, text)
	}
}

// toolMessages are the tool messages that print a tool's name, argument or placeholder
// as accesskey.ShownName shows it. Each entry is the error for v in that part, the
// message it gives for p in the part's place, whether v may be in any case or only in
// lower case, as the name grammar holds a name a check sees after Check, and how the
// part shows for the clean v "files".
var toolMessages = map[string]struct {
	err     func(v string) error
	want    func(p string) string
	anyCase bool
	clean   string
}{
	"a name outside the grammar": {
		func(v string) error {
			return Definition{Name: v + "!", Command: []string{"x"}, Serves: []string{"a.internal"}}.Check()
		},
		func(p string) string {
			return "the tool name " + p + " is not 1 to 64 of a-z, 0-9, underscore, dot and dash"
		},
		true, `"files!"`,
	},
	"no command": {
		func(v string) error { return Definition{Name: v, Serves: []string{"a.internal"}}.Check() },
		func(p string) string { return "tool " + p + ": the command is empty" }, false, "files",
	},
	"the argument in the program": {
		func(v string) error {
			return Definition{Name: v, Command: []string{"/opt/${argument}"}, Serves: []string{"a.internal"}}.Check()
		},
		func(p string) string {
			return "tool " + p + ": the argument goes in the command's arguments, not in the program's name"
		}, false, "files",
	},
	"a pattern that does not compile": {
		func(v string) error {
			return Definition{Name: v, Command: []string{"x"}, Argument: "(", Serves: []string{"a.internal"}}.Check()
		},
		func(p string) string { return "tool " + p + ": argument: error parsing regexp: missing closing ): `(`" }, false, "files",
	},
	"no host": {
		func(v string) error { return Definition{Name: v, Command: []string{"x"}}.Check() },
		func(p string) string {
			return "tool " + p + " serves no host; a tool is reached by the hosts it serves"
		}, false, "files",
	},
	"a host outside the grammar": {
		func(v string) error {
			return Definition{Name: v, Command: []string{"x"}, Serves: []string{"A.internal"}}.Check()
		},
		func(p string) string {
			return "tool " + p + `: "A.internal" is not a lower-case host name or a *. suffix`
		}, false, "files",
	},
	"a placeholder outside the grammar, the name": {
		func(v string) error {
			return Definition{Name: v, Command: []string{"x"}, Serves: []string{"a.internal"}, Placeholders: []string{"A-B"}}.Check()
		},
		func(p string) string { return "tool " + p + `: the placeholder "A-B" is not a variable's name` }, false, "files",
	},
	"a placeholder outside the grammar, the placeholder": {
		func(v string) error {
			return Definition{Name: "files", Command: []string{"x"}, Serves: []string{"a.internal"}, Placeholders: []string{v + "-"}}.Check()
		},
		func(p string) string { return "tool files: the placeholder " + p + " is not a variable's name" }, true, `"files-"`,
	},
	"an argument for a tool that takes none, the name": {
		func(v string) error {
			_, err := Choose([]Definition{def(v, "", "a.internal")}, []policy.Selected{{Name: v, Argument: "x"}})
			return err
		},
		func(p string) string { return "tool " + p + ` takes no argument and the policy gives "x"` }, false, "files",
	},
	"an argument for a tool that takes none, the argument": {
		func(v string) error {
			_, err := Choose([]Definition{def("plain", "", "a.internal")}, []policy.Selected{{Name: "plain", Argument: v}})
			return err
		},
		func(p string) string { return "tool plain takes no argument and the policy gives " + p }, true, `"files"`,
	},
	"an argument the machine does not provide for, the name": {
		func(v string) error {
			_, err := Choose([]Definition{def(v, `[a-z]+/[a-z]+`, "a.internal")}, []policy.Selected{{Name: v, Argument: "x"}})
			return err
		},
		func(p string) string { return "tool " + p + `: the argument "x" is not one the machine provides for` }, false, "files",
	},
	"an argument the machine does not provide for, the argument": {
		func(v string) error {
			_, err := Choose([]Definition{def("files", `[a-z]+/[a-z]+`, "a.internal")}, []policy.Selected{{Name: "files", Argument: v}})
			return err
		},
		func(p string) string { return "tool files: the argument " + p + " is not one the machine provides for" }, true, `"files"`,
	},
	"a tool the machine does not define": {
		func(v string) error { _, err := Choose(nil, []policy.Selected{{Name: v}}); return err },
		func(p string) string {
			return "the policy selects the tool " + p + ", which this machine does not define: tool_unknown: " + strings.Trim(p, `"`)
		}, true, `"files"`,
	},
	"a tool selected twice": {
		func(v string) error {
			_, err := Choose([]Definition{def(v, "", "a.internal")}, []policy.Selected{{Name: v}, {Name: v}})
			return err
		},
		func(p string) string { return "the policy selects the tool " + p + " twice" }, false, `"files"`,
	},
	"the first of two tools that serve one host": {
		func(v string) error {
			_, err := Choose([]Definition{def(v, "", "a.internal"), def("other", "", "a.internal")}, []policy.Selected{{Name: v}, {Name: "other"}})
			return err
		},
		func(p string) string { return "the tools " + p + " and other both serve a.internal; a host has one" }, false, "files",
	},
	"the second of two tools that serve one host": {
		func(v string) error {
			_, err := Choose([]Definition{def("other", "", "a.internal"), def(v, "", "a.internal")}, []policy.Selected{{Name: "other"}, {Name: v}})
			return err
		},
		func(p string) string { return "the tools other and " + p + " both serve a.internal; a host has one" }, false, "files",
	},
	"a host a tool and a credential claim": {
		func(v string) error {
			chosen, err := Choose([]Definition{def(v, "", "a.internal")}, []policy.Selected{{Name: v}})
			if err != nil {
				return err
			}
			return Check(chosen, policy.Observe, nil, func(string) string { return "token" })
		},
		func(p string) string {
			return "the tool " + p + " and the credential token both claim a.internal; a host has one"
		}, false, "files",
	},
	"a host the allow list does not cover": {
		func(v string) error {
			chosen, err := Choose([]Definition{def(v, "", "a.internal")}, []policy.Selected{{Name: v}})
			if err != nil {
				return err
			}
			return Check(chosen, policy.Enforce, nil, func(string) string { return "" })
		},
		func(p string) string {
			return "the tool " + p + " serves a.internal, which the run's allow list does not cover"
		}, false, "files",
	},
}

// TestAToolMessagePrintsAPhraseForASecret pins that the messages of toolMessages print
// the name's phrase in place of a tool's name, argument or placeholder that contains
// qak_ or qrk_ in any case, the access key secret's when it contains both, with the
// rest of the sentence word for word, and the part as before for a clean value. A
// refusal's names, which its text ends with, are the phrase too.
func TestAToolMessagePrintsAPhraseForASecret(t *testing.T) {
	for what, m := range toolMessages {
		values := map[string]string{"qak_x": accessKeyPhrase, "a.qak_b": accessKeyPhrase, "qrk_x": runKeyPhrase, "a.qrk_b": runKeyPhrase, "qrk_x.qak_y": accessKeyPhrase}
		if m.anyCase {
			maps.Copy(values, map[string]string{"QAK_x": accessKeyPhrase, "qRk_x": runKeyPhrase, "QRK_x.QAK_y": accessKeyPhrase})
		}
		for v, phrase := range values {
			err := m.err(v)
			if err == nil {
				t.Errorf("%s, %s: no error", what, v)
				continue
			}
			if got, want := err.Error(), m.want(phrase); got != want {
				t.Errorf("%s, %s:\n got %s\nwant %s", what, v, got, want)
			}
			noSecretPrefix(t, what+", "+v, err.Error())
		}
		err := m.err("files")
		if err == nil {
			t.Errorf("%s, files: no error", what)
		} else if got, want := err.Error(), m.want(m.clean); got != want {
			t.Errorf("%s, files:\n got %s\nwant %s", what, got, want)
		}
	}
}

// TestARunningToolsReportPrintsAPhraseForASecretInAName pins what a tool's run is told
// of it: the lines the tool writes, before it listens and after, a tool that exits
// while the run goes on, and a tool that exits before it listens. A tool's name that
// contains qak_ or qrk_ prints the name's phrase, and a clean name prints as it is.
func TestARunningToolsReportPrintsAPhraseForASecretInAName(t *testing.T) {
	for name, shown := range map[string]string{"qak_x": accessKeyPhrase, "a.qrk_b": runKeyPhrase, "qrk_x.qak_y": accessKeyPhrase, "files": "files"} {
		t.Setenv(envMode, "serve")
		chosen, err := Choose([]Definition{def(name, `[a-z]+/[a-z]+`, "files.tools.internal")}, []policy.Selected{{Name: name, Argument: "acme/shop"}})
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
		if resp, err := client.Get("http://files.tools.internal/leave"); err == nil {
			resp.Body.Close()
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			said := slices.Clone(lines)
			mu.Unlock()
			if slices.ContainsFunc(said, func(l string) bool { return strings.Contains(l, "exited while the run goes on") }) {
				if !slices.Contains(said, "tool "+shown+": listening for the-run with --prefix media/acme/shop/") {
					t.Errorf("%s: the tool's line is not among %q", name, said)
				}
				if !slices.ContainsFunc(said, func(l string) bool { return strings.HasPrefix(l, "tool "+shown+" exited while the run goes on (") }) {
					t.Errorf("%s: the tool's exit is not among %q", name, said)
				}
				for _, l := range said {
					noSecretPrefix(t, name, l)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: the tool's exit was not reported: %q", name, said)
			}
			time.Sleep(20 * time.Millisecond)
		}
		set.Close()

		t.Setenv(envMode, "fail")
		_, err = Start(context.Background(), chosen, "the-run", os.Environ(), func(string) {})
		if err == nil || !strings.HasPrefix(err.Error(), "tool "+shown+": ") {
			t.Errorf("%s: a tool that exits before it listens: %v", name, err)
		} else {
			noSecretPrefix(t, name, err.Error())
		}
	}
}

// TestAToolsArgumentPatternErrorPrintsAPhraseForASecret pins the error of a tool's
// argument pattern that does not compile, which quotes the pattern: when its text
// contains qak_ or qrk_ in any case, the value's phrase is printed in its place, the
// error still wraps the regular expression's, and a clean error prints as it is.
func TestAToolsArgumentPatternErrorPrintsAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a value that contains an access key secret)", "(a value that contains a run key)"
	for pattern, phrase := range map[string]string{"qak_x(": ak, "QRK_x(": rk, "qrk_x qAk_y(": ak, `QAK_x\Q`: ak} {
		err := Definition{Name: "files", Command: []string{"x"}, Argument: pattern, Serves: []string{"a.internal"}}.Check()
		if want := "tool files: argument: " + phrase; err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", pattern, err, want)
			continue
		}
		noSecretPrefix(t, pattern, err.Error())
		var se *syntax.Error
		if !errors.As(err, &se) {
			t.Errorf("%s: %v does not wrap the regular expression's error", pattern, err)
		}
	}
	err := Definition{Name: "files", Command: []string{"x"}, Argument: "files(", Serves: []string{"a.internal"}}.Check()
	if want := "tool files: argument: error parsing regexp: missing closing ): `files(`"; err == nil || err.Error() != want {
		t.Errorf("a clean pattern:\n got %v\nwant %s", err, want)
	}
}

// TestAToolsProgramAndOutputPrintAPhraseForASecret pins the messages that print a
// tool's program, what it writes to standard error and a host it serves: a value that
// contains qak_ or qrk_ in any case prints the value's phrase in its place, and a clean
// value prints as it is.
func TestAToolsProgramAndOutputPrintAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a value that contains an access key secret)", "(a value that contains a run key)"
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "qak_x-tool")
	if err := os.Symlink(exe, program); err != nil {
		t.Fatal(err)
	}
	chosen := func(program string) []Chosen {
		t.Helper()
		d := Definition{Name: "files", Command: []string{program}, Serves: []string{"files.tools.internal"}}
		c, err := Choose([]Definition{d}, []policy.Selected{{Name: "files"}})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Setenv(envMode, "fail")
	t.Setenv(envLine, "no store for QRK_y")
	_, err = Start(context.Background(), chosen(program), "the-run", os.Environ(), func(string) {})
	if want := "tool files: " + ak + " exited before it listened: exit status 2: " + rk; err == nil || err.Error() != want {
		t.Errorf("a tool that exits:\n got %v\nwant %s", err, want)
	}
	t.Setenv(envLine, "no key for the store")
	_, err = Start(context.Background(), chosen(exe), "the-run", os.Environ(), func(string) {})
	if want := "tool files: " + exe + " exited before it listened: exit status 2: no key for the store"; err == nil || err.Error() != want {
		t.Errorf("a clean tool that exits:\n got %v\nwant %s", err, want)
	}

	t.Setenv(envMode, "stall")
	was := listenWait
	listenWait = 300 * time.Millisecond
	_, err = Start(context.Background(), chosen(program), "the-run", os.Environ(), func(string) {})
	listenWait = was
	if want := "tool files: " + ak + " did not listen on "; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("a tool that stalls:\n got %v\nwant %s…", err, want)
	} else {
		noSecretPrefix(t, "a tool that stalls", err.Error())
	}

	_, err = Start(context.Background(), chosen(filepath.Join(dir, "qrk_none")), "the-run", os.Environ(), func(string) {})
	if want := "tool files: " + rk; err == nil || err.Error() != want {
		t.Errorf("a tool that does not start:\n got %v\nwant %s", err, want)
	}

	t.Setenv(envMode, "serve")
	for line, want := range map[string]string{"the store is qak_z": ak, "the run key is qRk_z": rk, "the store is ready": "the store is ready"} {
		t.Setenv(envLine, line)
		var mu sync.Mutex
		var lines []string
		set, err := Start(context.Background(), chosen(exe), "the-run", os.Environ(), func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() })
		if err != nil {
			t.Fatal(err)
		}
		set.Close()
		mu.Lock()
		said := slices.Clone(lines)
		mu.Unlock()
		if !slices.Contains(said, "tool files: "+want) {
			t.Errorf("%s: no %q among %q", line, "tool files: "+want, said)
		}
	}

	// A line with a match of mask.Shapes has *** in its place, in a report and in the
	// error of a tool that exits.
	key := "AKIA" + strings.Repeat("X", 16)
	t.Setenv(envLine, "the store key is "+key)
	var shaped []string
	var shapedMu sync.Mutex
	set, err := Start(context.Background(), chosen(exe), "the-run", os.Environ(), func(l string) { shapedMu.Lock(); shaped = append(shaped, l); shapedMu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	set.Close()
	shapedMu.Lock()
	if !slices.Contains(shaped, "tool files: the store key is ***") {
		t.Errorf("a line with a key: no masked line among %q", shaped)
	}
	shapedMu.Unlock()
	t.Setenv(envMode, "fail")
	_, err = Start(context.Background(), chosen(exe), "the-run", os.Environ(), func(string) {})
	if want := "tool files: " + exe + " exited before it listened: exit status 2: the store key is ***"; err == nil || err.Error() != want {
		t.Errorf("a tool that exits with a key in its line:\n got %v\nwant %s", err, want)
	}

	for host, want := range map[string]string{"qak_x.example": ak, "a.QRK_x": rk, "Files.example": `"Files.example"`} {
		err := Definition{Name: "files", Command: []string{"x"}, Serves: []string{host}}.Check()
		if want := "tool files: " + want + " is not a lower-case host name or a *. suffix"; err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", host, err, want)
		}
	}
}
