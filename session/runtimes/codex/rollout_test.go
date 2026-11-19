package codex_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/codex"
)

// The files of testdata/usage are what Codex 0.167.2 wrote behind the wall against a
// stub of the Responses API (stub-usage.json), with only the workspace's temporary path
// replaced: launch 1, codex exec --json, whose thread starts one child agent, and
// launch 2, codex exec --json resume <thread id>, on launch 1's restored rollout. The
// stub's response n has each count as one digit times 10^(n-1): input 5, cached 1,
// cache write 2, output 4, reasoning 3, total 9. Responses 1, 2 and 4 are launch 1's
// thread's, 3 the child's, and 5 launch 2's.

// The usage of each launch, from stub-usage.json: input is input less cached less
// cache write, 5 - 1 - 2 = 2 of each digit.
//   - Launch 1: the thread's responses 1, 2 and 4 are 1011 of each digit, the child's
//     response 3 is 100: 1111, so input 2222, output 4444, cache_read 1111 and
//     cache_write 2222.
//   - Launch 2: response 5 is 10000 of each digit: input 20000, output 40000,
//     cache_read 10000 and cache_write 20000.
var (
	launch1Usage = codex.Usage{Input: 2222, Output: 4444, CacheRead: 1111, CacheWrite: 2222}
	launch2Usage = codex.Usage{Input: 20000, Output: 40000, CacheRead: 10000, CacheWrite: 20000}
)

// usageFile reads testdata/usage/name.
func usageFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "usage", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rollout parses testdata/usage/name with restored bytes restored.
func rollout(t *testing.T, name string, restored int64) codex.Rollout {
	t.Helper()
	r, err := codex.ParseRollout(usageFile(t, name), restored)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

// launchUsage is [codex.LaunchUsage] that fails the test on an error or no count.
func launchUsage(t *testing.T, parent codex.Rollout, others ...codex.Rollout) codex.Usage {
	t.Helper()
	u, counted, clamped, err := codex.LaunchUsage(parent, others)
	if err != nil || !counted || clamped {
		t.Fatalf("usage %+v, counted %v, clamped %v, %v", u, counted, clamped, err)
	}
	return u
}

// stubUsage is the usage of the stub's responses of each class in stub-usage.json,
// mapped as dev.qory.runtime.result's usage.
func stubUsage(t *testing.T, classes ...string) codex.Usage {
	t.Helper()
	var stub struct {
		Requests []struct {
			Class string           `json:"class"`
			Usage map[string]int64 `json:"usage_returned"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(usageFile(t, "stub-usage.json"), &stub); err != nil {
		t.Fatal(err)
	}
	var u codex.Usage
	for _, r := range stub.Requests {
		for _, c := range classes {
			if r.Class == c {
				cached, write := r.Usage["input_tokens_details.cached_tokens"], r.Usage["input_tokens_details.cache_write_tokens"]
				u = u.Add(codex.Usage{Input: r.Usage["input_tokens"] - cached - write, Output: r.Usage["output_tokens"], CacheRead: cached, CacheWrite: write})
			}
		}
	}
	return u
}

// TestCodexLaunchUsageOfTheFixture pins the usage of the fixture's two launches: launch
// 1's thread plus its child, and launch 2's thread less the restored launch 1. The
// expected values match the stub's numbers. A change of the rollout's format, such as
// another name of a field, fails it.
func TestCodexLaunchUsageOfTheFixture(t *testing.T) {
	if want := stubUsage(t, "launch1-parent-spawn", "launch1-parent-wait", "child", "launch1-parent-final"); want != launch1Usage {
		t.Fatalf("the stub's launch 1 is %+v; the test states %+v", want, launch1Usage)
	}
	if want := stubUsage(t, "launch2-parent-final"); want != launch2Usage {
		t.Fatalf("the stub's launch 2 is %+v; the test states %+v", want, launch2Usage)
	}
	parent1, child := rollout(t, "launch1-parent-rollout.jsonl", 0), rollout(t, "launch1-child-rollout.jsonl", 0)
	const thread = "01a1f100-87f8-7123-a174-ba291730eec1"
	if parent1.ThreadID != thread || parent1.ParentID != "" || child.ThreadID != "01a1f100-885b-7140-a145-b604ffe0117a" || child.ParentID != thread {
		t.Errorf("thread %q of %q, child %q of %q", parent1.ThreadID, parent1.ParentID, child.ThreadID, child.ParentID)
	}
	if want := (codex.Tokens{Input: 5055, CachedInput: 1011, CacheWriteInput: 2022, Output: 4044, ReasoningOutput: 3033, Total: 9099}); parent1.Last == nil || *parent1.Last != want || parent1.Restored != nil {
		t.Errorf("launch 1's thread has the last total %+v and restored %+v; want %+v and none", parent1.Last, parent1.Restored, want)
	}
	if got := launchUsage(t, parent1, child); got != launch1Usage {
		t.Errorf("launch 1's usage is %+v; want %+v", got, launch1Usage)
	}

	restored := int64(len(usageFile(t, "launch1-parent-rollout.jsonl")))
	parent2 := rollout(t, "launch2-parent-rollout.jsonl", restored)
	if parent2.Restored == nil || *parent2.Restored != *parent1.Last {
		t.Errorf("launch 2's restored total is %+v; want launch 1's last %+v", parent2.Restored, parent1.Last)
	}
	if got := launchUsage(t, parent2); got != launch2Usage {
		t.Errorf("launch 2's usage is %+v; want %+v", got, launch2Usage)
	}
}

// TestCodexLaunchUsageIsNotTheThreadsTotal checks that no line of standard output maps
// to dev.qory.runtime.result, which the session writes from the rollouts, and that
// turn.completed has the thread's total since its first launch, not the launch's: 55055
// input tokens on launch 2.
func TestCodexLaunchUsageIsNotTheThreadsTotal(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"launch1-stdout.jsonl", "launch2-stdout.jsonl"} {
		sc := bufio.NewScanner(bytes.NewReader(usageFile(t, name)))
		for line := 1; sc.Scan(); line++ {
			var rec map[string]any
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				t.Fatalf("%s:%d: %v", name, line, err)
			}
			for _, e := range rt.Map(runtimes.Record{Source: runtimes.SourceOutput, Record: rec}) {
				if e.Type == "dev.qory.runtime.result" {
					t.Errorf("%s:%d maps to %s", name, line, e.Type)
				}
			}
		}
	}
	if b := usageFile(t, "launch2-stdout.jsonl"); !bytes.Contains(b, []byte(`"turn.completed","usage":{"input_tokens":55055,`)) {
		t.Errorf("launch 2's turn.completed has no input of 55055:\n%s", b)
	}
}

// meta is a session_meta line of thread id, started by the thread parent when it is
// not empty.
func meta(id, parent string) string {
	if parent == "" {
		return fmt.Sprintf(`{"type":"session_meta","payload":{"id":%q,"session_id":%q,"source":"exec"}}`, id, id)
	}
	return fmt.Sprintf(`{"type":"session_meta","payload":{"id":%q,"session_id":"root","parent_thread_id":%q,"thread_source":"subagent"}}`, id, parent)
}

// total is a token_count line with the input n, cached n/5, cache write 2n/5, output
// 4n/5, reasoning 3n/5 and total 9n/5.
func total(n int64) string {
	return fmt.Sprintf(`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":%d,"cached_input_tokens":%d,"cache_write_input_tokens":%d,"output_tokens":%d,"reasoning_output_tokens":%d,"total_tokens":%d},"last_token_usage":{}}}}`,
		n, n/5, 2*n/5, 4*n/5, 3*n/5, 9*n/5)
}

// parsed is [codex.ParseRollout] of lines, each followed by a newline.
func parsed(t *testing.T, restored int64, lines ...string) codex.Rollout {
	t.Helper()
	r, err := codex.ParseRollout([]byte(strings.Join(lines, "\n")+"\n"), restored)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestCodexLaunchUsageCases covers a child of a child, a child whose file is missing,
// a thread with no token_count, a token_count with info null, a part of a line, a
// rollout of another thread, a loop of parents, a child too deep, and a count below 0.
func TestCodexLaunchUsageCases(t *testing.T) {
	// u5 is the usage of a total of input 5n: 2n, 4n, n and 2n.
	u5 := func(n int64) codex.Usage {
		return codex.Usage{Input: 2 * n, Output: 4 * n, CacheRead: n, CacheWrite: 2 * n}
	}
	parent := parsed(t, 0, meta("p", ""), total(5), `{"type":"event_msg","payload":{"type":"token_count","info":null,"rate_limits":{}}}`, total(50))
	t.Run("child of a child", func(t *testing.T) {
		got := launchUsage(t, parent, parsed(t, 0, meta("c", "p"), total(500)), parsed(t, 0, meta("g", "c"), total(5000)), parsed(t, 0, meta("x", "other"), total(50000)))
		if want := u5(10 + 100 + 1000); got != want {
			t.Errorf("usage %+v; want %+v", got, want)
		}
	})
	t.Run("child's file missing", func(t *testing.T) {
		got := launchUsage(t, parent, parsed(t, 0, meta("g", "c"), total(5000)))
		if want := u5(10); got != want {
			t.Errorf("usage %+v; want the thread's %+v alone", got, want)
		}
	})
	t.Run("thread with no token_count", func(t *testing.T) {
		u, counted, _, err := codex.LaunchUsage(parsed(t, 0, meta("p", "")), nil)
		if err != nil || counted {
			t.Errorf("usage %+v, counted %v, %v; want none counted", u, counted, err)
		}
		got := launchUsage(t, parsed(t, 0, meta("p", "")), parsed(t, 0, meta("c", "p"), total(500)))
		if want := u5(100); got != want {
			t.Errorf("usage %+v; want the child's %+v", got, want)
		}
	})
	t.Run("restored with nothing new", func(t *testing.T) {
		b := meta("p", "") + "\n" + total(5) + "\n"
		r := parsed(t, int64(len(b)), meta("p", ""), total(5))
		if u, counted, _, err := codex.LaunchUsage(r, nil); err != nil || counted {
			t.Errorf("usage %+v, counted %v, %v; want none counted", u, counted, err)
		}
	})
	t.Run("part of a line", func(t *testing.T) {
		r, err := codex.ParseRollout([]byte(meta("p", "")+"\n"+total(5)+"\n"+total(50)[:40]), 0)
		if err != nil || r.Last == nil || r.Last.Input != 5 {
			t.Errorf("rollout %+v, %v; want the last whole total, input 5", r, err)
		}
	})
	t.Run("no session_meta", func(t *testing.T) {
		if _, err := codex.ParseRollout([]byte(total(5)+"\n"), 0); err == nil {
			t.Error("a rollout with no session_meta parsed")
		}
		if _, err := codex.ParseRollout([]byte(meta("p", "")+"\n"), 100); err == nil {
			t.Error("a rollout shorter than its restored bytes parsed")
		}
	})
	t.Run("thread_spawn's parent", func(t *testing.T) {
		r := parsed(t, 0, `{"type":"session_meta","payload":{"id":"c","source":{"subagent":{"thread_spawn":{"parent_thread_id":"p","depth":1}}}}}`)
		if r.ParentID != "p" {
			t.Errorf("parent %q; want p", r.ParentID)
		}
	})
	t.Run("loop", func(t *testing.T) {
		got := launchUsage(t, parent, parsed(t, 0, meta("c", "p"), total(500)), parsed(t, 0, meta("p", "c"), total(5000)))
		if want := u5(10 + 100); got != want {
			t.Errorf("usage %+v; want %+v", got, want)
		}
	})
	t.Run("too deep", func(t *testing.T) {
		others := []codex.Rollout{}
		up := "p"
		for i := range codex.MaxDepth + 1 {
			id := fmt.Sprint("c", i)
			others = append(others, parsed(t, 0, meta(id, up), total(5)))
			up = id
		}
		if _, _, _, err := codex.LaunchUsage(parent, others[:codex.MaxDepth]); err != nil {
			t.Errorf("%d levels: %v", codex.MaxDepth, err)
		}
		if _, _, _, err := codex.LaunchUsage(parent, others); !errors.Is(err, codex.ErrTooDeep) {
			t.Errorf("%d levels: %v; want %v", codex.MaxDepth+1, err, codex.ErrTooDeep)
		}
	})
	t.Run("below 0", func(t *testing.T) {
		u, clamped := codex.Map(codex.Tokens{Input: 2, CachedInput: 2, CacheWriteInput: 1, Output: 3})
		if want := (codex.Usage{Input: 0, Output: 3, CacheRead: 2, CacheWrite: 1}); u != want || !clamped {
			t.Errorf("usage %+v, clamped %v; want %+v, clamped", u, clamped, want)
		}
	})
}
