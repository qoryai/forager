package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// What the Node test's origin serves: a package document at /nodePackage, whose latest
// version is nodeVersion, and "ok" at every other path. nodeLine opens the line the
// Node script prints.
const (
	nodePackage = "walltest-node-pkg"
	nodeVersion = "1.2.3"
	nodeLine    = "walltest-node "
)

// nodeOrigin is the program of the origin container: an HTTP server on port 8080.
const nodeOrigin = `const doc = JSON.stringify({name: "` + nodePackage + `", "dist-tags": {latest: "` + nodeVersion + `"},
  versions: {"` + nodeVersion + `": {name: "` + nodePackage + `", version: "` + nodeVersion + `"}}});
require("http").createServer((req, res) => {
  if (req.url === "/` + nodePackage + `") {
    res.setHeader("content-type", "application/json");
    res.end(doc);
    return;
  }
  res.end("ok");
}).listen(8080);`

// nodeFetch is the script each container runs with node: Node's built-in fetch of the
// allowed URL and of the denied one, given as its two arguments. Node's fetch sends
// every request through the proxy in a CONNECT tunnel, so the proxy's 403 for the
// denied host is the error "Proxy response (403) !== 200 when HTTP Tunneling", and not
// a response. It prints nodeLine and a [nodeReport], and exits 0 only when the allowed
// URL returned 200 and the denied one ended with that error.
const nodeFetch = `const [allowed, denied] = process.argv.slice(2);
(async () => {
  const out = {};
  for (const [key, url] of [["allowed", allowed], ["denied", denied]]) {
    try {
      const res = await fetch(url, {signal: AbortSignal.timeout(30000)});
      out[key] = res.status;
      out[key + "_body"] = (await res.text()).slice(0, 200);
    } catch (e) {
      const chain = [];
      for (let c = e; c; c = c.cause) chain.push(String(c.code || "") + " " + c.message);
      out[key + "_err"] = chain.join(" <- ");
    }
  }
  console.log("` + nodeLine + `" + JSON.stringify(out));
  const refused = String(out.denied_err).includes("Proxy response (403) !== 200");
  process.exit(out.allowed === 200 && refused ? 0 : 1);
})();`

// nodeReport is what nodeFetch found.
type nodeReport struct {
	Allowed     int    `json:"allowed"`
	AllowedBody string `json:"allowed_body"`
	AllowedErr  string `json:"allowed_err"`
	Denied      int    `json:"denied"`
	DeniedBody  string `json:"denied_body"`
	DeniedErr   string `json:"denied_err"`
}

// TestDockerNodeUsesTheRunsProxy runs Node behind the Docker adapter in the image of
// QORY_WALL_NODE_IMAGE, which has Node 24 and npm. The origin, a container of the same
// image, is the one host the policy allows; denied.invalid is not allowed. In a setup
// container, a step container and the session, Node's built-in fetch gets 200 and "ok"
// from the origin, and the proxy's 403 to its tunnel for denied.invalid: the container
// has no route out and no resolver, so both answers come through the proxy, which Node
// uses only with NODE_USE_ENV_PROXY=1. In the session, npm view, with the origin as its registry,
// prints the package's version. The record lists each fetch of the origin as allowed,
// and each of denied.invalid as denied.
//
// The test is skipped without QORY_WALL_NODE_IMAGE, without an engine the docker
// command reaches, and, off Linux, without a Linux build of the test binary in
// QORY_WALL_HELPER.
func TestDockerNodeUsesTheRunsProxy(t *testing.T) {
	image := os.Getenv("QORY_WALL_NODE_IMAGE")
	if image == "" {
		Skip(t, "QORY_WALL_NODE_IMAGE is empty: it selects an image with Node 24 and npm")
	}
	command := os.Getenv("QORY_WALL_COMMAND")
	if command == "" {
		command = "docker"
	}
	if out, err := exec.Command(command, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		Skip(t, command+" reaches no engine: "+strings.TrimSpace(string(out)))
	}
	helper := Helper(t)
	name := fmt.Sprintf("qory-walltest-node-origin-%d", os.Getpid())
	if out, err := exec.Command(command, "run", "--detach", "--rm", "--name", name, "--entrypoint", "node", image, "-e", nodeOrigin).CombinedOutput(); err != nil {
		t.Fatalf("the origin: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(command, "kill", name).Run() })
	ready := `fetch("http://127.0.0.1:8080/").then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))`
	for i := 0; exec.Command(command, "exec", name, "node", "-e", ready).Run() != nil; i++ {
		if i == 30 {
			t.Fatal("the origin did not answer on port 8080 within 30 seconds")
		}
		time.Sleep(time.Second)
	}
	ip, err := exec.Command(command, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	origin := strings.TrimSpace(string(ip))
	allowed, denied := "http://"+origin+":8080/", "http://denied.invalid/"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fetch.js"), []byte(nodeFetch), 0o644); err != nil {
		t.Fatal(err)
	}
	runs := filepath.Join(t.TempDir(), "runs")
	var reports reportLines
	gw, closeGateway := startGateway(t, gateway.Config{Version: "walltest",
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{origin}}},
		Report: func(l string) { reports.add(t, l) }}, runs)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r, err := session.Open(ctx, session.OpenSpec{RunsDir: runs, RunID: event.NewRunID(), Gateway: gw, ForagerVersion: "walltest",
		Wall:  &wall.Docker{Command: command, Helper: helper, RelayArgs: RelayArgs, NestArgs: NestArgs, HoldArgs: HoldArgs},
		Image: image, Report: func(l string) { reports.add(t, l) }})
	if err != nil {
		t.Fatal(err)
	}
	fetchArgs := []string{"/usr/local/bin/node", "fetch.js", allowed, denied}
	setupErr := r.Setup(ctx, session.SetupSpec{Dir: dir, Commands: []session.SetupCommand{{Name: "node fetch", Args: fetchArgs}}})
	removeErr := r.RemoveSetup(ctx)
	step, stepErr := r.RunStep(ctx, session.StepSpec{Name: "node fetch", Command: fetchArgs, Dir: dir, Timeout: 2 * time.Minute})
	var out, errs strings.Builder
	res, joinErr := r.Join(ctx, session.SessionSpec{
		Command: "/bin/sh",
		Args: []string{"-c", `/usr/local/bin/node fetch.js "$1" "$2" && npm view --registry "$3" ` + nodePackage + ` version`,
			"sh", allowed, denied, allowed},
		Env:    []string{"npm_config_update_notifier=false"},
		Dir:    dir,
		Stdout: &out,
		Stderr: &errs,
		Exec:   append([]string{wall.HelperPath}, ExecArgs...),
	})
	outcome := session.Outcome{State: event.StateFailed, ExitCode: -1}
	if joinErr == nil {
		outcome = session.Outcome{State: res.State, ExitCode: res.ExitCode}
	}
	if _, err := r.Close(ctx, outcome); err != nil {
		t.Fatal(err)
	}
	closeGateway()

	// report reads the line of nodeFetch in text and checks it.
	report := func(t *testing.T, text string) {
		t.Helper()
		_, rest, ok := strings.Cut(text, nodeLine)
		if !ok {
			t.Fatalf("no line of the Node script in:\n%s", text)
		}
		line, _, _ := strings.Cut(rest, "\n")
		var p nodeReport
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			t.Fatalf("the Node script's line %q: %v", line, err)
		}
		if p.Allowed != 200 || p.AllowedBody != "ok" {
			t.Errorf("the fetch of the origin: %d %q %s; want 200 and ok", p.Allowed, p.AllowedBody, p.AllowedErr)
		}
		if p.Denied != 0 || !strings.Contains(p.DeniedErr, "Proxy response (403) !== 200 when HTTP Tunneling") {
			t.Errorf("the fetch of denied.invalid: %d %q %s; want the proxy's 403 to the tunnel", p.Denied, p.DeniedBody, p.DeniedErr)
		}
	}
	events := readEvents(t, filepath.Join(r.Dir(), "events.jsonl"))
	t.Run("a setup's fetch goes through the proxy", func(t *testing.T) {
		if setupErr != nil || removeErr != nil {
			t.Errorf("the setup: %v; its removal: %v", setupErr, removeErr)
		}
		var lines strings.Builder
		for _, e := range events {
			if d, _ := e["data"].(map[string]any); e["type"] == "dev.qory.run.log" && d["session"] == nil {
				b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["bytes"]))
				lines.Write(b)
			}
		}
		report(t, lines.String())
	})
	t.Run("a step's fetch goes through the proxy", func(t *testing.T) {
		if stepErr != nil {
			t.Fatalf("the step: %v", stepErr)
		}
		if step.ExitCode != 0 {
			t.Errorf("the step exited %d", step.ExitCode)
		}
		report(t, string(step.Output))
	})
	t.Run("a session's fetch goes through the proxy", func(t *testing.T) {
		if joinErr != nil {
			t.Fatalf("the join: %v\nstderr:\n%s", joinErr, errs.String())
		}
		report(t, out.String())
	})
	t.Run("npm view in a session goes through the proxy", func(t *testing.T) {
		if joinErr != nil {
			t.Fatalf("the join: %v", joinErr)
		}
		if res.ExitCode != 0 || !strings.Contains(out.String(), "\n"+nodeVersion+"\n") {
			t.Errorf("the session exited %d; want 0 and the version %s from npm view\nstdout:\n%s\nstderr:\n%s", res.ExitCode, nodeVersion, out.String(), errs.String())
		}
	})
	t.Run("the record lists each request", func(t *testing.T) {
		var toOrigin, toDenied int
		for _, e := range events {
			d, _ := e["data"].(map[string]any)
			switch {
			case e["type"] != event.RunEgress:
			case d["host"] == origin && d["decision"] == "allowed":
				toOrigin++
			case d["host"] == "denied.invalid" && d["decision"] == "denied":
				toDenied++
			}
		}
		// Three fetches and at least one request of npm reach the origin.
		if toOrigin < 4 || toDenied != 3 {
			t.Errorf("the record lists %d allowed requests to the origin and %d denied ones to denied.invalid; want at least 4 and 3", toOrigin, toDenied)
		}
	})
}

// readEvents reads the events of a run's events.jsonl.
func readEvents(t *testing.T, file string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}
