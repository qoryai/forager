package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/e2e"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/wall"
)

func TestMain(m *testing.M) {
	e2e.Main()
	os.Exit(m.Run())
}

// TestDockerConforms runs the suite against the Docker adapter and whatever engine the
// docker command reaches, and then the adapter's own checks of its relay.
// QORY_WALL_COMMAND names another command, podman say, and QORY_WALL_IMAGE another image
// with a shell.
func TestDockerConforms(t *testing.T) {
	image := os.Getenv("QORY_WALL_IMAGE")
	if image == "" {
		image = "ghcr.io/qoryai/ci-images:busybox-stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	}
	conform(t, image, "", false)
	t.Run("the relay runs no health check", relayRunsNoHealthCheck)
	t.Run("the relay listens on the inside network alone", relayListensInsideAlone)
	t.Run("the relay takes a connection from the inside network alone", relayTakesInsideAlone)
}

// TestDockerNestedConforms runs the suite against an image with a Docker of the agent's
// own, started under the runtime set in QORY_WALL_RUNTIME, such as sysbox-runc, which the
// engine must have. QORY_WALL_NESTED_IMAGE defines the image, one that contains dockerd
// and the docker command; without QORY_WALL_RUNTIME the test is skipped.
func TestDockerNestedConforms(t *testing.T) {
	rt := os.Getenv("QORY_WALL_RUNTIME")
	if rt == "" {
		e2e.Skip(t, "QORY_WALL_RUNTIME names no runtime that runs a Docker of the agent's own")
	}
	image := os.Getenv("QORY_WALL_NESTED_IMAGE")
	if image == "" {
		image = "ghcr.io/qoryai/ci-images:docker-dind@sha256:0b6d18a4a222e71c88be6034926b4f6cde2fc33c2218643d03ccfddc65995470"
	}
	conform(t, image, rt, true)
}

// conform runs the suite with the adapter and the engine the docker command reaches.
func conform(t *testing.T, image, rt string, docker bool) {
	command := os.Getenv("QORY_WALL_COMMAND")
	if command == "" {
		command = "docker"
	}
	if out, err := exec.Command(command, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		e2e.Skip(t, command+" reaches no engine: "+strings.TrimSpace(string(out)))
	}
	engine, err := exec.Command(command, "info", "--format", "{{.ID}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	// The origin an allowed request reaches is a container of its own, because the proxy
	// of a walled run never dials this machine. An image with a Docker of its own need not
	// hold httpd, so the origin is then busybox.
	origin := image
	if docker {
		origin = "ghcr.io/qoryai/ci-images:busybox-stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	}
	helper := e2e.Helper(t)
	name := fmt.Sprintf("qory-walltest-origin-%d", os.Getpid())
	if out, err := exec.Command(command, "run", "--detach", "--rm", "--name", name, origin, "sh", "-c", "mkdir /w && echo ok > /w/index.html && httpd -f -p 8080 -h /w").CombinedOutput(); err != nil {
		t.Fatalf("the origin: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(command, "rm", "--force", name).Run() })
	ip, err := exec.Command(command, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	// Three recorders, the helper in a busybox of its own each: the hosts of a runtime's
	// two credentials and a host with none.
	var recorders []e2e.Recorder
	for i := range 3 {
		name := fmt.Sprintf("qory-walltest-recorder-%d-%d", os.Getpid(), i)
		args := []string{"run", "--detach", "--name", name, "--mount", "type=bind,src=" + helper + ",dst=/walltest,readonly"}
		for _, kv := range e2e.RecorderEnv() {
			args = append(args, "--env", kv)
		}
		args = append(append(args, "--entrypoint", "/walltest", "ghcr.io/qoryai/ci-images:busybox-stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"), e2e.RecorderArgs...)
		if out, err := exec.Command(command, args...).CombinedOutput(); err != nil {
			t.Fatalf("a recorder: %v: %s", err, out)
		}
		t.Cleanup(func() { exec.Command(command, "rm", "--force", name).Run() })
		e2e.AwaitRecorder(t, command, name)
		ip, err := exec.Command(command, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
		if err != nil {
			t.Fatal(err)
		}
		recorders = append(recorders, e2e.Recorder{Host: strings.TrimSpace(string(ip)), Recorded: func() ([]byte, error) {
			return exec.Command(command, "exec", name, "cat", e2e.RecorderFile).Output()
		}})
	}
	volumes := func() map[string]bool {
		out, _ := exec.Command(command, "volume", "ls", "--quiet").Output()
		m := map[string]bool{}
		for _, v := range strings.Fields(string(out)) {
			m[v] = true
		}
		return m
	}
	before := volumes()
	// The engine is recorded first, as a session records it, so every command of the
	// adapter's runs with the recorded selection.
	w := &wall.Docker{Command: command, Helper: helper, RelayArgs: e2e.RelayArgs,
		NestArgs: e2e.NestArgs}
	if e := w.Engine(context.Background()); e.ID != strings.TrimSpace(string(engine)) {
		t.Fatalf("the engine recorded: %+v", e)
	}
	e2e.Run(t, e2e.Options{
		Origin:    "http://" + strings.TrimSpace(string(ip)) + ":8080/",
		Wall:      w,
		Image:     image,
		Runtime:   rt,
		Docker:    docker,
		EngineID:  strings.TrimSpace(string(engine)),
		Recorders: recorders,
		Forwarder: []string{wall.HelperPath, "forward"},
		Probe:     wall.HelperPath,
		// A socket crosses a bind mount on a Linux host and not a virtual machine's file
		// share.
		Hooks: runtime.GOOS == "linux",
		Leftovers: func(runID string) ([]string, error) {
			var left []string
			for _, list := range [][]string{{"ps", "--all", "--quiet"}, {"network", "ls", "--quiet"}} {
				out, err := exec.Command(command, append(list, "--filter", "label=dev.qory.run="+runID)...).CombinedOutput()
				if err != nil {
					return nil, err
				}
				left = append(left, strings.Fields(string(out))...)
			}
			// The daemon's store inside is a volume of the run's, and goes with it.
			for v := range volumes() {
				if !before[v] {
					left = append(left, "volume "+v)
				}
			}
			return left, nil
		},
	})
	t.Run("the agent's container runs no health check", func(t *testing.T) { agentRunsNoHealthCheck(t, command, helper, image, rt, docker) })
	t.Run("no IPv6 inside but loopback's", func(t *testing.T) { insideHasNoIPv6(t, command, helper, image, rt, docker) })
}

// busybox is the image the relay's own tests start from.
const busybox = "ghcr.io/qoryai/ci-images:busybox-stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

// relaySecret is the run's proxy secret in the relay's own tests.
const relaySecret = "walltest-relay-secret"

// relayRun is a run of the Docker adapter's, prepared and wrapped: its relay listens and
// forwards to proxy, a listener of the test's in the gateway's place, and agent is the
// launch that starts the agent's container.
type relayRun struct {
	// relay is the relay's container, inside the enclosure's network and outside its
	// ordinary one, and container the agent's container once the agent starts.
	relay, inside, outside, container string
	proxy                             net.Listener
	agent                             wall.Launch
}

// relayEngine is the command the relay's own tests run, QORY_WALL_COMMAND or docker, and
// the helper; it skips when the command reaches no engine or there is no helper.
func relayEngine(t *testing.T) (command, helper string) {
	t.Helper()
	command = os.Getenv("QORY_WALL_COMMAND")
	if command == "" {
		command = "docker"
	}
	if out, err := exec.Command(command, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		e2e.Skip(t, command+" reaches no engine: "+strings.TrimSpace(string(out)))
	}
	return command, e2e.Helper(t)
}

// startRelay prepares an enclosure of the command's for a run of its own in the image
// and wraps the agent's command, sh with args, which starts the relay. Everything is
// removed when the test ends.
func startRelay(t *testing.T, command, helper, image string, args ...string) relayRun {
	t.Helper()
	return startEnclosure(t, command, helper, wall.Request{Image: image}, args...)
}

// startEnclosure is startRelay for the request's image, runtime and Docker of the
// agent's own; the request's run id is the test's own.
func startEnclosure(t *testing.T, command, helper string, req wall.Request, args ...string) relayRun {
	t.Helper()
	w := &wall.Docker{Command: command, Helper: helper, RelayArgs: e2e.RelayArgs, NestArgs: e2e.NestArgs}
	runID := fmt.Sprintf("walltest-relay-%d-%d", os.Getpid(), time.Now().UnixNano())
	req.RunID = runID
	ctx := context.Background()
	e, err := w.Prepare(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close(ctx) })
	proxy, err := net.Listen("tcp", e.ProxyAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })
	dir := t.TempDir()
	agent, err := e.Wrap(ctx, wall.Launch{Command: "sh", Args: args, Dir: dir, Mounts: []wall.Mount{{Path: dir}},
		Proxy: proxy.Addr().String(), ProxyToken: relaySecret})
	if err != nil {
		t.Fatal(err)
	}
	return relayRun{relay: "qory-" + runID + "-relay", inside: "qory-" + runID + "-in", outside: "qory-" + runID + "-out",
		container: "qory-" + runID + "-agent", proxy: proxy, agent: agent}
}

// start starts the agent's container and returns what it printed when it ends, or
// when ctx ends, which kills the docker command and leaves the container to Close.
func (r relayRun) start(ctx context.Context, t *testing.T) func() string {
	t.Helper()
	var out strings.Builder
	agent := exec.CommandContext(ctx, r.agent.Command, r.agent.Args...)
	agent.Env, agent.Dir, agent.Stdout, agent.Stderr = r.agent.Env, r.agent.Dir, &out, &out
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	return func() string {
		agent.Wait()
		return out.String()
	}
}

// relayRunsNoHealthCheck starts the relay from an image with a health check and requires
// that the engine runs none in the relay's container, where it would run beside the
// run's proxy secret, with the relay's way out.
func relayRunsNoHealthCheck(t *testing.T) {
	command, helper := relayEngine(t)
	tag := fmt.Sprintf("qory-walltest-health:%d", os.Getpid())
	build := exec.Command(command, "build", "--quiet", "--tag", tag, "-")
	build.Stdin = strings.NewReader("FROM " + busybox + "\nHEALTHCHECK --interval=1s CMD true\n")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("the image with a health check: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(command, "rmi", "--force", tag).Run() })
	r := startRelay(t, command, helper, tag)
	out, err := exec.Command(command, "inspect", "--format", "{{json .State.Health}}", r.relay).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "null" {
		t.Errorf("the relay runs the image's health check: %s", got)
	}
}

// relayListensInsideAlone dials the relay's port on its address on the ordinary network
// from a container on the engine's default network and from one on the host's, and
// requires that neither connects, and then that the agent still reaches the relay by its
// name inside, its traffic arriving with the preamble.
func relayListensInsideAlone(t *testing.T) {
	command, helper := relayEngine(t)
	r := startRelay(t, command, helper, busybox, "-c", "printf hello | nc qory-proxy 3128")
	out, err := exec.Command(command, "inspect", "--format",
		fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", r.outside), r.relay).CombinedOutput()
	ip := strings.TrimSpace(string(out))
	if err != nil || net.ParseIP(ip) == nil {
		t.Fatalf("the relay's address on its ordinary network: %v: %s", err, out)
	}
	for _, network := range []string{"bridge", "host"} {
		dial := fmt.Sprintf("if nc -z -w 3 %s 3128; then echo connected; else echo refused; fi", ip)
		out, err := exec.Command(command, "run", "--rm", "--network", network, busybox, "sh", "-c", dial).CombinedOutput()
		if err != nil {
			t.Fatalf("the dial from the %s network: %v: %s", network, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "refused" {
			t.Errorf("a container on the %s network dialled the relay at %s:3128: %s", network, ip, got)
		}
	}

	want := link.RelayLine(relaySecret) + "hello"
	got := make(chan string, 1)
	go func() {
		c, err := r.proxy.Accept()
		if err != nil {
			got <- err.Error()
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(time.Minute))
		b := make([]byte, len(want))
		n, _ := io.ReadFull(c, b)
		got <- string(b[:n])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	agent := exec.CommandContext(ctx, r.agent.Command, r.agent.Args...)
	agent.Env, agent.Dir = r.agent.Env, r.agent.Dir
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	// A failure stops the agent rather than wait for it.
	defer func() {
		if t.Failed() {
			cancel()
		}
		agent.Wait()
	}()
	select {
	case s := <-got:
		if s != want {
			t.Errorf("the proxy read %q from the agent's connection, want %q", s, want)
		}
	case <-ctx.Done():
		t.Fatal("the agent's connection never reached the proxy")
	}
}

// relayTakesInsideAlone dials the relay's port on its address inside from a container on
// the relay's ordinary network, routed there through the relay's address on that network,
// and requires that the proxy never sees the connection, which the relay's port takes
// unless the engine drops it on the way.
func relayTakesInsideAlone(t *testing.T) {
	command, helper := relayEngine(t)
	r := startRelay(t, command, helper, busybox)
	address := func(network string) string {
		t.Helper()
		out, err := exec.Command(command, "inspect", "--format",
			fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", network), r.relay).CombinedOutput()
		ip := strings.TrimSpace(string(out))
		if err != nil || net.ParseIP(ip) == nil {
			t.Fatalf("the relay's address on %s: %v: %s", network, err, out)
		}
		return ip
	}
	inside, outside := address(r.inside), address(r.outside)
	out, err := exec.Command(command, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", r.inside).CombinedOutput()
	subnets := strings.Fields(string(out))
	if err != nil || len(subnets) == 0 {
		t.Fatalf("the inside network's subnets: %v: %s", err, out)
	}

	accepted := make(chan string, 1)
	go func() {
		c, err := r.proxy.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		accepted <- string(b)
	}()
	dial := fmt.Sprintf("ip route add %s via %s && if nc -z -w 3 %s 3128; then echo connected; else echo refused; fi && printf hello | nc -w 3 %s 3128; true",
		subnets[0], outside, inside, inside)
	out, err = exec.Command(command, "run", "--rm", "--network", r.outside, "--cap-add", "NET_ADMIN", busybox, "sh", "-c", dial).CombinedOutput()
	if err != nil {
		t.Fatalf("the dial from the relay's ordinary network: %v: %s", err, out)
	}
	// An engine that drops the routed packets leaves the relay's port out of reach, which
	// keeps the guarantee and tests nothing of the relay's own.
	switch got := strings.TrimSpace(string(out)); got {
	case "connected":
	case "refused":
		t.Log("the engine dropped the routed dial before it reached the relay")
	default:
		t.Fatalf("the dial from the relay's ordinary network: %s", got)
	}
	select {
	case s := <-accepted:
		t.Errorf("a connection from the relay's ordinary network reached the proxy: %q", s)
	case <-time.After(3 * time.Second):
	}
}

// agentRunsNoHealthCheck starts the agent from an image with a health check and requires
// that the engine runs none in the agent's container, where it would run beside the
// agent's environment and, with a Docker of the agent's own, as the enclosure's root.
func agentRunsNoHealthCheck(t *testing.T, command, helper, image, rt string, docker bool) {
	tag := fmt.Sprintf("qory-walltest-agent-health:%d", os.Getpid())
	build := exec.Command(command, "build", "--quiet", "--tag", tag, "-")
	build.Stdin = strings.NewReader("FROM " + image + "\nHEALTHCHECK --interval=1s CMD true\n")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("the image with a health check: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(command, "rmi", "--force", tag).Run() })
	r := startEnclosure(t, command, helper, wall.Request{Image: tag, Runtime: rt, Docker: docker}, "-c", "sleep 120")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	wait := r.start(ctx, t)
	defer func() {
		cancel()
		wait()
	}()
	for {
		out, err := exec.Command(command, "inspect", "--format", "{{.State.Running}} {{json .State.Health}}", r.container).CombinedOutput()
		if got := strings.TrimSpace(string(out)); err == nil && strings.HasPrefix(got, "true ") {
			if got != "true null" {
				t.Errorf("the agent's container runs the image's health check: %s", got)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the agent's container never ran: %s", out)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// insideHasNoIPv6 requires that the inside network has no IPv6 subnet, and that the
// agent's container starts with no IPv6 address but loopback's ::1 and with IPv6 off by
// default for an interface made later.
func insideHasNoIPv6(t *testing.T, command, helper, image, rt string, docker bool) {
	r := startEnclosure(t, command, helper, wall.Request{Image: image, Runtime: rt, Docker: docker},
		"-c", "cat /proc/net/if_inet6; echo default=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)")
	t.Run("the inside network has none", func(t *testing.T) {
		out, err := exec.Command(command, "network", "inspect", "--format", "{{.EnableIPv6}}", r.inside).CombinedOutput()
		if got := strings.TrimSpace(string(out)); err != nil || got != "false" {
			t.Errorf("the inside network's IPv6 is enabled: %v: %s", err, out)
		}
	})
	t.Run("the agent's container has loopback's alone", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out := r.start(ctx, t)()
		var loopback, others []string
		disabled := false
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			f := strings.Fields(line)
			switch {
			case line == "default=1":
				disabled = true
			case len(f) == 6 && f[0] == "00000000000000000000000000000001" && f[5] == "lo":
				loopback = append(loopback, line)
			case len(f) == 6:
				others = append(others, line)
			}
		}
		if len(loopback) != 1 || len(others) != 0 {
			t.Errorf("the agent's IPv6 addresses, want loopback's ::1 alone:\n%s", out)
		}
		if !disabled {
			t.Errorf("the agent's container starts with IPv6 on by default for an interface made later:\n%s", out)
		}
	})
}
