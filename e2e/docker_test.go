package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/e2e"
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
		image = "public.ecr.aws/docker/library/busybox:stable"
	}
	conform(t, image, "", false)
	t.Run("the relay runs no health check", relayRunsNoHealthCheck)
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
		image = "public.ecr.aws/docker/library/docker:dind"
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
		origin = "public.ecr.aws/docker/library/busybox:stable"
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
		args = append(append(args, "--entrypoint", "/walltest", "public.ecr.aws/docker/library/busybox:stable"), e2e.RecorderArgs...)
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
}

// busybox is the image the relay's own tests start from.
const busybox = "public.ecr.aws/docker/library/busybox:stable"

// relaySecret is the run's proxy secret in the relay's own tests.
const relaySecret = "walltest-relay-secret"

// relayRun is a run of the Docker adapter's, prepared and wrapped: its relay listens and
// forwards to a listener of the test's in the gateway's place.
type relayRun struct {
	// relay is the relay's container.
	relay string
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
	w := &wall.Docker{Command: command, Helper: helper, RelayArgs: e2e.RelayArgs}
	runID := fmt.Sprintf("walltest-relay-%d-%d", os.Getpid(), time.Now().UnixNano())
	ctx := context.Background()
	e, err := w.Prepare(ctx, wall.Request{RunID: runID, Image: image})
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
	if _, err := e.Wrap(ctx, wall.Launch{Command: "sh", Args: args, Dir: dir, Mounts: []wall.Mount{{Path: dir}},
		Proxy: proxy.Addr().String(), ProxyToken: relaySecret}); err != nil {
		t.Fatal(err)
	}
	return relayRun{relay: "qory-" + runID + "-relay"}
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
