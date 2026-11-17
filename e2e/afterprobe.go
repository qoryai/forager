package e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/forager/link"
)

// The files After's probes write in the workspace.
const (
	afterRouteFile   = "after-route.out"
	afterInspectFile = "after-inspect.out"
)

// plantPassword is [modePlantPassword]'s program: the agent writes the password of its
// proxy URL into routePasswordFile, as any program of its container could, and exits.
// It prints an empty report.
func plantPassword() int {
	u, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || u.User == nil {
		fmt.Fprintln(os.Stderr, "plant-password: the agent's HTTP_PROXY has no password")
		return 1
	}
	password, _ := u.User.Password()
	if err := os.WriteFile(routePasswordFile, []byte(password), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "plant-password:", err)
		return 1
	}
	fmt.Println(probePrefix + "{}")
	return 0
}

// afterRoute is [modeAfterRoute]'s program, After's command: it sends a GET to the route
// to link.QoryHost through After's proxy, once without a password and once with the one
// the agent planted, and writes the two statuses into afterRouteFile, 0 for a request
// that failed.
func afterRoute() int {
	b, err := os.ReadFile(routePasswordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "after-route:", err)
		return 1
	}
	proxy, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxy.Host == "" {
		fmt.Fprintln(os.Stderr, "after-route: After's container has no HTTP_PROXY")
		return 1
	}
	withPassword := *proxy
	withPassword.User = url.UserPassword(link.ProxyUser, strings.TrimSpace(string(b)))
	var statuses []string
	for _, p := range []*url.URL{proxy, &withPassword} {
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(p), DisableKeepAlives: true}, Timeout: 20 * time.Second}
		status := 0
		if resp, err := client.Get(link.QoryHostURL + "/after"); err == nil {
			status = resp.StatusCode
			resp.Body.Close()
		}
		statuses = append(statuses, strconv.Itoa(status))
	}
	if err := os.WriteFile(afterRouteFile, []byte(strings.Join(statuses, " ")), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "after-route:", err)
		return 1
	}
	return 0
}
