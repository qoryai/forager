package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// What the run of a sealed credential is: the variable its placeholder is in, the
// variable that names the recorder the credential is for, the mark every sealed value
// of the suite contains and nothing else does, and the prefix of the one line of
// standard output that holds the sealed probe's report.
const (
	sealedPlaceholder = "MODEL_API_KEY"
	sealedHostVar     = "PROBE_SEALED_HOST"
	sealedMark        = "-SEALED-not-a-secret-"
	sealedPrefix      = "walltest-sealed: "
	// sealedRenew is the argument that makes the sealed probe send its request every
	// sealedEvery for sealedFor, so a renewal of the value reaches the recorder.
	sealedRenew = "renew"
	sealedEvery = 2 * time.Second
	sealedFor   = 50 * time.Second
)

// sealedReport is what the sealed probe found inside the enclosure: the placeholder
// variable's value, the status of the request it sent with it and the error of one that
// failed, where it saw a sealed value, and how many process environments it read.
type sealedReport struct {
	Placeholder string   `json:"placeholder"`
	Status      int      `json:"status"`
	Err         string   `json:"err"`
	Seen        []string `json:"seen"`
	Environs    int      `json:"environs"`
}

// sealedProbe is the run of a sealed credential inside the enclosure: it sends the
// placeholder variable's value in x-api-key to the recorder sealedHostVar names,
// through the proxy, as a model client sends its key; and it looks for sealedMark in
// its environment, every process environment under /proc it can read and the answer.
// With sealedRenew it sends the request every sealedEvery for sealedFor, and reports
// the last status and the first error. It prints one line, sealedPrefix and the report
// as JSON, and exits 0.
func sealedProbe(args []string) int {
	r := sealedReport{Placeholder: os.Getenv(sealedPlaceholder)}
	u := "https://" + net.JoinHostPort(os.Getenv(sealedHostVar), recorderTLS) + modelPath
	end := time.Now()
	if len(args) > 0 && args[0] == sealedRenew {
		end = end.Add(sealedFor)
	}
	for {
		status, answer, err := postAnswer(u, "x-api-key", r.Placeholder)
		r.Status = status
		if r.Err == "" {
			r.Err = err
		}
		if strings.Contains(answer, sealedMark) {
			r.Seen = append(r.Seen, "the answer of "+u)
		}
		if !time.Now().Add(sealedEvery).Before(end) {
			break
		}
		time.Sleep(sealedEvery)
	}
	for _, kv := range os.Environ() {
		if name, value, _ := strings.Cut(kv, "="); strings.Contains(value, sealedMark) {
			r.Seen = append(r.Seen, name)
		}
	}
	environs, _ := filepath.Glob("/proc/[0-9]*/environ")
	for _, e := range environs {
		b, err := os.ReadFile(e)
		if err != nil {
			continue
		}
		r.Environs++
		if strings.Contains(string(b), sealedMark) {
			r.Seen = append(r.Seen, e)
		}
	}
	b, _ := json.Marshal(r)
	fmt.Println(sealedPrefix + string(b))
	return 0
}
