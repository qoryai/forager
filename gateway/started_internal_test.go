package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
)

// TestARunStartedWithRawValuesGoesOnPhrased pins a run.started a session sends with
// its values as they are: the gateway phrases every member a session phrases, so none
// that contains qak_ or qrk_ in any case goes on, the event still validates, and a
// run.started without one is kept byte for byte.
func TestARunStartedWithRawValuesGoesOnPhrased(t *testing.T) {
	const (
		ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
		av, rv = "(a value that contains an access key secret)", "(a value that contains a run key)"
	)
	raw := `{"opened_by":"session","forager_version":"test","interactive":false,` +
		`"runtime":"qak_rt","host":"QRK_host","command":"/bin/qak_cmd","args":["a","--x=qrk_FAKE"],"dir":"/work/QAK_d",` +
		`"runtime_version":"1 qrk_v","preparation":["true","qak_p"],"image":"registry.example/qrk_i@sha256:` + strings.Repeat("0", 64) + `",` +
		`"labels":{"repository":"acme/qak_FAKE"},"about":{"title":"qrk_t","subjects":[{"type":"issue","ref":"qak_r"},{"type":"issue","ref":"7"}]}}`
	evs := []event.Event{{Type: event.RunStarted, Data: json.RawMessage(raw)}}
	shownStarted(evs)
	b, _ := evs[0].Data.(json.RawMessage)
	if low := strings.ToLower(string(b)); strings.Contains(low, "qak_") || strings.Contains(low, "qrk_") {
		t.Errorf("the run.started goes on as %s", b)
	}
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[string]any{"runtime": ak, "host": rk, "command": av, "dir": av, "runtime_version": rv, "image": rk} {
		if data[member] != want {
			t.Errorf("%s: %v, want %v", member, data[member], want)
		}
	}
	if args, _ := data["args"].([]any); len(args) != 2 || args[0] != "a" || args[1] != rv {
		t.Errorf("args: %v", data["args"])
	}
	if about, _ := data["about"].(map[string]any); about["title"] != rk || len(about["subjects"].([]any)) != 1 {
		t.Errorf("about: %v", data["about"])
	}
	schema, err := contracts.Compile("events/run.started.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(data); err != nil {
		t.Errorf("the run.started does not validate: %v", err)
	}
	clean := `{"opened_by":"session","command":"true","args":["a\/b"],"dir":"/w","about":{"title":"t","kind":"k"},"labels":{"z":"1","a":"2"}}`
	evs = []event.Event{{Type: event.RunStarted, Data: json.RawMessage(clean)}}
	shownStarted(evs)
	if got := string(evs[0].Data.(json.RawMessage)); got != clean {
		t.Errorf("a clean run.started goes on as %s", got)
	}
}
