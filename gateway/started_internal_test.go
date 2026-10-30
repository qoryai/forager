package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
)

// TestARunStartedWithRawValuesGoesOnPhrased pins a run.started and a session.started a
// session sends with its values as they are: the gateway phrases every member a
// session phrases, so none that contains qak_ or qrk_ in any case goes on, each event
// still validates, and one without such a value is kept byte for byte.
func TestARunStartedWithRawValuesGoesOnPhrased(t *testing.T) {
	const (
		ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
		av, rv = "(a value that contains an access key secret)", "(a value that contains a run key)"
	)
	run := `{"opened_by":"run","forager_version":"test","host":"QRK_host",` +
		`"labels":{"repository":"acme/qak_FAKE"},"about":{"title":"qrk_t","subjects":[{"type":"issue","ref":"qak_r"},{"type":"issue","ref":"7"}]}}`
	session := `{"session":1,"interactive":false,` +
		`"runtime":"qak_rt","command":"/bin/qak_cmd","args":["a","--x=qrk_FAKE"],"dir":"/work/QAK_d",` +
		`"runtime_version":"1 qrk_v","setup_commands":["install","qak_p"],"image":"registry.example/qrk_i@sha256:` + strings.Repeat("0", 64) + `"}`
	evs := []event.Event{{Type: event.RunStarted, Data: json.RawMessage(run)}, {Type: event.SessionStarted, Data: json.RawMessage(session)}}
	shownStarted(evs)
	decoded := make([]map[string]any, len(evs))
	for i, ev := range evs {
		b, _ := ev.Data.(json.RawMessage)
		if low := strings.ToLower(string(b)); strings.Contains(low, "qak_") || strings.Contains(low, "qrk_") || strings.Contains(low, "qecr_") || strings.Contains(low, "qecn_") || strings.Contains(low, "qecp_") || strings.Contains(low, "qecg_") || strings.Contains(low, "qeci_") || strings.Contains(low, "qecd_") {
			t.Errorf("the %s goes on as %s", ev.Type, b)
		}
		if err := json.Unmarshal(b, &decoded[i]); err != nil {
			t.Fatal(err)
		}
	}
	runData, sessionData := decoded[0], decoded[1]
	if runData["host"] != rk {
		t.Errorf("host: %v, want %v", runData["host"], rk)
	}
	if about, _ := runData["about"].(map[string]any); about["title"] != rk || len(about["subjects"].([]any)) != 1 {
		t.Errorf("about: %v", runData["about"])
	}
	for member, want := range map[string]any{"runtime": ak, "command": av, "dir": av, "runtime_version": rv, "image": rk} {
		if sessionData[member] != want {
			t.Errorf("%s: %v, want %v", member, sessionData[member], want)
		}
	}
	if args, _ := sessionData["args"].([]any); len(args) != 2 || args[0] != "a" || args[1] != rv {
		t.Errorf("args: %v", sessionData["args"])
	}
	if names, _ := sessionData["setup_commands"].([]any); len(names) != 2 || names[0] != "install" || names[1] != av {
		t.Errorf("setup_commands: %v", sessionData["setup_commands"])
	}
	for name, data := range map[string]map[string]any{"events/run.started.schema.json": runData, "events/session.started.schema.json": sessionData} {
		schema, err := contracts.Compile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	cleanRun := `{"opened_by":"run","forager_version":"test","about":{"title":"t","kind":"k"},"labels":{"z":"1","a":"2"}}`
	cleanSession := `{"session":1,"command":"true","args":["a\/b"],"dir":"/w"}`
	evs = []event.Event{{Type: event.RunStarted, Data: json.RawMessage(cleanRun)}, {Type: event.SessionStarted, Data: json.RawMessage(cleanSession)}}
	shownStarted(evs)
	for i, want := range []string{cleanRun, cleanSession} {
		if got := string(evs[i].Data.(json.RawMessage)); got != want {
			t.Errorf("a clean %s goes on as %s", evs[i].Type, got)
		}
	}
}
