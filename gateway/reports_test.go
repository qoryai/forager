package gateway_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
)

// TestResendReportsItsConstants pins that each line Resend reports of a record is
// exactly the value of the constant that names it, so a caller can tell them apart
// without copying their text.
func TestResendReportsItsConstants(t *testing.T) {
	line := func(typ, seq string) string {
		return `{"type":"` + typ + `","sequence":"` + seq + `","data":{}}` + "\n"
	}
	run := func(t *testing.T, record string) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), event.NewRunID())
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	resend := func(t *testing.T, cfg gateway.ResendConfig) (gateway.Delivery, []string) {
		t.Helper()
		var reports []string
		cfg.Report = func(l string) { reports = append(reports, l) }
		d, err := gateway.Resend(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return d, reports
	}

	t.Run("torn", func(t *testing.T) {
		dir := run(t, line(event.RunStarted, "0000000001")+"not an event\n"+line(event.RunLog, "0000000002"))
		_, reports := resend(t, gateway.ResendConfig{Dir: dir})
		want := fmt.Sprintf(gateway.ResendTorn, 1, filepath.Join(dir, "events.jsonl"))
		if !slices.Equal(reports, []string{want}) {
			t.Errorf("reports %q, want %q", reports, want)
		}
	})
	t.Run("not opened", func(t *testing.T) {
		dir := run(t, line(event.RunRefused, "0000000001"))
		d, reports := resend(t, gateway.ResendConfig{Dir: dir})
		if !slices.Equal(reports, []string{gateway.ResendNotOpened}) || !d.NotOpened {
			t.Errorf("reports %q, delivery %+v", reports, d)
		}
	})
	t.Run("no server", func(t *testing.T) {
		dir := run(t, line(event.RunStarted, "0000000001"))
		d, reports := resend(t, gateway.ResendConfig{Server: newControl(t).server(), Dir: dir})
		if !slices.Equal(reports, []string{gateway.ResendNoServer}) || !d.NotOpened {
			t.Errorf("reports %q, delivery %+v", reports, d)
		}
	})
}
