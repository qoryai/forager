package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// TestTheExpiredRefusalsAreBounded pins what the gateway keeps of the server's
// run_key_expired: only a refusal of the server's with that code, each until its time,
// at most keepExpired at once, those past their time going first and then the one whose
// time ends soonest.
func TestTheExpiredRefusalsAreBounded(t *testing.T) {
	now := time.Now()
	ref := func(code, from string) error {
		return &accesskey.Refusal{Code: code, Status: http.StatusConflict, Detail: "attach https://apiary.example/v1/runs/x", From: from}
	}
	var e expired
	for _, err := range []error{ref(codeRunKeyExpired, accesskey.FromGateway), ref("run_attached", accesskey.FromApiary), errors.New("no answer")} {
		e.keep("qrk_other", err, now.Add(time.Minute), now)
		if got := e.refusal("qrk_other", now); got != nil {
			t.Errorf("kept %v", err)
		}
	}
	expiredRef := ref(codeRunKeyExpired, accesskey.FromApiary)
	e.keep("qrk_past", expiredRef, now, now)
	if e.refusal("qrk_past", now) != nil {
		t.Error("kept a refusal whose time is past")
	}
	e.keep("qrk_lapses", expiredRef, now.Add(time.Second), now)
	if e.refusal("qrk_lapses", now) != expiredRef || e.refusal("qrk_lapses", now.Add(time.Second)) != nil {
		t.Error("a refusal is not kept until its time alone")
	}
	e.keep("qrk_lapses", expiredRef, now.Add(time.Second), now)
	e.keep("qrk_lapses_too", expiredRef, now.Add(time.Second), now)
	for i := range keepExpired - 2 {
		e.keep(fmt.Sprint("qrk_", i), expiredRef, now.Add(time.Hour+time.Duration(i)*time.Second), now)
	}
	if len(e.kept) != keepExpired {
		t.Fatalf("%d kept; want %d", len(e.kept), keepExpired)
	}
	// One more, past the time of two: both go, nothing else.
	later := now.Add(2 * time.Second)
	e.keep("qrk_new", expiredRef, later.Add(time.Hour), later)
	if len(e.kept) != keepExpired-1 || e.refusal("qrk_0", later) == nil {
		t.Errorf("%d kept, qrk_0 %v; want the two past their time gone alone", len(e.kept), e.refusal("qrk_0", later))
	}
	// Two more: the first fills the place, and the second sends the one whose time ends
	// soonest.
	e.keep("qrk_newer", expiredRef, later.Add(2*time.Hour), later)
	e.keep("qrk_newest", expiredRef, later.Add(2*time.Hour), later)
	if len(e.kept) != keepExpired || e.refusal("qrk_0", later) != nil || e.refusal("qrk_1", later) == nil || e.refusal("qrk_newest", later) == nil {
		t.Errorf("%d kept; want qrk_0, the soonest, gone", len(e.kept))
	}
}
