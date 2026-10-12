package gateway

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// keepExpired is how many of the server's run_key_expired refusals of an attach the
// gateway keeps at once.
const keepExpired = 4096

// expired are the server's run_key_expired refusals of an attach, by the SHA-256 of the
// run key the attach carried, each kept until the run key's attach_by plus the skew of
// [server.Window] by the gateway's clock: a run request with that run key gets the
// refusal again and sends no attach. Past that time the gateway refuses the run key
// itself ([Gateway.admitRunKey]). Its zero value keeps none yet.
type expired struct {
	mu   sync.Mutex
	kept map[[sha256.Size]byte]expiredRefusal
}

// expiredRefusal is a run_key_expired refusal of the server's, and until when it is
// kept.
type expiredRefusal struct {
	err   error
	until time.Time
}

// refusal is the refusal kept of the run key, nil for none: none was kept, or its time
// is past as of now.
func (e *expired) refusal(runKey string, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	sum := sha256.Sum256([]byte(runKey))
	k, ok := e.kept[sum]
	if !ok {
		return nil
	}
	if !now.Before(k.until) {
		delete(e.kept, sum)
		return nil
	}
	return k.err
}

// keep keeps err for the run key until the time given, when it is the server's
// refusal with the code run_key_expired and the time is after now; anything else is not
// kept. The refusals past their time go first; when the most are kept still, the one
// whose time ends soonest goes.
func (e *expired) keep(runKey string, err error, until, now time.Time) {
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) || ref.From != accesskey.FromApiary || ref.Code != codeRunKeyExpired || !now.Before(until) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.kept == nil {
		e.kept = map[[sha256.Size]byte]expiredRefusal{}
	}
	for s, k := range e.kept {
		if !now.Before(k.until) {
			delete(e.kept, s)
		}
	}
	sum := sha256.Sum256([]byte(runKey))
	if _, ok := e.kept[sum]; !ok && len(e.kept) >= keepExpired {
		var soonest [sha256.Size]byte
		first := true
		for s, k := range e.kept {
			if first || k.until.Before(e.kept[soonest].until) {
				soonest, first = s, false
			}
		}
		delete(e.kept, soonest)
	}
	e.kept[sum] = expiredRefusal{err: err, until: until}
}
