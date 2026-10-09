package gateway

import (
	"net/http"
	"time"
)

// SetQuiet makes a run whose session sends nothing for d end, in place of three
// heartbeat intervals.
func SetQuiet(c *Config, d time.Duration) { c.quiet = d }

// SetLinkUID makes the link serve the user uid in place of this process's.
func SetLinkUID(c *Config, uid int) { c.uid = &uid }

// RefuseOpen answers a run that did not open with err.
func RefuseOpen(w http.ResponseWriter, err error) { refuseOpen(w, err) }

// MessageOf is err's text as a refusal's message holds it.
func MessageOf(err error) string { return message(err.Error()) }

// SetCloseWait bounds each run's flush when it closes by d.
func SetCloseWait(c *Config, d time.Duration) { c.closeWait = d }
