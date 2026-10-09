package gateway

import "time"

// SetQuiet makes a run whose session sends nothing for d end, in place of three
// heartbeat intervals.
func SetQuiet(c *Config, d time.Duration) { c.quiet = d }

// SetLinkUID makes the link serve the user uid in place of this process's.
func SetLinkUID(c *Config, uid int) { c.uid = &uid }

// SetCloseWait bounds each run's flush when it closes by d.
func SetCloseWait(c *Config, d time.Duration) { c.closeWait = d }
