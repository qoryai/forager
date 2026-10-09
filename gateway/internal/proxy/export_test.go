package proxy

import "time"

// SetWait sets how long a connection to l has to send its preamble.
func (l *Listener) SetWait(d time.Duration) { l.wait.Store(int64(d)) }
