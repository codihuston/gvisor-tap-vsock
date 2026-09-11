// Package egresslog reports denials at Info without allowing guest traffic to
// flood the host logs. Storage is fixed: one counter per reason, never per host.
package egresslog

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Reason uint8

const (
	TCP Reason = iota
	UDP
	DNS
	SNIParse
	SNIMismatch
	SNILookup
	SNIDestination
	reasonCount
)

var names = [reasonCount]string{"tcp", "udp", "dns", "sni-parse", "sni-mismatch", "sni-lookup", "sni-destination"}

type window struct {
	next       time.Time
	suppressed uint64
}

type Logger struct {
	mu      sync.Mutex
	windows [reasonCount]window
	sink    *log.Logger
	now     func() time.Time
}

func New(sink *log.Logger, now func() time.Time) *Logger {
	return &Logger{sink: sink, now: now}
}

var Default = New(log.StandardLogger(), time.Now)

// Denied emits at most one record per reason per second. The next emitted
// record includes the number suppressed since the last one. Formatting is only
// performed for emitted records, and the policy verdict never depends on logging.
func (l *Logger) Denied(reason Reason, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := &l.windows[reason]
	now := l.now()
	if now.Before(w.next) {
		w.suppressed++
		return
	}
	l.sink.WithFields(log.Fields{"reason": names[reason], "suppressed": w.suppressed}).Infof(format, args...)
	w.next = now.Add(time.Second)
	w.suppressed = 0
}
