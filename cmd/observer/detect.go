package main

import (
	"sync"
	"time"
) 

const (
	scanWindow = 10 * time.Second
	scanThreshold = 50
)

type scanDetector struct {
	mu sync.Mutex
	windowStart time.Time
	seen map[string]map[string]bool
	alerted map[string]bool
}

func newScanDetector () *scanDetector {
	return &scanDetector{
		windowStart: time.Now(),
		seen: make(map[string]map[string]bool),
		alerted: make(map[string]bool),
	}
}

func (d *scanDetector) observe(process, destination string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if time.Since(d.windowStart) > scanWindow {
		d.windowStart = time.Now()
		d.seen = make(map[string]map[string]bool)
		d.alerted = make(map[string]bool)
	}

	dests, ok := d.seen[process]
	if !ok {
		dests = make(map[string]bool)
		d.seen[process] = dests
	}
	dests[destination] = true

	if len(dests) >= scanThreshold && !d.alerted[process] {
		d.alerted[process] = true
		return true
	}

	return false
}