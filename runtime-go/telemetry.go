package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type Telemetry struct {
	startedAt       time.Time
	requestsTotal   uint64
	requestsRunning int64
	successTotal    uint64
	failureTotal    uint64
	timeoutTotal    uint64
	lastHeartbeat   atomic.Int64
	mu              sync.Mutex
}

func NewTelemetry() *Telemetry {
	t := &Telemetry{startedAt: time.Now().UTC()}
	t.TouchHeartbeat()
	return t
}

func (t *Telemetry) StartRequest() {
	atomic.AddUint64(&t.requestsTotal, 1)
	atomic.AddInt64(&t.requestsRunning, 1)
	t.TouchHeartbeat()
}

func (t *Telemetry) FinishRequest(success bool, timedOut bool) {
	if success {
		atomic.AddUint64(&t.successTotal, 1)
	} else {
		atomic.AddUint64(&t.failureTotal, 1)
	}
	if timedOut {
		atomic.AddUint64(&t.timeoutTotal, 1)
	}
	atomic.AddInt64(&t.requestsRunning, -1)
	t.TouchHeartbeat()
}

func (t *Telemetry) TouchHeartbeat() {
	t.lastHeartbeat.Store(time.Now().UTC().Unix())
}

func (t *Telemetry) Snapshot() map[string]any {
	return map[string]any{
		"started_at":        t.startedAt.Format(time.RFC3339),
		"requests_total":    atomic.LoadUint64(&t.requestsTotal),
		"requests_running":  atomic.LoadInt64(&t.requestsRunning),
		"success_total":     atomic.LoadUint64(&t.successTotal),
		"failure_total":     atomic.LoadUint64(&t.failureTotal),
		"timeout_total":     atomic.LoadUint64(&t.timeoutTotal),
		"last_heartbeat_unix": t.lastHeartbeat.Load(),
	}
}

