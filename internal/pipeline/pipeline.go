// Package pipeline wires decoding, detection, alerting and response into one
// stream processor.
//
// Two properties matter more than throughput here:
//
//   - Order does not have to be assumed. Audit logs arrive late and shuffled;
//     a credential may be used, revoked, and only then have its earlier events
//     delivered. The processor keeps per-key ordering for state transitions
//     while treating event time as authoritative for windowing.
//   - Processing must be idempotent. Repositories deliver duplicates after a
//     retry, and a provider may deliver the same record through two paths
//     (S3 + EventBridge). A duplicate must never produce a second page or a
//     second revocation.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"credwatch/internal/audit"
	"credwatch/internal/engine"
	"credwatch/internal/model"
	"credwatch/internal/response"
	"credwatch/internal/unit"
)

// Sink receives incidents that cross the alert threshold.
type Sink interface {
	Deliver(ctx context.Context, inc *model.Incident) error
}

// SinkFunc adapts a function.
type SinkFunc func(ctx context.Context, inc *model.Incident) error

func (f SinkFunc) Deliver(ctx context.Context, inc *model.Incident) error { return f(ctx, inc) }

type Config struct {
	Workers   int
	QueueSize int
	// DedupRetention bounds the seen-event-id set.
	DedupRetention unit.Duration
	// DedupMaxIDs caps memory if events arrive faster than retention expires.
	DedupMaxIDs int
	// AlertDedupeWindow suppresses repeat pages for the same credential.
	AlertDedupeWindow unit.Duration
}

func DefaultConfig() Config {
	return Config{
		Workers:           4,
		QueueSize:         4096,
		DedupRetention:    unit.Duration(6 * time.Hour),
		DedupMaxIDs:       500_000,
		AlertDedupeWindow: unit.Duration(15 * time.Minute),
	}
}

type Stats struct {
	Received    atomic.Int64
	Duplicates  atomic.Int64
	DecodeError atomic.Int64
	Processed   atomic.Int64
	Allowed     atomic.Int64
	Watched     atomic.Int64
	Alerted     atomic.Int64
	Revoked     atomic.Int64
	AlertErrors atomic.Int64
	// MaxLagSeconds is the largest audit lag observed; a leading indicator
	// that the ingestion path is falling behind, which directly reduces the
	// window in which revocation can still help.
	MaxLagNanos atomic.Int64
}

type Processor struct {
	cfg     Config
	decoder audit.Decoder
	det     *engine.Detector
	actor   *response.Actor
	sink    Sink

	stats Stats

	mu      sync.Mutex
	seen    map[string]time.Time
	seenAt  []seenEntry
	alerted map[string]time.Time

	// incident archive (bounded) for the admin API.
	incidents []*model.Incident

	// per-key locks keep decisions for one credential serialized, because the
	// engine's concurrency state is per key.
	keyLocks sync.Map // string -> *sync.Mutex
}

type seenEntry struct {
	id string
	at time.Time
}

func New(cfg Config, decoder audit.Decoder, det *engine.Detector, actor *response.Actor, sink Sink) *Processor {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	return &Processor{
		cfg:     cfg,
		decoder: decoder,
		det:     det,
		actor:   actor,
		sink:    sink,
		seen:    make(map[string]time.Time),
		alerted: make(map[string]time.Time),
	}
}

var ErrDuplicate = errors.New("duplicate event")

// Ingest decodes and evaluates one raw audit record synchronously. It returns
// the decision so callers (and tests) can inspect non-alert verdicts too.
func (p *Processor) Ingest(ctx context.Context, raw []byte) (engine.Decision, error) {
	p.stats.Received.Add(1)
	ev, err := p.decoder.Decode(raw)
	if err != nil {
		p.stats.DecodeError.Add(1)
		return engine.Decision{}, fmt.Errorf("decode: %w", err)
	}
	return p.ProcessEvent(ctx, ev)
}

func (p *Processor) ProcessEvent(ctx context.Context, ev model.Event) (engine.Decision, error) {
	if ev.ID != "" {
		if dup := p.markSeen(ev.ID, time.Now()); dup {
			p.stats.Duplicates.Add(1)
			return engine.Decision{}, ErrDuplicate
		}
	}

	// Serialize per credential key.
	lockKey := ev.AccessKeyID
	if lockKey == "" {
		lockKey = ev.PrincipalID
	}
	muI, _ := p.keyLocks.LoadOrStore(lockKey, &sync.Mutex{})
	mu := muI.(*sync.Mutex)
	mu.Lock()
	dec := p.det.Process(ev)
	mu.Unlock()

	p.stats.Processed.Add(1)
	if n := dec.Lag.Nanoseconds(); n > p.stats.MaxLagNanos.Load() {
		p.stats.MaxLagNanos.CompareAndSwap(p.stats.MaxLagNanos.Load(), n)
	}

	switch dec.Verdict {
	case model.VerdictAllow:
		p.stats.Allowed.Add(1)
	case model.VerdictWatch:
		p.stats.Watched.Add(1)
	}

	if dec.Incident == nil {
		return dec, nil
	}

	inc := dec.Incident
	if p.suppressAlert(inc) {
		// Still action containment: the credential is compromised even if we
		// do not page again.
		p.act(ctx, inc)
		return dec, nil
	}

	p.act(ctx, inc)

	if p.sink != nil {
		if err := p.sink.Deliver(ctx, inc); err != nil {
			p.stats.AlertErrors.Add(1)
			// A sink failure must not lose the incident; keep it archived.
			p.archive(inc)
			return dec, fmt.Errorf("alert: %w", err)
		}
	}
	p.archive(inc)
	return dec, nil
}

func (p *Processor) act(ctx context.Context, inc *model.Incident) {
	if inc.Duplicate {
		return
	}
	res := p.actor.Act(ctx, inc)
	if res != nil && res.Performed {
		p.stats.Revoked.Add(1)
	}
	if inc.Verdict == model.VerdictRevoke {
		p.stats.Alerted.Add(1)
	} else {
		p.stats.Alerted.Add(1)
	}
}

// suppressAlert dedupes pages per credential. The first incident still goes
// out; repeats inside the window are archived silently.
func (p *Processor) suppressAlert(inc *model.Incident) bool {
	if inc.CredentialID == "" {
		return false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.alerted[inc.CredentialID]; ok && now.Sub(t) < p.cfg.AlertDedupeWindow.Duration() {
		return true
	}
	p.alerted[inc.CredentialID] = now
	return false
}

func (p *Processor) markSeen(id string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[id]; ok {
		return true
	}
	p.seen[id] = now
	p.seenAt = append(p.seenAt, seenEntry{id: id, at: now})
	// Trim by retention then by cap, whichever is stricter.
	if len(p.seenAt) > p.cfg.DedupMaxIDs {
		cut := len(p.seenAt) - p.cfg.DedupMaxIDs
		for _, e := range p.seenAt[:cut] {
			delete(p.seen, e.id)
		}
		p.seenAt = append([]seenEntry(nil), p.seenAt[cut:]...)
	}
	horizon := now.Add(-p.cfg.DedupRetention.Duration())
	i := 0
	for ; i < len(p.seenAt); i++ {
		if p.seenAt[i].at.After(horizon) {
			break
		}
		delete(p.seen, p.seenAt[i].id)
	}
	if i > 0 {
		p.seenAt = append([]seenEntry(nil), p.seenAt[i:]...)
	}
	return false
}

func (p *Processor) archive(inc *model.Incident) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.incidents = append(p.incidents, inc)
	if len(p.incidents) > 5000 {
		p.incidents = p.incidents[len(p.incidents)-5000:]
	}
}

// Incidents returns archived incidents newest first.
func (p *Processor) Incidents(limit int) []*model.Incident {
	p.mu.Lock()
	defer p.mu.Unlock()
	if limit <= 0 || limit > len(p.incidents) {
		limit = len(p.incidents)
	}
	out := make([]*model.Incident, 0, limit)
	for i := len(p.incidents) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, p.incidents[i])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DetectedAt.After(out[j].DetectedAt) })
	return out
}

// StatsSnapshot renders counters for /metrics.
func (p *Processor) StatsSnapshot() map[string]int64 {
	return map[string]int64{
		"events_received":     p.stats.Received.Load(),
		"events_duplicate":    p.stats.Duplicates.Load(),
		"events_decode_error": p.stats.DecodeError.Load(),
		"events_processed":    p.stats.Processed.Load(),
		"verdict_allow":       p.stats.Allowed.Load(),
		"verdict_watch":       p.stats.Watched.Load(),
		"verdict_alert":       p.stats.Alerted.Load(),
		"actions_performed":   p.stats.Revoked.Load(),
		"alert_errors":        p.stats.AlertErrors.Load(),
		"max_lag_seconds":     p.stats.MaxLagNanos.Load() / int64(time.Second),
	}
}

// Run consumes raw records from ch until it closes or ctx is cancelled.
func (p *Processor) Run(ctx context.Context, ch <-chan []byte) error {
	queue := make(chan []byte, p.cfg.QueueSize)
	var wg sync.WaitGroup
	for i := 0; i < p.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range queue {
				_, _ = p.Ingest(ctx, raw)
			}
		}()
	}
	defer func() {
		close(queue)
		wg.Wait()
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case raw, ok := <-ch:
			if !ok {
				return nil
			}
			select {
			case queue <- raw:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
