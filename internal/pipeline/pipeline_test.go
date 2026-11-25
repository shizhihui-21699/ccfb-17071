package pipeline_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"credwatch/internal/audit"
	"credwatch/internal/credstore"
	"credwatch/internal/engine"
	"credwatch/internal/model"
	"credwatch/internal/pipeline"
	"credwatch/internal/response"
	"credwatch/internal/scenario"
)

type recordingSink struct {
	mu   sync.Mutex
	incs []*model.Incident
	fail bool
}

func (r *recordingSink) Deliver(_ context.Context, inc *model.Incident) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return context.DeadlineExceeded
	}
	r.incs = append(r.incs, inc)
	return nil
}

type harness struct {
	f     *scenario.Fixture
	proc  *pipeline.Processor
	sink  *recordingSink
	creds *credstore.Store
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := scenario.NewFixture(now)
	det := f.Detector(f.Policy)
	creds := credstore.New() // separate store so resolver is explicit
	creds.Put(&model.Credential{
		KeyID: f.KeyInstASession, KeyKind: model.KeyExactSession, SessionName: "sess-a",
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		IssuerKind: model.IssuerInstance,
		Scope:      model.Scope{Kind: model.ScopeInstance, ID: "i-a"},
	})
	// Re-point the detector at the new store by rebuilding.
	det = engine.New(creds, f.Att, f.Policy)
	det.SetClock(func() time.Time { return now })
	det.SetAttester(f.Attester)
	sink := &recordingSink{}
	actor := response.NewActor(response.Config{
		Enabled: true, DryRun: true, MinSeverity: model.SevHigh,
		PrincipalMechanism: response.MechPrincipalDeny, PerCredentialCooldown: 10 * time.Minute, MaxActionsPerMinute: 30,
	}, &response.MemoryRevoker{}, creds, func() time.Time { return now })
	proc := pipeline.New(pipeline.DefaultConfig(), audit.AWSDecoder{}, det, actor, sink)
	return &harness{f: f, proc: proc, sink: sink, creds: creds}
}

func awsRecord(t *testing.T, id, key, session, ip, at string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"eventVersion": "1.09", "eventID": id, "eventTime": at,
		"eventSource": "s3.amazonaws.com", "eventName": "GetObject",
		"awsRegion": "us-east-1", "sourceIPAddress": ip, "readOnly": true,
		"userIdentity": map[string]any{
			"type": "AssumedRole", "accountId": "111122223333", "accessKeyId": key,
			"arn": "arn:aws:sts::111122223333:assumed-role/web-role/" + session,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDuplicateEventIgnored(t *testing.T) {
	h := newHarness(t)
	raw := awsRecord(t, "dup-1", h.f.KeyInstASession, "sess-a", "198.51.100.77", "2026-03-01T11:59:00Z")
	if _, err := h.proc.Ingest(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	_, err := h.proc.Ingest(context.Background(), raw)
	if err != pipeline.ErrDuplicate {
		t.Fatalf("second identical record must be deduped, got %v", err)
	}
	if len(h.sink.incs) != 1 {
		t.Fatalf("expected exactly one alert, got %d", len(h.sink.incs))
	}
}

func TestRepeatAttackAlertsOnce(t *testing.T) {
	h := newHarness(t)
	raw1 := awsRecord(t, "a1", h.f.KeyInstASession, "sess-a", "198.51.100.77", "2026-03-01T11:58:00Z")
	raw2 := awsRecord(t, "a2", h.f.KeyInstASession, "sess-a", "198.51.100.77", "2026-03-01T11:58:30Z")
	raw3 := awsRecord(t, "a3", h.f.KeyInstASession, "sess-a", "198.51.100.77", "2026-03-01T11:59:00Z")
	for _, r := range [][]byte{raw1, raw2, raw3} {
		_, _ = h.proc.Ingest(context.Background(), r)
	}
	if len(h.sink.incs) != 1 {
		t.Fatalf("repeat incidents for the same credential must not re-page, got %d pages", len(h.sink.incs))
	}
}

func TestSinkFailureKeepsIncidentArchived(t *testing.T) {
	h := newHarness(t)
	h.sink.fail = true
	raw := awsRecord(t, "f1", h.f.KeyInstASession, "sess-a", "198.51.100.77", "2026-03-01T11:59:00Z")
	if _, err := h.proc.Ingest(context.Background(), raw); err == nil {
		t.Fatal("expected delivery error to surface")
	}
	if len(h.proc.Incidents(10)) != 1 {
		t.Fatal("incident must be archived even when the sink fails")
	}
	stats := h.proc.StatsSnapshot()
	if stats["alert_errors"] != 1 {
		t.Fatalf("alert_errors should be 1, got %d", stats["alert_errors"])
	}
}

func TestNonAlertVerdictNotDelivered(t *testing.T) {
	h := newHarness(t)
	raw := awsRecord(t, "ok1", h.f.KeyInstASession, "sess-a", h.f.InstA, "2026-03-01T11:59:00Z")
	dec, err := h.proc.Ingest(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Verdict == model.VerdictRevoke {
		t.Fatalf("legit call should not revoke, got %s", dec.Verdict)
	}
	if len(h.sink.incs) != 0 {
		t.Fatal("non-incident verdicts must not page")
	}
}

func TestMaxLagTracked(t *testing.T) {
	h := newHarness(t)
	// Event an hour old at ingest.
	raw := awsRecord(t, "late1", h.f.KeyInstASession, "sess-a", "198.51.100.77", "2026-03-01T11:00:00Z")
	_, _ = h.proc.Ingest(context.Background(), raw)
	if got := h.proc.StatsSnapshot()["max_lag_seconds"]; got < 3000 {
		t.Fatalf("max lag should reflect the stale event, got %d", got)
	}
}
