package engine_test

import (
	"net/netip"
	"testing"
	"time"

	"credwatch/internal/engine"
	"credwatch/internal/inventory"
	"credwatch/internal/model"
	"credwatch/internal/scenario"
)

func TestScenarioExpectations(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range scenario.All() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			_, ok, err := scenario.RunCase(c, now)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("%s: expectation not met", c.Description)
			}
		})
	}
}

// TestConcurrencyIgnoresNonExactOrigins locks in the fix for the most
// damaging false positive found during development: after one stolen call
// from an unresolved address, a legitimate call from the real instance was
// flagged as "concurrent use from a different origin" and revoked.
func TestConcurrencyIgnoresNonExactOrigins(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := scenario.NewFixture(now)
	d := f.Detector(f.Policy)

	foreign := model.Event{
		ID: "e1", Provider: model.ProviderAWS, EventTime: now.Add(-time.Minute),
		AccessKeyID: f.KeyInstASession, SessionName: "sess-a",
		SourceIP: "198.51.100.77", Action: "s3:GetObject", ReadOnly: true,
	}
	d.Process(foreign)

	legit := model.Event{
		ID: "e2", Provider: model.ProviderAWS, EventTime: now.Add(-30 * time.Second),
		AccessKeyID: f.KeyInstASession, SessionName: "sess-a",
		SourceIP: f.InstA, Action: "s3:GetObject", ReadOnly: true,
	}
	dec := d.Process(legit)
	for _, e := range dec.Evidence {
		if e.Rule == "concurrent_distinct_origin" {
			t.Fatalf("legitimate call wrongly flagged as concurrent with an unresolved origin: %s", dec.Binding.Reason)
		}
	}
	if dec.Verdict != model.VerdictAllow {
		t.Fatalf("legitimate call should be allowed after inventory is consulted, got %s score=%d", dec.Verdict, dec.Score)
	}
}

// TestExpiredCredentialStillResolves ensures a credential that expires while
// still present in the store is judged as "expired credential in use", not as
// an unknown key. Hide-the-record would be a silent miss.
func TestExpiredCredentialStillResolves(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := scenario.NewFixture(now)
	// Move the clock far past expiry.
	later := now.Add(48 * time.Hour)
	f.Creds.Put(&model.Credential{
		KeyID: "ASIAEXPIRED00000000", KeyKind: model.KeyExactSession,
		SessionName: "sess-x", IssuedAt: now.Add(-4 * time.Hour), ExpiresAt: now.Add(-time.Hour),
		IssuerKind: model.IssuerInstance,
		Scope:      model.Scope{Kind: model.ScopeInstance, ID: "i-a"},
	})
	d := engine.New(f.Creds, f.Att, f.Policy)
	d.SetClock(func() time.Time { return later })
	d.SetAttester(f.Attester)

	dec := d.Process(model.Event{
		ID: "e1", Provider: model.ProviderAWS, EventTime: later.Add(-time.Minute),
		AccessKeyID: "ASIAEXPIRED00000000", SessionName: "sess-x",
		SourceIP: "198.51.100.77", Action: "s3:GetObject",
	})
	if dec.Binding.Class == model.UnregisteredCredential {
		t.Fatal("expired-but-known credential must not be reported as unregistered")
	}
	if dec.Verdict != model.VerdictRevoke {
		t.Fatalf("expired credential used from a foreign address should revoke, got %s score=%d", dec.Verdict, dec.Score)
	}
}

func TestLateLogFlaggedButStillRevoked(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := scenario.NewFixture(now)
	d := f.Detector(f.Policy)
	dec := d.Process(model.Event{
		ID: "late", Provider: model.ProviderAWS, EventTime: now.Add(-20 * time.Minute),
		AccessKeyID: f.KeyInstASession, SessionName: "sess-a",
		SourceIP: "198.51.100.77", Action: "s3:GetObject",
	})
	if dec.Verdict != model.VerdictRevoke {
		t.Fatalf("late foreign call must still revoke, got %s", dec.Verdict)
	}
	if dec.Incident == nil || dec.Incident.LagSeconds < 1100 {
		t.Fatalf("incident must record audit lag, got %+v", dec.Incident)
	}
	found := false
	for _, e := range dec.Evidence {
		if e.Rule == "audit_lag_critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected audit_lag_critical evidence on a 20-minute-late event")
	}
}

func TestServiceForwardedNotScoredByClientBehaviour(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := scenario.NewFixture(now)
	d := f.Detector(f.Policy)
	ev := model.Event{
		ID: "svc", Provider: model.ProviderAWS, EventTime: now.Add(-time.Minute),
		AccessKeyID: f.KeyInstASession, SessionName: "sess-a",
		SourceIP: f.ProviderIP, InvokedBy: "s3.amazonaws.com",
		Action: "s3:ReplicateObject", ReadOnly: false, UserAgent: "aws-internal",
	}
	dec := d.Process(ev)
	if dec.Verdict != model.VerdictAllow {
		t.Fatalf("service-forwarded call must be allowed, got %s score=%d", dec.Verdict, dec.Score)
	}
	if dec.Score != 0 {
		t.Fatalf("service-forwarded call must not accrue client-behaviour score, got %d", dec.Score)
	}
}

func TestAutoRevokeRequiresConclusive(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := scenario.NewFixture(now)
	// Make the inventory stale so an unmatched address cannot be conclusive.
	f.Inv.Set(inventoryStale(now.Add(-time.Hour), f))
	d := f.Detector(f.Policy)
	dec := d.Process(model.Event{
		ID: "stale", Provider: model.ProviderAWS, EventTime: now.Add(-time.Minute),
		AccessKeyID: f.KeyInstASession, SessionName: "sess-a",
		SourceIP: "198.51.100.77", Action: "s3:GetObject",
	})
	if dec.Verdict == model.VerdictRevoke {
		t.Fatalf("must not auto-revoke on stale inventory, got revoke score=%d", dec.Score)
	}
	if dec.Verdict != model.VerdictAlert {
		t.Fatalf("want alert, got %s", dec.Verdict)
	}
}

func inventoryStale(builtAt time.Time, f *scenario.Fixture) *inventory.Snapshot {
	return inventory.BuildSnapshot("stale", builtAt, inventory.SnapshotData{
		Records: []inventory.Record{
			{Addr: netip.MustParsePrefix(f.InstA + "/32"), Kind: model.OriginInstance, Specificity: model.SpecExact, InstanceID: "i-a"},
		},
	})
}
