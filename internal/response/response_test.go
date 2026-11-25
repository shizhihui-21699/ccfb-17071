package response_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"credwatch/internal/credstore"
	"credwatch/internal/model"
	"credwatch/internal/response"
)

func setup(t *testing.T, sessKey bool) (*response.Actor, *response.MemoryRevoker, *credstore.Store, time.Time) {
	t.Helper()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	creds := credstore.New()
	kind := model.KeyExactSession
	if !sessKey {
		kind = model.KeyPrincipal
	}
	creds.Put(&model.Credential{KeyID: "ASIA1", KeyKind: kind, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), RoleARN: "arn:aws:iam::1:role/r"})
	rv := &response.MemoryRevoker{}
	cfg := response.DefaultConfig()
	cfg.DryRun = false
	cfg.Enabled = true
	a := response.NewActor(cfg, rv, creds, func() time.Time { return now })
	return a, rv, creds, now
}

func incident(now time.Time) *model.Incident {
	return &model.Incident{
		ID: "inc-1", CredentialID: "ASIA1", Verdict: model.VerdictRevoke, Severity: model.SevCritical,
		Event:   model.Event{SourceIP: "198.51.100.77", EventTime: now.Add(-time.Minute)},
		Binding: model.BindingResult{Class: model.External, Reason: "outside scope"},
	}
}

func TestExactSessionRevokedNotPrincipal(t *testing.T) {
	a, rv, _, now := setup(t, true)
	inc := incident(now)
	res := a.Act(context.Background(), inc)
	if !res.Performed {
		t.Fatalf("expected performed, got %+v", res)
	}
	if len(rv.Revoked) != 1 || rv.Revoked[0] != "ASIA1" {
		t.Fatalf("expected session revoke, got revoked=%v denied=%v", rv.Revoked, rv.Denied)
	}
	if len(rv.Denied) != 0 {
		t.Fatal("must not apply a principal deny for a session-scoped key")
	}
}

func TestPrincipalScopedUsesDenyNotSessionRevoke(t *testing.T) {
	a, rv, _, now := setup(t, false)
	inc := incident(now)
	res := a.Act(context.Background(), inc)
	if !res.Performed {
		t.Fatalf("expected performed, got %+v", res)
	}
	if len(rv.Revoked) != 0 {
		t.Fatal("a bearer-token principal has no session to revoke")
	}
	if len(rv.Denied) != 1 {
		t.Fatalf("expected principal deny, got %+v", rv)
	}
	if !strings.Contains(res.PolicyDocument, "198.51.100.77/32") {
		t.Fatalf("deny policy should be scoped to the offending address, got %s", res.PolicyDocument)
	}
}

func TestDryRunDoesNotCallProviderButReports(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	rv := &response.MemoryRevoker{}
	creds := credstore.New()
	creds.Put(&model.Credential{KeyID: "ASIA1", KeyKind: model.KeyExactSession, ExpiresAt: now.Add(time.Hour)})
	a := response.NewActor(response.Config{
		Enabled: true, DryRun: true, MinSeverity: model.SevHigh,
		PrincipalMechanism: response.MechPrincipalDeny, PerCredentialCooldown: time.Minute, MaxActionsPerMinute: 10,
	}, rv, creds, func() time.Time { return now })
	res := a.Act(context.Background(), incident(now))
	if !res.Performed || !strings.Contains(res.Mechanism, "dry-run") {
		t.Fatalf("dry-run should report without mutating, got %+v", res)
	}
	if len(rv.Revoked) != 0 {
		t.Fatal("dry-run must not call the provider")
	}
}

func TestOnlyRevokeVerdictActs(t *testing.T) {
	a, rv, _, now := setup(t, true)
	inc := incident(now)
	inc.Verdict = model.VerdictAlert
	res := a.Act(context.Background(), inc)
	if res.Performed {
		t.Fatal("alert must not revoke")
	}
	if len(rv.Revoked) != 0 {
		t.Fatal("no provider call expected for alert")
	}
}

func TestCooldownSuppressesDuplicates(t *testing.T) {
	a, rv, _, now := setup(t, true)
	a.Act(context.Background(), incident(now))
	a.Act(context.Background(), incident(now)) // same key, same instant
	if len(rv.Revoked) != 1 {
		t.Fatalf("duplicate action should be suppressed by cooldown, got %d calls", len(rv.Revoked))
	}
}

func TestCircuitBreaker(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	creds := credstore.New()
	rv := &response.MemoryRevoker{}
	a := response.NewActor(response.Config{
		Enabled: true, MinSeverity: model.SevHigh, PrincipalMechanism: response.MechPrincipalDeny,
		PerCredentialCooldown: time.Minute, MaxActionsPerMinute: 2,
	}, rv, creds, func() time.Time { return now })
	for i := 0; i < 5; i++ {
		key := string(rune('A' + i))
		creds.Put(&model.Credential{KeyID: key, KeyKind: model.KeyExactSession, ExpiresAt: now.Add(time.Hour)})
		inc := incident(now)
		inc.CredentialID = key
		a.Act(context.Background(), inc)
	}
	if len(rv.Revoked) != 2 {
		t.Fatalf("circuit breaker should cap at 2 actions, got %d", len(rv.Revoked))
	}
}
