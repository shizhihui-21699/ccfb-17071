package attrib_test

import (
	"net/netip"
	"testing"
	"time"

	"credwatch/internal/attrib"
	"credwatch/internal/inventory"
	"credwatch/internal/model"
)

func fixedStore(t *testing.T, now time.Time) *inventory.Store {
	t.Helper()
	s := inventory.NewStore(10 * time.Minute)
	s.Set(inventory.BuildSnapshot("t", now, inventory.SnapshotData{
		Instances: []inventory.InstanceInfo{
			{ID: "i-a", NATGatewayIDs: []string{"nat-1"}},
			{ID: "i-b", NATGatewayIDs: []string{"nat-1"}},
		},
		Fleets:    []inventory.FleetInfo{{ID: "eks", NATGatewayIDs: []string{"nat-1"}}},
		Functions: []inventory.FunctionInfo{{ID: "fn", NATGatewayIDs: []string{"nat-1"}}},
		Records: []inventory.Record{
			{Addr: p("10.0.1.10"), Kind: model.OriginInstance, Specificity: model.SpecExact, InstanceID: "i-a", NATGateway: "nat-1", Zone: "account"},
			{Addr: p("10.0.1.20"), Kind: model.OriginInstance, Specificity: model.SpecExact, InstanceID: "i-b", NATGateway: "nat-1", Zone: "account"},
			{Addr: p("203.0.113.45"), Kind: model.OriginNAT, Specificity: model.SpecAmbiguous, NATGateway: "nat-1", Zone: "account", SharedEgress: true},
			{Addr: p("10.0.3.0/24"), Kind: model.OriginFleetPod, Specificity: model.SpecScoped, FleetID: "eks", Zone: "account"},
			{Addr: p("10.0.2.50"), Kind: model.OriginFunctionENI, Specificity: model.SpecExact, FunctionID: "fn", Zone: "account"},
		},
	}))
	return s
}

func p(s string) netip.Prefix {
	pref, err := netip.ParsePrefix(s)
	if err != nil {
		a := netip.MustParseAddr(s)
		return netip.PrefixFrom(a, a.BitLen())
	}
	return pref
}

func cred(scopeKind model.ScopeKind, id string) *model.Credential {
	return &model.Credential{
		KeyID: "ASIAX", KeyKind: model.KeyExactSession, Scope: model.Scope{Kind: scopeKind, ID: id, AllowSharedEgress: true},
	}
}

func TestBindOwnInstance(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := attrib.New(fixedStore(t, now), attrib.Config{})
	c := cred(model.ScopeInstance, "i-a")
	ev := model.Event{SourceIP: "10.0.1.10"}
	origin, _ := at.ResolveAt(&ev, now)
	got := at.Bind(c, origin, at.Expectation(c))
	if got.Class != model.BoundDirect {
		t.Fatalf("want bound_direct, got %s (%s)", got.Class, got.Reason)
	}
}

func TestBindCrossInstanceIsForeign(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := attrib.New(fixedStore(t, now), attrib.Config{})
	c := cred(model.ScopeInstance, "i-a")
	ev := model.Event{SourceIP: "10.0.1.20"}
	origin, _ := at.ResolveAt(&ev, now)
	got := at.Bind(c, origin, at.Expectation(c))
	if got.Class != model.ForeignPrincipal {
		t.Fatalf("want foreign_principal, got %s", got.Class)
	}
	if got.NetworkBound() {
		t.Fatal("foreign principal must not be network-bound")
	}
}

func TestBindSharedNATOfScope(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := attrib.New(fixedStore(t, now), attrib.Config{})
	c := cred(model.ScopeInstance, "i-a")
	ev := model.Event{SourceIP: "203.0.113.45"}
	origin, _ := at.ResolveAt(&ev, now)
	got := at.Bind(c, origin, at.Expectation(c))
	if got.Class != model.BoundSharedEgress {
		t.Fatalf("want bound_shared_egress, got %s (%s)", got.Class, got.Reason)
	}
	if got.Specificity != model.SpecAmbiguous {
		t.Fatalf("shared egress must be ambiguous, got %s", got.Specificity)
	}
}

func TestInvokedByWins(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := attrib.New(fixedStore(t, now), attrib.Config{ProviderRanges: []netip.Prefix{p("52.94.0.0/16")}})
	c := cred(model.ScopeInstance, "i-a")
	ev := model.Event{SourceIP: "52.94.0.10", InvokedBy: "s3.amazonaws.com"}
	origin, _ := at.ResolveAt(&ev, now)
	if origin.Kind != model.OriginCloudService {
		t.Fatalf("invokedBy must win, got %s", origin.Kind)
	}
	got := at.Bind(c, origin, at.Expectation(c))
	if got.Class != model.BoundService {
		t.Fatalf("want bound_service, got %s", got.Class)
	}
}

func TestProviderEgressAllowedForFunction(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := attrib.New(fixedStore(t, now), attrib.Config{ProviderRanges: []netip.Prefix{p("52.94.0.0/16")}})
	c := cred(model.ScopeFunction, "fn")
	c.Scope.AllowProviderEgress = true
	ev := model.Event{SourceIP: "52.94.0.10"}
	origin, _ := at.ResolveAt(&ev, now)
	if origin.Kind != model.OriginProviderInternal {
		t.Fatalf("want provider_internal, got %s", origin.Kind)
	}
	got := at.Bind(c, origin, at.Expectation(c))
	if got.Class != model.BoundProviderEgress {
		t.Fatalf("want bound_provider_egress, got %s (%s)", got.Class, got.Reason)
	}
	if got.Specificity != model.SpecNone {
		t.Fatalf("provider egress must carry no specificity, got %s", got.Specificity)
	}
}

func TestBlocklistOverridesEverything(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := attrib.New(fixedStore(t, now), attrib.Config{Blocklist: []netip.Prefix{p("198.51.100.0/24")}})
	c := cred(model.ScopeInstance, "i-a")
	ev := model.Event{SourceIP: "198.51.100.77"}
	origin, _ := at.ResolveAt(&ev, now)
	if !origin.Blocklisted {
		t.Fatal("expected blocklisted origin")
	}
	got := at.Bind(c, origin, at.Expectation(c))
	if got.Class != model.External {
		t.Fatalf("want external for blocklisted, got %s", got.Class)
	}
}

func TestUnanchoredRoleScopeDoesNotCondemn(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := attrib.New(fixedStore(t, now), attrib.Config{})
	c := cred(model.ScopeRole, "arn:aws:iam::1:role/x")
	ev := model.Event{SourceIP: "198.51.100.9"}
	origin, _ := at.ResolveAt(&ev, now)
	got := at.Bind(c, origin, at.Expectation(c))
	if got.Class != model.BoundUnanchored {
		t.Fatalf("role scope with no network expectation must be unanchored, got %s (%s)", got.Class, got.Reason)
	}
	if !got.NetworkBound() {
		t.Fatal("unanchored must not read as a network violation")
	}
	if got.Conclusive() {
		t.Fatal("unanchored must not be conclusive")
	}
}

func TestStalenessAtExplicitClock(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := inventory.NewStore(10 * time.Minute)
	s.Set(inventory.BuildSnapshot("t", now.Add(-time.Hour), inventory.SnapshotData{}))
	_, st := s.SnapshotAt(now)
	if !st.Stale {
		t.Fatal("snapshot an hour old against a 10m max age must be stale")
	}
	// Replay with a clock close to build time must judge it fresh.
	_, st2 := s.SnapshotAt(now.Add(-time.Hour).Add(time.Minute))
	if st2.Stale {
		t.Fatal("staleness must use the supplied clock, not wall time")
	}
}

func TestGlobBaseline(t *testing.T) {
	c := &model.Credential{BaselineActions: []string{"s3:Get*", "sqs:SendMessage"}}
	if !attrib.ActionInBaseline(c, "s3:GetObject") {
		t.Fatal("s3:GetObject should match s3:Get*")
	}
	if attrib.ActionInBaseline(c, "ec2:RunInstances") {
		t.Fatal("ec2:RunInstances should not match")
	}
}
