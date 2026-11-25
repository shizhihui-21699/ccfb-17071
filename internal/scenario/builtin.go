package scenario

import (
	"fmt"
	"net/netip"
	"time"

	"credwatch/internal/attest"
	"credwatch/internal/attrib"
	"credwatch/internal/credstore"
	"credwatch/internal/engine"
	"credwatch/internal/inventory"
	"credwatch/internal/model"
)

// Expectation is the assertion attached to a scenario.
type Expectation struct {
	WantVerdict model.Verdict
	// ForVerbatim, when set, is a substring that must appear in the binding
	// reason of the flagged decision. It exists so a test can insist on the
	// *reason* (e.g. "shared NAT") and not merely on a verdict.
	ReasonContains string
	// AllAtMost, when set, requires every decision to be at or below it.
	AllAtMost   model.Verdict
	Revocations int // minimum expected revocation actions
}

// Fixture builds a canonical environment: two instances behind one NAT, an EKS
// fleet, a VPC lambda, and one serverless lambda outside a VPC.
type Fixture struct {
	Now      time.Time
	Creds    *credstore.Store
	Inv      *inventory.Store
	Attester *attest.Store
	Att      *attrib.Attributor
	Policy   engine.Policy

	// Addresses used by scenarios.
	InstA      string // 10.0.1.10  instance i-a
	InstB      string // 10.0.1.20  instance i-b
	NatIP      string // 203.0.113.45  shared NAT for subnet A/B
	InternetIP string // 198.51.100.77 attacker / external
	FuncENI    string // 10.0.2.50  VPC-attached lambda
	PodIP      string // 10.0.3.0/24 fleet pod
	ProviderIP string // 52.94.0.10 provider-owned (serverless, outside VPC)

	KeyInstASession string
	KeyInstBSession string
	KeyFleetPod     string
	KeyFuncVPC      string
	KeyFuncNoVPC    string
	KeyCanary       string
}

func NewFixture(now time.Time) *Fixture {
	f := &Fixture{Now: now, Policy: engine.DefaultPolicy()}
	f.InstA = "10.0.1.10"
	f.InstB = "10.0.1.20"
	f.NatIP = "203.0.113.45"
	f.InternetIP = "198.51.100.77"
	f.FuncENI = "10.0.2.50"
	f.PodIP = "10.0.3.17"
	f.ProviderIP = "52.94.0.10"

	f.KeyInstASession = "ASIAINSTA0000000000AA"
	f.KeyInstBSession = "ASIAINSTB0000000000BB"
	f.KeyFleetPod = "ASIAFLEET0000000000CC"
	f.KeyFuncVPC = "ASIAFUNCV0000000000DD"
	f.KeyFuncNoVPC = "ASIAFUNCN0000000000EE"
	f.KeyCanary = "ASIACANARY0000000000FF"

	f.Creds = credstore.New()
	f.Inv = inventory.NewStore(10 * time.Minute)
	f.Attester = attest.NewStore(func() time.Time { return now }, 2*time.Minute, time.Hour)

	f.Inv.Set(inventory.BuildSnapshot("fixture", now, inventory.SnapshotData{
		Instances: []inventory.InstanceInfo{
			{ID: "i-a", PrivateAddrs: []string{f.InstA}, NATGatewayIDs: []string{"nat-1"}, SubnetID: "subnet-a", AccountID: "111122223333", IAMRole: "web-role"},
			{ID: "i-b", PrivateAddrs: []string{f.InstB}, NATGatewayIDs: []string{"nat-1"}, SubnetID: "subnet-a", AccountID: "111122223333", IAMRole: "web-role"},
		},
		Fleets: []inventory.FleetInfo{
			{ID: "eks-prod", Kind: "eks", Nodes: []string{"i-a"}, PodCIDRs: []string{"10.0.3.0/24"}, NATGatewayIDs: []string{"nat-1"}, AccountID: "111122223333"},
		},
		Functions: []inventory.FunctionInfo{
			{ID: "fn-vpc", ENIs: []string{f.FuncENI}, VPCID: "vpc-1", NATGatewayIDs: []string{"nat-1"}, AccountID: "111122223333"},
			{ID: "fn-novpc", AccountID: "111122223333"},
		},
		Records: []inventory.Record{
			{Addr: mustPrefix(f.InstA), Kind: model.OriginInstance, Specificity: model.SpecExact, InstanceID: "i-a", SubnetID: "subnet-a", NATGateway: "nat-1", AccountID: "111122223333", Zone: "account", Source: "ec2:describe-instances"},
			{Addr: mustPrefix(f.InstB), Kind: model.OriginInstance, Specificity: model.SpecExact, InstanceID: "i-b", SubnetID: "subnet-a", NATGateway: "nat-1", AccountID: "111122223333", Zone: "account", Source: "ec2:describe-instances"},
			{Addr: mustPrefix(f.NatIP), Kind: model.OriginNAT, Specificity: model.SpecAmbiguous, NATGateway: "nat-1", SubnetID: "subnet-a", AccountID: "111122223333", Zone: "account", SharedEgress: true, Source: "ec2:describe-nat-gateways"},
			{Addr: mustPrefix(f.FuncENI), Kind: model.OriginFunctionENI, Specificity: model.SpecExact, FunctionID: "fn-vpc", AccountID: "111122223333", Zone: "account", Source: "lambda:list-functions"},
			{Addr: mustPrefix(f.PodIP), Kind: model.OriginFleetPod, Specificity: model.SpecScoped, FleetID: "eks-prod", AccountID: "111122223333", Zone: "account", Source: "eks:pod-cidrs"},
		},
	}))

	cfg := attrib.Config{
		ProviderRanges: []netip.Prefix{mustPrefix("52.94.0.0/16"), mustPrefix("3.5.0.0/16")},
		Blocklist:      []netip.Prefix{mustPrefix("185.220.101.0/24")},
	}
	f.Att = attrib.New(f.Inv, cfg)

	iss := time.Time{}
	_ = iss
	issued := now.Add(-2 * time.Hour)
	exp := now.Add(10 * time.Hour)
	mk := func(key, session, scopeID string, scope model.ScopeKind, kind model.IssuerKind, baseline []string) *model.Credential {
		return &model.Credential{
			KeyID: key, KeyKind: model.KeyExactSession, Provider: model.ProviderAWS,
			AccountID: "111122223333", RoleARN: "arn:aws:iam::111122223333:role/web-role",
			SessionName: session, IssuedAt: issued, ExpiresAt: exp,
			IssuerKind: kind, IssuerID: scopeID,
			Scope:           model.Scope{Kind: scope, ID: scopeID, AllowSharedEgress: true, AllowProviderEgress: true},
			BaselineActions: baseline,
		}
	}
	f.Creds.Put(mk(f.KeyInstASession, "sess-a", "i-a", model.ScopeInstance, model.IssuerInstance, []string{"s3:GetObject", "s3:ListBucket"}))
	f.Creds.Put(mk(f.KeyInstBSession, "sess-b", "i-b", model.ScopeInstance, model.IssuerInstance, []string{"s3:GetObject"}))
	f.Creds.Put(mk(f.KeyFleetPod, "sess-pod", "eks-prod", model.ScopeFleet, model.IssuerFleet, []string{"s3:GetObject", "sqs:SendMessage"}))
	f.Creds.Put(mk(f.KeyFuncVPC, "sess-fn", "fn-vpc", model.ScopeFunction, model.IssuerFunction, []string{"dynamodb:GetItem"}))
	f.Creds.Put(mk(f.KeyFuncNoVPC, "sess-fn2", "fn-novpc", model.ScopeFunction, model.IssuerFunction, []string{"dynamodb:GetItem"}))
	canary := mk(f.KeyCanary, "canary", "i-a", model.ScopeInstance, model.IssuerInstance, nil)
	canary.Canary = true
	f.Creds.Put(canary)
	return f
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err := netip.ParseAddr(s)
		if err != nil {
			panic(s)
		}
		return netip.PrefixFrom(a, a.BitLen())
	}
	return p
}

// Detector builds a detector wired to the fixture with a frozen clock.
func (f *Fixture) Detector(policy engine.Policy) *engine.Detector {
	d := engine.New(f.Creds, f.Att, policy)
	d.SetClock(func() time.Time { return f.Now })
	d.SetAttester(f.Attester)
	return d
}

func (f *Fixture) ev(at time.Duration, ip, key, session, action string) model.Event {
	return model.Event{
		ID:          fmt.Sprintf("%s-%d-%s", f.Now.Format("150405"), at, ip),
		Provider:    model.ProviderAWS,
		AccountID:   "111122223333",
		EventTime:   f.Now.Add(at - 2*time.Minute), // delivered 2 min late, like real CloudTrail
		EventSource: "s3.amazonaws.com",
		EventName:   "GetObject",
		Action:      action,
		ReadOnly:    true,
		AccessKeyID: key,
		SessionName: session,
		SourceIP:    ip,
		UserAgent:   "aws-sdk-go/1.55",
	}
}

// Cases returns all evaluation scenarios.
func Cases() []Case {
	return []Case{
		{
			Name:        "legit_instance_direct",
			Description: "instance uses its own key from its own address",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{f.ev(0, f.InstA, f.KeyInstASession, "sess-a", "s3:GetObject")}
			},
			Expect: Expectation{AllAtMost: model.VerdictAllow},
		},
		{
			Name:        "legit_shared_nat_from_own_instance",
			Description: "instance's key surfaces as the subnet NAT; attestation corroborates",
			Build: func(f *Fixture) []model.Event {
				// Attest that i-a used the key at that instant.
				claim := attest.Claim{KeyID: f.KeyInstASession, WorkloadID: "i-a", WorkloadKind: "instance",
					IssuedAt: f.Now.Add(-3 * time.Minute), ExpiresAt: f.Now.Add(3 * time.Minute), AgentID: "agent-i-a"}
				f.Attester.SetAgentKey("agent-i-a", []byte("secret-a"))
				_ = f.Attester.Sign(&claim)
				_ = f.Attester.Submit(claim)
				return []model.Event{f.ev(0, f.NatIP, f.KeyInstASession, "sess-a", "s3:GetObject")}
			},
			Expect: Expectation{AllAtMost: model.VerdictAllow},
		},
		{
			Name:        "legit_service_forwarded",
			Description: "S3 replication invoked by the S3 service itself",
			Build: func(f *Fixture) []model.Event {
				ev := f.ev(0, f.ProviderIP, f.KeyInstASession, "sess-a", "s3:ReplicateObject")
				ev.InvokedBy = "s3.amazonaws.com"
				return []model.Event{ev}
			},
			Expect: Expectation{AllAtMost: model.VerdictAllow},
		},
		{
			Name:        "legit_fleet_pod",
			Description: "EKS pod uses the fleet-scoped key from the pod CIDR",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{f.ev(0, f.PodIP, f.KeyFleetPod, "sess-pod", "s3:GetObject")}
			},
			Expect: Expectation{AllAtMost: model.VerdictAllow},
		},
		{
			Name:        "legit_vpc_lambda",
			Description: "VPC-attached function egresses through the shared NAT",
			Build: func(f *Fixture) []model.Event {
				claim := attest.Claim{KeyID: f.KeyFuncVPC, WorkloadID: "fn-vpc", WorkloadKind: "function",
					IssuedAt: f.Now.Add(-3 * time.Minute), ExpiresAt: f.Now.Add(3 * time.Minute), AgentID: "agent-fn"}
				f.Attester.SetAgentKey("agent-fn", []byte("secret-fn"))
				_ = f.Attester.Sign(&claim)
				_ = f.Attester.Submit(claim)
				return []model.Event{f.ev(0, f.NatIP, f.KeyFuncVPC, "sess-fn", "dynamodb:GetItem")}
			},
			Expect: Expectation{AllAtMost: model.VerdictAllow},
		},
		{
			Name:        "legit_serverless_no_vpc",
			Description: "function outside a VPC surfaces from provider-owned ranges",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{f.ev(0, f.ProviderIP, f.KeyFuncNoVPC, "sess-fn2", "dynamodb:GetItem")}
			},
			// Serverless egress cannot be tied to an address; the scope must
			// opt into provider egress, and the result is "watch" at most,
			// never "revoke".
			Expect: Expectation{AllAtMost: model.VerdictWatch},
		},
		{
			Name:        "attack_external_use",
			Description: "instance key replayed from the attacker's own host",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{
					f.ev(0, f.InstA, f.KeyInstASession, "sess-a", "s3:GetObject"),
					f.ev(30*time.Second, f.InternetIP, f.KeyInstASession, "sess-a", "s3:ListBuckets"),
					f.ev(60*time.Second, f.InternetIP, f.KeyInstASession, "sess-a", "ec2:RunInstances"),
				}
			},
			Expect: Expectation{WantVerdict: model.VerdictRevoke, ReasonContains: "outside the credential's network scope", Revocations: 1},
		},
		{
			Name:        "attack_cross_instance",
			Description: "instance A's key used from instance B's address (lateral)",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{f.ev(0, f.InstB, f.KeyInstASession, "sess-a", "s3:GetObject")}
			},
			Expect: Expectation{WantVerdict: model.VerdictRevoke, ReasonContains: "not the credential's scope"},
		},
		{
			Name:        "attack_sole_event_conclusive",
			Description: "single foreign call is enough for an exact-session key",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{f.ev(0, f.InternetIP, f.KeyInstASession, "sess-a", "s3:GetObject")}
			},
			// A single call must revoke: waiting for a second call gives the
			// attacker a free request.
			Expect: Expectation{WantVerdict: model.VerdictRevoke},
		},
		{
			Name:        "attack_canary",
			Description: "decoy credential used from anywhere at all",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{f.ev(0, f.InternetIP, f.KeyCanary, "canary", "s3:ListAllMyBuckets")}
			},
			Expect: Expectation{WantVerdict: model.VerdictRevoke, ReasonContains: "canary"},
		},
		{
			Name:        "hard_case_stale_inventory",
			Description: "foreign call while inventory is stale must alert, not auto-revoke",
			Build: func(f *Fixture) []model.Event {
				// Push inventory far into the past so it is stale at decision time.
				f.Inv.Set(inventory.BuildSnapshot("stale", f.Now.Add(-45*time.Minute), inventory.SnapshotData{
					Records: []inventory.Record{
						{Addr: mustPrefix(f.InstA), Kind: model.OriginInstance, Specificity: model.SpecExact, InstanceID: "i-a", AccountID: "111122223333", Source: "ec2"},
					},
				}))
				return []model.Event{f.ev(0, f.InternetIP, f.KeyInstASession, "sess-a", "s3:GetObject")}
			},
			Expect: Expectation{WantVerdict: model.VerdictAlert, ReasonContains: "stale"},
		},
		{
			Name:        "hard_case_shared_nat_no_attestation",
			Description: "shared NAT without attestation is ambiguous: alert, do not revoke",
			Build: func(f *Fixture) []model.Event {
				// No claim submitted. The address is the scope's own NAT, so
				// network says 'inside account'; the engine must not conclude
				// theft, and must not clear it silently either.
				return []model.Event{f.ev(0, f.NatIP, f.KeyInstASession, "sess-a", "s3:GetObject")}
			},
			Expect: Expectation{AllAtMost: model.VerdictAlert},
		},
		{
			Name:        "attack_concurrent_distinct_origins",
			Description: "same exact-session key from two exact origins inside the window",
			Build: func(f *Fixture) []model.Event {
				return []model.Event{
					f.ev(0, f.InstA, f.KeyInstASession, "sess-a", "s3:GetObject"),
					f.ev(20*time.Second, f.InstB, f.KeyInstASession, "sess-a", "s3:GetObject"),
				}
			},
			Expect: Expectation{WantVerdict: model.VerdictRevoke, ReasonContains: "not the credential's scope"},
		},
		{
			Name:        "late_log_urgency",
			Description: "a 30-minute-late foreign call is still revoked, with lag recorded",
			Build: func(f *Fixture) []model.Event {
				ev := f.ev(0, f.InternetIP, f.KeyInstASession, "sess-a", "s3:GetObject")
				ev.EventTime = f.Now.Add(-30 * time.Minute)
				return []model.Event{ev}
			},
			Expect: Expectation{WantVerdict: model.VerdictRevoke},
		},
	}
}

// Case is one evaluation scenario.
type Case struct {
	Name        string
	Description string
	Build       func(f *Fixture) []model.Event
	Expect      Expectation
}

// RunCase runs a case against a fresh fixture and returns the decisions plus
// whether the expectation held.
func RunCase(c Case, now time.Time) ([]engine.Decision, bool, error) {
	f := NewFixture(now)
	d := f.Detector(f.Policy)
	evs := c.Build(f)
	var decs []engine.Decision
	for _, ev := range evs {
		if ev.EventTime.IsZero() {
			ev.EventTime = f.Now.Add(-2 * time.Minute)
		}
		decs = append(decs, d.Process(ev))
	}
	ok := check(c.Expect, decs)
	if !ok {
		return decs, false, nil
	}
	return decs, true, nil
}

func check(e Expectation, decs []engine.Decision) bool {
	if len(decs) == 0 {
		return false
	}
	if e.AllAtMost != "" {
		rank := map[model.Verdict]int{model.VerdictAllow: 0, model.VerdictWatch: 1, model.VerdictAlert: 2, model.VerdictRevoke: 3}
		for _, d := range decs {
			if rank[d.Verdict] > rank[e.AllAtMost] {
				return false
			}
		}
		return true
	}
	found := false
	for _, d := range decs {
		if e.WantVerdict != "" && d.Verdict != e.WantVerdict {
			continue
		}
		if e.ReasonContains != "" {
			all := d.Binding.Reason
			for _, ev := range d.Evidence {
				all += " " + ev.Detail
			}
			if !containsFold(all, e.ReasonContains) {
				continue
			}
		}
		found = true
	}
	if !found {
		return false
	}
	if e.Revocations > 0 {
		n := 0
		for _, d := range decs {
			if d.Incident != nil && d.Incident.Verdict == model.VerdictRevoke {
				n++
			}
		}
		if n < e.Revocations {
			return false
		}
	}
	return true
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || stringsContainsLower(s, sub)
}

func stringsContainsLower(s, sub string) bool {
	ls, lsub := lower(s), lower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// RunAndCheck adapts a case for the CLI's simulate subcommand: it runs the
// case and prints decisions.
func RunAndCheck(c Case, verbose bool) (bool, error) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	decs, ok, err := RunCase(c, now)
	if err != nil {
		return false, err
	}
	if verbose {
		for _, d := range decs {
			fmt.Printf("    %-6s score=%-3d binding=%-20s src=%-15s %s\n",
				d.Verdict, d.Score, d.Binding.Class, d.Event.SourceIP, d.Binding.Reason)
			for _, e := range engine.SnapshotSorted(d.Evidence) {
				fmt.Printf("       - %s (+%d): %s\n", e.Rule, e.Score, e.Detail)
			}
		}
	}
	if !ok {
		for _, d := range decs {
			fmt.Printf("      got verdict=%s score=%d binding=%s reason=%s\n", d.Verdict, d.Score, d.Binding.Class, d.Binding.Reason)
		}
	}
	return ok, nil
}

// All returns the built-in cases, in a stable order.
func All() []Case { return Cases() }

// Silence unused-import guards that exist only for the full-pipeline variant.
