// Package attrib turns an audit event's source address into a structured
// Origin, then compares that Origin against what the credential's scope says
// is legitimate.
//
// The design principle: an audit source address is a *representation*, never
// an identity. The same instance can appear as its private IP, its NAT EIP, a
// VPC-endpoint ENI, or a provider service address; all of those are legitimate
// for some workloads and wrong for others. So the package refuses to answer
// "is this address good?" and answers "which workload could have produced
// traffic from this address, and how strong is that inference?".
package attrib

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"credwatch/internal/inventory"
	"credwatch/internal/model"
)

type Config struct {
	// ProviderRanges are provider-owned address ranges used for egress we
	// cannot tie to a workload (e.g. Lambda outside a VPC). Empty means such
	// traffic resolves to Unknown.
	ProviderRanges []netip.Prefix
	// Blocklist prefixes are never legitimate for this account's credentials.
	Blocklist []netip.Prefix
	// AllowProviderEgressDefault is the fallback when a credential's scope
	// does not say; serverless and some managed services need it.
	AllowProviderEgressDefault bool
}

type Attributor struct {
	inv *inventory.Store
	cfg Config
	// providerCache caches prefix membership checks.
	providerRanges []netip.Prefix
	blocklist      []netip.Prefix
}

func New(inv *inventory.Store, cfg Config) *Attributor {
	pr := append([]netip.Prefix(nil), cfg.ProviderRanges...)
	sort.Slice(pr, func(i, j int) bool { return pr[i].Bits() > pr[j].Bits() })
	bl := append([]netip.Prefix(nil), cfg.Blocklist...)
	return &Attributor{inv: inv, cfg: cfg, providerRanges: pr, blocklist: bl}
}

// Resolve maps an event's trusted attribution fields onto an Origin.
//
// Precedence:
//  1. invokedBy — the provider itself says a cloud service made the call.
//     This is trusted and must win, otherwise every service-forwarded call
//     looks like an external caller.
//  2. the source address, resolved through inventory, longest prefix first.
//  3. static classification (provider range, blocklist, unknown).
func (a *Attributor) Resolve(ev *model.Event) (model.Origin, inventory.Staleness) {
	return a.ResolveAt(ev, time.Now())
}

// ResolveAt is Resolve with an explicit evaluation clock, so replay and
// backtests judge staleness at event time rather than wall time.
func (a *Attributor) ResolveAt(ev *model.Event, now time.Time) (model.Origin, inventory.Staleness) {
	snap, st := a.inv.SnapshotAt(now)
	origin := model.Origin{Zone: "external", Specificity: model.SpecNone}

	if ev.InvokedBy != "" {
		origin.Kind = model.OriginCloudService
		origin.CloudService = ev.InvokedBy
		origin.Zone = "provider"
		origin.Reason = "audit log: invokedBy=" + ev.InvokedBy
		// Even for service-forwarded calls, resolve the address so an
		// incident can show the actual network origin.
		if a, ok := matchPrefix(a.providerRanges, ev.IP()); ok {
			origin.Reason += fmt.Sprintf(" (address in provider range %s)", a)
		}
		return origin, st
	}

	addr := ev.IP()
	if !addr.IsValid() {
		origin.Kind = model.OriginUnknown
		origin.Reason = "event carries no parseable source address"
		return origin, st
	}

	for _, b := range a.blocklist {
		if b.Contains(addr) {
			origin.Kind = model.OriginUnknown
			origin.Blocklisted = true
			origin.Zone = "external"
			origin.Reason = fmt.Sprintf("source %s is on the blocklist (%s)", addr, b)
			return origin, st
		}
	}

	if snap != nil {
		if rec, ok := snap.Lookup(addr); ok {
			o := originFromRecord(rec)
			o.Reason = fmt.Sprintf("address %s matched inventory record from %s", addr, rec.Source)
			return o, st
		}
	}

	if p, ok := matchPrefix(a.providerRanges, addr); ok {
		origin.Kind = model.OriginProviderInternal
		origin.Zone = "provider"
		origin.Reason = fmt.Sprintf("address %s is in provider range %s but matched no inventory record", addr, p)
		return origin, st
	}

	origin.Kind = model.OriginUnknown
	if st.HasSnapshot && st.Stale {
		origin.Reason = fmt.Sprintf("address %s matched nothing; inventory is %s stale so absence is unverified", addr, st.Age.Round(time.Second))
	} else if st.HasSnapshot {
		origin.Reason = fmt.Sprintf("address %s is outside every recorded address", addr)
	} else {
		origin.Reason = fmt.Sprintf("address %s could not be resolved: no inventory snapshot loaded", addr)
	}
	return origin, st
}

func originFromRecord(r inventory.Record) model.Origin {
	return model.Origin{
		Kind:         r.Kind,
		Specificity:  r.Specificity,
		Zone:         r.Zone,
		InstanceID:   r.InstanceID,
		FleetID:      r.FleetID,
		FunctionID:   r.FunctionID,
		ProxyID:      r.ProxyID,
		CloudService: "",
		NATGatewayID: r.NATGateway,
		SubnetID:     r.SubnetID,
		AccountID:    r.AccountID,
		Blocklisted:  r.Blocklisted,
	}
}

func matchPrefix(ps []netip.Prefix, a netip.Addr) (netip.Prefix, bool) {
	if !a.IsValid() {
		return netip.Prefix{}, false
	}
	for _, p := range ps {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// ScopeExpectation is what the credential's scope lets us infer about network
// legitimacy, expanded against inventory (NAT ids, pod ranges, ...).
type ScopeExpectation struct {
	// Anchored means the scope has network expectations at all. Role and user
	// credentials used from arbitrary places are unanchored: an unexpected
	// address is not by itself evidence of theft.
	Anchored            bool
	Instance            string
	Fleet               string
	Function            string
	NATs                map[string]bool
	Proxies             map[string]bool
	VPCEndpoints        map[string]bool
	AllowSharedEgress   bool
	AllowProviderEgress bool
	RequireAttestation  bool
}

// Expectation expands a credential's scope using the current inventory.
func (a *Attributor) Expectation(c *model.Credential) ScopeExpectation {
	snap, _ := a.inv.Snapshot()
	ex := ScopeExpectation{
		AllowSharedEgress:   c.Scope.AllowSharedEgress,
		AllowProviderEgress: c.Scope.AllowProviderEgress,
		RequireAttestation:  c.Scope.RequireAttestation,
		NATs:                map[string]bool{},
		Proxies:             map[string]bool{},
		VPCEndpoints:        map[string]bool{},
	}
	if c.Scope.AllowProviderEgress == false && a.cfg.AllowProviderEgressDefault && c.IssuerKind == model.IssuerFunction {
		ex.AllowProviderEgress = true
	}
	for _, p := range c.Scope.TrustedProxies {
		ex.Proxies[p] = true
	}
	switch c.Scope.Kind {
	case model.ScopeInstance:
		ex.Anchored = true
		ex.Instance = c.Scope.ID
		if snap != nil {
			if info, ok := snap.Instance(c.Scope.ID); ok {
				for _, n := range info.NATGatewayIDs {
					ex.NATs[n] = true
				}
			}
		}
	case model.ScopeFleet:
		ex.Anchored = true
		ex.Fleet = c.Scope.ID
		if snap != nil {
			if info, ok := snap.Fleet(c.Scope.ID); ok {
				for _, n := range info.NATGatewayIDs {
					ex.NATs[n] = true
				}
			}
		}
	case model.ScopeFunction:
		ex.Anchored = true
		ex.Function = c.Scope.ID
		if snap != nil {
			if info, ok := snap.Function(c.Scope.ID); ok {
				for _, n := range info.NATGatewayIDs {
					ex.NATs[n] = true
				}
			}
		}
	case model.ScopeRole, model.ScopeUser:
		ex.Anchored = len(c.Scope.ExtraCIDRs) > 0 || len(c.Scope.TrustedProxies) > 0
	}
	return ex
}

// Bind decides whether an Origin is legitimate for a credential. It separates
// three outcomes: bound (strong benign), ambiguous (tolerated but weak), and
// unbound (evidence of use outside the scope).
func (a *Attributor) Bind(c *model.Credential, origin model.Origin, ex ScopeExpectation) model.BindingResult {
	res := model.BindingResult{Specificity: origin.Specificity}
	if c == nil {
		return model.BindingResult{Class: model.UnregisteredCredential, Reason: "no issuance record for this key", Specificity: model.SpecNone}
	}
	res.ScopeRef = scopeRef(c)
	// A principal-scoped credential cannot be pinned to one session, so every
	// reason must say so rather than imply session precision.
	suffix := ""
	if c.KeyKind == model.KeyPrincipal {
		suffix = " (key is principal-scoped, not session-scoped)"
	}
	finish := func() model.BindingResult {
		res.Reason += suffix
		return res
	}

	if origin.Blocklisted {
		res.Class = model.External
		res.Reason = "source address is blocklisted: " + origin.Reason
		return finish()
	}

	switch origin.Kind {
	case model.OriginCloudService:
		res.Class = model.BoundService
		res.Reason = "call was made by cloud service " + origin.CloudService + " on the workload's behalf"
		return finish()

	case model.OriginInstance:
		if !ex.Anchored {
			res.Class = model.BoundUnanchored
			res.Reason = "scope has no instance expectation"
			return finish()
		}
		if ex.Instance != "" && origin.InstanceID == ex.Instance {
			res.Class = model.BoundDirect
			res.Reason = "source is the credential's own instance " + origin.InstanceID
			return finish()
		}
		if ex.Fleet != "" && origin.FleetID == ex.Fleet {
			res.Class = model.BoundDirect
			res.Reason = "source is a node in the credential's fleet " + origin.FleetID
			return finish()
		}
		res.Class = model.ForeignPrincipal
		res.Reason = fmt.Sprintf("source is instance %s, which is not the credential's scope %s", origin.InstanceID, scopeRef(c))
		return finish()

	case model.OriginFleetPod:
		if ex.Fleet != "" && origin.FleetID == ex.Fleet {
			res.Class = model.BoundDirect
			res.Reason = "source is a pod in the credential's fleet " + origin.FleetID
			return finish()
		}
		if ex.Instance != "" && origin.InstanceID == ex.Instance {
			res.Class = model.BoundDirect
			res.Reason = "source is a pod on the credential's instance " + ex.Instance
			return finish()
		}
		if !ex.Anchored {
			res.Class = model.BoundUnanchored
			res.Reason = "scope has no fleet expectation"
			return finish()
		}
		res.Class = model.ForeignPrincipal
		res.Reason = fmt.Sprintf("source is pod/fleet %s, not the credential's fleet %s", origin.FleetID, ex.Fleet)
		return finish()

	case model.OriginFunctionENI:
		if ex.Function != "" && origin.FunctionID == ex.Function {
			res.Class = model.BoundDirect
			res.Reason = "source is the credential's function ENI"
			return finish()
		}
		if !ex.Anchored {
			res.Class = model.BoundUnanchored
			res.Reason = "scope has no function expectation"
			return finish()
		}
		res.Class = model.ForeignPrincipal
		res.Reason = fmt.Sprintf("source is function %s, not the credential's function %s", origin.FunctionID, ex.Function)
		return finish()

	case model.OriginVPCEndpoint:
		// A VPC endpoint is shared by everything in its VPC. It proves the
		// caller is inside the account's VPC, not which workload it is.
		res.Class = model.BoundSharedEgress
		res.Specificity = model.SpecAmbiguous
		res.Reason = "source is a VPC endpoint ENI, shared inside its VPC"
		return finish()

	case model.OriginNAT:
		if !ex.AllowSharedEgress {
			res.Class = model.UnexplainedInternal
			res.Reason = "source is NAT gateway egress but the scope does not permit shared egress"
			return finish()
		}
		if ex.NATs[origin.NATGatewayID] {
			res.Class = model.BoundSharedEgress
			res.Specificity = model.SpecAmbiguous
			res.Reason = "source is a NAT gateway " + origin.NATGatewayID + " owned by the credential's scope"
			return finish()
		}
		// Same-account NAT not tied to this scope is weaker than external but
		// still wrong: it means a different subnet used the credential.
		res.Class = model.UnexplainedInternal
		res.Reason = "source is NAT gateway " + origin.NATGatewayID + ", which is not in the credential's scope"
		return finish()

	case model.OriginProxy:
		if ex.Proxies[origin.ProxyID] {
			res.Class = model.BoundViaProxy
			res.Specificity = model.SpecAmbiguous
			res.Reason = "source is registered forward proxy " + origin.ProxyID + " used by the scope"
			return finish()
		}
		if !ex.Anchored {
			res.Class = model.BoundUnanchored
			res.Reason = "scope has no network expectation, proxy not attributable"
			return finish()
		}
		res.Class = model.UnexplainedInternal
		res.Reason = "source is proxy " + origin.ProxyID + ", which the scope does not trust"
		return finish()

	case model.OriginAccountOther:
		if !ex.Anchored {
			res.Class = model.BoundUnanchored
			res.Reason = "scope has no network expectation"
			return finish()
		}
		res.Class = model.ForeignPrincipal
		res.Reason = "source belongs to another resource in the account but not the credential's scope"
		return finish()

	case model.OriginProviderInternal:
		if ex.AllowProviderEgress {
			res.Class = model.BoundProviderEgress
			res.Specificity = model.SpecNone
			res.Reason = "source is provider-owned; egress from this workload is not attributable to an address"
			return finish()
		}
		if !ex.Anchored {
			res.Class = model.BoundUnanchored
			res.Reason = "scope has no network expectation"
			return finish()
		}
		res.Class = model.UnexplainedInternal
		res.Reason = "source is provider-owned but the scope does not permit provider egress"
		return finish()
	}

	// Unknown / external.
	if !ex.Anchored {
		res.Class = model.BoundUnanchored
		res.Reason = "source " + origin.Reason + "; scope has no network expectation so this is not conclusive"
		return finish()
	}
	res.Class = model.External
	res.Reason = "source is outside the credential's network scope: " + origin.Reason
	return finish()
}

func scopeRef(c *model.Credential) string {
	if c == nil {
		return ""
	}
	return string(c.Scope.Kind) + ":" + c.Scope.ID
}

// ActionInBaseline reports whether an action matches the credential's learned
// baseline glob patterns. Used only as supporting evidence.
func ActionInBaseline(c *model.Credential, action string) bool {
	if c == nil || len(c.BaselineActions) == 0 {
		return true
	}
	for _, pat := range c.BaselineActions {
		if globMatch(pat, action) {
			return true
		}
	}
	return false
}

func globMatch(pat, s string) bool {
	pat = strings.TrimSpace(pat)
	if pat == "" || pat == "*" {
		return true
	}
	if !strings.Contains(pat, "*") {
		return strings.EqualFold(pat, s)
	}
	parts := strings.Split(pat, "*")
	if !strings.HasPrefix(strings.ToLower(s), strings.ToLower(parts[0])) {
		return false
	}
	rest := strings.ToLower(s)[len(parts[0]):]
	for i := 1; i < len(parts); i++ {
		p := strings.ToLower(parts[i])
		if p == "" {
			continue
		}
		idx := strings.Index(rest, p)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(p):]
	}
	if last := parts[len(parts)-1]; last != "" {
		return strings.HasSuffix(strings.ToLower(s), strings.ToLower(last))
	}
	return true
}
