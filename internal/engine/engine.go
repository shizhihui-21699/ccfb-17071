// Package engine turns attributed audit events into verdicts.
//
// The engine never decides from a single field. It builds a set of evidence
// items, each tagged trusted/untrusted, and combines them under a policy that
// distinguishes:
//
//   - hard evidence: the network path contradicts the credential scope, the
//     credential is a canary, the source is blocklisted, or the credential is
//     used outside its lifetime. These do not depend on client-supplied data.
//   - soft evidence: baseline deviation, unusual client fingerprints,
//     concurrency patterns. These only add urgency; they never carry a
//     verdict on their own, because attackers can forge them and ordinary
//     workloads can produce them.
//
// Late logs are a first-class concern: an event's age is part of the verdict,
// because a two-minute-old theft is recoverable and a two-hour-old one is a
// postmortem. The engine therefore reports LagSeconds on every incident and
// escalates urgency when lag is high rather than pretending detection was
// timely.
package engine

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"credwatch/internal/attest"
	"credwatch/internal/attrib"
	"credwatch/internal/credstore"
	"credwatch/internal/inventory"
	"credwatch/internal/model"
	"credwatch/internal/unit"
)

type Policy struct {
	// AutoRevokeMinScore is the score at which an automated revocation runs.
	// It is deliberately higher than the alert threshold.
	AutoRevokeMinScore int `json:"auto_revoke_min_score"`
	// AutoRevoke requires trusted, conclusive evidence (network binding
	// mismatch on a non-stale inventory, canary, blocklist). Without it the
	// verdict caps at alert so an incomplete inventory cannot break prod.
	AutoRevokeRequiresConclusive bool `json:"auto_revoke_requires_conclusive"`
	// AlertMinScore and WatchMinScore set the lower bands.
	AlertMinScore int `json:"alert_min_score"`
	WatchMinScore int `json:"watch_min_score"`
	// ConcurrencyWindow: the same session-scoped key seen from two different
	// exact origins inside this window is treated as conclusive separate use.
	ConcurrencyWindow unit.Duration `json:"concurrency_window"`
	// LagWarn/LagCrit mark audit staleness that changes urgency.
	LagWarn unit.Duration `json:"lag_warn"`
	LagCrit unit.Duration `json:"lag_crit"`
	// WatchEscalationCount / WatchEscalationWindow: N watch-level events for
	// one key inside the window escalate to alert (slow-drip exfiltration).
	WatchEscalationCount  int           `json:"watch_escalation_count"`
	WatchEscalationWindow unit.Duration `json:"watch_escalation_window"`
	// ExpiryGrace tolerates clock skew when judging "expired".
	ExpiryGrace unit.Duration `json:"expiry_grace"`
	// UntrustedAnomalyScore is how much a purely client-side anomaly may add.
	UntrustedAnomalyScore int `json:"untrusted_anomaly_score"`
}

func DefaultPolicy() Policy {
	return Policy{
		AutoRevokeMinScore:           85,
		AutoRevokeRequiresConclusive: true,
		AlertMinScore:                50,
		WatchMinScore:                20,
		ConcurrencyWindow:            unit.Duration(15 * time.Minute),
		LagWarn:                      unit.Duration(3 * time.Minute),
		LagCrit:                      unit.Duration(15 * time.Minute),
		WatchEscalationCount:         3,
		WatchEscalationWindow:        unit.Duration(30 * time.Minute),
		ExpiryGrace:                  unit.Duration(10 * time.Minute),
		UntrustedAnomalyScore:        10,
	}
}

// Decision is the engine's per-event output.
type Decision struct {
	Event      model.Event         `json:"event"`
	Credential *model.Credential   `json:"credential,omitempty"`
	Origin     model.Origin        `json:"origin"`
	Binding    model.BindingResult `json:"binding"`
	Score      int                 `json:"score"`
	Verdict    model.Verdict       `json:"verdict"`
	Severity   model.Severity      `json:"severity"`
	Evidence   []model.Evidence    `json:"evidence"`
	Lag        time.Duration       `json:"lag"`

	// Incident is set when the verdict is at least watch and policy says the
	// event should surface. Callers turn it into pages/revocations.
	Incident  *model.Incident     `json:"incident,omitempty"`
	Staleness inventory.Staleness `json:"inventory,omitempty"`
}

type keyState struct {
	firstSeen  time.Time
	lastSeen   time.Time
	events     []eventMark // bounded
	watchCount []time.Time
	origins    map[string]time.Time // origin signature -> first seen
	userAgents map[string]bool
	actioned   bool
	alerted    bool
}

type eventMark struct {
	at     time.Time
	origin string
	exact  bool
}

type Detector struct {
	creds    *credstore.Store
	attrib   *attrib.Attributor
	attester *attest.Store
	policy   Policy
	now      func() time.Time

	mu    sync.Mutex
	state map[string]*keyState
	// maxEvents bounds per-key history.
	maxEvents int
	// incidentSeq makes incident IDs deterministic per process run.
	incidentSeq uint64
	runID       string
}

func New(creds *credstore.Store, at *attrib.Attributor, policy Policy) *Detector {
	return &Detector{
		creds:     creds,
		attrib:    at,
		policy:    policy,
		now:       time.Now,
		state:     make(map[string]*keyState),
		maxEvents: 64,
		runID:     "cw",
	}
}

// SetClock is used by tests to make lag deterministic.
func (d *Detector) SetClock(f func() time.Time) { d.now = f }

// SetAttester enables workload attestation corroboration. Optional: the
// detector works without it, with weaker attribution on shared egress.
func (d *Detector) SetAttester(a *attest.Store) { d.attester = a }

// reconcileAttestation adjusts a network binding using an independent
// workload-side claim.
//
// The crucial limitation, stated here because it is easy to get wrong:
// attestation proves *which workload* used the key, not that the use was
// authorized. An SSRF that makes the instance call the API from the instance
// itself produces a perfectly matching claim. So a matching claim may only
// clear the *network-attribution* doubt (shared NAT, provider egress,
// unknown-but-internal); it must never clear behavioural evidence.
func (d *Detector) reconcileAttestation(cred *model.Credential, dec *Decision, ev *model.Event) {
	if d.attester == nil {
		return
	}
	claim, ok := d.attester.ClaimFor(cred.KeyID, ev.EventTime)
	if !ok {
		return
	}
	_, matches := attest.MatchScope(claim, cred.Scope)
	if !matches {
		dec.Binding = model.BindingResult{
			Class:       model.ForeignPrincipal,
			Reason:      fmt.Sprintf("agent attestation: key used by workload %s (%s), which is not the credential's scope %s", claim.WorkloadID, claim.WorkloadKind, scopeRef(cred)),
			ScopeRef:    scopeRef(cred),
			Specificity: model.SpecExact,
		}
		return
	}
	switch dec.Binding.Class {
	case model.BoundSharedEgress, model.BoundProviderEgress, model.UnexplainedInternal, model.BoundUnanchored:
		dec.Binding = model.BindingResult{
			Class:       model.BoundDirect,
			Reason:      "agent attestation corroborates workload " + claim.WorkloadID + " despite the network egress being shared",
			ScopeRef:    scopeRef(cred),
			Specificity: model.SpecExact,
		}
		dec.Evidence = append(dec.Evidence, model.Evidence{
			Rule:    "attested_workload",
			Detail:  "independent agent claim matches the credential's workload",
			Trusted: true,
		})
	case model.External, model.ForeignPrincipal:
		// Contradiction: the agent says the scoped workload used the key, but
		// the traffic left from somewhere we cannot tie to it. Either an
		// unmodelled egress path or a compromised instance; keep suspicion.
		dec.Evidence = append(dec.Evidence, model.Evidence{
			Rule:    "attested_network_conflict",
			Detail:  "agent claims the scoped workload used the key, but the source address is outside its network scope; verify the egress path",
			Score:   15,
			Trusted: true,
		})
	}
}

// Process evaluates one event end-to-end.
func (d *Detector) Process(ev model.Event) Decision {
	now := d.now()
	if ev.IngestTime.IsZero() {
		ev.IngestTime = now
	}
	dec := Decision{Event: ev}

	lag := now.Sub(ev.EventTime)
	if lag < 0 {
		// Clock skew or provider timestamps in the future: clamp, but record
		// it rather than silently pretending the event is current.
		lag = 0
	}
	dec.Lag = lag

	cred, found := d.creds.Resolve(&ev, now)
	dec.Credential = cred

	if !found {
		dec.Binding = model.BindingResult{
			Class:  model.UnregisteredCredential,
			Reason: "no issuance record matches this key/session",
		}
		dec.Origin, dec.Staleness = d.attrib.ResolveAt(&ev, now)
		// An unknown key is normal right after startup or when issuance
		// records are missing. It is only suspicious if it looks like an STS
		// key that we should have seen, and it can never auto-revoke: there
		// is no session to revoke and no scope to compare against.
		if isTemporaryKey(ev.AccessKeyID) {
			dec.Evidence = append(dec.Evidence, model.Evidence{
				Rule:    "unregistered_temporary_key",
				Detail:  "temporary-format key has no issuance record; issuance feed may lag or be incomplete",
				Score:   25,
				Trusted: true,
			})
		}
		dec.Score = 25
		dec.Verdict = model.VerdictWatch
		dec.Severity = model.SevLow
		return d.finalize(&dec, now)
	}

	ex := d.attrib.Expectation(cred)
	dec.Origin, dec.Staleness = d.attrib.ResolveAt(&ev, now)
	dec.Binding = d.attrib.Bind(cred, dec.Origin, ex)
	d.reconcileAttestation(cred, &dec, &ev)

	var evid []model.Evidence
	add := func(e model.Evidence) { evid = append(evid, e) }
	score := 0
	conclusive := dec.Binding.Conclusive()

	// --- hard evidence: network binding -------------------------------------
	switch dec.Binding.Class {
	case model.BoundDirect:
		// no evidence
	case model.BoundService:
		// provider-forwarded; benign
	case model.BoundViaProxy:
		add(model.Evidence{Rule: "via_registered_proxy", Detail: dec.Binding.Reason, Score: 0, Trusted: true})
	case model.BoundSharedEgress:
		add(model.Evidence{Rule: "shared_egress", Detail: dec.Binding.Reason, Score: 0, Trusted: true})
		if dec.Binding.Specificity == model.SpecAmbiguous && ex.RequireAttestation {
			// Scopes that demand attestation must corroborate shared egress;
			// absence is handled by the attest stage, which sets
			// Binding.Class=UnexplainedInternal before this point in strict
			// deployments.
			add(model.Evidence{Rule: "unattributable_egress", Detail: "scope requires attestation but egress is shared", Score: 10, Trusted: true})
			score += 10
		}
	case model.BoundProviderEgress:
		add(model.Evidence{Rule: "provider_egress", Detail: dec.Binding.Reason, Score: 0, Trusted: true})
	case model.BoundUnanchored:
		add(model.Evidence{Rule: "unanchored_scope", Detail: dec.Binding.Reason, Score: 0, Trusted: true})
		conclusive = false
	case model.ForeignPrincipal:
		s := 70
		if dec.Origin.Specificity == model.SpecExact {
			s = 78
		}
		add(model.Evidence{Rule: "foreign_principal", Detail: dec.Binding.Reason, Score: s, Hard: true, Trusted: true})
		score += s
	case model.External:
		// A scoped temporary credential used from an address outside every
		// known path is the core signal. It must be sufficient on its own:
		// requiring a second call to cross the threshold hands the attacker a
		// free request, and the audit lag means we are already late.
		s := 90
		if dec.Staleness.HasSnapshot && dec.Staleness.Stale {
			// The address matched nothing, but we cannot vouch for the
			// inventory itself. Downgrade below the auto-revoke threshold and
			// say why; an operator must look. It still lands above the alert
			// threshold on its own: an unmatched address on a scoped
			// credential is exactly the shape of the attack, and requiring a
			// second signal (a fresh user agent, say) to reach the alert band
			// would make the alert depend on attacker-side fields.
			s = 55
			conclusive = false
			add(model.Evidence{Rule: "inventory_stale", Detail: fmt.Sprintf("inventory snapshot is %s old; an unmatched address cannot be called external with confidence", dec.Staleness.Age.Round(time.Second)), Score: 0, Trusted: true})
		}
		add(model.Evidence{Rule: "external_origin", Detail: dec.Binding.Reason, Score: s, Hard: true, Trusted: true})
		score += s
		if dec.Origin.Blocklisted {
			// A blocklisted address is independent of inventory freshness: we
			// know it is hostile regardless of whether the snapshot is current.
			conclusive = true
		}
	case model.UnexplainedInternal:
		s := 55
		add(model.Evidence{Rule: "unexplained_internal", Detail: dec.Binding.Reason, Score: s, Hard: true, Trusted: true})
		score += s
	case model.ExpiredCredential:
		add(model.Evidence{Rule: "expired_credential", Detail: dec.Binding.Reason, Score: 60, Hard: true, Trusted: true})
		score += 60
	case model.NoNetworkEvidence:
		conclusive = false
	}

	// --- hard evidence: credential facts ------------------------------------
	if cred.Canary {
		add(model.Evidence{Rule: "canary_credential", Detail: "canary decoy credential used; no legitimate workload holds it", Score: 100, Hard: true, Trusted: true})
		score += 100
		conclusive = true
	}
	if dec.Origin.Blocklisted {
		add(model.Evidence{Rule: "blocklisted_source", Detail: "source address is on the blocklist", Score: 60, Hard: true, Trusted: true})
		score += 60
	}
	if cred.Expired(ev.EventTime, d.policy.ExpiryGrace.Duration()) {
		add(model.Evidence{Rule: "expired_credential", Detail: "credential was already expired when the call was made", Score: 55, Hard: true, Trusted: true})
		score += 55
		conclusive = true
	} else if cred.Expired(now, d.policy.ExpiryGrace.Duration()) {
		// The call was inside the credential's lifetime, but we are only
		// seeing it after the credential expired. That is not proof of theft —
		// it is the normal shape of a late audit log — but it does mean the
		// key outlived its intended window in our view, so it is worth noting.
		add(model.Evidence{Rule: "detected_after_expiry", Detail: fmt.Sprintf("call made while valid, delivered %.0fs after the credential expired", now.Sub(cred.ExpiresAt).Seconds()), Score: 0, Trusted: true})
	}
	if cred.KeyKind == model.KeyPrincipal {
		// Principal-scoped correlation weakens address-based conclusions, and
		// only when we actually reached one. Applying the penalty to an
		// already-clean binding would subtract from zero and turn a benign
		// call into a "watch"; a positive score means the address *did*
		// contradict the scope, so the caveat belongs in the reason instead.
		if score > 0 {
			score -= 10
			add(model.Evidence{Rule: "principal_scoped", Detail: "credential cannot be tied to one session; address evidence is weaker", Score: -10, Trusted: true})
		} else {
			dec.Binding.Reason += " (key is principal-scoped; conclusions are about the principal, not one session)"
		}
	}

	// --- soft evidence: behaviour -------------------------------------------
	// Service-forwarded calls are excluded from client-behaviour scoring. When
	// AWS calls AWS on the workload's behalf there is no client, so user agent,
	// baseline actions and session naming describe the *service's* behaviour,
	// not the workload's. Scoring them produces false positives on every S3
	// replication, EventBridge delivery and autoscaling action.
	serviceForwarded := dec.Binding.Class == model.BoundService
	if !serviceForwarded && !attrib.ActionInBaseline(cred, ev.Action) {
		bonus := 12
		if ev.ReadOnly == false {
			bonus = 18
		}
		add(model.Evidence{Rule: "action_outside_baseline", Detail: fmt.Sprintf("action %q is not in the workload's baseline", ev.Action), Score: bonus, Trusted: true})
		score += bonus
	}

	// Session-name mismatch is trusted metadata from the provider and a
	// surprisingly good signal: a stolen key replayed under the same name is
	// fine, but a new session for the same role from a foreign origin is not.
	if !serviceForwarded && cred.SessionName != "" && ev.SessionName != "" && ev.SessionName != cred.SessionName {
		add(model.Evidence{Rule: "session_name_mismatch", Detail: "audit session name differs from the issuance record", Score: 20, Trusted: true})
		score += 20
	}

	// --- soft evidence: client-supplied, capped -----------------------------
	if !serviceForwarded && ev.UserAgent != "" && cred.KeyKind == model.KeyExactSession {
		if !d.userAgentKnown(cred.KeyID, ev.UserAgent) {
			add(model.Evidence{Rule: "new_user_agent", Detail: "first use of this user agent for the credential", Score: min(8, d.policy.UntrustedAnomalyScore), Trusted: false})
			score += min(8, d.policy.UntrustedAnomalyScore)
		}
	}

	// --- concurrency: strongest corroboration of separate use ---------------
	if d.concurrencyConflict(cred.KeyID, dec.Origin, ev.EventTime) {
		add(model.Evidence{Rule: "concurrent_distinct_origin", Detail: "the same session-scoped key was used from a different origin inside the concurrency window", Score: 45, Hard: true, Trusted: true})
		score += 45
		conclusive = true
	}

	// --- late-log urgency ----------------------------------------------------
	if lag >= d.policy.LagCrit.Duration() {
		add(model.Evidence{Rule: "audit_lag_critical", Detail: fmt.Sprintf("audit log delivered %.0fs late; the credential had a long exploitation window", lag.Seconds()), Score: 10, Trusted: true})
		score += 10
	} else if lag >= d.policy.LagWarn.Duration() {
		add(model.Evidence{Rule: "audit_lag_high", Detail: fmt.Sprintf("audit log delivered %.0fs late", lag.Seconds()), Score: 5, Trusted: true})
		score += 5
	}

	if score < 0 {
		score = 0
	}
	dec.Score = score
	dec.Evidence = evid
	dec.Verdict, dec.Severity = d.classify(score, conclusive)

	// Watch-level noise is aggregated per key so a slow drip escalates.
	if dec.Verdict == model.VerdictWatch {
		if n := d.recordWatch(cred.KeyID, ev.EventTime); n >= d.policy.WatchEscalationCount {
			dec.Evidence = append(dec.Evidence, model.Evidence{
				Rule:   "repeated_watch_events",
				Detail: fmt.Sprintf("%d watch-level events for this key inside %s", n, d.policy.WatchEscalationWindow.Duration()),
				Score:  30, Trusted: true,
			})
			dec.Score += 30
			dec.Verdict, dec.Severity = d.classify(dec.Score, conclusive)
		}
	}

	d.recordOrigin(cred.KeyID, dec.Origin, ev)
	return d.finalize(&dec, now)
}

func (d *Detector) classify(score int, conclusive bool) (model.Verdict, model.Severity) {
	p := d.policy
	switch {
	case score >= p.AutoRevokeMinScore:
		if p.AutoRevokeRequiresConclusive && !conclusive {
			return model.VerdictAlert, model.SevHigh
		}
		return model.VerdictRevoke, model.SevCritical
	case score >= p.AlertMinScore:
		sev := model.SevHigh
		if score >= p.AutoRevokeMinScore-15 {
			sev = model.SevCritical
		}
		return model.VerdictAlert, sev
	case score >= p.WatchMinScore:
		return model.VerdictWatch, model.SevMedium
	default:
		return model.VerdictAllow, model.SevInfo
	}
}

func (d *Detector) finalize(dec *Decision, now time.Time) Decision {
	if dec.Verdict == model.VerdictAllow {
		return *dec
	}
	if dec.Verdict == model.VerdictWatch {
		// Watch does not create an incident; it is retained for aggregation.
		return *dec
	}
	inc := &model.Incident{
		ID:         fmt.Sprintf("%s-%d", d.runID, d.nextSeq()),
		Severity:   dec.Severity,
		Verdict:    dec.Verdict,
		Score:      dec.Score,
		EventTime:  dec.Event.EventTime,
		DetectedAt: now,
		LagSeconds: dec.Lag.Seconds(),
		Event:      dec.Event,
		Origin:     dec.Origin,
		Binding:    dec.Binding,
		Evidence:   dec.Evidence,
	}
	if dec.Credential != nil {
		inc.CredentialID = dec.Credential.KeyID
		inc.KeyKind = dec.Credential.KeyKind
		inc.Scope = dec.Binding.ScopeRef
		inc.IssuerKind = dec.Credential.IssuerKind
	}
	inc.RecommendedActions = recommend(dec)
	if at, reason, ok := d.creds.Actioned(dec.Event.AccessKeyID); ok {
		inc.Duplicate = true
		inc.RecommendedActions = append([]string{fmt.Sprintf("credential already actioned at %s (%s); this event predates or is concurrent with revocation", at.UTC().Format(time.RFC3339), reason)}, inc.RecommendedActions...)
	}
	dec.Incident = inc
	return *dec
}

func recommend(dec *Decision) []string {
	var out []string
	switch dec.Binding.Class {
	case model.External, model.ForeignPrincipal:
		out = append(out, "Revoke the credential and block the source address at the network edge")
		out = append(out, "Pull the full action list for this key from the audit log for the credential's lifetime")
		out = append(out, "Check whether other credentials were used from the same source address")
	default:
		out = append(out, "Review the action sequence for this key around the detection time")
	}
	if dec.Lag > 5*time.Minute {
		out = append(out, "Audit log lag is high: review everything done with this credential between theft and detection, not just the alerting call")
	}
	if dec.Credential != nil && dec.Credential.IssuerKind == model.IssuerInstance {
		out = append(out, "Inspect the instance for SSRF paths that reach the metadata service, and confirm IMDSv2 is enforced")
	}
	if dec.Credential != nil && dec.Credential.IssuerKind == model.IssuerFunction {
		out = append(out, "Check the function's environment and egress path; serverless egress is not attributable to an address")
	}
	return out
}

func (d *Detector) nextSeq() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.incidentSeq++
	return d.incidentSeq
}

func (d *Detector) recordWatch(key string, at time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.stateFor(key)
	cut := at.Add(-d.policy.WatchEscalationWindow.Duration())
	kept := st.watchCount[:0]
	for _, t := range st.watchCount {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, at)
	st.watchCount = kept
	return len(st.watchCount)
}

func (d *Detector) recordOrigin(key string, o model.Origin, ev model.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.stateFor(key)
	sig := originSig(o)
	if _, ok := st.origins[sig]; !ok {
		st.origins[sig] = ev.EventTime
	}
	if ev.UserAgent != "" {
		st.userAgents[ev.UserAgent] = true
	}
	st.events = append(st.events, eventMark{at: ev.EventTime, origin: sig, exact: o.Specificity == model.SpecExact})
	if len(st.events) > d.maxEvents {
		st.events = st.events[len(st.events)-d.maxEvents:]
	}
	if st.firstSeen.IsZero() {
		st.firstSeen = ev.EventTime
	}
	if ev.EventTime.After(st.lastSeen) {
		st.lastSeen = ev.EventTime
	}
}

func (d *Detector) userAgentKnown(key, ua string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.state[key]
	if !ok {
		return false
	}
	return st.userAgents[ua]
}

func (d *Detector) concurrencyConflict(key string, o model.Origin, at time.Time) bool {
	// Only exact origins establish "two different machines"; shared egress
	// cannot distinguish concurrent legitimate load from theft.
	if o.Specificity != model.SpecExact {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.state[key]
	if !ok {
		return false
	}
	sig := originSig(o)
	cut := at.Add(-d.policy.ConcurrencyWindow.Duration())
	for _, e := range st.events {
		// Only two *exact* origins establish separate machines. An earlier
		// unresolved or shared origin must not count: that is precisely the
		// false-positive shape where one stolen call from an unknown address
		// makes every later legitimate call look "concurrent".
		if !e.exact {
			continue
		}
		if e.at.After(cut) && e.origin != sig {
			return true
		}
	}
	return false
}

func (d *Detector) stateFor(key string) *keyState {
	st, ok := d.state[key]
	if !ok {
		st = &keyState{origins: map[string]time.Time{}, userAgents: map[string]bool{}}
		d.state[key] = st
	}
	return st
}

func originSig(o model.Origin) string {
	switch o.Kind {
	case model.OriginInstance:
		return "inst:" + o.InstanceID
	case model.OriginFleetPod:
		return "pod:" + o.FleetID + ":" + o.InstanceID
	case model.OriginFunctionENI:
		return "fn:" + o.FunctionID
	case model.OriginNAT:
		return "nat:" + o.NATGatewayID
	case model.OriginProxy:
		return "proxy:" + o.ProxyID
	case model.OriginCloudService:
		return "svc:" + o.CloudService
	default:
		return "unknown"
	}
}

func scopeRef(c *model.Credential) string {
	if c == nil {
		return ""
	}
	return string(c.Scope.Kind) + ":" + c.Scope.ID
}

// isTemporaryKey recognizes provider key formats that are always temporary
// session keys. A key of this shape that has no issuance record means the
// issuance feed is incomplete or lagging — worth watching, never enough to
// revoke, because there is no session record to revoke.
func isTemporaryKey(k string) bool {
	// AWS STS access keys start with ASIA. Other prefixes (AIDA, AROA, ...)
	// are long-lived IAM identities and must not be treated as sessions.
	return len(k) >= 4 && strings.HasPrefix(k, "ASIA")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SweepState bounds detector memory for keys that have gone quiet.
func (d *Detector) SweepState(now time.Time, idle time.Duration) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for k, st := range d.state {
		if st.lastSeen.IsZero() || now.Sub(st.lastSeen) > idle {
			delete(d.state, k)
			n++
		}
	}
	return n
}

// SnapshotSorted is a test helper that returns evidence sorted by descending
// score, which is also the order used when rendering incidents.
func SnapshotSorted(ev []model.Evidence) []model.Evidence {
	out := append([]model.Evidence(nil), ev...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}
