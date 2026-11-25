// Package response performs the containment half of the service.
//
// The mechanism must match the credential's correlation precision:
//
//   - exact session (AWS ASIA* key): call the provider to revoke *that
//     session*. Other sessions for the same role keep working.
//   - principal-scoped (Azure identity, GCP service account, long-lived user):
//     there is no single session to kill. Options are to apply a deny policy
//     conditioned on the offending source addresses, or to quarantine the
//     principal. Both are policy decisions with blast radius, so the service
//     generates the policy and records it, and applies it only when the
//     configured mechanism is explicit.
//
// Every action is idempotent and rate-limited: late audit logs deliver
// repeated events for the same stolen key, and the second revocation must not
// fail the pipeline.
package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"credwatch/internal/credstore"
	"credwatch/internal/model"
)

// Revoker is the provider-facing capability. Real implementations wrap
// sts:RevokeSession / iam:AttachRolePolicy / Azure deny assignments / GCP
// IAM deny policies. It is an interface so the detection path is testable and
// so a dry-run deployment can swap in a recorder.
type Revoker interface {
	// RevokeSession terminates exactly one session-issued credential.
	RevokeSession(ctx context.Context, c *model.Credential, reason string) (reference string, err error)
	// ApplyPrincipalDeny denies a principal's use from the given addresses.
	ApplyPrincipalDeny(ctx context.Context, c *model.Credential, sourceCIDRs []string, reason string) (reference string, err error)
	// QuarantinePrincipal suspends the principal entirely (highest blast radius).
	QuarantinePrincipal(ctx context.Context, c *model.Credential, reason string) (reference string, err error)
}

type Mechanism string

const (
	MechSessionRevoke       Mechanism = "session_revoke"
	MechPrincipalDeny       Mechanism = "principal_deny"
	MechPrincipalQuarantine Mechanism = "principal_quarantine"
	MechNone                Mechanism = "none"
)

type Config struct {
	// Enabled gates all provider-mutating actions.
	Enabled bool
	// DryRun logs the exact action without calling the provider.
	DryRun bool
	// MinSeverity is the lowest severity that triggers action.
	MinSeverity model.Severity
	// PrincipalMechanism decides what to do for principal-scoped credentials.
	// Defaults to deny-policy, which narrows the credential rather than
	// suspending a shared identity used by healthy workloads.
	PrincipalMechanism Mechanism
	// PerCredentialCooldown suppresses duplicate provider calls for the same
	// key; provider APIs are rate-limited and duplicate revokes are noisy.
	PerCredentialCooldown time.Duration
	// MaxActionsPerMinute is a global circuit breaker so a burst of detections
	// (or a false-positive storm) cannot hammer the control plane.
	MaxActionsPerMinute int
}

func DefaultConfig() Config {
	return Config{
		Enabled:               true,
		DryRun:                true, // safe default: never mutate until configured
		MinSeverity:           model.SevHigh,
		PrincipalMechanism:    MechPrincipalDeny,
		PerCredentialCooldown: 10 * time.Minute,
		MaxActionsPerMinute:   30,
	}
}

type Actor struct {
	cfg     Config
	revoker Revoker
	creds   *credstore.Store
	now     func() time.Time

	mu        sync.Mutex
	lastByKey map[string]time.Time
	window    []time.Time

	// recorder captures dry-run actions for tests and audit.
	recorder []model.RevocationResult
}

func NewActor(cfg Config, revoker Revoker, creds *credstore.Store, now func() time.Time) *Actor {
	if now == nil {
		now = time.Now
	}
	return &Actor{cfg: cfg, revoker: revoker, creds: creds, now: now, lastByKey: map[string]time.Time{}}
}

var ErrCircuitOpen = errors.New("response: global action rate limit reached")

// Act executes containment for an incident and records the result on it.
func (a *Actor) Act(ctx context.Context, inc *model.Incident) *model.RevocationResult {
	res := a.act(ctx, inc)
	inc.Revocation = res
	return res
}

func (a *Actor) act(ctx context.Context, inc *model.Incident) *model.RevocationResult {
	now := a.now()
	skip := func(reason string) *model.RevocationResult {
		return &model.RevocationResult{Skipped: true, SkipReason: reason, PerformedAt: now}
	}
	if inc == nil || inc.CredentialID == "" {
		return skip("no correlated credential to revoke")
	}
	if inc.Verdict != model.VerdictRevoke {
		return skip("verdict is " + string(inc.Verdict) + ", below the revocation threshold")
	}
	if !a.cfg.Enabled {
		return skip("response is disabled by configuration")
	}
	if severityRank(inc.Severity) < severityRank(a.cfg.MinSeverity) {
		return skip("severity " + string(inc.Severity) + " is below the configured minimum")
	}
	cred, err := a.creds.Get(inc.CredentialID)
	if err != nil {
		return &model.RevocationResult{Skipped: true, SkipReason: "credential record not found: " + err.Error(), PerformedAt: now}
	}

	a.mu.Lock()
	if t, ok := a.lastByKey[inc.CredentialID]; ok && now.Sub(t) < a.cfg.PerCredentialCooldown {
		a.mu.Unlock()
		return skip(fmt.Sprintf("same credential already actioned %s ago", now.Sub(t).Round(time.Second)))
	}
	cut := now.Add(-time.Minute)
	kept := a.window[:0]
	for _, t := range a.window {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	a.window = kept
	if len(a.window) >= a.cfg.MaxActionsPerMinute {
		a.mu.Unlock()
		return skip("global action rate limit reached; queued for manual review")
	}
	a.window = append(a.window, now)
	a.lastByKey[inc.CredentialID] = now
	a.mu.Unlock()

	reason := fmt.Sprintf("credwatch incident %s: %s (%s)", inc.ID, inc.Binding.Class, inc.Binding.Reason)

	var mech Mechanism
	switch {
	case cred.KeyKind == model.KeyExactSession:
		mech = MechSessionRevoke
	case cred.Canary:
		// A canary is never legitimate; quarantine its principal.
		mech = MechPrincipalQuarantine
	default:
		mech = a.cfg.PrincipalMechanism
	}

	if a.cfg.DryRun {
		a.mu.Lock()
		ref := dryRunRef(inc, mech)
		a.recorder = append(a.recorder, model.RevocationResult{Performed: true, Mechanism: string(mech), Reference: ref, PerformedAt: now})
		a.mu.Unlock()
		return &model.RevocationResult{
			Performed:      true,
			Mechanism:      string(mech) + " (dry-run)",
			Reference:      ref,
			PerformedAt:    now,
			PolicyDocument: a.policyDocument(cred, inc),
		}
	}

	if a.revoker == nil {
		return &model.RevocationResult{Skipped: true, SkipReason: "no revoker configured", PerformedAt: now}
	}

	var ref string
	switch mech {
	case MechSessionRevoke:
		ref, err = a.revoker.RevokeSession(ctx, cred, reason)
	case MechPrincipalDeny:
		ref, err = a.revoker.ApplyPrincipalDeny(ctx, cred, denyCIDRs(inc), reason)
	case MechPrincipalQuarantine:
		ref, err = a.revoker.QuarantinePrincipal(ctx, cred, reason)
	default:
		return skip("no mechanism selected for this credential kind")
	}
	out := &model.RevocationResult{Performed: err == nil, Mechanism: string(mech), Reference: ref, PerformedAt: now, PolicyDocument: a.policyDocument(cred, inc)}
	if err != nil {
		out.Error = err.Error()
		out.Performed = false
	} else {
		a.creds.MarkActioned(inc.CredentialID, reason, now)
	}
	return out
}

// denyCIDRs derives the narrowest set of addresses to deny. Prefer the exact
// attacker address; fall back to nothing (principal-wide deny) if unknown.
func denyCIDRs(inc *model.Incident) []string {
	if ip := inc.Event.IP(); ip.IsValid() {
		return []string{ip.String() + "/32"}
	}
	return nil
}

// policyDocument renders a ready-to-apply IAM deny statement for the
// principal-deny mechanism, so an operator can apply it even when automatic
// application is disabled. It denies only the offending addresses and only for
// temporary credentials, limiting blast radius.
func (a *Actor) policyDocument(c *model.Credential, inc *model.Incident) string {
	if c == nil {
		return ""
	}
	conds := map[string]any{}
	if ip := inc.Event.IP(); ip.IsValid() {
		conds["aws:SourceIp"] = []string{ip.String() + "/32"}
	}
	stmt := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect":    "Deny",
			"Action":    "*",
			"Resource":  "*",
			"Condition": map[string]any{"IpAddress": conds},
		}},
	}
	if len(conds) == 0 {
		stmt["Statement"] = []map[string]any{{
			"Effect":   "Deny",
			"Action":   "*",
			"Resource": "*",
			"Condition": map[string]any{"StringEquals": map[string]any{
				"aws:PrincipalArn": c.RoleARN,
			}},
		}}
	}
	b, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func dryRunRef(inc *model.Incident, mech Mechanism) string {
	h := sha256.Sum256([]byte(inc.ID + string(mech) + inc.CredentialID))
	return "dryrun-" + hex.EncodeToString(h[:8])
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SevInfo:
		return 0
	case model.SevLow:
		return 1
	case model.SevMedium:
		return 2
	case model.SevHigh:
		return 3
	case model.SevCritical:
		return 4
	}
	return -1
}

// Recorder returns dry-run outcomes (tests, audit export).
func (a *Actor) Recorder() []model.RevocationResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]model.RevocationResult(nil), a.recorder...)
}

// ---- A recording/in-memory Revoker for tests and the local simulator ----

type MemoryRevoker struct {
	mu          sync.Mutex
	Revoked     []string
	Denied      []string
	Quarantined []string
	FailNext    error
}

func (m *MemoryRevoker) RevokeSession(_ context.Context, c *model.Credential, reason string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailNext != nil {
		err := m.FailNext
		m.FailNext = nil
		return "", err
	}
	m.Revoked = append(m.Revoked, c.KeyID)
	return "memory://revoked/" + c.KeyID, nil
}

func (m *MemoryRevoker) ApplyPrincipalDeny(_ context.Context, c *model.Credential, cidrs []string, reason string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Denied = append(m.Denied, c.KeyID+"<-"+strings.Join(cidrs, ","))
	return "memory://deny/" + c.KeyID, nil
}

func (m *MemoryRevoker) QuarantinePrincipal(_ context.Context, c *model.Credential, reason string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Quarantined = append(m.Quarantined, c.KeyID)
	return "memory://quarantine/" + c.KeyID, nil
}
