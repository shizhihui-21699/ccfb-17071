// Package model holds the canonical, provider-neutral data types used by the
// whole service: audit events, credential issuance records, network
// attribution results and verdicts.
package model

import (
	"net/netip"
	"strings"
	"time"
)

type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

// Event is one normalized API call taken from a cloud audit log.
//
// The fields are deliberately split into two classes by the detection engine:
//
//	Trusted   - values the cloud control plane wrote itself and the caller
//	            cannot influence: EventTime, SourceIP (as recorded by the
//	            provider), InvokedBy, VPCEndpointID, AccessKeyID, AccountID,
//	            EventName/EventSource, TLS material attested by the provider.
//	Untrusted - values supplied by the calling client: UserAgent, any header,
//	            request parameters.
//
// Only trusted fields may clear a suspicion. Untrusted fields may add to one.
type Event struct {
	ID         string    `json:"id"`
	Provider   Provider  `json:"provider"`
	AccountID  string    `json:"account_id,omitempty"`
	Region     string    `json:"region,omitempty"`
	EventTime  time.Time `json:"event_time"`
	IngestTime time.Time `json:"ingest_time,omitempty"`

	// EventSource/EventName are the provider-native coordinates, e.g.
	// "s3.amazonaws.com" / "GetObject". Action is the normalized
	// "service:name" form used by policy matching, e.g. "s3:GetObject".
	EventSource string `json:"event_source,omitempty"`
	EventName   string `json:"event_name,omitempty"`
	Action      string `json:"action,omitempty"`
	ReadOnly    bool   `json:"read_only,omitempty"`

	// AccessKeyID is the correlation key for AWS STS sessions. For providers
	// whose temporary credentials are bearer tokens (Azure managed identity,
	// GCP metadata server) it carries the best available principal-scoped
	// identifier and KeyKind on the Credential record tells the engine how
	// precise the correlation is.
	AccessKeyID string `json:"access_key_id,omitempty"`
	PrincipalID string `json:"principal_id,omitempty"`
	SessionName string `json:"session_name,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	// InvokedBy is set by the provider when one cloud service calls another on
	// the customer's behalf (CloudTrail userIdentity.invokedBy). It is
	// trustworthy and must not be confused with UserAgent.
	InvokedBy     string `json:"invoked_by,omitempty"`
	VPCEndpointID string `json:"vpc_endpoint_id,omitempty"`

	UserAgent      string `json:"user_agent,omitempty"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`

	ErrorCode string   `json:"error_code,omitempty"`
	Resources []string `json:"resources,omitempty"`
	TraceID   string   `json:"trace_id,omitempty"`
}

// IP returns the parsed source address; the zero Addr means "not recorded".
func (e *Event) IP() netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(e.SourceIP))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// KeyKind says how precisely a credential identifier maps to a session.
type KeyKind string

const (
	// KeyExactSession is a real temporary-session key (AWS ASIA* access key,
	// GCP OAuth token id when the log carries one). One key == one session,
	// so a single offending call can be attributed and that session revoked.
	KeyExactSession KeyKind = "exact_session"
	// KeyPrincipal scopes the record to a principal (Azure object id, GCP
	// service account) rather than a single token. Concurrent uses are
	// normal; revocation must target the principal or a deny rule rather
	// than "the session".
	KeyPrincipal KeyKind = "principal"
)

// IssuerKind describes what kind of workload a credential was minted for.
type IssuerKind string

const (
	IssuerInstance IssuerKind = "instance"
	IssuerFleet    IssuerKind = "fleet"    // EKS/ECS/self-managed containers
	IssuerFunction IssuerKind = "function" // serverless
	IssuerRole     IssuerKind = "role"
	IssuerUser     IssuerKind = "user"
	IssuerUnknown  IssuerKind = "unknown"
)

// ScopeKind decides which network origins are legitimate for a credential.
type ScopeKind string

const (
	ScopeInstance ScopeKind = "instance"
	ScopeFleet    ScopeKind = "fleet"
	ScopeFunction ScopeKind = "function"
	ScopeRole     ScopeKind = "role"
	ScopeUser     ScopeKind = "user"
)

// Scope is the set of principals the credential is allowed to be used by.
type Scope struct {
	Kind ScopeKind `json:"kind"`
	ID   string    `json:"id"`

	// AllowSharedEgress permits calls that surface as the NAT/EIP shared by
	// the scope's subnet. Necessary in most VPCs, but it dilutes attribution:
	// a call from the shared NAT is "inside the account", not "from this
	// instance". Enable attestation (Scope.RequireAttestation) if that gap
	// matters for your workloads.
	AllowSharedEgress bool `json:"allow_shared_egress"`

	// AllowProviderEgress permits origins the provider itself owns and cannot
	// be tied to the workload, e.g. Lambda executions outside a VPC, whose
	// traffic leaves from AWS-owned addresses. Origin is still recorded and
	// still contributes soft evidence.
	AllowProviderEgress bool `json:"allow_provider_egress"`

	// TrustedProxies lists proxy IDs (from the inventory) that are known to
	// forward this scope's traffic.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// ExtraCIDRs are statically declared egress ranges (corporate proxy pool,
	// dedicated NAT EIPs, ...). Unlike AllowProviderEgress these are still
	// tied to the scope, so a match here is a strong benign signal.
	ExtraCIDRs []string `json:"extra_cidrs,omitempty"`

	// RequireAttestation demands a matching local attestation for egress that
	// is not attributable exactly (shared NAT, provider egress). See
	// internal/attest.
	RequireAttestation bool `json:"require_attestation"`
}

// Credential is the issuance record for one set of temporary credentials.
type Credential struct {
	KeyID   string  `json:"key_id"`
	KeyKind KeyKind `json:"key_kind"`

	Provider       Provider `json:"provider"`
	AccountID      string   `json:"account_id,omitempty"`
	Region         string   `json:"region,omitempty"`
	RoleARN        string   `json:"role_arn,omitempty"`
	PrincipalID    string   `json:"principal_id,omitempty"`
	SessionName    string   `json:"session_name,omitempty"`
	SourceIdentity string   `json:"source_identity,omitempty"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	IssuerKind IssuerKind `json:"issuer_kind"`
	IssuerID   string     `json:"issuer_id,omitempty"`
	Scope      Scope      `json:"scope"`

	// Canary marks decoy credentials that no legitimate workload ever uses.
	// Any call with one is proof of compromise.
	Canary bool `json:"canary,omitempty"`

	// BaselineActions are glob patterns of actions this workload normally
	// performs, e.g. "s3:GetObject", "sqs:*". Empty means "no baseline".
	BaselineActions []string `json:"baseline_actions,omitempty"`

	Tags map[string]string `json:"tags,omitempty"`
}

// Expired reports whether the credentials are past their lifetime, allowing a
// grace window for clock skew and provider-side propagation.
func (c *Credential) Expired(t time.Time, grace time.Duration) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return t.After(c.ExpiresAt.Add(grace))
}

// OriginKind is what a source address turns out to be after resolution against
// inventory and provider metadata.
type OriginKind string

const (
	OriginInstance         OriginKind = "instance"          // an instance's own address
	OriginFleetPod         OriginKind = "fleet_pod"         // pod IP or host-network node IP
	OriginFunctionENI      OriginKind = "function_eni"      // serverless VPC ENI address
	OriginNAT              OriginKind = "nat"               // NAT gateway / EIP
	OriginProxy            OriginKind = "proxy"             // registered forward proxy
	OriginVPCEndpoint      OriginKind = "vpc_endpoint"      // provider VPC endpoint ENI
	OriginCloudService     OriginKind = "cloud_service"     // provider service (invokedBy)
	OriginProviderInternal OriginKind = "provider_internal" // provider-owned, unattributable
	OriginAccountOther     OriginKind = "account_other"     // other account resource
	OriginUnknown          OriginKind = "unknown"
)

// Specificity says how strongly an origin identifies the calling workload.
type Specificity string

const (
	SpecExact     Specificity = "exact"     // one instance/pod/function
	SpecScoped    Specificity = "scoped"    // a bounded group (fleet node, function ENIs)
	SpecAmbiguous Specificity = "ambiguous" // shared NAT/proxy pool
	SpecNone      Specificity = "none"
)

// Origin is the network attribution of one event's source address.
type Origin struct {
	Kind        OriginKind  `json:"kind"`
	Specificity Specificity `json:"specificity"`
	Zone        string      `json:"zone"` // "account", "provider", "external"

	InstanceID   string `json:"instance_id,omitempty"`
	FleetID      string `json:"fleet_id,omitempty"`
	FunctionID   string `json:"function_id,omitempty"`
	ProxyID      string `json:"proxy_id,omitempty"`
	CloudService string `json:"cloud_service,omitempty"`
	NATGatewayID string `json:"nat_gateway_id,omitempty"`
	SubnetID     string `json:"subnet_id,omitempty"`
	AccountID    string `json:"account_id,omitempty"`

	Blocklisted bool   `json:"blocklisted,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// BindingClass is the outcome of comparing an Origin with a Credential scope.
type BindingClass string

const (
	BoundDirect            BindingClass = "bound_direct"
	BoundSharedEgress      BindingClass = "bound_shared_egress"
	BoundViaProxy          BindingClass = "bound_via_proxy"
	BoundService           BindingClass = "bound_service"
	BoundProviderEgress    BindingClass = "bound_provider_egress" // tolerated, unattributable
	BoundUnanchored        BindingClass = "bound_unanchored"      // scope has no network expectation at all
	ForeignPrincipal       BindingClass = "foreign_principal"     // resolved to someone else we know
	UnexplainedInternal    BindingClass = "unexplained_internal"  // provider/account internal, unmatched
	External               BindingClass = "external"              // outside every known path
	ExpiredCredential      BindingClass = "expired_credential"
	UnregisteredCredential BindingClass = "unregistered_credential"
	NoNetworkEvidence      BindingClass = "no_network_evidence"
)

// BindingResult is the scope-vs-origin decision plus its justification.
type BindingResult struct {
	Class       BindingClass `json:"class"`
	Reason      string       `json:"reason"`
	ScopeRef    string       `json:"scope_ref,omitempty"`
	Specificity Specificity  `json:"specificity"`
}

// NetworkBound reports whether the origin is consistent with the credential's
// scope. It is not the same as "safe": BoundSharedEgress and
// BoundProviderEgress are consistent but unattributable, and the engine weighs
// them accordingly.
func (b BindingResult) NetworkBound() bool {
	switch b.Class {
	case BoundDirect, BoundSharedEgress, BoundViaProxy, BoundService, BoundProviderEgress, BoundUnanchored:
		return true
	default:
		return false
	}
}

// Conclusive says the binding decision was based on precise correlation
// rather than "we have no expectation either way".
func (b BindingResult) Conclusive() bool {
	return b.Class != BoundUnanchored
}

type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictWatch  Verdict = "watch"
	VerdictAlert  Verdict = "alert"
	VerdictRevoke Verdict = "revoke"
)

// Severity is the user-facing incident priority.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Evidence is one scored observation that contributed to a verdict.
type Evidence struct {
	Rule    string            `json:"rule"`
	Detail  string            `json:"detail"`
	Score   int               `json:"score"`
	Hard    bool              `json:"hard,omitempty"`
	Trusted bool              `json:"trusted"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// Incident is emitted for verdicts that need human or automated attention.
type Incident struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Verdict  Verdict  `json:"verdict"`
	Score    int      `json:"score"`

	CredentialID string     `json:"credential_id"`
	KeyKind      KeyKind    `json:"key_kind,omitempty"`
	Scope        string     `json:"scope,omitempty"`
	IssuerKind   IssuerKind `json:"issuer_kind,omitempty"`

	EventTime  time.Time `json:"event_time"`
	DetectedAt time.Time `json:"detected_at"`
	// LagSeconds is how stale the audit log was when we saw it. Recorded on
	// every incident because it bounds what revocation can still salvage.
	LagSeconds float64 `json:"lag_seconds"`

	Event    Event         `json:"event"`
	Origin   Origin        `json:"origin"`
	Binding  BindingResult `json:"binding"`
	Evidence []Evidence    `json:"evidence"`

	Revocation         *RevocationResult `json:"revocation,omitempty"`
	RecommendedActions []string          `json:"recommended_actions,omitempty"`
	// Duplicate marks a repeat incident for a credential that was already
	// actioned; alerting still fires at low priority for timeline purposes.
	Duplicate bool `json:"duplicate,omitempty"`
}

// RevocationResult records what the response stage actually did.
type RevocationResult struct {
	Performed   bool      `json:"performed"`
	Skipped     bool      `json:"skipped,omitempty"`
	SkipReason  string    `json:"skip_reason,omitempty"`
	Mechanism   string    `json:"mechanism,omitempty"`
	Reference   string    `json:"reference,omitempty"`
	PerformedAt time.Time `json:"performed_at,omitempty"`
	Error       string    `json:"error,omitempty"`
	// PolicyDocument is populated by the deny-policy mechanism so an operator
	// (or an automation job) can apply it without re-deriving the conditions.
	PolicyDocument string `json:"policy_document,omitempty"`
}
